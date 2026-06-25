// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

// ─────────────────────────────────────────────────────────────────────────────
// Red-team exploit tests — ROUND 2
//
// Covers new attack surface introduced by the 13 post-v1 security fixes:
//   • collectFees: recipient now pulled from IFeePolicy.feeRecipient()
//   • MandateFactory.receive() reverts unless msg.sender == kernel
//   • MAX_ALLOWLIST_LENGTH = 50 (OOG / duplicate checks)
//   • rotateEmergencyAdmin() timelocked rotation
//   • replacePermission: existence check before nonce increment
//   • Cross-template interaction attacks
//   • registerAccount front-run deeper variants
//   • Bundle ordering attacks
//
// Run with:
//   forge test --match-path "test/redteam/*" -vvv
// ─────────────────────────────────────────────────────────────────────────────

import "forge-std/Test.sol";
import "forge-std/console.sol";

import {SailKernel}                  from "../../contracts/core/SailKernel.sol";
import {SailGovernance}              from "../../contracts/governance/SailGovernance.sol";
import {TimelockDeployer}            from "../support/TimelockDeployer.sol";
import {MandateFactory}           from "../../contracts/factory/MandateFactory.sol";
import {StandardFeePolicy}           from "../../contracts/policies/StandardFeePolicy.sol";
import {ConfigurablePermission}        from "../../contracts/templates/ConfigurablePermission.sol";
import {IPermission, Context}        from "../../contracts/interfaces/IPermission.sol";
import {IFeePolicy}                  from "../../contracts/interfaces/IFeePolicy.sol";
import {IOracle}                     from "../../contracts/interfaces/IOracle.sol";
import {TimelockController}          from "@openzeppelin/contracts/governance/TimelockController.sol";

// ─────────────────────────────────────────────────────────────────────────────
// Shared mocks
// ─────────────────────────────────────────────────────────────────────────────

contract MockSafe2 {
    // Octane group 1a test support: a finalized Safe reports nonce>=1 (setup never bumps it)
    // and exposes its trusted singleton via masterCopy() (intercepted by a real SafeProxy fallback).
    function nonce() external pure returns (uint256) { return 1; }
    function masterCopy() external pure returns (address) { return address(0x5AFE); }

    mapping(address => bool) public moduleEnabled;
    bool public execSucceeds = true;
    uint256 public execCallCount;

    receive() external payable {}

    function enableModule(address m) external { moduleEnabled[m] = true; }
    function isModuleEnabled(address m) external view returns (bool) { return moduleEnabled[m]; }
    function setExecSucceeds(bool v) external { execSucceeds = v; }

    function execTransactionFromModule(address to, uint256 value, bytes calldata data, uint8)
        external
        returns (bool)
    {
        execCallCount++;
        if (!execSucceeds) return false;
        if (value > 0 && data.length == 0) {
            (bool ok,) = payable(to).call{value: value}("");
            return ok;
        }
        return true;
    }
}

contract AlwaysTruePerm2 is IPermission {
    function evaluate(bytes calldata, Context calldata) external pure returns (bool) { return true; }
    function discriminator() external pure returns (bytes32) { return keccak256("AlwaysTrue2"); }
}

/// @dev A fee policy that lets its feeRecipient be changed by the deployer after construction.
///      Models a compromised/malleable policy.
contract MutableRecipientFeePolicy is IFeePolicy {
    address public recipient;
    uint256 public maxFee_;

    constructor(address _recipient, uint256 _maxFee) {
        recipient = _recipient;
        maxFee_   = _maxFee;
    }

    function setRecipient(address r) external { recipient = r; }

    function feeRecipient() external view returns (address) { return recipient; }

    function computeFee(address, uint256) external view returns (uint256, address, uint256) {
        return (maxFee_, address(0), 0);
    }

    function recordCollection(address, uint256, uint256) external {}
}

contract ManipulableOracle2 is IOracle {
    uint256 public price;
    uint8   public dec;
    constructor(uint256 _p, uint8 _d) { price = _p; dec = _d; }
    function setPrice(uint256 p) external { price = p; }
    function getPrice(address, address) external view returns (uint256, uint8, uint256) { return (price, dec, block.timestamp); }
}

// ─────────────────────────────────────────────────────────────────────────────
// Base setup — mirrors RedTeamBase from RedTeam.t.sol
// ─────────────────────────────────────────────────────────────────────────────
abstract contract RedTeamBase2 is Test {
    uint256 internal constant PERM_SIGNER_KEY = 0xA11CE;
    uint256 internal constant MANAGER_KEY     = 0xB0B;
    uint256 internal constant ATTACKER_KEY    = 0xDEAD;

    address internal permSigner;
    address internal manager;
    address internal attacker;

    address internal constant TREASURY = address(0xAAAA);

    SailGovernance    internal gov;
    SailKernel        internal kernel;
    MandateFactory internal factory;
    MockSafe2         internal safe;
    AlwaysTruePerm2   internal alwaysTrue;

    function setUp() public virtual {
        permSigner = vm.addr(PERM_SIGNER_KEY);
        manager    = vm.addr(MANAGER_KEY);
        attacker   = vm.addr(ATTACKER_KEY);

        vm.deal(address(this), 1000 ether);
        vm.deal(attacker,      100 ether);

        gov = new SailGovernance(address(this), 0.001 ether, address(this), 0, TimelockDeployer.deploy(address(this)));
        vm.startPrank(address(gov.timelock()));
        gov.setProtocolCutBps(1_000);
        gov.setPermissionRegistrationFee(0.001 ether);
        vm.stopPrank();

        kernel  = new SailKernel(address(gov), TREASURY);
        factory = new MandateFactory(address(kernel));

        safe = new MockSafe2();
        safe.enableModule(address(kernel));
        vm.deal(address(safe), 100 ether);

        // registerAccount requires an allowlisted Safe-proxy codehash (Octane #4a). One seed
        // covers all MockSafe2 instances (targetSafe/newSafe/unregisteredSafe).
        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeProxyCodehash(address(safe).codehash, true);
        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeSingleton(address(0x5AFE), true); // Octane #9: trust the mock singleton

        vm.prank(address(safe));
        kernel.registerAccount(permSigner, manager, address(0), address(0));

        alwaysTrue = new AlwaysTruePerm2();
    }

    // ── Signature helpers ─────────────────────────────────────────────────────

    function _signRegisterPermission(address account, address permission, uint256 nonce, uint256 signerKey)
        internal view returns (bytes memory)
    {
        uint256 deadline = block.timestamp + 1 days;
        bytes32 sh = keccak256(abi.encode(
            kernel.REGISTER_PERMISSION_TYPEHASH(), account, permission, nonce, deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }

    function _signRevokePermission(address account, address permission, uint256 nonce, uint256 signerKey)
        internal view returns (bytes memory)
    {
        uint256 deadline = block.timestamp + 1 days;
        bytes32 sh = keccak256(abi.encode(
            kernel.REVOKE_PERMISSION_TYPEHASH(), account, permission, nonce, deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }

    function _signReplacePermission(address account, address oldP, address newP, uint256 nonce, uint256 signerKey)
        internal view returns (bytes memory)
    {
        uint256 deadline = block.timestamp + 1 days;
        bytes32 sh = keccak256(abi.encode(
            kernel.REPLACE_PERMISSION_TYPEHASH(), account, oldP, newP, nonce, deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }

    function _signDispatch(
        address account,
        address permission,
        address target,
        uint256 value,
        bytes memory data,
        uint256 nonce,
        uint256 deadline,
        uint256 signerKey
    ) internal view returns (bytes memory) {
        bytes32 sh = keccak256(abi.encode(
            kernel.DISPATCH_TYPEHASH(), account, permission, target, value, keccak256(data), nonce, deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }

    function _signSetFeePolicy(address account, address newFeePolicy, uint256 nonce, uint256 signerKey)
        internal view returns (bytes memory)
    {
        uint256 deadline = type(uint256).max;
        bytes32 sh = keccak256(abi.encode(kernel.SET_FEE_POLICY_TYPEHASH(), account, newFeePolicy, address(0), nonce, deadline));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }

    function _trustFeePolicy(address policy) internal {
        vm.prank(address(gov.timelock()));
        gov.setTrustedFeePolicy(policy, true);
    }

    function _signSetFeePolicyWithAsset(
        address account, address newFeePolicy, address feeAsset, uint256 nonce, uint256 signerKey
    ) internal view returns (bytes memory) {
        uint256 deadline = type(uint256).max;
        bytes32 sh = keccak256(abi.encode(kernel.SET_FEE_POLICY_TYPEHASH(), account, newFeePolicy, feeAsset, nonce, deadline));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }

    function _signRegisterPermissions(
        address account,
        address[] memory permissions,
        uint256 nonce,
        uint256 deadline,
        uint256 signerKey
    ) internal view returns (bytes memory) {
        // Must reproduce _hashAddressArray from the kernel
        bytes32[] memory buf = new bytes32[](permissions.length);
        for (uint256 i; i < permissions.length; i++) {
            buf[i] = bytes32(uint256(uint160(permissions[i])));
        }
        bytes32 arrHash = keccak256(abi.encodePacked(buf));
        bytes32 sh = keccak256(abi.encode(
            kernel.REGISTER_PERMISSIONS_TYPEHASH(), account, arrHash, nonce, deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }

    function _registerAlwaysTrue() internal {
        uint256 nonce = kernel.signerNonces(address(safe));
        uint256 deadline = block.timestamp + 1 days;
        bytes memory sig = _signRegisterPermission(address(safe), address(alwaysTrue), nonce, PERM_SIGNER_KEY);
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(alwaysTrue), deadline, sig);
    }

    receive() external payable {}
}

// =============================================================================
// SECTION 11 — feeRecipient() path after fix
// =============================================================================
contract FeeRecipientFixTests is RedTeamBase2 {

    // ── 11a. Manager cannot supply a custom recipient anymore — must come from policy ──
    //   Before the fix, collectFees accepted a `recipient` param.
    //   Now: recipient = IFeePolicy.feeRecipient(). Manager has no say.
    //   Test that a manager cannot redirect fees by deploying a custom policy whose
    //   feeRecipient they control and then swapping it in.

    function test_Attack_FeeRecipient_ManagerRedirectionViaPolicy() public {
        // Attacker-controlled policy: feeRecipient == attacker
        MutableRecipientFeePolicy badPolicy = new MutableRecipientFeePolicy(attacker, 10 ether);
        _trustFeePolicy(address(badPolicy));

        // permSigner (trust anchor) sets this policy
        uint256 nonce = kernel.signerNonces(address(safe));
        bytes memory fpSig = _signSetFeePolicy(address(safe), address(badPolicy), nonce, PERM_SIGNER_KEY);
        kernel.setFeePolicy(address(safe), address(badPolicy), address(0), type(uint256).max, fpSig);

        uint256 attackerBefore = attacker.balance;
        uint256 safeBefore     = address(safe).balance;

        // Manager collects 10 ether — kernel pulls recipient from policy (= attacker)
        vm.prank(manager);
        kernel.collectFees(address(safe), 10 ether, 1_000_000e18, address(0));

        // Attacker received the manager's net take (after protocol cut)
        // VULNERABILITY (documented): if permSigner installs a policy they collude with,
        // fees go directly to attacker. This is a trust-assumption issue, not a bypass.
        uint256 attackerGain = attacker.balance - attackerBefore;
        console.log("Attacker gained (via policy recipient):", attackerGain);
        assertLt(address(safe).balance, safeBefore, "Safe should lose funds");
        assertGt(attackerGain, 0, "Attacker should gain from fee redirect via policy");
    }

    // ── 11b. Zero-address feeRecipient from policy must revert ──
    //   If feeRecipient() returns address(0), kernel should revert with ZeroAddress.

    function test_Attack_FeeRecipient_ZeroAddressFromPolicy() public {
        // Deploy a policy whose feeRecipient returns address(0)
        MutableRecipientFeePolicy zeroPolicy = new MutableRecipientFeePolicy(address(0), 1 ether);
        _trustFeePolicy(address(zeroPolicy));

        uint256 nonce = kernel.signerNonces(address(safe));
        bytes memory fpSig = _signSetFeePolicy(address(safe), address(zeroPolicy), nonce, PERM_SIGNER_KEY);
        kernel.setFeePolicy(address(safe), address(zeroPolicy), address(0), type(uint256).max, fpSig);

        // collectFees should revert when feeRecipient() == address(0)
        vm.prank(manager);
        vm.expectRevert(SailKernel.ZeroAddress.selector);
        kernel.collectFees(address(safe), 1 ether, 1_000_000e18, address(0));
    }

    // ── 11c. Policy with mutable feeRecipient: can manager front-run the recipient mid-tx? ──
    //   The policy's feeRecipient is read inside collectFees. If the policy stores a
    //   mutable recipient and the manager controls the policy contract (through colluding
    //   with permSigner), they can change the recipient at any time.
    //   Test that the kernel correctly uses whatever feeRecipient() returns at call time.

    function test_Attack_FeeRecipient_MidCollectionRecipientSwitch() public {
        address legitRecipient  = address(0xFACE);
        address malicRecipient  = attacker;

        MutableRecipientFeePolicy policy = new MutableRecipientFeePolicy(legitRecipient, 10 ether);
        _trustFeePolicy(address(policy));

        uint256 nonce = kernel.signerNonces(address(safe));
        bytes memory fpSig = _signSetFeePolicy(address(safe), address(policy), nonce, PERM_SIGNER_KEY);
        kernel.setFeePolicy(address(safe), address(policy), address(0), type(uint256).max, fpSig);

        // Change recipient to attacker BEFORE collectFees is called
        policy.setRecipient(malicRecipient);

        uint256 attackerBefore = attacker.balance;

        vm.prank(manager);
        kernel.collectFees(address(safe), 10 ether, 1_000_000e18, address(0));

        // Fees should flow to malicRecipient (attacker) since that was current at call time
        assertGt(attacker.balance, attackerBefore, "Fees should reach attacker via mutable recipient");
    }

    // ── 11d. StandardFeePolicy feeRecipient is the feeManager — cannot be redirected mid-collection ──
    //   Verify that for the canonical StandardFeePolicy, feeRecipient == feeManager
    //   and a manager cannot redirect by calling anything within collectFees.

    function test_Attack_StandardFeePolicy_RecipientIsImmutableFeeManager() public {
        StandardFeePolicy sfp = new StandardFeePolicy(
            0, 0, address(0), 0, address(kernel), permSigner
        );
        _trustFeePolicy(address(sfp));

        // feeRecipient() should return feeManager (permSigner here)
        assertEq(sfp.feeRecipient(), permSigner);

        uint256 nonce = kernel.signerNonces(address(safe));
        bytes memory fpSig = _signSetFeePolicy(address(safe), address(sfp), nonce, PERM_SIGNER_KEY);
        kernel.setFeePolicy(address(safe), address(sfp), address(0), type(uint256).max, fpSig);

        // H-5 fix: feeManager must seed HWM before manager can collect.
        // seedHighWaterMark now initialises lastCollectionTimestamp; no zero-fee collection needed.
        vm.prank(permSigner);
        sfp.seedHighWaterMark(address(safe), 1_000_000e18);

        // Confirm feeRecipient is still permSigner
        assertEq(sfp.feeRecipient(), permSigner, "feeRecipient should remain feeManager");
    }
}

// =============================================================================
// SECTION 12 — MandateFactory.receive() restricted
// =============================================================================
contract FactoryReceiveFixTests is RedTeamBase2 {

    // ── 12a. Attacker sends ETH to factory directly — must revert ──
    //   Before fix: factory would silently accept ETH from anyone.
    //   After fix: receive() reverts unless msg.sender == kernel.

    function test_Attack_FactoryReceive_DirectETHSend() public {
        vm.prank(attacker);
        (bool ok,) = address(factory).call{value: 1 ether}("");
        // After fix: RefundFailed should be thrown, call reverts
        assertFalse(ok, "Factory should reject ETH from non-kernel senders");
    }

    // ── 12c. Attacker cannot inflate factory balance to poison excess-refund accounting ──
    //   Before fix: attacker sends ETH to factory, inflating its balance.
    //   This would make `address(this).balance - preBalance` underestimate excess,
    //   causing the caller to lose ETH to the factory.

    function test_Attack_FactoryReceive_BalanceInflationPoisoning() public {
        // Attempt to send ETH to factory to inflate its balance
        vm.prank(attacker);
        (bool ok,) = address(factory).call{value: 1 ether}("");
        assertFalse(ok, "Factory should refuse attacker ETH");

        // Factory balance should still be 0 (or unchanged)
        assertEq(address(factory).balance, 0, "Factory balance should be zero after refused send");
    }
}

// =============================================================================
// SECTION 16 — rotateEmergencyAdmin timelocked
// =============================================================================
contract EmergencyAdminRotationTests is RedTeamBase2 {

    // ── 16a. Current emergencyAdmin cannot rotate themselves without timelock ──
    //   rotateEmergencyAdmin is onlyTimelock. The current emergencyAdmin calling it
    //   directly must revert.

    function test_Attack_RotateEmergencyAdmin_DirectCallByAdmin() public {
        // In setUp, address(this) is both governance and emergencyAdmin
        vm.expectRevert(SailGovernance.NotTimelock.selector);
        gov.rotateEmergencyAdmin(attacker);
    }

    // ── 16b. Attacker cannot rotate emergencyAdmin ──

    function test_Attack_RotateEmergencyAdmin_AttackerCannotRotate() public {
        vm.prank(attacker);
        vm.expectRevert(SailGovernance.NotTimelock.selector);
        gov.rotateEmergencyAdmin(attacker);
    }

    // ── 16c. Valid rotation via timelock succeeds ──

    function test_Attack_RotateEmergencyAdmin_ValidTimelockRotation() public {
        address newAdmin = address(0xAD111);

        // Call via timelock (address(this) has proposer role in setUp)
        vm.prank(address(gov.timelock()));
        gov.rotateEmergencyAdmin(newAdmin);

        assertEq(gov.emergencyAdmin(), newAdmin, "emergencyAdmin should be updated to newAdmin");
    }

    // ── 16d. After rotation, old admin can no longer pause ──

    function test_Attack_RotateEmergencyAdmin_OldAdminCannotPauseAfterRotation() public {
        address newAdmin = address(0xAD111);

        // Rotate via timelock
        vm.prank(address(gov.timelock()));
        gov.rotateEmergencyAdmin(newAdmin);

        // address(this) was the old admin — should be blocked now
        vm.expectRevert(SailGovernance.NotEmergencyAdmin.selector);
        gov.pause();
    }

    // ── 16e. Compromised emergency admin cannot block rotation ──
    //   Rotation goes through the 48-hour timelock — the emergencyAdmin has no veto.
    //   This test confirms that even if the emergencyAdmin tries to pause
    //   (perhaps hoping to disrupt protocol operations), rotation still succeeds.

    function test_Attack_RotateEmergencyAdmin_PausedAdminCannotBlockRotation() public {
        // Current admin pauses
        gov.pause();
        assertTrue(gov.isPaused());

        address newAdmin = address(0xAD222);
        // Timelock rotation succeeds even while paused
        vm.prank(address(gov.timelock()));
        gov.rotateEmergencyAdmin(newAdmin);

        assertEq(gov.emergencyAdmin(), newAdmin);
    }

    // ── 16f. Zero address rotation must revert ──

    function test_Attack_RotateEmergencyAdmin_ZeroAddressReverts() public {
        vm.prank(address(gov.timelock()));
        vm.expectRevert(SailGovernance.ZeroAddress.selector);
        gov.rotateEmergencyAdmin(address(0));
    }
}

// =============================================================================
// SECTION 17 — replacePermission existence check
// =============================================================================
contract ReplacePermissionTests is RedTeamBase2 {

    // ── 17a. replacePermission on non-existent oldPermission must revert before nonce bump ──
    //   Before fix: nonce was incremented before existence check → nonce burnt on failure.
    //   After fix: existence checked first → nonce only incremented if check passes.

    function test_Attack_ReplacePermission_NonExistentOldPermission() public {
        AlwaysTruePerm2 p2 = new AlwaysTruePerm2();

        // old permission is NOT registered — nonce should NOT be consumed
        uint256 nonceBefore = kernel.signerNonces(address(safe));
        uint256 replaceDeadline = block.timestamp + 1 days;
        bytes memory sig = _signReplacePermission(
            address(safe), address(alwaysTrue), address(p2), nonceBefore, PERM_SIGNER_KEY
        );

        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionNotRegistered.selector, address(alwaysTrue)));
        kernel.replacePermission{value: 0.001 ether}(address(safe), address(alwaysTrue), address(p2), replaceDeadline, sig);

        // Nonce must NOT have advanced
        assertEq(kernel.signerNonces(address(safe)), nonceBefore,
            "Nonce should NOT increment when old permission is not registered");
    }

    // ── 17b. replacePermission with newPermission already registered must revert ──

    function test_Attack_ReplacePermission_NewPermissionAlreadyRegistered() public {
        _registerAlwaysTrue();

        // Try to replace alwaysTrue with alwaysTrue itself
        uint256 nonce = kernel.signerNonces(address(safe));
        uint256 replaceDeadline = block.timestamp + 1 days;
        bytes memory sig = _signReplacePermission(
            address(safe), address(alwaysTrue), address(alwaysTrue), nonce, PERM_SIGNER_KEY
        );

        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionAlreadyRegistered.selector, address(alwaysTrue)));
        kernel.replacePermission{value: 0.001 ether}(address(safe), address(alwaysTrue), address(alwaysTrue), replaceDeadline, sig);
    }

    // ── 17c. Valid replacePermission succeeds and old is deregistered ──

    function test_Attack_ReplacePermission_ValidReplace() public {
        _registerAlwaysTrue();
        AlwaysTruePerm2 p2 = new AlwaysTruePerm2();

        uint256 nonce = kernel.signerNonces(address(safe));
        uint256 replaceDeadline = block.timestamp + 1 days;
        bytes memory sig = _signReplacePermission(
            address(safe), address(alwaysTrue), address(p2), nonce, PERM_SIGNER_KEY
        );

        kernel.replacePermission{value: 0.001 ether}(address(safe), address(alwaysTrue), address(p2), replaceDeadline, sig);

        assertFalse(kernel.isPermissionRegistered(address(safe), address(alwaysTrue)), "Old should be deregistered");
        assertTrue(kernel.isPermissionRegistered(address(safe), address(p2)), "New should be registered");
    }

    // ── 17d. Nonce advances exactly once on successful replace ──

    function test_Attack_ReplacePermission_NonceAdvancesOnce() public {
        _registerAlwaysTrue();
        AlwaysTruePerm2 p2 = new AlwaysTruePerm2();

        uint256 nonceBefore = kernel.signerNonces(address(safe));
        uint256 replaceDeadline = block.timestamp + 1 days;
        bytes memory sig = _signReplacePermission(
            address(safe), address(alwaysTrue), address(p2), nonceBefore, PERM_SIGNER_KEY
        );
        kernel.replacePermission{value: 0.001 ether}(address(safe), address(alwaysTrue), address(p2), replaceDeadline, sig);

        assertEq(kernel.signerNonces(address(safe)), nonceBefore + 1, "Nonce must advance exactly 1");
    }
}

// =============================================================================
// SECTION 20 — registerAccount deeper front-run analysis
// =============================================================================
contract RegisterAccountDeepTests is RedTeamBase2 {

    // ── 20a. Attacker EOA cannot self-register (Octane #4a) ──
    //   Post-fix, registerAccount rejects callers whose codehash is not an allowlisted Safe
    //   proxy. An EOA (codehash 0) is rejected outright.

    function test_Attack_RegisterAccount_AttackerRegistersOwnAddress() public {
        assertFalse(kernel.registered(attacker));

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(SailKernel.UntrustedProxyCodehash.selector, attacker.codehash));
        kernel.registerAccount(address(0xDEAD), address(0xBEEF), address(0), address(0));

        assertFalse(kernel.registered(attacker));
    }

    // ── 20b. Victim's Safe cannot be front-run; attacker EOA is rejected by codehash gate ──

    function test_Attack_RegisterAccount_CannotFrontRunSafe() public {
        MockSafe2 targetSafe = new MockSafe2();
        targetSafe.enableModule(address(kernel));

        // Attacker EOA cannot register anything — codehash gate rejects it.
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(SailKernel.UntrustedProxyCodehash.selector, attacker.codehash));
        kernel.registerAccount(address(0x111), address(0x222), address(0), address(0));

        assertFalse(kernel.registered(attacker));
        assertFalse(kernel.registered(address(targetSafe)));

        // Now targetSafe (allowlisted MockSafe2 codehash, module enabled) registers itself.
        vm.prank(address(targetSafe));
        kernel.registerAccount(permSigner, manager, address(0), address(0));
        assertTrue(kernel.registered(address(targetSafe)));
    }

    // ── 20c. Safe that already has a kernel module but is not yet registered:
    //   manager cannot dispatch before registerAccount is called ──

    function test_Attack_RegisterAccount_DispatchBeforeRegistrationReverts() public {
        MockSafe2 unregisteredSafe = new MockSafe2();
        unregisteredSafe.enableModule(address(kernel));

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory data = "";
        bytes memory sig  = _signDispatch(
            address(unregisteredSafe), address(alwaysTrue), attacker, 0, data, 0, deadline, MANAGER_KEY
        );

        vm.expectRevert(abi.encodeWithSelector(SailKernel.AccountNotRegistered.selector, address(unregisteredSafe)));
        kernel.dispatch(address(unregisteredSafe), address(alwaysTrue), attacker, 0, data, sig, deadline);
    }

    // ── 20d. Manager cannot register an account — only the account itself can ──

    function test_Attack_RegisterAccount_ManagerCannotRegisterForSafe() public {
        MockSafe2 newSafe = new MockSafe2();
        newSafe.enableModule(address(kernel));

        // Manager is an EOA — codehash gate (Octane #4a) rejects its registration attempt.
        vm.prank(manager);
        vm.expectRevert(abi.encodeWithSelector(SailKernel.UntrustedProxyCodehash.selector, manager.codehash));
        kernel.registerAccount(permSigner, address(0x1234), address(0), address(0));

        assertFalse(kernel.registered(manager));
        assertFalse(kernel.registered(address(newSafe)));
    }
}

// =============================================================================
// SECTION 21 — MAX_PERMISSION_FEE_WEI ceiling guard
// =============================================================================
contract FeeCapTests is RedTeamBase2 {

    // ── 21a. Deploy governance with maxPermissionFeeWei > 0.01 ether must revert ──

    function test_Attack_FeeCap_MaxPermissionFeeExceedsCeiling() public {
        // Deploy the injected timelock first; the fee-cap check fires before any timelock check,
        // so expectRevert wraps only the SailGovernance construction.
        TimelockController tl = TimelockDeployer.deploy(address(this));
        vm.expectRevert(
            abi.encodeWithSelector(SailGovernance.FeeExceedsCap.selector, 0.01 ether + 1, 0.01 ether)
        );
        new SailGovernance(address(this), 0.01 ether + 1, address(this), 0, tl);
    }

    // ── 21b. Governance cannot set permissionRegistrationFee above MAX_PERMISSION_FEE_WEI ──

    function test_Attack_FeeCap_SetFeeAboveCapReverts() public {
        vm.prank(address(gov.timelock()));
        vm.expectRevert(
            abi.encodeWithSelector(SailGovernance.FeeExceedsCap.selector, 0.001 ether + 1, 0.001 ether)
        );
        gov.setPermissionRegistrationFee(0.001 ether + 1);
    }

    // ── 21c. Setting fee to exactly 0.001 ether (the cap) is allowed ──

    function test_Attack_FeeCap_SetFeeExactlyAtCap() public {
        vm.prank(address(gov.timelock()));
        gov.setPermissionRegistrationFee(0.001 ether);
        assertEq(gov.permissionRegistrationFee(), 0.001 ether);
    }

    // ── 21d. Deploy governance with maxPermissionFeeWei exactly at the 0.01 ether ceiling is allowed ──

    function test_Attack_FeeCap_MaxPermissionFeeExactlyAtCeiling() public {
        TimelockController tl = TimelockDeployer.deploy(address(this));
        SailGovernance g = new SailGovernance(address(this), 0.01 ether, address(this), 0, tl);
        assertEq(g.MAX_PERMISSION_FEE_WEI(), 0.01 ether);
    }
}

// =============================================================================
// SECTION 22 — StandardFeePolicy feeRecipient = feeManager, manager cannot hijack
// =============================================================================
contract StandardFeePolicyRecipientTests is RedTeamBase2 {

    // ── 22a. Manager cannot change feeManager of StandardFeePolicy ──
    //   Only the feeManager (permSigner in tests) can propose a feeManager transfer.

    function test_Attack_StandardFeePolicy_ManagerCannotChangeFeeManager() public {
        StandardFeePolicy sfp = new StandardFeePolicy(
            0, 0, address(0), 0, address(kernel), permSigner
        );
        _trustFeePolicy(address(sfp));

        // Manager tries to call proposeFeeManager — must revert
        vm.prank(manager);
        vm.expectRevert(StandardFeePolicy.NotFeeManager.selector);
        sfp.proposeFeeManager(attacker);
    }

    // ── 22b. Attacker cannot accept feeManager transfer they were not nominated for ──

    function test_Attack_StandardFeePolicy_AttackerCannotAcceptFeeManager() public {
        StandardFeePolicy sfp = new StandardFeePolicy(
            0, 0, address(0), 0, address(kernel), permSigner
        );
        _trustFeePolicy(address(sfp));

        // permSigner nominates address(0x1234), not attacker
        vm.prank(permSigner);
        sfp.proposeFeeManager(address(0x1234));

        // Attacker tries to accept — must revert
        vm.prank(attacker);
        vm.expectRevert(StandardFeePolicy.NotPendingFeeManager.selector);
        sfp.acceptFeeManager();
    }

    // ── 22c. After feeManager transfer, feeRecipient changes to new feeManager ──

    function test_Attack_StandardFeePolicy_FeeRecipientChangesWithFeeManager() public {
        StandardFeePolicy sfp = new StandardFeePolicy(
            0, 0, address(0), 0, address(kernel), permSigner
        );
        _trustFeePolicy(address(sfp));

        assertEq(sfp.feeRecipient(), permSigner);

        // permSigner proposes and address(0x1234) accepts
        vm.prank(permSigner);
        sfp.proposeFeeManager(address(0x1234));
        vm.prank(address(0x1234));
        sfp.acceptFeeManager();

        // feeRecipient should now be address(0x1234)
        assertEq(sfp.feeRecipient(), address(0x1234));
    }

    // ── 22d. collectFees with ERC-20 token via policy with zero recipient reverts ──

    function test_Attack_CollectFees_ERC20ZeroRecipient() public {
        MutableRecipientFeePolicy zeroPolicy = new MutableRecipientFeePolicy(address(0), 1 ether);
        _trustFeePolicy(address(zeroPolicy));

        address mockToken = address(0x7070);

        // Bind feeAsset = mockToken so the FeeTokenMismatch guard passes,
        // then the kernel's ZeroAddress check on feeRecipient() fires.
        uint256 nonce = kernel.signerNonces(address(safe));
        bytes memory fpSig = _signSetFeePolicyWithAsset(address(safe), address(zeroPolicy), mockToken, nonce, PERM_SIGNER_KEY);
        kernel.setFeePolicy(address(safe), address(zeroPolicy), mockToken, type(uint256).max, fpSig);

        vm.prank(manager);
        vm.expectRevert(SailKernel.ZeroAddress.selector);
        kernel.collectFees(address(safe), 1 ether, 1_000_000e18, mockToken);
    }
}

// =============================================================================
// SECTION 23 — registerPermissions batch with duplicate entries
// =============================================================================
contract BatchRegistrationTests is RedTeamBase2 {

    // ── 23a. Batch with duplicate permission addresses: first duplicate reverts ──
    //   registerPermissions adds permissions one by one and checks for duplicates
    //   inside the loop. A batch with the same address twice must revert atomically.

    function test_Attack_BatchRegister_DuplicateInBatch() public {
        AlwaysTruePerm2 p1 = new AlwaysTruePerm2();
        // p1 listed twice
        address[] memory perms = new address[](2);
        perms[0] = address(p1);
        perms[1] = address(p1); // duplicate

        uint256 nonce    = kernel.signerNonces(address(safe));
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _signRegisterPermissions(address(safe), perms, nonce, deadline, PERM_SIGNER_KEY);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionAlreadyRegistered.selector, address(p1)));
        kernel.registerPermissions{value: 0.002 ether}(address(safe), perms, deadline, sig);

        // Verify no permissions were registered (atomic revert)
        assertFalse(kernel.isPermissionRegistered(address(safe), address(p1)));
    }

    // ── 23b. Batch: already-registered permission in batch must revert atomically ──

    function test_Attack_BatchRegister_AlreadyRegisteredInBatch() public {
        _registerAlwaysTrue(); // registers alwaysTrue

        AlwaysTruePerm2 p2 = new AlwaysTruePerm2();
        address[] memory perms = new address[](2);
        perms[0] = address(alwaysTrue); // already registered
        perms[1] = address(p2);

        uint256 nonce    = kernel.signerNonces(address(safe));
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _signRegisterPermissions(address(safe), perms, nonce, deadline, PERM_SIGNER_KEY);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionAlreadyRegistered.selector, address(alwaysTrue)));
        kernel.registerPermissions{value: 0.002 ether}(address(safe), perms, deadline, sig);

        // p2 should NOT have been registered (atomic revert)
        assertFalse(kernel.isPermissionRegistered(address(safe), address(p2)));
    }

    // ── 23c. Nonce not consumed on failed batch ──

    function test_Attack_BatchRegister_NonceNotConsumedOnFailure() public {
        AlwaysTruePerm2 p1 = new AlwaysTruePerm2();
        address[] memory perms = new address[](2);
        perms[0] = address(p1);
        perms[1] = address(p1);

        uint256 nonceBefore = kernel.signerNonces(address(safe));
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _signRegisterPermissions(address(safe), perms, nonceBefore, deadline, PERM_SIGNER_KEY);

        try kernel.registerPermissions{value: 0.002 ether}(address(safe), perms, deadline, sig) {} catch {}

        // Nonce must NOT advance on revert
        assertEq(kernel.signerNonces(address(safe)), nonceBefore,
            "Nonce should not advance on failed batch registration");
    }
}
