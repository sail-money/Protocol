// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

// ─────────────────────────────────────────────────────────────────────────────
// Red-team exploit tests — ROUND 2
//
// Covers new attack surface introduced by the 13 post-v1 security fixes:
//   • collectFees: recipient now pulled from IFeePolicy.feeRecipient()
//   • PermissionFactory.receive() reverts unless msg.sender == kernel
//   • TransferTargetPermission: ETH path requires txData.length == 0 (not < 4)
//   • SharedDeFiBundlePermission._ltvCheck: colValue now normalised by colDec
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
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";

import {SailKernel}                  from "../../contracts/core/SailKernel.sol";
import {SailGovernance}              from "../../contracts/governance/SailGovernance.sol";
import {PermissionFactory}           from "../../contracts/factory/PermissionFactory.sol";
import {StandardFeePolicy}           from "../../contracts/policies/StandardFeePolicy.sol";
import {TransferTargetPermission}    from "../../contracts/templates/TransferTargetPermission.sol";
import {BoundedBorrowPermission}     from "../../contracts/templates/BoundedBorrowPermission.sol";
import {SharedDeFiBundlePermission}  from "../../contracts/templates/shared/SharedDeFiBundlePermission.sol";
import {BaseSharedPermission}        from "../../contracts/templates/shared/BaseSharedPermission.sol";
import {IPermission, Context}        from "../../contracts/interfaces/IPermission.sol";
import {IFeePolicy}                  from "../../contracts/interfaces/IFeePolicy.sol";
import {IOracle}                     from "../../contracts/interfaces/IOracle.sol";
import {TimelockController}          from "@openzeppelin/contracts/governance/TimelockController.sol";

// ─────────────────────────────────────────────────────────────────────────────
// Shared mocks
// ─────────────────────────────────────────────────────────────────────────────

contract MockSafe2 {
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
    PermissionFactory internal factory;
    MockSafe2         internal safe;
    AlwaysTruePerm2   internal alwaysTrue;

    function setUp() public virtual {
        permSigner = vm.addr(PERM_SIGNER_KEY);
        manager    = vm.addr(MANAGER_KEY);
        attacker   = vm.addr(ATTACKER_KEY);

        vm.deal(address(this), 1000 ether);
        vm.deal(attacker,      100 ether);

        gov = new SailGovernance(address(this), 0.001 ether, address(this), 0);
        vm.startPrank(address(gov.timelock()));
        gov.setProtocolCutBps(1_000);
        gov.setPermissionRegistrationFee(0.001 ether);
        vm.stopPrank();

        kernel  = new SailKernel(address(gov), TREASURY);
        factory = new PermissionFactory(address(kernel));

        safe = new MockSafe2();
        safe.enableModule(address(kernel));
        vm.deal(address(safe), 100 ether);

        vm.prank(address(safe));
        kernel.registerAccount(permSigner, manager, address(0));

        alwaysTrue = new AlwaysTruePerm2();
    }

    // ── Signature helpers ─────────────────────────────────────────────────────

    function _signRegisterPermission(address account, address permission, uint256 nonce, uint256 signerKey)
        internal view returns (bytes memory)
    {
        bytes32 sh = keccak256(abi.encode(
            kernel.REGISTER_PERMISSION_TYPEHASH(), account, permission, nonce
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }

    function _signRevokePermission(address account, address permission, uint256 nonce, uint256 signerKey)
        internal view returns (bytes memory)
    {
        bytes32 sh = keccak256(abi.encode(
            kernel.REVOKE_PERMISSION_TYPEHASH(), account, permission, nonce
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }

    function _signReplacePermission(address account, address oldP, address newP, uint256 nonce, uint256 signerKey)
        internal view returns (bytes memory)
    {
        bytes32 sh = keccak256(abi.encode(
            kernel.REPLACE_PERMISSION_TYPEHASH(), account, oldP, newP, nonce
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
        bytes32 sh = keccak256(abi.encode(kernel.SET_FEE_POLICY_TYPEHASH(), account, newFeePolicy, nonce));
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
        bytes memory sig = _signRegisterPermission(address(safe), address(alwaysTrue), nonce, PERM_SIGNER_KEY);
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(alwaysTrue), sig);
    }

    /// @dev Helper: configure a minimal SharedDeFiBundlePermission for `account` via configureDirect.
    function _configureBundleEmpty(SharedDeFiBundlePermission bundle, address account) internal {
        address[] memory empty = new address[](0);
        SharedDeFiBundlePermission.SwapConfig memory swapCfg;
        swapCfg.routers = empty; swapCfg.tokensIn = empty; swapCfg.tokensOut = empty;
        SharedDeFiBundlePermission.BorrowConfig memory borCfg;
        borCfg.protocols = empty; borCfg.assets = empty;
        SharedDeFiBundlePermission.TransferConfig memory xferCfg;
        xferCfg.recipients = empty; xferCfg.tokens = empty;
        bytes memory params = abi.encode(swapCfg, borCfg, xferCfg);
        vm.prank(permSigner);
        bundle.configureDirect(account, params);
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

        // permSigner (trust anchor) sets this policy
        uint256 nonce = kernel.signerNonces(address(safe));
        bytes memory fpSig = _signSetFeePolicy(address(safe), address(badPolicy), nonce, PERM_SIGNER_KEY);
        kernel.setFeePolicy(address(safe), address(badPolicy), fpSig);

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

        uint256 nonce = kernel.signerNonces(address(safe));
        bytes memory fpSig = _signSetFeePolicy(address(safe), address(zeroPolicy), nonce, PERM_SIGNER_KEY);
        kernel.setFeePolicy(address(safe), address(zeroPolicy), fpSig);

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

        uint256 nonce = kernel.signerNonces(address(safe));
        bytes memory fpSig = _signSetFeePolicy(address(safe), address(policy), nonce, PERM_SIGNER_KEY);
        kernel.setFeePolicy(address(safe), address(policy), fpSig);

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

        // feeRecipient() should return feeManager (permSigner here)
        assertEq(sfp.feeRecipient(), permSigner);

        uint256 nonce = kernel.signerNonces(address(safe));
        bytes memory fpSig = _signSetFeePolicy(address(safe), address(sfp), nonce, PERM_SIGNER_KEY);
        kernel.setFeePolicy(address(safe), address(sfp), fpSig);

        // H-5 fix: feeManager must seed HWM before manager can collect.
        vm.prank(permSigner);
        sfp.seedHighWaterMark(address(safe), 1_000_000e18);

        // Manager cannot change who receives fees — they're bound to sfp.feeManager
        vm.prank(manager);
        kernel.collectFees(address(safe), 0, 1_000_000e18, address(0));

        // Confirm feeRecipient is still permSigner after collection
        assertEq(sfp.feeRecipient(), permSigner, "feeRecipient should remain feeManager");
    }
}

// =============================================================================
// SECTION 12 — PermissionFactory.receive() restricted
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

    // ── 12b. Normal factory overpay refund still works (ETH from kernel is accepted) ──
    //   The factory's receive() accepts ETH from the kernel for excess refunds.
    //   Verify that the standard attach flow (with overpay) still refunds correctly.

    function test_Attack_FactoryReceive_LegitRefundStillWorks() public {
        SharedDeFiBundlePermission bundle = new SharedDeFiBundlePermission(address(kernel));
        _configureBundleEmpty(bundle, address(safe));

        uint256 cfgNonce = bundle.configNonces(address(safe));
        uint256 cfgDeadline = block.timestamp + 1 hours;

        address[] memory empty = new address[](0);
        SharedDeFiBundlePermission.SwapConfig memory swapCfg;
        swapCfg.routers = empty; swapCfg.tokensIn = empty; swapCfg.tokensOut = empty;
        SharedDeFiBundlePermission.BorrowConfig memory borCfg;
        borCfg.protocols = empty; borCfg.assets = empty;
        SharedDeFiBundlePermission.TransferConfig memory xferCfg;
        xferCfg.recipients = empty; xferCfg.tokens = empty;
        bytes memory params = abi.encode(swapCfg, borCfg, xferCfg);

        bytes32 cfgStructHash = keccak256(abi.encode(
            bundle.CONFIGURE_TYPEHASH(), address(safe), keccak256(params), cfgNonce, cfgDeadline
        ));
        (uint8 cv, bytes32 cr, bytes32 cs) = vm.sign(PERM_SIGNER_KEY, bundle.hashTypedDataV4(cfgStructHash));
        bytes memory cfgSig = abi.encodePacked(cr, cs, cv);

        // Fresh nonce after configureDirect was called in setUp helper
        uint256 kNonce = kernel.signerNonces(address(safe));
        bytes memory kSig = _signRegisterPermission(address(safe), address(bundle), kNonce, PERM_SIGNER_KEY);

        uint256 balBefore = address(this).balance;

        // Need a second configure sig since configureDirect already consumed nonce 0
        // Re-deploy bundle to start fresh
        SharedDeFiBundlePermission bundle2 = new SharedDeFiBundlePermission(address(kernel));
        cfgNonce = bundle2.configNonces(address(safe)); // 0
        cfgStructHash = keccak256(abi.encode(
            bundle2.CONFIGURE_TYPEHASH(), address(safe), keccak256(params), cfgNonce, cfgDeadline
        ));
        (cv, cr, cs) = vm.sign(PERM_SIGNER_KEY, bundle2.hashTypedDataV4(cfgStructHash));
        cfgSig = abi.encodePacked(cr, cs, cv);

        kNonce = kernel.signerNonces(address(safe));
        kSig = _signRegisterPermission(address(safe), address(bundle2), kNonce, PERM_SIGNER_KEY);

        // Overpay by 0.999 ether (fee is 0.001 ether)
        factory.attach{value: 1 ether}(address(safe), address(bundle2), params, cfgDeadline, cfgSig, kSig);

        uint256 netCost = balBefore - address(this).balance;
        assertEq(netCost, 0.001 ether, "Factory should refund excess after receiving from kernel");
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
// SECTION 13 — TransferTargetPermission: 1-3 byte calldata no longer bypasses
// =============================================================================
contract TransferTargetCalldataTests is RedTeamBase2 {

    // ── 13a. 1-byte calldata now falls to the ERC-20 path, which fails token check ──
    //   Before fix: data.length < 4 triggered the ETH path (isAllowedRecipient + amount check).
    //   After fix: only data.length == 0 triggers the ETH path.
    //   1-3 byte inputs fall through to the ERC-20 block which first checks ctx.value == 0,
    //   then isAllowedToken[ctx.target]. A non-token target returns false.

    function test_Attack_TransferTarget_OneByteCalldataRejected() public {
        address[] memory recipients = new address[](1);
        recipients[0] = address(0xBEEF);
        address[] memory tokens = new address[](0);

        TransferTargetPermission ttp = TransferTargetPermission(Clones.clone(address(new TransferTargetPermission())));
        ttp.initialize(recipients, tokens, 10 ether, permSigner);

        uint256 nonce = kernel.signerNonces(address(safe));
        bytes memory regSig = _signRegisterPermission(address(safe), address(ttp), nonce, PERM_SIGNER_KEY);
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(ttp), regSig);

        uint256 deadline = block.timestamp + 1 hours;
        // 1-byte calldata — old code would have taken the ETH path; new code falls through
        bytes memory data = hex"aa";
        bytes memory dispatchSig = _signDispatch(
            address(safe), address(ttp), address(0xBEEF), 1 ether, data, 0, deadline, MANAGER_KEY
        );

        // Must revert — 1-byte calldata is NOT the ETH path anymore
        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(ttp)));
        kernel.dispatch(address(safe), address(ttp), address(0xBEEF), 1 ether, data, dispatchSig, deadline);
    }

    // ── 13b. 2-byte calldata also rejected ──

    function test_Attack_TransferTarget_TwoByteCalldataRejected() public {
        address[] memory recipients = new address[](1);
        recipients[0] = attacker;
        address[] memory tokens = new address[](0);

        TransferTargetPermission ttp = TransferTargetPermission(Clones.clone(address(new TransferTargetPermission())));
        ttp.initialize(recipients, tokens, 10 ether, permSigner);

        uint256 nonce = kernel.signerNonces(address(safe));
        bytes memory regSig = _signRegisterPermission(address(safe), address(ttp), nonce, PERM_SIGNER_KEY);
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(ttp), regSig);

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory data = hex"aabb"; // 2 bytes
        bytes memory dispatchSig = _signDispatch(
            address(safe), address(ttp), attacker, 1 ether, data, 0, deadline, MANAGER_KEY
        );

        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(ttp)));
        kernel.dispatch(address(safe), address(ttp), attacker, 1 ether, data, dispatchSig, deadline);
    }

    // ── 13c. 3-byte calldata also rejected ──

    function test_Attack_TransferTarget_ThreeByteCalldataRejected() public {
        address[] memory recipients = new address[](1);
        recipients[0] = attacker;
        address[] memory tokens = new address[](0);

        TransferTargetPermission ttp = TransferTargetPermission(Clones.clone(address(new TransferTargetPermission())));
        ttp.initialize(recipients, tokens, 10 ether, permSigner);

        uint256 nonce = kernel.signerNonces(address(safe));
        bytes memory regSig = _signRegisterPermission(address(safe), address(ttp), nonce, PERM_SIGNER_KEY);
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(ttp), regSig);

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory data = hex"aabbcc"; // 3 bytes
        bytes memory dispatchSig = _signDispatch(
            address(safe), address(ttp), attacker, 1 ether, data, 0, deadline, MANAGER_KEY
        );

        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(ttp)));
        kernel.dispatch(address(safe), address(ttp), attacker, 1 ether, data, dispatchSig, deadline);
    }

    // ── 13d. Legitimate zero-byte ETH send to allowed recipient still passes ──

    function test_Attack_TransferTarget_ZeroByteETHStillAllowed() public {
        address[] memory recipients = new address[](1);
        recipients[0] = address(0xBEEF);
        address[] memory tokens = new address[](0);

        TransferTargetPermission ttp = TransferTargetPermission(Clones.clone(address(new TransferTargetPermission())));
        ttp.initialize(recipients, tokens, 10 ether, permSigner);

        uint256 nonce = kernel.signerNonces(address(safe));
        bytes memory regSig = _signRegisterPermission(address(safe), address(ttp), nonce, PERM_SIGNER_KEY);
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(ttp), regSig);

        // Give 0xBEEF a receive()
        vm.deal(address(0xBEEF), 0);

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory data = ""; // exactly 0 bytes
        bytes memory dispatchSig = _signDispatch(
            address(safe), address(ttp), address(0xBEEF), 1 ether, data, 0, deadline, MANAGER_KEY
        );

        // Should succeed — empty calldata + allowed recipient
        kernel.dispatch(address(safe), address(ttp), address(0xBEEF), 1 ether, data, dispatchSig, deadline);
    }

    // ── 13e. Exactly 4-byte calldata (invalid selector) — not ETH path, must fail ──
    //   Confirms that only data.length == 0 is the ETH path.
    //   4-byte data goes to selector matching, finds no match, returns false.

    function test_Attack_TransferTarget_FourByteInvalidSelectorRejected() public {
        address[] memory recipients = new address[](1);
        recipients[0] = attacker;
        address[] memory tokens = new address[](0);

        TransferTargetPermission ttp = TransferTargetPermission(Clones.clone(address(new TransferTargetPermission())));
        ttp.initialize(recipients, tokens, 10 ether, permSigner);

        uint256 nonce = kernel.signerNonces(address(safe));
        bytes memory regSig = _signRegisterPermission(address(safe), address(ttp), nonce, PERM_SIGNER_KEY);
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(ttp), regSig);

        uint256 deadline = block.timestamp + 1 hours;
        // 4 bytes that don't match transfer(0xa9059cbb) or transferFrom(0x23b872dd)
        bytes memory data = hex"deadbeef";
        bytes memory dispatchSig = _signDispatch(
            address(safe), address(ttp), attacker, 1 ether, data, 0, deadline, MANAGER_KEY
        );

        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(ttp)));
        kernel.dispatch(address(safe), address(ttp), attacker, 1 ether, data, dispatchSig, deadline);
    }
}

// =============================================================================
// SECTION 14 — SharedDeFiBundlePermission LTV normalisation
// =============================================================================
contract BundleLTVNormalisationTests is RedTeamBase2 {

    // ── 14a. colValue / 10^colDec = 0 when colValue < 10^colDec → denied (fail-closed) ──
    //   After the fix, colNorm = colValue / 10^colDec. If colValue < colDec decimal places,
    //   colNorm rounds down to 0, and the check returns false (fail-closed).

    function test_Attack_BundleLTV_SubDecimalColValue_FailClosed() public {
        address protocol = address(0xAABB);
        address asset    = address(0xCCDD);

        // 8 decimals: colValue = 1 (less than 10^8) → colNorm = 0 → denied
        ManipulableOracle2 collOracle = new ManipulableOracle2(1, 8);
        ManipulableOracle2 borOracle  = new ManipulableOracle2(1e8, 8);

        SharedDeFiBundlePermission bundle = new SharedDeFiBundlePermission(address(kernel));

        address[] memory emptyAddrs = new address[](0);
        address[] memory protocols  = new address[](1); protocols[0]  = protocol;
        address[] memory assets     = new address[](1); assets[0]     = asset;

        SharedDeFiBundlePermission.SwapConfig memory swapCfg;
        swapCfg.routers = emptyAddrs; swapCfg.tokensIn = emptyAddrs; swapCfg.tokensOut = emptyAddrs;
        SharedDeFiBundlePermission.BorrowConfig memory borCfg;
        borCfg.protocols        = protocols;
        borCfg.assets           = assets;
        borCfg.maxAmountPerTx   = type(uint256).max;
        borCfg.maxLtvBps        = 10_000; // 100% LTV — should still fail due to colNorm == 0
        borCfg.collateralOracle = address(collOracle);
        borCfg.borrowOracle     = address(borOracle);
        SharedDeFiBundlePermission.TransferConfig memory xferCfg;
        xferCfg.recipients = emptyAddrs; xferCfg.tokens = emptyAddrs;

        bytes memory params = abi.encode(swapCfg, borCfg, xferCfg);
        vm.prank(permSigner);
        bundle.configureDirect(address(safe), params);

        uint256 nonce = kernel.signerNonces(address(safe));
        bytes memory regSig = _signRegisterPermission(address(safe), address(bundle), nonce, PERM_SIGNER_KEY);
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(bundle), regSig);

        bytes4 AAVE_SEL = bytes4(keccak256("borrow(address,uint256,uint256,uint16,address)"));
        bytes memory data = abi.encodeWithSelector(AAVE_SEL, asset, uint256(1), uint256(2), uint16(0), address(safe));

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory dispatchSig = _signDispatch(address(safe), address(bundle), protocol, 0, data, 0, deadline, MANAGER_KEY);

        // colNorm = 1 / 1e8 = 0 → _ltvCheck returns false → denied
        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(bundle)));
        kernel.dispatch(address(safe), address(bundle), protocol, 0, data, dispatchSig, deadline);
    }

    // ── 14b. Attacker tries exact-boundary borrow after normalisation ──
    //   colValue = 1_000_000 * 1e8, colDec = 8 → colNorm = 1_000_000.
    //   75% LTV → borrow limit = 750_000 units at $1/unit (borDec=8).
    //   Borrow exactly 750_001 → ltvBps = 750_001 * 10_000 / 1_000_000 = 7_500.01 → rounds to 7_500 (pass)
    //   Borrow 750_001 at borPrice = 1e8 (8 dec): borrowScaled = 750_001*1e8/1e8 = 750_001
    //   ltvBps = 750_001 * 10_000 / 1_000_000 = 7_500.01 → mulDiv truncates → 7_500 → passes!

    function test_Attack_BundleLTV_BoundaryBorrowPassesAfterNorm() public {
        address protocol = address(0xAABB);
        address asset    = address(0xCCDD);

        ManipulableOracle2 collOracle = new ManipulableOracle2(1_000_000e8, 8);
        ManipulableOracle2 borOracle  = new ManipulableOracle2(1e8, 8);

        SharedDeFiBundlePermission bundle = new SharedDeFiBundlePermission(address(kernel));

        address[] memory emptyAddrs = new address[](0);
        address[] memory protocols  = new address[](1); protocols[0]  = protocol;
        address[] memory assets     = new address[](1); assets[0]     = asset;

        SharedDeFiBundlePermission.SwapConfig memory swapCfg;
        swapCfg.routers = emptyAddrs; swapCfg.tokensIn = emptyAddrs; swapCfg.tokensOut = emptyAddrs;
        SharedDeFiBundlePermission.BorrowConfig memory borCfg;
        borCfg.protocols        = protocols;
        borCfg.assets           = assets;
        borCfg.maxAmountPerTx   = type(uint256).max;
        borCfg.maxLtvBps        = 7_500;
        borCfg.collateralOracle = address(collOracle);
        borCfg.borrowOracle     = address(borOracle);
        SharedDeFiBundlePermission.TransferConfig memory xferCfg;
        xferCfg.recipients = emptyAddrs; xferCfg.tokens = emptyAddrs;

        bytes memory params = abi.encode(swapCfg, borCfg, xferCfg);
        vm.prank(permSigner);
        bundle.configureDirect(address(safe), params);

        uint256 nonce = kernel.signerNonces(address(safe));
        bytes memory regSig = _signRegisterPermission(address(safe), address(bundle), nonce, PERM_SIGNER_KEY);
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(bundle), regSig);

        bytes4 AAVE_SEL = bytes4(keccak256("borrow(address,uint256,uint256,uint16,address)"));
        uint256 deadline = block.timestamp + 1 hours;

        // Borrow 750_000 → exactly 75% → should pass
        bytes memory data750k = abi.encodeWithSelector(AAVE_SEL, asset, uint256(750_000), uint256(2), uint16(0), address(safe));
        bytes memory sig750k = _signDispatch(address(safe), address(bundle), protocol, 0, data750k, 0, deadline, MANAGER_KEY);
        kernel.dispatch(address(safe), address(bundle), protocol, 0, data750k, sig750k, deadline); // Should pass

        // Borrow 750_001 — ltvBps = mulDiv(750_001, 10_000, 1_000_000) = 7 (truncation!) — passes
        // NOTE: integer truncation means values just above 75% still pass. This is expected
        // Solidity mulDiv behaviour, not a bug introduced by the fix.
        bytes memory data750k1 = abi.encodeWithSelector(AAVE_SEL, asset, uint256(750_001), uint256(2), uint16(0), address(safe));
        bytes memory sig750k1 = _signDispatch(address(safe), address(bundle), protocol, 0, data750k1, 1, deadline, MANAGER_KEY);
        // This passes due to integer truncation in mulDiv — protocol-level precision boundary
        kernel.dispatch(address(safe), address(bundle), protocol, 0, data750k1, sig750k1, deadline);
        console.log("NOTE: 750_001 borrow passes due to integer truncation in ltvBps calculation");

        // Borrow 10x over limit → ltvBps = 7_500_001 > 7_500 → denied
        bytes memory data10x = abi.encodeWithSelector(AAVE_SEL, asset, uint256(7_500_001), uint256(2), uint16(0), address(safe));
        bytes memory sig10x = _signDispatch(address(safe), address(bundle), protocol, 0, data10x, 2, deadline, MANAGER_KEY);
        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(bundle)));
        kernel.dispatch(address(safe), address(bundle), protocol, 0, data10x, sig10x, deadline);
    }

    // ── 14c. LTV check: borPrice == 0 → denied (fail-closed) ──

    function test_Attack_BundleLTV_ZeroBorPrice_FailClosed() public {
        address protocol = address(0xAABB);
        address asset    = address(0xCCDD);

        ManipulableOracle2 collOracle = new ManipulableOracle2(1_000_000e8, 8);
        ManipulableOracle2 borOracle  = new ManipulableOracle2(0, 8); // zero bor price

        SharedDeFiBundlePermission bundle = new SharedDeFiBundlePermission(address(kernel));

        address[] memory emptyAddrs = new address[](0);
        address[] memory protocols  = new address[](1); protocols[0]  = protocol;
        address[] memory assets     = new address[](1); assets[0]     = asset;

        SharedDeFiBundlePermission.SwapConfig memory swapCfg;
        swapCfg.routers = emptyAddrs; swapCfg.tokensIn = emptyAddrs; swapCfg.tokensOut = emptyAddrs;
        SharedDeFiBundlePermission.BorrowConfig memory borCfg;
        borCfg.protocols = protocols; borCfg.assets = assets;
        borCfg.maxAmountPerTx = type(uint256).max;
        borCfg.maxLtvBps = 10_000;
        borCfg.collateralOracle = address(collOracle);
        borCfg.borrowOracle = address(borOracle);
        SharedDeFiBundlePermission.TransferConfig memory xferCfg;
        xferCfg.recipients = emptyAddrs; xferCfg.tokens = emptyAddrs;

        bytes memory params = abi.encode(swapCfg, borCfg, xferCfg);
        vm.prank(permSigner);
        bundle.configureDirect(address(safe), params);

        uint256 nonce = kernel.signerNonces(address(safe));
        bytes memory regSig = _signRegisterPermission(address(safe), address(bundle), nonce, PERM_SIGNER_KEY);
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(bundle), regSig);

        bytes4 AAVE_SEL = bytes4(keccak256("borrow(address,uint256,uint256,uint16,address)"));
        bytes memory data = abi.encodeWithSelector(AAVE_SEL, asset, uint256(1), uint256(2), uint16(0), address(safe));
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory dispatchSig = _signDispatch(address(safe), address(bundle), protocol, 0, data, 0, deadline, MANAGER_KEY);

        // borPrice == 0 → _ltvCheck returns false
        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(bundle)));
        kernel.dispatch(address(safe), address(bundle), protocol, 0, data, dispatchSig, deadline);
    }
}

// =============================================================================
// SECTION 15 — MAX_ALLOWLIST_LENGTH = 50
// =============================================================================
contract AllowlistLengthTests is RedTeamBase2 {

    // ── 15a. Exactly 50 entries is accepted; 51 reverts ──

    function test_Attack_AllowlistLength_Exactly50Accepted() public {
        SharedDeFiBundlePermission bundle = new SharedDeFiBundlePermission(address(kernel));

        address[] memory recipients = new address[](50);
        for (uint256 i = 0; i < 50; i++) recipients[i] = address(uint160(0x1000 + i));
        address[] memory tokens = new address[](1);
        tokens[0] = address(0xABC1);

        address[] memory emptyAddrs = new address[](0);
        SharedDeFiBundlePermission.SwapConfig memory swapCfg;
        swapCfg.routers = emptyAddrs; swapCfg.tokensIn = emptyAddrs; swapCfg.tokensOut = emptyAddrs;
        SharedDeFiBundlePermission.BorrowConfig memory borCfg;
        borCfg.protocols = emptyAddrs; borCfg.assets = emptyAddrs;
        SharedDeFiBundlePermission.TransferConfig memory xferCfg;
        xferCfg.recipients = recipients; // 50 entries
        xferCfg.tokens = tokens;
        xferCfg.maxAmountPerTx = 0;

        bytes memory params = abi.encode(swapCfg, borCfg, xferCfg);
        vm.prank(permSigner);
        // 50 recipients should be accepted
        bundle.configureDirect(address(safe), params);
        assertTrue(bundle.isConfigured(address(safe)));
    }

    // ── 15b. 51 entries must revert with AllowlistTooLong ──

    function test_Attack_AllowlistLength_51Reverts() public {
        SharedDeFiBundlePermission bundle = new SharedDeFiBundlePermission(address(kernel));

        address[] memory recipients = new address[](51);
        for (uint256 i = 0; i < 51; i++) recipients[i] = address(uint160(0x1000 + i));

        address[] memory emptyAddrs = new address[](0);
        SharedDeFiBundlePermission.SwapConfig memory swapCfg;
        swapCfg.routers = emptyAddrs; swapCfg.tokensIn = emptyAddrs; swapCfg.tokensOut = emptyAddrs;
        SharedDeFiBundlePermission.BorrowConfig memory borCfg;
        borCfg.protocols = emptyAddrs; borCfg.assets = emptyAddrs;
        SharedDeFiBundlePermission.TransferConfig memory xferCfg;
        xferCfg.recipients = recipients; // 51 entries
        xferCfg.tokens = emptyAddrs;

        bytes memory params = abi.encode(swapCfg, borCfg, xferCfg);
        vm.prank(permSigner);
        vm.expectRevert(SharedDeFiBundlePermission.AllowlistTooLong.selector);
        bundle.configureDirect(address(safe), params);
    }

    // ── 15c. 50 duplicate addresses: storage deduplication means only last value matters ──
    //   An attacker tries to configure 50 identical addresses (all the same router).
    //   This should not cause OOG because the loop only iterates 50 times.
    //   Each iteration overwrites the same storage slot with true — no infinite loop.

    function test_Attack_AllowlistLength_50DuplicatesNotOOG() public {
        SharedDeFiBundlePermission bundle = new SharedDeFiBundlePermission(address(kernel));

        address dupeAddress = address(0xDDDD);
        address[] memory routers = new address[](50);
        for (uint256 i = 0; i < 50; i++) routers[i] = dupeAddress; // all same

        address[] memory emptyAddrs = new address[](0);
        address[] memory oneToken   = new address[](1);
        oneToken[0] = address(0xABC);

        SharedDeFiBundlePermission.SwapConfig memory swapCfg;
        swapCfg.routers = routers; // 50 duplicates
        swapCfg.tokensIn = oneToken;
        swapCfg.tokensOut = oneToken;
        swapCfg.maxAmountPerTx = 0;
        swapCfg.maxSlippageBps = 0;
        swapCfg.priceOracle = address(0);

        SharedDeFiBundlePermission.BorrowConfig memory borCfg;
        borCfg.protocols = emptyAddrs; borCfg.assets = emptyAddrs;
        SharedDeFiBundlePermission.TransferConfig memory xferCfg;
        xferCfg.recipients = emptyAddrs; xferCfg.tokens = emptyAddrs;

        bytes memory params = abi.encode(swapCfg, borCfg, xferCfg);
        vm.prank(permSigner);
        // Should succeed — 50 dupe addresses < 51, no OOG
        uint256 gasBefore = gasleft();
        bundle.configureDirect(address(safe), params);
        uint256 gasUsed = gasBefore - gasleft();
        console.log("Gas used for 50-dupe configure:", gasUsed);
        assertTrue(gasUsed < 3_000_000, "50-dupe configure should not be OOG (< 3M gas)");
    }

    // ── 15d. Dispatch with 50 recipients: evaluate loop should not OOG ──
    //   After configuring 50 routers/recipients, a dispatch that hits the allowlist check
    //   should still succeed without OOG — the mapping lookups are O(1).

    function test_Attack_AllowlistLength_DispatchWith50RoutersMappingIsO1() public {
        SharedDeFiBundlePermission bundle = new SharedDeFiBundlePermission(address(kernel));

        address targetRouter = address(0x9999);
        address[] memory routers = new address[](50);
        routers[0] = targetRouter;
        for (uint256 i = 1; i < 50; i++) routers[i] = address(uint160(0x8000 + i));

        address tokenIn  = address(0xAAAA);
        address tokenOut = address(0xBBBB);
        address[] memory tIn  = new address[](1); tIn[0]  = tokenIn;
        address[] memory tOut = new address[](1); tOut[0] = tokenOut;
        address[] memory emptyAddrs = new address[](0);

        SharedDeFiBundlePermission.SwapConfig memory swapCfg;
        swapCfg.routers        = routers;
        swapCfg.tokensIn       = tIn;
        swapCfg.tokensOut      = tOut;
        swapCfg.maxAmountPerTx = 1_000 ether;
        swapCfg.maxSlippageBps = 0;
        swapCfg.priceOracle    = address(0);

        SharedDeFiBundlePermission.BorrowConfig memory borCfg;
        borCfg.protocols = emptyAddrs; borCfg.assets = emptyAddrs;
        SharedDeFiBundlePermission.TransferConfig memory xferCfg;
        xferCfg.recipients = emptyAddrs; xferCfg.tokens = emptyAddrs;

        bytes memory params = abi.encode(swapCfg, borCfg, xferCfg);
        vm.prank(permSigner);
        bundle.configureDirect(address(safe), params);

        uint256 nonce = kernel.signerNonces(address(safe));
        bytes memory regSig = _signRegisterPermission(address(safe), address(bundle), nonce, PERM_SIGNER_KEY);
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(bundle), regSig);

        // Build a valid V3 swap
        bytes4 V3_SEL = 0x414bf389;
        bytes memory swapData = abi.encodeWithSelector(
            V3_SEL,
            tokenIn,
            tokenOut,
            uint24(3000),
            address(safe), // recipient == account
            uint256(0),    // deadline (ignored by permission)
            uint256(100 ether), // amountIn
            uint256(0),    // amountOutMin
            uint160(0)     // sqrtPriceLimitX96
        );

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory dispatchSig = _signDispatch(address(safe), address(bundle), targetRouter, 0, swapData, 0, deadline, MANAGER_KEY);

        uint256 gasBefore = gasleft();
        kernel.dispatch(address(safe), address(bundle), targetRouter, 0, swapData, dispatchSig, deadline);
        uint256 gasUsed = gasBefore - gasleft();
        console.log("Dispatch gas with 50-router allowlist:", gasUsed);
        assertTrue(gasUsed < 500_000, "Dispatch with 50-router allowlist should be well under 500k gas");
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
        bytes memory sig = _signReplacePermission(
            address(safe), address(alwaysTrue), address(p2), nonceBefore, PERM_SIGNER_KEY
        );

        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionNotRegistered.selector, address(alwaysTrue)));
        kernel.replacePermission{value: 0.001 ether}(address(safe), address(alwaysTrue), address(p2), sig);

        // Nonce must NOT have advanced
        assertEq(kernel.signerNonces(address(safe)), nonceBefore,
            "Nonce should NOT increment when old permission is not registered");
    }

    // ── 17b. replacePermission with newPermission already registered must revert ──

    function test_Attack_ReplacePermission_NewPermissionAlreadyRegistered() public {
        _registerAlwaysTrue();

        // Try to replace alwaysTrue with alwaysTrue itself
        uint256 nonce = kernel.signerNonces(address(safe));
        bytes memory sig = _signReplacePermission(
            address(safe), address(alwaysTrue), address(alwaysTrue), nonce, PERM_SIGNER_KEY
        );

        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionAlreadyRegistered.selector, address(alwaysTrue)));
        kernel.replacePermission{value: 0.001 ether}(address(safe), address(alwaysTrue), address(alwaysTrue), sig);
    }

    // ── 17c. Valid replacePermission succeeds and old is deregistered ──

    function test_Attack_ReplacePermission_ValidReplace() public {
        _registerAlwaysTrue();
        AlwaysTruePerm2 p2 = new AlwaysTruePerm2();

        uint256 nonce = kernel.signerNonces(address(safe));
        bytes memory sig = _signReplacePermission(
            address(safe), address(alwaysTrue), address(p2), nonce, PERM_SIGNER_KEY
        );

        kernel.replacePermission{value: 0.001 ether}(address(safe), address(alwaysTrue), address(p2), sig);

        assertFalse(kernel.isPermissionRegistered(address(safe), address(alwaysTrue)), "Old should be deregistered");
        assertTrue(kernel.isPermissionRegistered(address(safe), address(p2)), "New should be registered");
    }

    // ── 17d. Nonce advances exactly once on successful replace ──

    function test_Attack_ReplacePermission_NonceAdvancesOnce() public {
        _registerAlwaysTrue();
        AlwaysTruePerm2 p2 = new AlwaysTruePerm2();

        uint256 nonceBefore = kernel.signerNonces(address(safe));
        bytes memory sig = _signReplacePermission(
            address(safe), address(alwaysTrue), address(p2), nonceBefore, PERM_SIGNER_KEY
        );
        kernel.replacePermission{value: 0.001 ether}(address(safe), address(alwaysTrue), address(p2), sig);

        assertEq(kernel.signerNonces(address(safe)), nonceBefore + 1, "Nonce must advance exactly 1");
    }
}

// =============================================================================
// SECTION 18 — Cross-template interaction attacks
// =============================================================================
contract CrossTemplateAttackTests is RedTeamBase2 {

    // ── 18a. Manager registers two templates: AlwaysTrue + TTP. Uses AlwaysTrue to
    //   bypass TTP: both must return true. If AlwaysTrue is present and TTP is also
    //   registered, TTP still gates — all permissions must pass.

    function test_Attack_CrossTemplate_AlwaysTruePlusTTPBothMustPass() public {
        address[] memory recipients = new address[](1);
        recipients[0] = address(0xBEEF); // only beef allowed
        address[] memory tokens = new address[](0);

        TransferTargetPermission ttp = TransferTargetPermission(Clones.clone(address(new TransferTargetPermission())));
        ttp.initialize(recipients, tokens, 10 ether, permSigner);

        // Register BOTH alwaysTrue and ttp
        uint256 nonce1 = kernel.signerNonces(address(safe));
        bytes memory sig1 = _signRegisterPermission(address(safe), address(alwaysTrue), nonce1, PERM_SIGNER_KEY);
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(alwaysTrue), sig1);

        uint256 nonce2 = kernel.signerNonces(address(safe));
        bytes memory sig2 = _signRegisterPermission(address(safe), address(ttp), nonce2, PERM_SIGNER_KEY);
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(ttp), sig2);

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory data = "";

        // Try to send ETH to attacker (NOT in TTP allowlist)
        // Select ttp as the permission — ttp denies the attacker address
        bytes memory dispatchSig = _signDispatch(
            address(safe), address(ttp), attacker, 1 ether, data, 0, deadline, MANAGER_KEY
        );

        // TTP returns false (attacker not in allowlist) → denied
        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(ttp)));
        kernel.dispatch(address(safe), address(ttp), attacker, 1 ether, data, dispatchSig, deadline);
    }

    // ── 18b. Manager registers TTP + Bundle: can an attacker use the bundle's borrow
    //   path to satisfy one permission while the TTP denies? All must pass.

    function test_Attack_CrossTemplate_BundleBorrowDeniedByTTP() public {
        address protocol = address(0xAABB);
        address asset    = address(0xCCDD);
        address[] memory protocols = new address[](1); protocols[0] = protocol;
        address[] memory assets    = new address[](1); assets[0]    = asset;

        // TTP: only allows ETH sends to 0xBEEF
        address[] memory ttpRecipients = new address[](1); ttpRecipients[0] = address(0xBEEF);
        TransferTargetPermission ttp = TransferTargetPermission(Clones.clone(address(new TransferTargetPermission())));
        ttp.initialize(ttpRecipients, new address[](0), 10 ether, permSigner);

        SharedDeFiBundlePermission bundle = new SharedDeFiBundlePermission(address(kernel));

        address[] memory emptyAddrs = new address[](0);
        SharedDeFiBundlePermission.SwapConfig memory swapCfg;
        swapCfg.routers = emptyAddrs; swapCfg.tokensIn = emptyAddrs; swapCfg.tokensOut = emptyAddrs;
        SharedDeFiBundlePermission.BorrowConfig memory borCfg;
        borCfg.protocols = protocols; borCfg.assets = assets;
        borCfg.maxAmountPerTx = type(uint256).max; borCfg.maxLtvBps = 0;
        borCfg.collateralOracle = address(0); borCfg.borrowOracle = address(0);
        SharedDeFiBundlePermission.TransferConfig memory xferCfg;
        xferCfg.recipients = emptyAddrs; xferCfg.tokens = emptyAddrs;

        bytes memory params = abi.encode(swapCfg, borCfg, xferCfg);
        vm.prank(permSigner);
        bundle.configureDirect(address(safe), params);

        // Register both permissions
        uint256 n1 = kernel.signerNonces(address(safe));
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(ttp),
            _signRegisterPermission(address(safe), address(ttp), n1, PERM_SIGNER_KEY));

        uint256 n2 = kernel.signerNonces(address(safe));
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(bundle),
            _signRegisterPermission(address(safe), address(bundle), n2, PERM_SIGNER_KEY));

        // Build Aave borrow calldata — Bundle allows it, TTP must also evaluate it
        bytes4 AAVE_SEL = bytes4(keccak256("borrow(address,uint256,uint256,uint16,address)"));
        bytes memory borrowData = abi.encodeWithSelector(AAVE_SEL, asset, uint256(1000), uint256(2), uint16(0), address(safe));

        uint256 deadline = block.timestamp + 1 hours;
        // Select ttp as the permission — ttp denies the Aave borrow selector
        bytes memory dispatchSig = _signDispatch(address(safe), address(ttp), protocol, 0, borrowData, 0, deadline, MANAGER_KEY);

        // TTP sees Aave borrow selector, not transfer/transferFrom, not empty data → returns false
        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(ttp)));
        kernel.dispatch(address(safe), address(ttp), protocol, 0, borrowData, dispatchSig, deadline);
    }

    // ── 18c. Manager registers two bundles (two SharedDeFiBundlePermission instances) ──
    //   Both are configured for the same account but with different allowlists.
    //   A dispatch must satisfy BOTH bundles simultaneously.

    function test_Attack_CrossTemplate_TwoBundlesBothMustApprove() public {
        address router1 = address(0x1111);
        address router2 = address(0x2222);
        address tokenIn  = address(0xAA11);
        address tokenOut = address(0xBB22);

        SharedDeFiBundlePermission bundle1 = new SharedDeFiBundlePermission(address(kernel));
        SharedDeFiBundlePermission bundle2 = new SharedDeFiBundlePermission(address(kernel));

        address[] memory r1 = new address[](1); r1[0] = router1;
        address[] memory r2 = new address[](1); r2[0] = router2; // different router!
        address[] memory tIn  = new address[](1); tIn[0]  = tokenIn;
        address[] memory tOut = new address[](1); tOut[0] = tokenOut;
        address[] memory empty = new address[](0);

        SharedDeFiBundlePermission.BorrowConfig memory borCfg;
        borCfg.protocols = empty; borCfg.assets = empty;
        SharedDeFiBundlePermission.TransferConfig memory xferCfg;
        xferCfg.recipients = empty; xferCfg.tokens = empty;

        SharedDeFiBundlePermission.SwapConfig memory swapCfg1;
        swapCfg1.routers = r1; swapCfg1.tokensIn = tIn; swapCfg1.tokensOut = tOut;
        swapCfg1.maxAmountPerTx = 1_000 ether; swapCfg1.maxSlippageBps = 0;

        SharedDeFiBundlePermission.SwapConfig memory swapCfg2;
        swapCfg2.routers = r2; swapCfg2.tokensIn = tIn; swapCfg2.tokensOut = tOut;
        swapCfg2.maxAmountPerTx = 1_000 ether; swapCfg2.maxSlippageBps = 0;

        vm.prank(permSigner);
        bundle1.configureDirect(address(safe), abi.encode(swapCfg1, borCfg, xferCfg));
        vm.prank(permSigner);
        bundle2.configureDirect(address(safe), abi.encode(swapCfg2, borCfg, xferCfg));

        uint256 n1 = kernel.signerNonces(address(safe));
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(bundle1),
            _signRegisterPermission(address(safe), address(bundle1), n1, PERM_SIGNER_KEY));

        uint256 n2 = kernel.signerNonces(address(safe));
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(bundle2),
            _signRegisterPermission(address(safe), address(bundle2), n2, PERM_SIGNER_KEY));

        // Swap via router1 — bundle1 allows it, bundle2 does NOT (router2 only) → denied
        bytes4 V3_SEL = 0x414bf389;
        bytes memory swapData = abi.encodeWithSelector(
            V3_SEL,
            tokenIn, tokenOut, uint24(3000), address(safe),
            uint256(0), uint256(100 ether), uint256(0), uint160(0)
        );

        uint256 deadline = block.timestamp + 1 hours;
        // Select bundle2 — it only allows router2, so router1 is denied by bundle2
        bytes memory dispatchSig = _signDispatch(address(safe), address(bundle2), router1, 0, swapData, 0, deadline, MANAGER_KEY);

        // bundle2 returns false (router1 not in its list) → denied
        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(bundle2)));
        kernel.dispatch(address(safe), address(bundle2), router1, 0, swapData, dispatchSig, deadline);
    }
}

// =============================================================================
// SECTION 19 — Bundle ordering attacks
// =============================================================================
contract BundleOrderingAttackTests is RedTeamBase2 {

    // ── 19a. Bundle borrow: reordering calldata fields cannot bypass `onBehalfOf` check ──
    //   The bundle decodes Aave calldata positionally. An attacker cannot reorder to
    //   move their address to a different field that isn't checked.

    function test_Attack_BundleOrdering_AaveBorrowOnBehalfOfCheck() public {
        address protocol = address(0xAABB);
        address asset    = address(0xCCDD);

        SharedDeFiBundlePermission bundle = new SharedDeFiBundlePermission(address(kernel));

        address[] memory protocols = new address[](1); protocols[0] = protocol;
        address[] memory assets    = new address[](1); assets[0]    = asset;
        address[] memory empty     = new address[](0);

        SharedDeFiBundlePermission.SwapConfig memory swapCfg;
        swapCfg.routers = empty; swapCfg.tokensIn = empty; swapCfg.tokensOut = empty;
        SharedDeFiBundlePermission.BorrowConfig memory borCfg;
        borCfg.protocols = protocols; borCfg.assets = assets;
        borCfg.maxAmountPerTx = type(uint256).max; borCfg.maxLtvBps = 0;
        borCfg.collateralOracle = address(0); borCfg.borrowOracle = address(0);
        SharedDeFiBundlePermission.TransferConfig memory xferCfg;
        xferCfg.recipients = empty; xferCfg.tokens = empty;

        vm.prank(permSigner);
        bundle.configureDirect(address(safe), abi.encode(swapCfg, borCfg, xferCfg));

        uint256 nonce = kernel.signerNonces(address(safe));
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(bundle),
            _signRegisterPermission(address(safe), address(bundle), nonce, PERM_SIGNER_KEY));

        // Build calldata with onBehalfOf = attacker (not safe)
        bytes4 AAVE_SEL = bytes4(keccak256("borrow(address,uint256,uint256,uint16,address)"));
        bytes memory maliciousData = abi.encodeWithSelector(
            AAVE_SEL,
            asset,       // asset
            uint256(1000), // amount
            uint256(2),  // interestRateMode
            uint16(0),   // referralCode
            attacker     // onBehalfOf = ATTACKER — not ctx.account
        );

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory dispatchSig = _signDispatch(address(safe), address(bundle), protocol, 0, maliciousData, 0, deadline, MANAGER_KEY);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(bundle)));
        kernel.dispatch(address(safe), address(bundle), protocol, 0, maliciousData, dispatchSig, deadline);
    }

    // ── 19b. Bundle swap: reordering to put attacker as `recipient` must be denied ──
    //   V3 exactInputSingle requires recipient == ctx.account.
    //   An attacker setting recipient = attacker in calldata must be denied.

    function test_Attack_BundleOrdering_V3SwapRecipientMustBeAccount() public {
        address router   = address(0x3333);
        address tokenIn  = address(0xAA11);
        address tokenOut = address(0xBB22);

        SharedDeFiBundlePermission bundle = new SharedDeFiBundlePermission(address(kernel));

        address[] memory routers = new address[](1); routers[0] = router;
        address[] memory tIn  = new address[](1); tIn[0]  = tokenIn;
        address[] memory tOut = new address[](1); tOut[0] = tokenOut;
        address[] memory empty = new address[](0);

        SharedDeFiBundlePermission.SwapConfig memory swapCfg;
        swapCfg.routers = routers; swapCfg.tokensIn = tIn; swapCfg.tokensOut = tOut;
        swapCfg.maxAmountPerTx = 1_000 ether; swapCfg.maxSlippageBps = 0;

        SharedDeFiBundlePermission.BorrowConfig memory borCfg;
        borCfg.protocols = empty; borCfg.assets = empty;
        SharedDeFiBundlePermission.TransferConfig memory xferCfg;
        xferCfg.recipients = empty; xferCfg.tokens = empty;

        vm.prank(permSigner);
        bundle.configureDirect(address(safe), abi.encode(swapCfg, borCfg, xferCfg));

        uint256 nonce = kernel.signerNonces(address(safe));
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(bundle),
            _signRegisterPermission(address(safe), address(bundle), nonce, PERM_SIGNER_KEY));

        bytes4 V3_SEL = 0x414bf389;
        // recipient = attacker instead of safe
        bytes memory swapData = abi.encodeWithSelector(
            V3_SEL,
            tokenIn, tokenOut, uint24(3000),
            attacker,       // recipient = ATTACKER — not ctx.account
            uint256(0),
            uint256(100 ether),
            uint256(0),
            uint160(0)
        );

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory dispatchSig = _signDispatch(address(safe), address(bundle), router, 0, swapData, 0, deadline, MANAGER_KEY);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(bundle)));
        kernel.dispatch(address(safe), address(bundle), router, 0, swapData, dispatchSig, deadline);
    }

    // ── 19c. Bundle: Morpho borrow with receiver != account must be denied ──

    function test_Attack_BundleOrdering_MorphoBorrowReceiverMustBeAccount() public {
        address protocol = address(0x4444);
        address asset    = address(0xCCDD);

        SharedDeFiBundlePermission bundle = new SharedDeFiBundlePermission(address(kernel));

        address[] memory protocols = new address[](1); protocols[0] = protocol;
        address[] memory assets    = new address[](1); assets[0]    = asset;
        address[] memory empty     = new address[](0);

        SharedDeFiBundlePermission.SwapConfig memory swapCfg;
        swapCfg.routers = empty; swapCfg.tokensIn = empty; swapCfg.tokensOut = empty;
        SharedDeFiBundlePermission.BorrowConfig memory borCfg;
        borCfg.protocols = protocols; borCfg.assets = assets;
        borCfg.maxAmountPerTx = type(uint256).max; borCfg.maxLtvBps = 0;
        borCfg.collateralOracle = address(0); borCfg.borrowOracle = address(0);
        SharedDeFiBundlePermission.TransferConfig memory xferCfg;
        xferCfg.recipients = empty; xferCfg.tokens = empty;

        vm.prank(permSigner);
        bundle.configureDirect(address(safe), abi.encode(swapCfg, borCfg, xferCfg));

        uint256 nonce = kernel.signerNonces(address(safe));
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(bundle),
            _signRegisterPermission(address(safe), address(bundle), nonce, PERM_SIGNER_KEY));

        bytes4 MORPHO_SEL = bytes4(keccak256("borrow(address,uint256,address,address)"));
        // receiver = attacker — not ctx.account
        bytes memory malData = abi.encodeWithSelector(
            MORPHO_SEL,
            asset,
            uint256(1000),
            address(safe), // onBehalf = safe (ok)
            attacker       // receiver = ATTACKER (must be denied)
        );

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory dispatchSig = _signDispatch(address(safe), address(bundle), protocol, 0, malData, 0, deadline, MANAGER_KEY);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(bundle)));
        kernel.dispatch(address(safe), address(bundle), protocol, 0, malData, dispatchSig, deadline);
    }
}

// =============================================================================
// SECTION 20 — registerAccount deeper front-run analysis
// =============================================================================
contract RegisterAccountDeepTests is RedTeamBase2 {

    // ── 20a. Attacker can register an EOA address they control as an account ──
    //   Since registerAccount uses msg.sender as the account, the attacker registers
    //   themselves — not a vulnerability, but confirms the intent.
    //   The attacker's account will be separate from the victim's Safe.

    function test_Attack_RegisterAccount_AttackerRegistersOwnAddress() public {
        assertFalse(kernel.registered(attacker));

        vm.prank(attacker);
        kernel.registerAccount(address(0xDEAD), address(0xBEEF), address(0));

        assertTrue(kernel.registered(attacker));
        // attacker's account is registered with attacker-controlled parameters
        (address ps,,, ) = kernel.configs(attacker);
        assertEq(ps, address(0xDEAD));
    }

    // ── 20b. Victim's Safe cannot be front-run since only the Safe can call registerAccount
    //   for itself (msg.sender == account in registerAccount). An EOA cannot register
    //   the Safe's address because the Safe hasn't called the kernel.

    function test_Attack_RegisterAccount_CannotFrontRunSafe() public {
        MockSafe2 targetSafe = new MockSafe2();
        targetSafe.enableModule(address(kernel));

        // Attacker tries to register targetSafe's address — they cannot,
        // because attacker's msg.sender != targetSafe's address.
        // When attacker calls registerAccount, the kernel uses msg.sender (attacker) as account.
        vm.prank(attacker);
        kernel.registerAccount(address(0x111), address(0x222), address(0));

        // attacker is registered, not targetSafe
        assertTrue(kernel.registered(attacker));
        assertFalse(kernel.registered(address(targetSafe)));

        // Now targetSafe registers itself
        vm.prank(address(targetSafe));
        kernel.registerAccount(permSigner, manager, address(0));
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

        // Manager calls registerAccount — this registers the manager's address, not newSafe
        vm.prank(manager);
        kernel.registerAccount(permSigner, address(0x1234), address(0));

        assertTrue(kernel.registered(manager));   // manager registered itself
        assertFalse(kernel.registered(address(newSafe))); // newSafe still unregistered
    }
}

// =============================================================================
// SECTION 21 — MAX_PERMISSION_FEE_WEI = 0.001 ether guard
// =============================================================================
contract FeeCapTests is RedTeamBase2 {

    // ── 21a. Deploy governance with maxPermissionFeeWei > 0.001 ether must revert ──

    function test_Attack_FeeCap_MaxPermissionFeeExceeds1Ether() public {
        vm.expectRevert(
            abi.encodeWithSelector(SailGovernance.FeeExceedsCap.selector, 0.001 ether + 1, 0.001 ether)
        );
        new SailGovernance(address(this), 0.001 ether + 1, address(this), 0);
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

        uint256 nonce = kernel.signerNonces(address(safe));
        bytes memory fpSig = _signSetFeePolicy(address(safe), address(zeroPolicy), nonce, PERM_SIGNER_KEY);
        kernel.setFeePolicy(address(safe), address(zeroPolicy), fpSig);

        address mockToken = address(0x7070);

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
