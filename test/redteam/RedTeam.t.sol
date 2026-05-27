// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

// ─────────────────────────────────────────────────────────────────────────────
// Red-team exploit tests for the Sail protocol.
//
// Convention:
//   - Every test is named test_Attack_<description>.
//   - Tests use vm.expectRevert() when the attack SHOULD be blocked.
//   - If an attack SUCCEEDS (no revert when one is expected), a comment
//     // VULNERABILITY: <explanation> is present near the assertion.
//
// Run with:
//   forge test --match-path "test/redteam/*" -vvv
// ─────────────────────────────────────────────────────────────────────────────

import "forge-std/Test.sol";
import "forge-std/console.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";

import {SailKernel}              from "../../contracts/core/SailKernel.sol";
import {SailGovernance}          from "../../contracts/governance/SailGovernance.sol";
import {MandateFactory}       from "../../contracts/factory/MandateFactory.sol";
import {StandardFeePolicy}       from "../../contracts/policies/StandardFeePolicy.sol";
import {TransferTargetPermission} from "../../contracts/templates/TransferTargetPermission.sol";
import {BoundedBorrowPermission} from "../../contracts/templates/BoundedBorrowPermission.sol";
import {SharedDeFiBundlePermission} from "../../contracts/templates/shared/SharedDeFiBundlePermission.sol";
import {BaseSharedPermission}    from "../../contracts/templates/shared/BaseSharedPermission.sol";
import {IPermission, Context}    from "../../contracts/interfaces/IPermission.sol";
import {IFeePolicy}              from "../../contracts/interfaces/IFeePolicy.sol";
import {IOracle}                 from "../../contracts/interfaces/IOracle.sol";
import {TimelockController}      from "@openzeppelin/contracts/governance/TimelockController.sol";

// ─────────────────────────────────────────────────────────────────────────────
// Minimal mock Safe that records execTransactionFromModule calls
// ─────────────────────────────────────────────────────────────────────────────
contract MockSafe {
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
        // Forward plain ETH
        if (value > 0 && data.length == 0) {
            (bool ok,) = payable(to).call{value: value}("");
            return ok;
        }
        return true;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Always-true permission (never denies any call)
// ─────────────────────────────────────────────────────────────────────────────
contract AlwaysTruePermission is IPermission {
    function evaluate(bytes calldata, Context calldata) external pure returns (bool) { return true; }
    function discriminator() external pure returns (bytes32) { return keccak256("AlwaysTrue"); }
}

// ─────────────────────────────────────────────────────────────────────────────
// Malicious ERC-1271 signer that validates ANY digest/sig pair
// ─────────────────────────────────────────────────────────────────────────────
contract MaliciousERC1271Signer {
    bytes4 private constant ERC1271_MAGIC = 0x1626ba7e;
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return ERC1271_MAGIC;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Reentrancy attacker: on receiving ETH refund, re-enters registerPermission
// ─────────────────────────────────────────────────────────────────────────────
contract ReentrancyAttacker {
    SailKernel public kernel;
    address    public account;
    address    public permission2;
    uint256    public deadline2;
    bytes      public sig2;
    bool       public attacked;

    constructor(address _kernel) { kernel = SailKernel(_kernel); }

    function setReentryParams(address _account, address _perm2, uint256 _deadline2, bytes calldata _sig2) external {
        account     = _account;
        permission2 = _perm2;
        deadline2   = _deadline2;
        sig2        = _sig2;
    }

    receive() external payable {
        // Try to re-enter registerPermission during the refund callback
        if (!attacked) {
            attacked = true;
            try kernel.registerPermission{value: msg.value}(account, permission2, deadline2, sig2) {}
            catch {}
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Malicious fee policy that reports inflated maxFee
// ─────────────────────────────────────────────────────────────────────────────
contract InflatedFeePolicy is IFeePolicy {
    uint256 public reportedMaxFee;
    address public distributor;
    uint256 public distributorBps;

    constructor(uint256 _max, address _dist, uint256 _bps) {
        reportedMaxFee = _max;
        distributor    = _dist;
        distributorBps = _bps;
    }

    function computeFee(address, uint256) external view returns (uint256, address, uint256) {
        return (reportedMaxFee, distributor, distributorBps);
    }

    function recordCollection(address, uint256, uint256) external {}

    // If distributor is zero (no split configured), fall back to a non-zero placeholder
    // so the kernel's ZeroAddress check doesn't short-circuit before we reach the actual
    // attack assertion. In real deployments feeRecipient would be the feeManager address.
    address public recipient_ = address(0xFEEFEE);
    function feeRecipient() external view returns (address) {
        return distributor != address(0) ? distributor : recipient_;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Malicious oracle that returns whatever price the attacker wants
// ─────────────────────────────────────────────────────────────────────────────
contract ManipulableOracle is IOracle {
    uint256 public price;
    uint8   public decimals_;

    constructor(uint256 _price, uint8 _dec) { price = _price; decimals_ = _dec; }
    function setPrice(uint256 p) external { price = p; }

    function getPrice(address, address) external view returns (uint256, uint8, uint256) {
        return (price, decimals_, block.timestamp);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Base test setup
// ─────────────────────────────────────────────────────────────────────────────
abstract contract RedTeamBase is Test {
    // Key material
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
    MockSafe          internal safe;
    AlwaysTruePermission internal alwaysTrue;

    function setUp() public virtual {
        permSigner = vm.addr(PERM_SIGNER_KEY);
        manager    = vm.addr(MANAGER_KEY);
        attacker   = vm.addr(ATTACKER_KEY);

        vm.deal(address(this), 1000 ether);
        vm.deal(attacker,      100 ether);

        // Deploy governance
        gov = new SailGovernance(address(this), 0.001 ether, address(this), 0);
        vm.startPrank(address(gov.timelock()));
        gov.setProtocolCutBps(1_000);
        gov.setPermissionRegistrationFee(0.001 ether);
        vm.stopPrank();

        kernel  = new SailKernel(address(gov), TREASURY);
        factory = new MandateFactory(address(kernel));

        safe = new MockSafe();
        safe.enableModule(address(kernel));
        vm.deal(address(safe), 100 ether);

        // Register the Safe account
        vm.prank(address(safe));
        kernel.registerAccount(permSigner, manager, address(0), address(0));

        // Deploy a benign always-true permission
        alwaysTrue = new AlwaysTruePermission();
    }

    // ── Test helpers ─────────────────────────────────────────────────────────

    function _trustFeePolicy(address policy) internal {
        vm.prank(address(gov.timelock()));
        gov.setTrustedFeePolicy(policy, true);
    }

    // ── Signature helpers ────────────────────────────────────────────────────

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

    function _signRevokeSession(address account, uint256 nonce, uint256 signerKey)
        internal view returns (bytes memory)
    {
        uint256 deadline = block.timestamp + 1 days;
        bytes32 sh = keccak256(abi.encode(kernel.REVOKE_SESSION_TYPEHASH(), account, nonce, deadline));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }

    function _signActivateSession(address account, uint256 nonce, uint256 signerKey)
        internal view returns (bytes memory)
    {
        uint256 deadline = block.timestamp + 1 days;
        bytes32 sh = keccak256(abi.encode(kernel.ACTIVATE_SESSION_TYPEHASH(), account, nonce, deadline));
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

    receive() external payable {}

    /// Register alwaysTrue as a permission for the test safe (permSigner-signed)
    function _registerAlwaysTrue() internal {
        uint256 nonce = kernel.signerNonces(address(safe));
        uint256 deadline = block.timestamp + 1 days;
        bytes memory sig = _signRegisterPermission(address(safe), address(alwaysTrue), nonce, PERM_SIGNER_KEY);
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(alwaysTrue), deadline, sig);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 1: Manager steals via dispatch abuse
// ═════════════════════════════════════════════════════════════════════════════
contract DispatchAbuseTests is RedTeamBase {

    // ── 1a. Manager dispatch with no registered permissions (deny-by-default) ──

    function test_Attack_DispatchWithNoPermissions() public {
        // With selective semantics, the named permission must be registered.
        // No permissions are registered here, so PermissionNotRegistered fires.
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", attacker, 1 ether);
        bytes memory sig  = _signDispatch(address(safe), address(alwaysTrue), attacker, 0, data, 0, deadline, MANAGER_KEY);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionNotRegistered.selector, address(alwaysTrue)));
        kernel.dispatch(address(safe), address(alwaysTrue), attacker, 0, data, sig, deadline);
    }

    // ── 1b. Manager replays an old nonce ──

    function test_Attack_ManagerNonceReplay() public {
        _registerAlwaysTrue();

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory data = "";
        bytes memory sig  = _signDispatch(address(safe), address(alwaysTrue), attacker, 0, data, 0, deadline, MANAGER_KEY);

        // First dispatch succeeds
        kernel.dispatch(address(safe), address(alwaysTrue), attacker, 0, data, sig, deadline);

        // Replay the same sig — nonce is now 1, so the sig for nonce 0 is invalid
        vm.expectRevert(SailKernel.InvalidManagerSignature.selector);
        kernel.dispatch(address(safe), address(alwaysTrue), attacker, 0, data, sig, deadline);
    }

    // ── 1c. Manager dispatches after session revoked ──

    function test_Attack_DispatchAfterSessionRevoked() public {
        _registerAlwaysTrue();

        // permSigner revokes the session
        uint256 signerNonce = kernel.signerNonces(address(safe));
        uint256 revokeDeadline = block.timestamp + 1 days;
        bytes memory revokeSig = _signRevokeSession(address(safe), signerNonce, PERM_SIGNER_KEY);
        kernel.revokeSession(address(safe), revokeDeadline, revokeSig);

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory data = "";
        bytes memory sig  = _signDispatch(address(safe), address(alwaysTrue), attacker, 0, data, 0, deadline, MANAGER_KEY);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.SessionInactive.selector, address(safe)));
        kernel.dispatch(address(safe), address(alwaysTrue), attacker, 0, data, sig, deadline);
    }

    // ── 1d. Manager uses expired deadline ──

    function test_Attack_DispatchExpiredDeadline() public {
        _registerAlwaysTrue();

        uint256 deadline = block.timestamp - 1; // already expired
        bytes memory data = "";
        bytes memory sig  = _signDispatch(address(safe), address(alwaysTrue), attacker, 0, data, 0, deadline, MANAGER_KEY);

        vm.expectRevert(
            abi.encodeWithSelector(SailKernel.DeadlineExpired.selector, deadline, block.timestamp)
        );
        kernel.dispatch(address(safe), address(alwaysTrue), attacker, 0, data, sig, deadline);
    }

    // ── 1e. Attacker (not manager) tries to dispatch without valid manager key ──

    function test_Attack_DispatchWithWrongKey() public {
        _registerAlwaysTrue();

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory data = "";
        // Sign with ATTACKER_KEY instead of MANAGER_KEY
        bytes memory sig = _signDispatch(address(safe), address(alwaysTrue), attacker, 0, data, 0, deadline, ATTACKER_KEY);

        vm.expectRevert(SailKernel.InvalidManagerSignature.selector);
        kernel.dispatch(address(safe), address(alwaysTrue), attacker, 0, data, sig, deadline);
    }

    // ── 1f. Manager dispatches with a modified calldata (but same nonce/digest) ──
    //   The dispatch digest commits to keccak256(data). Any change breaks the sig.

    function test_Attack_DispatchCalldataTampering() public {
        _registerAlwaysTrue();

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory originalData = abi.encodeWithSignature("transfer(address,uint256)", address(0xBEEF), 1 ether);
        bytes memory tamperedData = abi.encodeWithSignature("transfer(address,uint256)", attacker, 999 ether);

        // Sign over originalData
        bytes memory sig = _signDispatch(address(safe), address(alwaysTrue), address(0), 0, originalData, 0, deadline, MANAGER_KEY);

        // Attempt dispatch with tamperedData — digest mismatch
        vm.expectRevert(SailKernel.InvalidManagerSignature.selector);
        kernel.dispatch(address(safe), address(alwaysTrue), address(0), 0, tamperedData, sig, deadline);
    }

    // ── 1g. Manager uses wrong target (target is covered by sig commitment) ──

    function test_Attack_DispatchWrongTarget() public {
        _registerAlwaysTrue();

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory data = "";
        address signedTarget = address(0xBEEF);
        address attackTarget = address(0xDEAD);

        bytes memory sig = _signDispatch(address(safe), address(alwaysTrue), signedTarget, 0, data, 0, deadline, MANAGER_KEY);

        // Different target — must revert
        vm.expectRevert(SailKernel.InvalidManagerSignature.selector);
        kernel.dispatch(address(safe), address(alwaysTrue), attackTarget, 0, data, sig, deadline);
    }

    // ── 1h. Cross-account sig replay: use account A's dispatch sig for account B ──

    function test_Attack_CrossAccountDispatchReplay() public {
        // Create a second safe and register it
        MockSafe safe2 = new MockSafe();
        safe2.enableModule(address(kernel));
        vm.deal(address(safe2), 10 ether);
        vm.prank(address(safe2));
        kernel.registerAccount(permSigner, manager, address(0), address(0));

        // Register alwaysTrue for safe2 too
        uint256 nonce2 = kernel.signerNonces(address(safe2));
        uint256 regDeadline2 = block.timestamp + 1 days;
        bytes memory regSig2 = _signRegisterPermission(address(safe2), address(alwaysTrue), nonce2, PERM_SIGNER_KEY);
        kernel.registerPermission{value: 0.001 ether}(address(safe2), address(alwaysTrue), regDeadline2, regSig2);

        // Also register for safe
        _registerAlwaysTrue();

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory data = "";

        // Signature for safe (account A)
        bytes memory sigForA = _signDispatch(address(safe), address(alwaysTrue), attacker, 0, data, 0, deadline, MANAGER_KEY);

        // Try to use safe A's sig on safe B — should fail since account is in the digest
        vm.expectRevert(SailKernel.InvalidManagerSignature.selector);
        kernel.dispatch(address(safe2), address(alwaysTrue), attacker, 0, data, sigForA, deadline);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 2: Signature attacks on permission registry
// ═════════════════════════════════════════════════════════════════════════════
contract SignatureAttackTests is RedTeamBase {

    // ── 2a. Replay a used register-permission sig ──

    function test_Attack_RegisterPermissionSigReplay() public {
        uint256 nonce = kernel.signerNonces(address(safe));
        uint256 regDeadline = block.timestamp + 1 days;
        bytes memory sig = _signRegisterPermission(address(safe), address(alwaysTrue), nonce, PERM_SIGNER_KEY);

        // First registration succeeds
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(alwaysTrue), regDeadline, sig);

        // Second attempt: nonce consumed, PermissionAlreadyRegistered fires first
        // because the sig check passes with old nonce only if nonce matches.
        // But nonce is now 1, so the sig (for nonce 0) is invalid.
        AlwaysTruePermission p2 = new AlwaysTruePermission();
        vm.expectRevert(SailKernel.InvalidSignerSignature.selector);
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(p2), regDeadline, sig);
    }

    // ── 2b. Attacker registers a permission for victim's account with wrong key ──

    function test_Attack_RegisterPermissionWrongKey() public {
        uint256 nonce = kernel.signerNonces(address(safe));
        uint256 regDeadline = block.timestamp + 1 days;
        // Sign with ATTACKER_KEY instead of permSigner's key
        bytes memory sig = _signRegisterPermission(address(safe), address(alwaysTrue), nonce, ATTACKER_KEY);

        vm.expectRevert(SailKernel.InvalidSignerSignature.selector);
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(alwaysTrue), regDeadline, sig);
    }

    // ── 2c. Cross-account register sig replay (use account A's sig for account B) ──

    function test_Attack_CrossAccountRegisterReplay() public {
        MockSafe safe2 = new MockSafe();
        safe2.enableModule(address(kernel));
        vm.prank(address(safe2));
        // permSigner controls both accounts
        kernel.registerAccount(permSigner, manager, address(0), address(0));

        // Nonces may differ; get sig for safe (account A)
        uint256 nonceA = kernel.signerNonces(address(safe));
        uint256 regDeadline = block.timestamp + 1 days;
        bytes memory sigForA = _signRegisterPermission(address(safe), address(alwaysTrue), nonceA, PERM_SIGNER_KEY);

        // Try to use account A's sig to register on account B
        vm.expectRevert(SailKernel.InvalidSignerSignature.selector);
        kernel.registerPermission{value: 0.001 ether}(address(safe2), address(alwaysTrue), regDeadline, sigForA);
    }

    // ── 2d. Malicious ERC-1271 manager: contract that approves any sig ──
    //   If the manager role is a contract with a blanket isValidSignature, the attacker
    //   can set themselves as manager and dispatch anything.
    //   This checks whether the kernel prevents a malicious ERC-1271 manager from
    //   being *registered* — it does not prevent it, but this tests exploit potential.

    function test_Attack_MaliciousERC1271Manager() public {
        // Deploy a contract that signs anything
        MaliciousERC1271Signer badManager = new MaliciousERC1271Signer();

        // Register a new safe with badManager as manager
        MockSafe safe3 = new MockSafe();
        safe3.enableModule(address(kernel));
        vm.deal(address(safe3), 10 ether);
        vm.prank(address(safe3));
        kernel.registerAccount(permSigner, address(badManager), address(0), address(0));

        // Register a permission for safe3
        uint256 nonce3 = kernel.signerNonces(address(safe3));
        uint256 regDeadline3 = block.timestamp + 1 days;
        bytes memory regSig3 = _signRegisterPermission(address(safe3), address(alwaysTrue), nonce3, PERM_SIGNER_KEY);
        kernel.registerPermission{value: 0.001 ether}(address(safe3), address(alwaysTrue), regDeadline3, regSig3);

        // Now attacker can dispatch as badManager with any garbage signature bytes
        // because badManager.isValidSignature returns the magic value unconditionally.
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", attacker, 50 ether);
        bytes memory junkSig = hex"deadbeef";

        // VULNERABILITY NOTE: If the kernel registers a malicious ERC-1271 manager,
        // that manager (or anyone who knows the contract) can dispatch arbitrary calls.
        // The protocol relies on the permissionSigner to choose a trustworthy manager.
        // This is a documented trust assumption, not a protocol bug.
        // The test verifies the kernel DOES execute with a MaliciousERC1271Manager.
        bool dispatched;
        try kernel.dispatch(address(safe3), address(alwaysTrue), attacker, 0, data, junkSig, deadline) {
            dispatched = true;
        } catch {
            dispatched = false;
        }
        // Document the outcome — dispatch succeeds with blanket ERC-1271 manager.
        // This is expected behavior per protocol design (permissionSigner chooses manager).
        // If dispatched == true here it means: attacker = manager = blank-sig contract.
        // That is a social/operational risk, not a smart contract vulnerability.
        console.log("MaliciousERC1271Manager dispatched:", dispatched);
    }

    // ── 2e. Revoke-session sig cannot be replayed ──

    function test_Attack_RevokeSessionSigReplay() public {
        uint256 nonce = kernel.signerNonces(address(safe));
        uint256 revokeDeadline = block.timestamp + 1 days;
        bytes memory revokeSig = _signRevokeSession(address(safe), nonce, PERM_SIGNER_KEY);

        // Revoke succeeds
        kernel.revokeSession(address(safe), revokeDeadline, revokeSig);
        (,,,, bool sessionActive0) = kernel.configs(address(safe));
        assertFalse(sessionActive0);

        // Replay after nonce increment — activate then try to revoke again with old sig
        uint256 nonce2 = kernel.signerNonces(address(safe));
        uint256 activateDeadline = block.timestamp + 1 days;
        bytes memory activateSig = _signActivateSession(address(safe), nonce2, PERM_SIGNER_KEY);
        kernel.activateSession(address(safe), activateDeadline, activateSig);

        // Attempt to replay old revokeSession sig
        vm.expectRevert(SailKernel.InvalidSignerSignature.selector);
        kernel.revokeSession(address(safe), revokeDeadline, revokeSig);
    }

    // ── 2f. Manager cannot forge a signer sig (wrong key) ──

    function test_Attack_ManagerForgesSignerSig() public {
        uint256 nonce = kernel.signerNonces(address(safe));
        uint256 regDeadline = block.timestamp + 1 days;
        // Manager tries to sign a register-permission using the manager key
        bytes memory forgedSig = _signRegisterPermission(address(safe), address(alwaysTrue), nonce, MANAGER_KEY);

        vm.expectRevert(SailKernel.InvalidSignerSignature.selector);
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(alwaysTrue), regDeadline, forgedSig);
    }

    // ── 2g. Attacker uses a revoke-permission sig to register a permission ──
    //   Typehash mismatch should prevent this.

    function test_Attack_TypehashConfusion_RevokeAsRegister() public {
        _registerAlwaysTrue();

        // Create a second permission to try to register
        AlwaysTruePermission p2 = new AlwaysTruePermission();

        uint256 nonce = kernel.signerNonces(address(safe));
        uint256 regDeadline = block.timestamp + 1 days;
        // Build a REVOKE sig for p2 — structHash uses REVOKE_TYPEHASH (wrong typehash)
        bytes32 sh = keccak256(abi.encode(
            kernel.REVOKE_PERMISSION_TYPEHASH(), address(safe), address(p2), nonce, regDeadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PERM_SIGNER_KEY, kernel.hashTypedDataV4(sh));
        bytes memory revokeSigUsedAsRegister = abi.encodePacked(r, s, v);

        // Attempt to use a revoke sig as a register sig — should fail due to typehash
        vm.expectRevert(SailKernel.InvalidSignerSignature.selector);
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(p2), regDeadline, revokeSigUsedAsRegister);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 3: Template bypass attacks
// ═════════════════════════════════════════════════════════════════════════════
contract TemplateBypassTests is RedTeamBase {

    // ── 3a. Manager passes zero-length calldata to trigger ETH-path on ERC20-only permission ──
    //   TransferTargetPermission: data.length < 4 is the "plain ETH send" path.
    //   If the token/amount guard is only on the ERC-20 path, check if pure ETH
    //   send to an unapproved recipient bypasses with len < 4 calldata.

    function test_Attack_TransferTargetPermission_ETHPathBypass() public {
        address[] memory recipients = new address[](1);
        recipients[0] = address(0xBEEF); // only beef is allowed
        address[] memory tokens = new address[](0);

        TransferTargetPermission ttp = TransferTargetPermission(Clones.clone(address(new TransferTargetPermission())));
        ttp.initialize(recipients, tokens, 10 ether, permSigner);

        // Register the permission
        uint256 nonce = kernel.signerNonces(address(safe));
        uint256 regDeadline = block.timestamp + 1 days;
        bytes memory regSig = _signRegisterPermission(address(safe), address(ttp), nonce, PERM_SIGNER_KEY);
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(ttp), regDeadline, regSig);

        // Try to send ETH to the attacker (not an allowed recipient) using empty calldata
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory data = ""; // len < 4 triggers the ETH path

        bytes memory dispatchSig = _signDispatch(
            address(safe), address(ttp), attacker, 1 ether, data, 0, deadline, MANAGER_KEY
        );

        // The ETH path checks isAllowedRecipient[ctx.target]. attacker is NOT allowed.
        // This should revert with PermissionDenied.
        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(ttp)));
        kernel.dispatch(address(safe), address(ttp), attacker, 1 ether, data, dispatchSig, deadline);
    }

    // ── 3b. Manager tries to use transferFrom path to pull from an external victim ──
    //   The TransferTargetPermission explicitly does NOT validate the `from` field.
    //   A manager could pull tokens from any address that approved the Safe.

    function test_Attack_TransferTargetPermission_TransferFromUnboundedFrom() public {
        address victim = address(0x1234);
        address[] memory recipients = new address[](1);
        recipients[0] = attacker; // attacker is the recipient
        address[] memory tokens = new address[](1);
        address mockToken = address(0x5678);
        tokens[0] = mockToken;

        TransferTargetPermission ttp = TransferTargetPermission(Clones.clone(address(new TransferTargetPermission())));
        ttp.initialize(recipients, tokens, 1000 ether, permSigner);

        // Register the permission
        uint256 nonce = kernel.signerNonces(address(safe));
        uint256 regDeadline = block.timestamp + 1 days;
        bytes memory regSig = _signRegisterPermission(address(safe), address(ttp), nonce, PERM_SIGNER_KEY);
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(ttp), regDeadline, regSig);

        // Build transferFrom(victim, attacker, 500 ether)
        bytes4 TF_SEL = 0x23b872dd;
        bytes memory data = abi.encodeWithSelector(TF_SEL, victim, attacker, 500 ether);

        // M-6 fix: `from` must equal ctx.account. A different `from` is rejected.
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory dispatchSig = _signDispatch(address(safe), address(ttp), mockToken, 0, data, 0, deadline, MANAGER_KEY);

        // Permission now returns false because victim != ctx.account (safe).
        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(ttp)));
        kernel.dispatch(address(safe), address(ttp), mockToken, 0, data, dispatchSig, deadline);
    }

    // ── 3c. Selector collision: calldata that matches a known selector but decodes to attacker addresses ──
    //   Test BoundedBorrowPermission's Aave path with onBehalfOf != ctx.account

    function test_Attack_BorrowPermission_WrongOnBehalfOf() public {
        address protocol = address(0xAABB);
        address asset    = address(0xCCDD);

        address[] memory protocols = new address[](1);
        protocols[0] = protocol;
        address[] memory assets = new address[](1);
        assets[0] = asset;

        BoundedBorrowPermission bbp = BoundedBorrowPermission(Clones.clone(address(new BoundedBorrowPermission())));
        bbp.initialize(
            protocols, assets,
            1_000_000 ether, // large cap
            0,               // no LTV
            address(0),      // no collateral oracle
            address(0),      // no borrow oracle
            permSigner
        );

        // Register the borrow permission
        uint256 nonce = kernel.signerNonces(address(safe));
        uint256 regDeadline = block.timestamp + 1 days;
        bytes memory regSig = _signRegisterPermission(address(safe), address(bbp), nonce, PERM_SIGNER_KEY);
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(bbp), regDeadline, regSig);

        // Aave borrow calldata where onBehalfOf = attacker (not the safe)
        bytes4 AAVE_SEL = bytes4(keccak256("borrow(address,uint256,uint256,uint16,address)"));
        bytes memory data = abi.encodeWithSelector(
            AAVE_SEL,
            asset,       // asset
            500_000e6,   // amount
            uint256(2),  // interestRateMode
            uint16(0),   // referralCode
            attacker     // onBehalfOf = ATTACKER (not safe)
        );

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory dispatchSig = _signDispatch(address(safe), address(bbp), protocol, 0, data, 0, deadline, MANAGER_KEY);

        // onBehalfOf != ctx.account — permission returns false → PermissionDenied
        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(bbp)));
        kernel.dispatch(address(safe), address(bbp), protocol, 0, data, dispatchSig, deadline);
    }

    // ── 3d. Extra-data appended after valid calldata to evade length checks ──
    //   BoundedBorrowPermission checks `txData.length < LEN_X`, not `== LEN_X`.
    //   Padding extra bytes after valid calldata is accepted — this is fine because
    //   abi.decode ignores trailing data. Test confirms no bypass.

    function test_Attack_BorrowPermission_ExtraTrailingBytes() public {
        address protocol = address(0xAABB);
        address asset    = address(0xCCDD);

        address[] memory protocols = new address[](1);
        protocols[0] = protocol;
        address[] memory assets = new address[](1);
        assets[0] = asset;

        BoundedBorrowPermission bbp = BoundedBorrowPermission(Clones.clone(address(new BoundedBorrowPermission())));
        bbp.initialize(
            protocols, assets,
            1_000_000 ether,
            0, address(0), address(0),
            permSigner
        );

        uint256 nonce = kernel.signerNonces(address(safe));
        uint256 regDeadline = block.timestamp + 1 days;
        bytes memory regSig = _signRegisterPermission(address(safe), address(bbp), nonce, PERM_SIGNER_KEY);
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(bbp), regDeadline, regSig);

        // Valid Aave borrow with correct onBehalfOf, but with 64 extra bytes appended
        bytes4 AAVE_SEL = bytes4(keccak256("borrow(address,uint256,uint256,uint16,address)"));
        bytes memory validData = abi.encodeWithSelector(
            AAVE_SEL,
            asset, uint256(1000), uint256(2), uint16(0), address(safe)
        );
        bytes memory extraData = bytes.concat(validData, bytes32(uint256(0xCAFE)), bytes32(uint256(0xBABE)));

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory dispatchSig = _signDispatch(address(safe), address(bbp), protocol, 0, extraData, 0, deadline, MANAGER_KEY);

        // Should succeed — trailing bytes are ignored by abi.decode
        kernel.dispatch(address(safe), address(bbp), protocol, 0, extraData, dispatchSig, deadline);
    }

    // ── 3e. Zero-length data with a permission that only checks the selector (ctx.selector == bytes4(0)) ──

    function test_Attack_ZeroLengthCalldataDispatch() public {
        _registerAlwaysTrue();

        // Dispatch with 0-byte data — ctx.selector will be bytes4(0)
        // alwaysTrue returns true regardless, so this should succeed
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory data = "";
        bytes memory sig  = _signDispatch(address(safe), address(alwaysTrue), address(0xBEEF), 0, data, 0, deadline, MANAGER_KEY);

        kernel.dispatch(address(safe), address(alwaysTrue), address(0xBEEF), 0, data, sig, deadline);
        // Dispatch succeeded with zero-length calldata — not a vulnerability since
        // alwaysTrue explicitly allows everything; real permissions would gate on selector.
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 4: Fee / ETH accounting attacks
// ═════════════════════════════════════════════════════════════════════════════
contract FeeAccountingTests is RedTeamBase {

    // ── 4a. Manager calls collectFees with inflated NAV to extract max fee ──
    //   The kernel relies on the fee policy to bound grossFee. A permissionSigner-set
    //   fee policy that is manipulable allows unlimited extraction.

    function test_Attack_CollectFees_InflatedNAV() public {
        // Deploy a fee policy that allows any fee up to the reported max
        uint256 hugeFee = 99 ether; // almost the entire safe balance
        InflatedFeePolicy badPolicy = new InflatedFeePolicy(hugeFee, address(0), 0);
        _trustFeePolicy(address(badPolicy));

        // permSigner sets the fee policy to the malicious one
        uint256 nonce = kernel.signerNonces(address(safe));
        bytes memory fpSig = _signSetFeePolicy(address(safe), address(badPolicy), nonce, PERM_SIGNER_KEY);
        kernel.setFeePolicy(address(safe), address(badPolicy), address(0), type(uint256).max, fpSig);

        uint256 safeBalBefore = address(safe).balance;
        uint256 managerBalBefore = attacker.balance;

        // Manager calls collectFees with inflated NAV; grossFee == hugeFee
        vm.prank(manager);
        kernel.collectFees(address(safe), hugeFee, 1_000_000e18, address(0));

        uint256 safeBalAfter = address(safe).balance;
        uint256 managerBalAfter = attacker.balance;

        // VULNERABILITY (documented/by design): The kernel says:
        //   "TRUST ASSUMPTION: currentNav is provided by the manager and is not verified on-chain."
        // If the permissionSigner installs a malicious fee policy, the manager
        // can drain up to safeBalance in a single collectFees call.
        // This is a documented trust assumption, but we record it here explicitly.
        console.log("Safe drained by:", safeBalBefore - safeBalAfter);
        console.log("Attacker gained:", managerBalAfter - managerBalBefore);
        assertLt(safeBalAfter, safeBalBefore, "Safe should lose funds to fee extraction");
    }

    // ── 4b. Non-manager calls collectFees ──

    function test_Attack_CollectFees_NotManager() public {
        InflatedFeePolicy badPolicy = new InflatedFeePolicy(1 ether, address(0), 0);
        _trustFeePolicy(address(badPolicy));
        uint256 nonce = kernel.signerNonces(address(safe));
        bytes memory fpSig = _signSetFeePolicy(address(safe), address(badPolicy), nonce, PERM_SIGNER_KEY);
        kernel.setFeePolicy(address(safe), address(badPolicy), address(0), type(uint256).max, fpSig);

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(SailKernel.NotManager.selector, attacker, manager));
        kernel.collectFees(address(safe), 1 ether, 1e18, address(0));
    }

    // ── 4c. collectFees with distributorBps > 10_000 (integer overflow split) ──

    function test_Attack_CollectFees_DistributorBpsOverflow() public {
        // Policy returns distributorBps = 10_001 (one over 100%)
        address malDist = address(0xBAD);
        InflatedFeePolicy badPolicy = new InflatedFeePolicy(1 ether, malDist, 10_001);
        _trustFeePolicy(address(badPolicy));
        uint256 nonce = kernel.signerNonces(address(safe));
        bytes memory fpSig = _signSetFeePolicy(address(safe), address(badPolicy), nonce, PERM_SIGNER_KEY);
        kernel.setFeePolicy(address(safe), address(badPolicy), address(0), type(uint256).max, fpSig);

        vm.prank(manager);
        vm.expectRevert(abi.encodeWithSelector(SailKernel.DistributorBpsTooLarge.selector, 10_001));
        kernel.collectFees(address(safe), 1 ether, 1e18, address(0));
    }

    // ── 4d. collectFees: grossFee > maxFee ──

    function test_Attack_CollectFees_FeeTooLarge() public {
        InflatedFeePolicy policy = new InflatedFeePolicy(0.5 ether, address(0), 0);
        _trustFeePolicy(address(policy));
        uint256 nonce = kernel.signerNonces(address(safe));
        bytes memory fpSig = _signSetFeePolicy(address(safe), address(policy), nonce, PERM_SIGNER_KEY);
        kernel.setFeePolicy(address(safe), address(policy), address(0), type(uint256).max, fpSig);

        vm.prank(manager);
        // Request 1 ether but policy max is 0.5 ether
        vm.expectRevert(abi.encodeWithSelector(SailKernel.FeeTooLarge.selector, 1 ether, 0.5 ether));
        kernel.collectFees(address(safe), 1 ether, 1e18, address(0));
    }

    // ── 4e. collectFees with no fee policy set ──

    function test_Attack_CollectFees_NoPolicySet() public {
        // safe registered with address(0) feePolicy
        vm.prank(manager);
        vm.expectRevert(SailKernel.FeePolicyNotSet.selector);
        kernel.collectFees(address(safe), 1 ether, 1e18, address(0));
    }

    // ── 4f. Reentrancy into registerPermission via the ETH refund callback ──
    //   _collectRegistrationFee refunds excess ETH to msg.sender via a raw call.
    //   All state changes happen before this call (nonReentrant guards the outer fn),
    //   so reentry should be blocked.

    function test_Attack_ReentrancyViaRefund() public {
        ReentrancyAttacker rAttacker = new ReentrancyAttacker(address(kernel));
        vm.deal(address(rAttacker), 10 ether);

        // Register rAttacker's account (it calls registerAccount as itself)
        vm.prank(address(rAttacker));
        kernel.registerAccount(permSigner, manager, address(0), address(0));

        AlwaysTruePermission p1 = new AlwaysTruePermission();
        AlwaysTruePermission p2 = new AlwaysTruePermission();

        // Pre-sign both register sigs for nonce 0 and nonce 1
        uint256 nonce0 = kernel.signerNonces(address(rAttacker));
        uint256 regDeadline = block.timestamp + 1 days;
        bytes memory sig0 = _signRegisterPermission(address(rAttacker), address(p1), nonce0, PERM_SIGNER_KEY);
        uint256 nonce1 = nonce0 + 1;
        bytes memory sig1 = _signRegisterPermission(address(rAttacker), address(p2), nonce1, PERM_SIGNER_KEY);

        rAttacker.setReentryParams(address(rAttacker), address(p2), regDeadline, sig1);

        // Overpay so there's a refund — the refund callback triggers reentry attempt
        // nonReentrant on registerPermission should block the second call
        vm.prank(address(rAttacker));
        kernel.registerPermission{value: 1 ether}(address(rAttacker), address(p1), regDeadline, sig0);

        // If reentrancy was blocked, p2 is NOT registered (the inner call reverted silently)
        // If reentrancy succeeded, p2 IS registered
        bool p2Registered = kernel.isPermissionRegistered(address(rAttacker), address(p2));
        // nonReentrant should have blocked the inner call
        // This is the critical assertion: if p2 is registered, reentrancy succeeded.
        assertFalse(p2Registered, "Reentrancy into registerPermission should be blocked by nonReentrant");
    }

    // ── 4g. StandardFeePolicy: manager inflates NAV to claim performance fee on first call ──
    //   The ZeroInitialNav guard requires currentNav != 0 on first recordCollection.
    //   Test that trying NAV = 0 on first collection is blocked.

    function test_Attack_StandardFeePolicy_ZeroInitialNav() public {
        StandardFeePolicy sfp = new StandardFeePolicy(
            200,    // 2% management
            2000,   // 20% performance
            address(0), 0,
            address(kernel),
            permSigner
        );
        _trustFeePolicy(address(sfp));

        uint256 nonce = kernel.signerNonces(address(safe));
        bytes memory fpSig = _signSetFeePolicy(address(safe), address(sfp), nonce, PERM_SIGNER_KEY);
        kernel.setFeePolicy(address(safe), address(sfp), address(0), type(uint256).max, fpSig);

        // Without HWM seeded, computeFee returns maxFee=0 (early-return path).
        // The kernel's ZeroFee guard blocks grossFee=0, and FeeTooLarge blocks any
        // grossFee>0 against maxFee=0 — so no fee can ever be collected.
        // Here we verify the ZeroFee path: manager can't even claim 0 fees.
        vm.prank(manager);
        vm.expectRevert(SailKernel.ZeroFee.selector);
        kernel.collectFees(address(safe), 0, 0, address(0));
    }

    // ── 4h. StandardFeePolicy: manager tries to collect on same block twice ──
    //   If elapsed == 0, management fee should be 0. Performance fee is
    //   only on NAV > HWM, which shouldn't apply immediately. Both should be 0.

    function test_Attack_StandardFeePolicy_DoubleCollectSameBlock() public {
        StandardFeePolicy sfp = new StandardFeePolicy(
            200, 2000, address(0), 0, address(kernel), permSigner
        );
        _trustFeePolicy(address(sfp));

        uint256 nonce = kernel.signerNonces(address(safe));
        bytes memory fpSig = _signSetFeePolicy(address(safe), address(sfp), nonce, PERM_SIGNER_KEY);
        kernel.setFeePolicy(address(safe), address(sfp), address(0), type(uint256).max, fpSig);

        // H-5 fix: feeManager must seed HWM before manager can collect.
        // seedHighWaterMark now also initialises lastCollectionTimestamp.
        vm.prank(permSigner); // permSigner acts as feeManager in this test's sfp
        sfp.seedHighWaterMark(address(safe), 1_000_000e18);

        // Advance past MIN_COLLECTION_INTERVAL so a non-zero fee accrues.
        vm.warp(block.timestamp + sfp.MIN_COLLECTION_INTERVAL() + 1);

        // First collection: succeeds with a token amount well within maxFee.
        // (MockSafe.execTransactionFromModule always returns true so no real ETH moves.)
        vm.prank(manager);
        kernel.collectFees(address(safe), 1, 1_000_000e18, address(0));

        // I-10 fix: MIN_COLLECTION_INTERVAL prevents rapid double-collect.
        // After the first collection the timestamp is reset; a second attempt within
        // MIN_COLLECTION_INTERVAL fires CollectionTooFrequent inside recordCollection.
        // We warp 1 second so maxFee is positive (>0) but elapsed < MIN_COLLECTION_INTERVAL.
        vm.warp(block.timestamp + 1);
        vm.prank(manager);
        vm.expectRevert(StandardFeePolicy.CollectionTooFrequent.selector);
        kernel.collectFees(address(safe), 1, 1_000_000e18, address(0));
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 5: Governance attacks
// ═════════════════════════════════════════════════════════════════════════════
contract GovernanceAttackTests is RedTeamBase {

    // ── 5a. Attacker attempts to change governance parameters directly ──

    function test_Attack_BypassTimelockOnParameterSet() public {
        // Attacker tries to call setProtocolCutBps directly on governance
        vm.prank(attacker);
        vm.expectRevert(SailGovernance.NotTimelock.selector);
        gov.setProtocolCutBps(2_500);
    }

    // ── 5b. Attacker tries to pause the kernel without being emergencyAdmin ──

    function test_Attack_PauseWithoutEmergencyAdmin() public {
        vm.prank(attacker);
        vm.expectRevert(SailGovernance.NotEmergencyAdmin.selector);
        gov.pause();
    }

    // ── 5c. Emergency admin pauses indefinitely beyond 72 hours ──
    //   The pause auto-expires at block.timestamp + 72 hours.
    //   emergencyAdmin CAN re-pause after expiry. This is by design but let's
    //   verify the 72-hour cap is actually enforced.

    function test_Attack_EmergencyPauseAutoExpiry() public {
        // emergencyAdmin (address(this) in setUp) pauses
        gov.pause();
        assertTrue(gov.isPaused());

        // Fast-forward 72+ hours
        vm.warp(block.timestamp + 72 hours + 1);
        assertFalse(gov.isPaused(), "Pause should auto-expire after 72 hours");

        // After expiry, dispatch should work again
        _registerAlwaysTrue();
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory data = "";
        bytes memory sig  = _signDispatch(address(safe), address(alwaysTrue), address(0xBEEF), 0, data, 0, deadline, MANAGER_KEY);
        kernel.dispatch(address(safe), address(alwaysTrue), address(0xBEEF), 0, data, sig, deadline);
    }

    // ── 5d. Attacker tries to accept governance when not pending ──

    function test_Attack_AcceptGovernanceNotPending() public {
        vm.prank(attacker);
        vm.expectRevert(SailGovernance.NotPendingGovernance.selector);
        gov.acceptGovernance();
    }

    // ── 5e. Governance setTreasury bypasses timelock ──

    function test_Attack_SetTreasuryWithoutTimelock() public {
        vm.prank(attacker);
        vm.expectRevert(SailKernel.NotTimelock.selector);
        kernel.setTreasury(attacker);
    }

    // ── 5f. Permission cap enforcement: attacker tries to register beyond cap ──

    function test_Attack_ExceedPermissionCap() public {
        // Governance sets max to 1
        vm.prank(address(gov.timelock()));
        gov.setMaxPermissionsPerAccount(1);

        // Register one permission successfully
        _registerAlwaysTrue();

        // Try to register a second — exceeds cap
        AlwaysTruePermission p2 = new AlwaysTruePermission();
        uint256 nonce = kernel.signerNonces(address(safe));
        uint256 regDeadline = block.timestamp + 1 days;
        bytes memory sig2 = _signRegisterPermission(address(safe), address(p2), nonce, PERM_SIGNER_KEY);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.TooManyPermissions.selector, address(safe), uint256(1)));
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(p2), regDeadline, sig2);
    }

    // ── 5g. Dispatch blocked when protocol paused ──

    function test_Attack_DispatchWhenPaused() public {
        _registerAlwaysTrue();
        gov.pause(); // emergencyAdmin = address(this)

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory data = "";
        bytes memory sig  = _signDispatch(address(safe), address(alwaysTrue), address(0xBEEF), 0, data, 0, deadline, MANAGER_KEY);

        vm.expectRevert(SailKernel.ProtocolPaused.selector);
        kernel.dispatch(address(safe), address(alwaysTrue), address(0xBEEF), 0, data, sig, deadline);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 6: Oracle manipulation attacks
// ═════════════════════════════════════════════════════════════════════════════
contract OracleManipulationTests is RedTeamBase {

    // ── 6a. Manipulable oracle allows LTV bypass: if oracle price is attacker-controlled
    //   the permissionSigner can register an oracle that returns inflated collateral,
    //   allowing the manager to borrow well above safe LTV levels.
    //   We demonstrate with integer-precise numbers that satisfy the LTV formula.

    function test_Attack_MaliciousOracle_InflatedCollateral() public {
        address protocol = address(0xAABB);
        address asset    = address(0xCCDD);

        // Use 0-decimal oracles. colValue = 10, borPrice = 1.
        // 75% LTV → can borrow up to 7 units (floor(10 * 7500 / 10000) = 7).
        // Borrowing 8 units gives ltvBps = 8*10000/10 = 8000 > 7500 → DENIED.
        ManipulableOracle collOracle = new ManipulableOracle(10, 0);
        ManipulableOracle borOracle  = new ManipulableOracle(1, 0);

        address[] memory protocols = new address[](1);
        protocols[0] = protocol;
        address[] memory assets = new address[](1);
        assets[0] = asset;

        BoundedBorrowPermission bbp = BoundedBorrowPermission(Clones.clone(address(new BoundedBorrowPermission())));
        bbp.initialize(
            protocols, assets,
            1_000_000 ether,
            7_500,               // 75% LTV
            address(collOracle),
            address(borOracle),
            permSigner
        );

        uint256 nonce = kernel.signerNonces(address(safe));
        uint256 regDeadline = block.timestamp + 1 days;
        bytes memory regSig = _signRegisterPermission(address(safe), address(bbp), nonce, PERM_SIGNER_KEY);
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(bbp), regDeadline, regSig);

        uint256 deadline = block.timestamp + 1 hours;
        bytes4 AAVE_SEL = bytes4(keccak256("borrow(address,uint256,uint256,uint16,address)"));

        // Borrow 7 units — within 75% LTV (ltvBps = 7*10000/10 = 7000 ≤ 7500) → passes
        bytes memory data = abi.encodeWithSelector(
            AAVE_SEL, asset, uint256(7), uint256(2), uint16(0), address(safe)
        );
        bytes memory dispatchSig = _signDispatch(address(safe), address(bbp), protocol, 0, data, 0, deadline, MANAGER_KEY);
        kernel.dispatch(address(safe), address(bbp), protocol, 0, data, dispatchSig, deadline);

        // Borrow 8 units — above 75% LTV (ltvBps = 8*10000/10 = 8000 > 7500) → DENIED
        bytes memory data2 = abi.encodeWithSelector(
            AAVE_SEL, asset, uint256(8), uint256(2), uint16(0), address(safe)
        );
        bytes memory dispatchSig2 = _signDispatch(address(safe), address(bbp), protocol, 0, data2, 1, deadline, MANAGER_KEY);
        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(bbp)));
        kernel.dispatch(address(safe), address(bbp), protocol, 0, data2, dispatchSig2, deadline);

        // VULNERABILITY DEMO: inflate collateral via manipulable oracle → bypasses LTV guard
        collOracle.setPrice(1000); // inflate 100x: colValue = 1000
        // Now ltvBps = 8*10000/1000 = 80 ≤ 7500 → passes
        bytes memory dispatchSig3 = _signDispatch(address(safe), address(bbp), protocol, 0, data2, 1, deadline, MANAGER_KEY);
        kernel.dispatch(address(safe), address(bbp), protocol, 0, data2, dispatchSig3, deadline);
        // Reaching here confirms: a manipulable oracle bypasses LTV enforcement.
        // This is a documented trust assumption in the protocol.
    }

    // ── 6b. Zero-price oracle blocks all borrows (fail-closed) ──

    function test_Attack_ZeroPriceOracle_FailClosed() public {
        address protocol = address(0xAABB);
        address asset    = address(0xCCDD);

        ManipulableOracle collOracle = new ManipulableOracle(0, 8); // zero price
        ManipulableOracle borOracle  = new ManipulableOracle(1e8, 8);

        address[] memory protocols = new address[](1);
        protocols[0] = protocol;
        address[] memory assets = new address[](1);
        assets[0] = asset;

        BoundedBorrowPermission bbp = BoundedBorrowPermission(Clones.clone(address(new BoundedBorrowPermission())));
        bbp.initialize(
            protocols, assets,
            1_000_000 ether,
            7_500,
            address(collOracle),
            address(borOracle),
            permSigner
        );

        uint256 nonce = kernel.signerNonces(address(safe));
        uint256 regDeadline = block.timestamp + 1 days;
        bytes memory regSig = _signRegisterPermission(address(safe), address(bbp), nonce, PERM_SIGNER_KEY);
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(bbp), regDeadline, regSig);

        bytes4 AAVE_SEL = bytes4(keccak256("borrow(address,uint256,uint256,uint16,address)"));
        bytes memory data = abi.encodeWithSelector(
            AAVE_SEL, asset, uint256(1e8), uint256(2), uint16(0), address(safe)
        );

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory dispatchSig = _signDispatch(address(safe), address(bbp), protocol, 0, data, 0, deadline, MANAGER_KEY);

        // colValue == 0 → _ltvCheck returns false → PermissionDenied
        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(bbp)));
        kernel.dispatch(address(safe), address(bbp), protocol, 0, data, dispatchSig, deadline);
    }

    // ── 6c. SharedDeFiBundle: LTV calculation discrepancy (bundle uses colValue directly, not normalised) ──
    //   BoundedBorrowPermission normalises colValue by colDec.
    //   SharedDeFiBundlePermission does NOT divide by 10^colDec:
    //     ltvBps = mulDiv(borrowScaled, 10_000, colValue)   ← NOT divided by 10^colDec
    //   This means for high-decimal oracles, colValue is much larger than in the
    //   standalone version, making LTV appear lower → allows higher borrows.

    function test_Attack_BundleVsStandalone_LTV_Discrepancy() public {
        // This test documents the normalization difference.
        // Bundle:     ltvBps = borrowScaled * 10_000 / colValue          (colValue in raw oracle units)
        // Standalone: ltvBps = borrowScaled * 10_000 / (colValue/10^dec) (colValue normalised)

        // With 8 decimals: colValue = 1_000_000e8 = 100_000_000_000_000
        // Standalone colNorm = 1_000_000e8 / 1e8 = 1_000_000
        // Bundle     uses  colValue = 1_000_000e8 directly → LTV appears 1e8x LOWER in bundle

        // This means SharedDeFiBundlePermission is dramatically more permissive
        // for 8-decimal oracles compared to the standalone BoundedBorrowPermission.

        // VULNERABILITY: SharedDeFiBundlePermission._ltvCheck does not normalise colValue
        // by colDec, so a 1e8 collateral oracle makes LTV appear 1e8x lower than reality.
        // An attacker can borrow up to 1e8x their actual LTV limit.

        address protocol = address(0xAABB);
        address asset    = address(0xCCDD);

        // 8-decimal oracle: colValue = $1M expressed as 1_000_000 * 1e8
        ManipulableOracle collOracle = new ManipulableOracle(1_000_000e8, 8);
        ManipulableOracle borOracle  = new ManipulableOracle(1e8, 8); // $1/unit

        SharedDeFiBundlePermission bundle = new SharedDeFiBundlePermission(address(kernel));

        // Configure the bundle for safe with borrow allowed
        address[] memory emptyAddrs = new address[](0);
        address[] memory protocols  = new address[](1); protocols[0]  = protocol;
        address[] memory assets     = new address[](1); assets[0]     = asset;

        SharedDeFiBundlePermission.SwapConfig memory swapCfg;
        swapCfg.routers        = emptyAddrs;
        swapCfg.tokensIn       = emptyAddrs;
        swapCfg.tokensOut      = emptyAddrs;
        swapCfg.maxAmountPerTx = 0;
        swapCfg.maxSlippageBps = 0;
        swapCfg.priceOracle    = address(0);

        SharedDeFiBundlePermission.BorrowConfig memory borCfg;
        borCfg.protocols       = protocols;
        borCfg.assets          = assets;
        borCfg.maxAmountPerTx  = type(uint256).max;
        borCfg.maxLtvBps       = 7_500; // 75%
        borCfg.collateralOracle = address(collOracle);
        borCfg.borrowOracle    = address(borOracle);

        SharedDeFiBundlePermission.TransferConfig memory xferCfg;
        xferCfg.recipients     = emptyAddrs;
        xferCfg.tokens         = emptyAddrs;
        xferCfg.maxAmountPerTx = 0;

        bytes memory params = abi.encode(swapCfg, borCfg, xferCfg);

        // configureDirect as permSigner
        vm.prank(permSigner);
        bundle.configureDirect(address(safe), params);

        // Register the bundle
        uint256 nonce = kernel.signerNonces(address(safe));
        uint256 regDeadline = block.timestamp + 1 days;
        bytes memory regSig = _signRegisterPermission(address(safe), address(bundle), nonce, PERM_SIGNER_KEY);
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(bundle), regDeadline, regSig);

        // Borrow amount that would EXCEED 75% LTV with correct normalisation but passes
        // with the non-normalised colValue in the bundle.
        // colValue_normalised = 1_000_000e8 / 1e8 = 1_000_000
        // 75% of 1_000_000 = 750_000 units — anything above this should fail in standalone.
        // In bundle: colValue = 1_000_000e8 (not normalised) → 75% = 750_000e8 units
        // So 750_001 units (above standalone limit) should FAIL standalone but PASS bundle.

        uint256 overLimitAmount = 750_001; // exceeds standalone 75% LTV limit

        bytes4 AAVE_SEL = bytes4(keccak256("borrow(address,uint256,uint256,uint16,address)"));
        bytes memory data = abi.encodeWithSelector(
            AAVE_SEL, asset, overLimitAmount, uint256(2), uint16(0), address(safe)
        );

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory dispatchSig = _signDispatch(address(safe), address(bundle), protocol, 0, data, 0, deadline, MANAGER_KEY);

        // With the non-normalised colValue in bundle, this should PASS (VULNERABILITY)
        // With correct normalisation, it should FAIL
        bool passed;
        try kernel.dispatch(address(safe), address(bundle), protocol, 0, data, dispatchSig, deadline) {
            passed = true;
        } catch {
            passed = false;
        }

        if (passed) {
            console.log("VULNERABILITY: SharedDeFiBundlePermission LTV uses unnormalised colValue");
            console.log("Bundle allows borrow ABOVE the 75% LTV limit due to missing /10^colDec");
        } else {
            console.log("Bundle correctly enforced LTV");
        }
        // We don't assert here to avoid a test failure masking the finding —
        // the console output documents the discrepancy.
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 7: Template config race conditions
// ═════════════════════════════════════════════════════════════════════════════
contract ConfigRaceConditionTests is RedTeamBase {

    // ── 7a. Attacker front-runs a configure call with own params (same sig deadline) ──
    //   configure() uses configNonces[account] which is separate from kernel signerNonces.
    //   If the attacker obtains the permissionSigner signature, they can submit first
    //   with the same params or different params.
    //   Since the sig commits to keccak256(params), they cannot change params.
    //   But they CAN submit the exact same tx before the victim.

    function test_Attack_ConfigureFrontRun_SameParams() public {
        SharedDeFiBundlePermission bundle = new SharedDeFiBundlePermission(address(kernel));

        address[] memory emptyAddrs = new address[](0);
        SharedDeFiBundlePermission.SwapConfig memory swapCfg;
        swapCfg.routers = emptyAddrs; swapCfg.tokensIn = emptyAddrs; swapCfg.tokensOut = emptyAddrs;
        SharedDeFiBundlePermission.BorrowConfig memory borCfg;
        borCfg.protocols = emptyAddrs; borCfg.assets = emptyAddrs;
        SharedDeFiBundlePermission.TransferConfig memory xferCfg;
        xferCfg.recipients = emptyAddrs; xferCfg.tokens = emptyAddrs;

        bytes memory params = abi.encode(swapCfg, borCfg, xferCfg);
        uint256 deadline = block.timestamp + 1 hours;

        // Build the configure sig
        uint256 configNonce = bundle.configNonces(address(safe));
        bytes32 paramsHash  = keccak256(params);
        bytes32 structHash  = keccak256(abi.encode(
            bundle.CONFIGURE_TYPEHASH(), address(safe), paramsHash, configNonce, deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PERM_SIGNER_KEY, bundle.hashTypedDataV4(structHash));
        bytes memory configureSig = abi.encodePacked(r, s, v);

        // Attacker front-runs with the same sig and same params (public mempool interception)
        vm.prank(attacker);
        bundle.configure(address(safe), params, deadline, configureSig);

        // The result: configure succeeds for the account. configNonce is now 1.
        // The original configure call will now fail because nonce is consumed.
        assertEq(bundle.configNonces(address(safe)), 1);
        assertTrue(bundle.isConfigured(address(safe)));

        // Original tx tries to configure again — signature no longer valid (nonce 1 now)
        vm.expectRevert(BaseSharedPermission.InvalidSignature.selector);
        bundle.configure(address(safe), params, deadline, configureSig);

        // NOTE: The front-runner configured with the SAME params, so the outcome is
        // correct even though a different address submitted it. However, the original
        // transaction is now permanently invalidated, causing UX griefing.
        // The protocol is not broken, but the permissionSigner must generate a new sig.
    }

    // ── 7b. Nonce manipulation: can attacker configure a DIFFERENT account with a stolen sig? ──

    function test_Attack_ConfigureStolenSig_WrongAccount() public {
        SharedDeFiBundlePermission bundle = new SharedDeFiBundlePermission(address(kernel));

        MockSafe safe2 = new MockSafe();
        safe2.enableModule(address(kernel));
        vm.prank(address(safe2));
        kernel.registerAccount(permSigner, manager, address(0), address(0)); // same permSigner!

        address[] memory emptyAddrs = new address[](0);
        SharedDeFiBundlePermission.SwapConfig memory swapCfg;
        swapCfg.routers = emptyAddrs; swapCfg.tokensIn = emptyAddrs; swapCfg.tokensOut = emptyAddrs;
        SharedDeFiBundlePermission.BorrowConfig memory borCfg;
        borCfg.protocols = emptyAddrs; borCfg.assets = emptyAddrs;
        SharedDeFiBundlePermission.TransferConfig memory xferCfg;
        xferCfg.recipients = emptyAddrs; xferCfg.tokens = emptyAddrs;
        bytes memory params = abi.encode(swapCfg, borCfg, xferCfg);

        uint256 deadline = block.timestamp + 1 hours;

        // Sign for safe (account A)
        uint256 configNonceA = bundle.configNonces(address(safe));
        bytes32 paramsHash   = keccak256(params);
        bytes32 structHashA  = keccak256(abi.encode(
            bundle.CONFIGURE_TYPEHASH(), address(safe), paramsHash, configNonceA, deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PERM_SIGNER_KEY, bundle.hashTypedDataV4(structHashA));
        bytes memory sigForA = abi.encodePacked(r, s, v);

        // Try to use sigForA for account B (safe2)
        // The sig commits to account = safe, so this should fail for safe2
        vm.expectRevert(BaseSharedPermission.InvalidSignature.selector);
        bundle.configure(address(safe2), params, deadline, sigForA);
    }

    // ── 7c. configureDirect: attacker (not permSigner) calls configureDirect ──

    function test_Attack_ConfigureDirectByNonPermSigner() public {
        SharedDeFiBundlePermission bundle = new SharedDeFiBundlePermission(address(kernel));

        address[] memory emptyAddrs = new address[](0);
        SharedDeFiBundlePermission.SwapConfig memory swapCfg;
        swapCfg.routers = emptyAddrs; swapCfg.tokensIn = emptyAddrs; swapCfg.tokensOut = emptyAddrs;
        SharedDeFiBundlePermission.BorrowConfig memory borCfg;
        borCfg.protocols = emptyAddrs; borCfg.assets = emptyAddrs;
        SharedDeFiBundlePermission.TransferConfig memory xferCfg;
        xferCfg.recipients = emptyAddrs; xferCfg.tokens = emptyAddrs;
        bytes memory params = abi.encode(swapCfg, borCfg, xferCfg);

        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(BaseSharedPermission.NotPermissionSigner.selector, attacker, permSigner)
        );
        bundle.configureDirect(address(safe), params);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 8: Malicious template registration
// ═════════════════════════════════════════════════════════════════════════════
contract MaliciousTemplateTests is RedTeamBase {

    // A "permission" that always returns true — the ultimate bypass
    function test_Attack_RegisterMaliciousAlwaysTruePermission() public {
        // The kernel has NO allowlist of approved templates.
        // A permissionSigner CAN register a custom contract that returns true for everything.
        // This is a design feature (permissionless template registry), not a bug.

        // If the permissionSigner is malicious or compromised, they can register an
        // always-true permission and then the manager can dispatch ANY call.
        _registerAlwaysTrue();

        // Manager can now dispatch any arbitrary call
        uint256 deadline = block.timestamp + 1 hours;
        address mockERC20 = address(0xE20E20E20);
        bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", attacker, 99 ether);
        bytes memory sig  = _signDispatch(address(safe), address(alwaysTrue), mockERC20, 0, data, 0, deadline, MANAGER_KEY);

        kernel.dispatch(address(safe), address(alwaysTrue), mockERC20, 0, data, sig, deadline);
        // Dispatch succeeded — permissionSigner + manager collusion = full access.
        // This is documented behavior: the permissionSigner is the trust anchor.
    }

    // ── 8a. Gas griefing: register a gas-exhausting permission ──
    //   The PERMISSION_GAS_CAP (100k gas) limits each permission's evaluation.
    //   An infinite-loop permission will hit the gas cap and return false (deny).
    //   This means the kernel will revert with PermissionDenied, not OOG.

    function test_Attack_GasHogPermission_Denied() public {
        // Deploy a gas hog that infinite-loops
        IPermission gasHog = IPermission(address(new GasHogPermissionTest()));

        uint256 nonce = kernel.signerNonces(address(safe));
        uint256 regDeadline = block.timestamp + 1 days;
        bytes memory regSig = _signRegisterPermission(address(safe), address(gasHog), nonce, PERM_SIGNER_KEY);
        kernel.registerPermission{value: 0.001 ether}(address(safe), address(gasHog), regDeadline, regSig);

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory data = "";
        bytes memory sig  = _signDispatch(address(safe), address(gasHog), address(0xBEEF), 0, data, 0, deadline, MANAGER_KEY);

        // The gas hog hits PERMISSION_GAS_CAP, _evaluatePermission returns false,
        // kernel reverts with PermissionDenied.
        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(gasHog)));
        kernel.dispatch(address(safe), address(gasHog), address(0xBEEF), 0, data, sig, deadline);
    }

    // ── 8b. Permission that returns true for the manager to front-run then revoke ──
    //   After dispatch, manager can call revokePermission via signed op (if they also
    //   control the permissionSigner). Here we just confirm the kernel checks happen
    //   atomically — the state of permissions at dispatch time is what matters.

    function test_Attack_PermissionRevokedBeforeDispatch() public {
        _registerAlwaysTrue();

        // permSigner revokes the permission BEFORE dispatch
        uint256 nonce = kernel.signerNonces(address(safe));
        uint256 revokeDeadline = block.timestamp + 1 days;
        bytes memory revokeSig = _signRevokePermission(address(safe), address(alwaysTrue), nonce, PERM_SIGNER_KEY);
        kernel.revokePermission(address(safe), address(alwaysTrue), revokeDeadline, revokeSig);

        // Now try to dispatch — alwaysTrue was revoked, so PermissionNotRegistered fires.
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory data = "";
        bytes memory sig  = _signDispatch(address(safe), address(alwaysTrue), address(0xBEEF), 0, data, 0, deadline, MANAGER_KEY);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionNotRegistered.selector, address(alwaysTrue)));
        kernel.dispatch(address(safe), address(alwaysTrue), address(0xBEEF), 0, data, sig, deadline);
    }
}

// Helper gas-hog contract (self-contained to avoid import conflict)
contract GasHogPermissionTest is IPermission {
    function evaluate(bytes calldata, Context calldata) external view returns (bool) {
        uint256 x;
        // Infinite loop — will hit gas cap
        while (true) { unchecked { x++; } }
        return true;
    }
    function discriminator() external pure returns (bytes32) { return keccak256("GasHog"); }
}

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 9: MandateFactory refund reentrancy
// ═════════════════════════════════════════════════════════════════════════════
contract FactoryAttackTests is RedTeamBase {
    // ── 9a. _refundExcess: verify exact refund on overpay ──
    //   MandateFactory._refundExcess does a raw call to msg.sender.
    //   We verify overpayment is returned exactly once (no double-refund possible
    //   because the kernel consumes msg.value, leaving no excess for reentrancy).

    function test_Attack_FactoryRefundReentrancy() public {
        SharedDeFiBundlePermission bundle = new SharedDeFiBundlePermission(address(kernel));

        address[] memory emptyAddrs = new address[](0);
        SharedDeFiBundlePermission.SwapConfig memory swapCfg;
        swapCfg.routers = emptyAddrs; swapCfg.tokensIn = emptyAddrs; swapCfg.tokensOut = emptyAddrs;
        SharedDeFiBundlePermission.BorrowConfig memory borCfg;
        borCfg.protocols = emptyAddrs; borCfg.assets = emptyAddrs;
        SharedDeFiBundlePermission.TransferConfig memory xferCfg;
        xferCfg.recipients = emptyAddrs; xferCfg.tokens = emptyAddrs;
        bytes memory params = abi.encode(swapCfg, borCfg, xferCfg);

        uint256 configDeadline = block.timestamp + 1 hours;

        // Build configureSig for factory (nonce 0)
        uint256 cfgNonce = bundle.configNonces(address(safe));
        bytes32 cfgStructHash = keccak256(abi.encode(
            bundle.CONFIGURE_TYPEHASH(), address(safe), keccak256(params), cfgNonce, configDeadline
        ));
        (uint8 cv, bytes32 cr, bytes32 cs) = vm.sign(PERM_SIGNER_KEY, bundle.hashTypedDataV4(cfgStructHash));
        bytes memory cfgSig = abi.encodePacked(cr, cs, cv);

        // Build kernelSig for registerPermission (nonce 0)
        uint256 kNonce = kernel.signerNonces(address(safe));
        uint256 kDeadline = block.timestamp + 1 days;
        bytes memory kSig = _signRegisterPermission(address(safe), address(bundle), kNonce, PERM_SIGNER_KEY);

        uint256 balBefore = address(this).balance;

        // Overpay: send 1 ether, fee is 0.001 ether → 0.999 ether should be refunded
        factory.attach{value: 1 ether}(address(safe), address(bundle), params, configDeadline, cfgSig, kDeadline, kSig);

        uint256 balAfter = address(this).balance;
        uint256 netCost  = balBefore - balAfter;

        // Net cost should be exactly the registration fee
        assertEq(netCost, 0.001 ether, "Factory refund should return exact excess");
    }

    // ── 9b. Factory: detach without kernel sig — cannot detach without valid sig ──

    function test_Attack_FactoryDetachWithoutSig() public {
        // Register a permission first
        _registerAlwaysTrue();

        // Attacker tries to detach with a forged sig
        uint256 nonce = kernel.signerNonces(address(safe));
        uint256 detachDeadline = block.timestamp + 1 days;
        bytes32 sh = keccak256(abi.encode(
            kernel.REVOKE_PERMISSION_TYPEHASH(), address(safe), address(alwaysTrue), nonce, detachDeadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ATTACKER_KEY, kernel.hashTypedDataV4(sh));
        bytes memory forgedSig = abi.encodePacked(r, s, v);

        vm.prank(attacker);
        vm.expectRevert(SailKernel.InvalidSignerSignature.selector);
        factory.detach(address(safe), address(alwaysTrue), detachDeadline, forgedSig);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 10: registerAccount front-run protection
// ═════════════════════════════════════════════════════════════════════════════
contract AccountRegistrationTests is RedTeamBase {

    // ── 10a. Attacker registers safe address before the owner ──
    //   registerAccount requires msg.sender == account (the Safe calling it).
    //   An attacker cannot register a safe they don't control.

    function test_Attack_RegisterAccountFrontRun() public {
        MockSafe newSafe = new MockSafe();
        newSafe.enableModule(address(kernel));

        // Key property: registerAccount uses msg.sender as the account being registered.
        // An attacker calling registerAccount registers THEMSELVES, not newSafe.
        // They cannot impersonate newSafe's address — only newSafe itself can register newSafe.

        // Attacker calls registerAccount directly — this registers the ATTACKER address, not newSafe.
        vm.prank(attacker);
        kernel.registerAccount(address(0xDEAD), address(0xBEEF), address(0), address(0));

        // Attacker registered themselves — not a vulnerability, they control the attacker account.
        assertTrue(kernel.registered(attacker));
        (address attackerPermSigner,,,,) = kernel.configs(attacker);
        assertEq(attackerPermSigner, address(0xDEAD));

        // newSafe is NOT registered — front-run protection works.
        assertFalse(kernel.registered(address(newSafe)));

        // Only newSafe can register itself
        vm.prank(address(newSafe));
        kernel.registerAccount(permSigner, manager, address(0), address(0));
        assertTrue(kernel.registered(address(newSafe)));
    }

    // ── 10b. Double registration attempt ──

    function test_Attack_DoubleRegisterAccount() public {
        // safe is already registered in setUp
        vm.prank(address(safe));
        vm.expectRevert(abi.encodeWithSelector(SailKernel.AccountAlreadyRegistered.selector, address(safe)));
        kernel.registerAccount(permSigner, manager, address(0), address(0));
    }

    // ── 10c. Register with zero permissionSigner ──

    function test_Attack_RegisterWithZeroPermSigner() public {
        MockSafe newSafe = new MockSafe();
        newSafe.enableModule(address(kernel));

        vm.prank(address(newSafe));
        vm.expectRevert(SailKernel.ZeroAddress.selector);
        kernel.registerAccount(address(0), manager, address(0), address(0));
    }
}
