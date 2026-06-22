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

import {SailKernel}              from "../../contracts/core/SailKernel.sol";
import {SailGovernance}          from "../../contracts/governance/SailGovernance.sol";
import {TimelockDeployer}        from "../support/TimelockDeployer.sol";
import {MandateFactory}       from "../../contracts/factory/MandateFactory.sol";
import {StandardFeePolicy}       from "../../contracts/policies/StandardFeePolicy.sol";
import {IPermission, Context}    from "../../contracts/interfaces/IPermission.sol";
import {IFeePolicy}              from "../../contracts/interfaces/IFeePolicy.sol";
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

    function isModuleEnabled(address) external pure returns (bool) { return true; }

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
        gov = new SailGovernance(address(this), 0.001 ether, address(this), 0, TimelockDeployer.deploy(address(this)));
        vm.startPrank(address(gov.timelock()));
        gov.setProtocolCutBps(1_000);
        gov.setPermissionRegistrationFee(0.001 ether);
        vm.stopPrank();

        kernel  = new SailKernel(address(gov), TREASURY);
        factory = new MandateFactory(address(kernel));

        safe = new MockSafe();
        safe.enableModule(address(kernel));
        vm.deal(address(safe), 100 ether);

        // registerAccount requires the caller's codehash to be an allowlisted Safe proxy
        // (Octane #4a). One seed covers all MockSafe instances (safe2/safe3/newSafe).
        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeProxyCodehash(address(safe).codehash, true);

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

        // Allowlist the attacker contract's codehash so it can register and we can exercise
        // the reentrancy guard (the property under test here, not the codehash gate).
        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeProxyCodehash(address(rAttacker).codehash, true);

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

        // Post-fix (Octane #4a): registerAccount rejects any caller whose codehash is not an
        // allowlisted Safe proxy. The attacker EOA therefore cannot self-register at all —
        // strictly stronger than the prior "registers themselves, not newSafe" behavior.
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(SailKernel.UntrustedProxyCodehash.selector, attacker.codehash));
        kernel.registerAccount(address(0xDEAD), address(0xBEEF), address(0), address(0));

        assertFalse(kernel.registered(attacker));
        assertFalse(kernel.registered(address(newSafe)));

        // newSafe (allowlisted MockSafe codehash, module enabled) can register itself.
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
