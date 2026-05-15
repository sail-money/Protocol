// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {SailKernel} from "../contracts/core/SailKernel.sol";
import {SailGovernance} from "../contracts/governance/SailGovernance.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {IPermission, Context} from "../contracts/interfaces/IPermission.sol";
import {IFeePolicy} from "../contracts/interfaces/IFeePolicy.sol";

// ─────────────────────────────────────────────────────────────────────────────
// Mocks
// ─────────────────────────────────────────────────────────────────────────────

contract MockSafe {
    struct Call {
        address to;
        uint256 value;
        bytes   data;
        uint8   operation;
    }

    Call[]  public calls;
    bool    public moduleCallSuccess = true;

    function execTransactionFromModule(address to, uint256 value, bytes calldata data, uint8 operation)
        external
        returns (bool)
    {
        calls.push(Call(to, value, data, operation));
        return moduleCallSuccess;
    }

    function callCount() external view returns (uint256) { return calls.length; }

    function getCall(uint256 i) external view returns (address, uint256, bytes memory, uint8) {
        Call storage c = calls[i];
        return (c.to, c.value, c.data, c.operation);
    }

    function setSuccess(bool s) external { moduleCallSuccess = s; }
    function clearCalls() external { delete calls; }

    receive() external payable {}
}

contract MockPermission is IPermission {
    bool public result = true;

    function setResult(bool r) external { result = r; }

    function evaluate(bytes calldata, Context calldata) external view returns (bool) {
        return result;
    }

    function discriminator() external pure returns (bytes32) { return bytes32(0); }
}

// Simulates a permission that exceeds the gas cap via an infinite loop.
contract GasHogPermission is IPermission {
    function evaluate(bytes calldata, Context calldata) external view returns (bool) {
        uint256 x;
        while (true) { unchecked { x++; } }
        return true;
    }

    function discriminator() external pure returns (bytes32) { return bytes32(0); }
}

// Simulates a permission that always reverts.
contract RevertingPermission is IPermission {
    function evaluate(bytes calldata, Context calldata) external pure returns (bool) {
        revert("denied");
    }

    function discriminator() external pure returns (bytes32) { return bytes32(0); }
}

contract MockFeePolicy is IFeePolicy {
    uint256 public grossFeeReturn;
    address public distributorReturn;
    uint256 public distributorBpsReturn;
    bool    public recordCalled;

    function setFee(uint256 gross, address dist, uint256 distBps) external {
        grossFeeReturn     = gross;
        distributorReturn  = dist;
        distributorBpsReturn = distBps;
    }

    function computeFee(address, uint256) external view returns (uint256, address, uint256) {
        return (grossFeeReturn, distributorReturn, distributorBpsReturn);
    }

    function recordCollection(address, uint256, uint256) external {
        recordCalled = true;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test harness
// ─────────────────────────────────────────────────────────────────────────────

contract SailKernelTest is Test {
    SailGovernance gov;
    SailKernel     kernel;
    MockSafe       safe;
    MockPermission perm;
    MockFeePolicy  feePolicy;

    address constant TEAM            = address(0x1111);
    address constant TREASURY        = address(0x2222);
    address constant DIST            = address(0x4444);
    address constant EMERGENCY_ADMIN = address(0xEEEE);

    uint256 constant MANAGER_KEY = 0xBEEF;
    uint256 constant SIGNER_KEY  = 0xDEAD;

    address manager;
    address permSigner;

    // ── setup ─────────────────────────────────────────────────────────────────

    function setUp() public {
        manager    = vm.addr(MANAGER_KEY);
        permSigner = vm.addr(SIGNER_KEY);

        gov      = new SailGovernance(TEAM, 1 ether, EMERGENCY_ADMIN);
        kernel   = new SailKernel(address(gov), TREASURY);
        safe     = new MockSafe();
        perm     = new MockPermission();
        feePolicy = new MockFeePolicy();

        // Register the Safe with the kernel
        kernel.registerAccount(address(safe), permSigner, manager, address(feePolicy));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    function _registerPermission(address permission) internal {
        uint256 nonce = kernel.signerNonces(address(safe));
        bytes32 structHash = keccak256(abi.encode(
            kernel.REGISTER_PERMISSION_TYPEHASH(), address(safe), permission, nonce
        ));
        bytes32 digest = kernel.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, digest);
        kernel.registerPermission(address(safe), permission, abi.encodePacked(r, s, v));
    }

    function _signDispatch(
        address account,
        address target,
        uint256 value,
        bytes memory data,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encode(
            kernel.DISPATCH_TYPEHASH(),
            account,
            target,
            value,
            keccak256(data),
            nonce,
            deadline
        ));
        bytes32 digest = kernel.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(MANAGER_KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    function _dispatch(address target, uint256 value, bytes memory data) internal {
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), target, value, data, nonce, deadline);
        kernel.dispatch(address(safe), target, value, data, sig, deadline);
    }

    function _signerSig(bytes32 structHash) internal view returns (bytes memory) {
        bytes32 digest = kernel.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    uint256 private _saltNonce;

    function _govSchedule(bytes memory data) internal returns (bytes32 salt) {
        salt = bytes32(_saltNonce++);
        TimelockController tl = gov.timelock();
        vm.prank(TEAM);
        tl.schedule(address(gov), 0, data, bytes32(0), salt, 48 hours);
        vm.warp(block.timestamp + 48 hours + 1);
    }

    function _govExecute(bytes memory data, bytes32 salt) internal {
        TimelockController tl = gov.timelock();
        vm.prank(TEAM);
        tl.execute(address(gov), 0, data, bytes32(0), salt);
    }

    function _govExec(bytes memory data) internal {
        _govExecute(data, _govSchedule(data));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 1. Account registration
    // ─────────────────────────────────────────────────────────────────────────

    function test_RegisterAccount_SetsConfig() public view {
        assertTrue(kernel.registered(address(safe)));
        (address ps, address mgr,, bool active) = kernel.configs(address(safe));
        assertEq(ps, permSigner);
        assertEq(mgr, manager);
        assertTrue(active);
    }

    function test_RegisterAccount_RevertsIfAlreadyRegistered() public {
        vm.expectRevert(abi.encodeWithSelector(SailKernel.AccountAlreadyRegistered.selector, address(safe)));
        kernel.registerAccount(address(safe), permSigner, manager, address(0));
    }

    function test_RegisterAccount_RevertsOnZeroPermissionSigner() public {
        address newSafe = address(new MockSafe());
        vm.expectRevert(SailKernel.ZeroAddress.selector);
        kernel.registerAccount(newSafe, address(0), manager, address(0));
    }

    function test_RegisterAccount_RevertsOnZeroManager() public {
        address newSafe = address(new MockSafe());
        vm.expectRevert(SailKernel.ZeroAddress.selector);
        kernel.registerAccount(newSafe, permSigner, address(0), address(0));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 2. Permission registry
    // ─────────────────────────────────────────────────────────────────────────

    function test_RegisterPermission_Succeeds() public {
        _registerPermission(address(perm));
        assertTrue(kernel.isPermissionRegistered(address(safe), address(perm)));
        assertEq(kernel.getPermissions(address(safe)).length, 1);
    }

    function test_RegisterPermission_IncrementsSignerNonce() public {
        assertEq(kernel.signerNonces(address(safe)), 0);
        _registerPermission(address(perm));
        assertEq(kernel.signerNonces(address(safe)), 1);
    }

    function test_RegisterPermission_RevertsOnDuplicate() public {
        _registerPermission(address(perm));
        uint256 nonce = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(kernel.REGISTER_PERMISSION_TYPEHASH(), address(safe), address(perm), nonce));
        bytes memory sig = _signerSig(sh);
        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionAlreadyRegistered.selector, address(perm)));
        kernel.registerPermission(address(safe), address(perm), sig);
    }

    function test_RegisterPermission_RevertsOnBadSig() public {
        uint256 nonce = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(kernel.REGISTER_PERMISSION_TYPEHASH(), address(safe), address(perm), nonce));
        bytes32 digest = kernel.hashTypedDataV4(sh);
        // Sign with wrong key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBAD, digest);
        vm.expectRevert(SailKernel.InvalidSignerSignature.selector);
        kernel.registerPermission(address(safe), address(perm), abi.encodePacked(r, s, v));
    }

    function test_RegisterPermission_ChargesFee() public {
        _govExec(abi.encodeCall(gov.setBaseFee, (0.1 ether)));

        uint256 nonce = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(kernel.REGISTER_PERMISSION_TYPEHASH(), address(safe), address(perm), nonce));
        bytes memory sig = _signerSig(sh);

        uint256 treasuryBefore = TREASURY.balance;
        kernel.registerPermission{value: 0.1 ether}(address(safe), address(perm), sig);
        assertEq(TREASURY.balance - treasuryBefore, 0.1 ether);
    }

    function test_RegisterPermission_RefundsExcess() public {
        _govExec(abi.encodeCall(gov.setBaseFee, (0.1 ether)));

        uint256 nonce = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(kernel.REGISTER_PERMISSION_TYPEHASH(), address(safe), address(perm), nonce));
        bytes memory sig = _signerSig(sh);

        address caller = address(0x9999);
        vm.deal(caller, 1 ether);
        uint256 balBefore = caller.balance;
        vm.prank(caller);
        kernel.registerPermission{value: 0.5 ether}(address(safe), address(perm), sig);
        assertEq(balBefore - caller.balance, 0.1 ether); // only fee deducted
    }

    function test_RegisterPermission_RevertsOnInsufficientFee() public {
        _govExec(abi.encodeCall(gov.setBaseFee, (0.1 ether)));

        uint256 nonce = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(kernel.REGISTER_PERMISSION_TYPEHASH(), address(safe), address(perm), nonce));
        bytes memory sig = _signerSig(sh);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.InsufficientFee.selector, 0.1 ether, 0.05 ether));
        kernel.registerPermission{value: 0.05 ether}(address(safe), address(perm), sig);
    }

    function test_RevokePermission_Succeeds() public {
        _registerPermission(address(perm));
        uint256 nonce = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(kernel.REVOKE_PERMISSION_TYPEHASH(), address(safe), address(perm), nonce));
        bytes memory sig = _signerSig(sh);
        kernel.revokePermission(address(safe), address(perm), sig);
        assertFalse(kernel.isPermissionRegistered(address(safe), address(perm)));
        assertEq(kernel.getPermissions(address(safe)).length, 0);
    }

    function test_RevokePermission_RevertsIfNotRegistered() public {
        uint256 nonce = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(kernel.REVOKE_PERMISSION_TYPEHASH(), address(safe), address(perm), nonce));
        bytes memory sig = _signerSig(sh);
        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionNotRegistered.selector, address(perm)));
        kernel.revokePermission(address(safe), address(perm), sig);
    }

    function test_ReplacePermission_Succeeds() public {
        _registerPermission(address(perm));
        MockPermission perm2 = new MockPermission();
        uint256 nonce = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(
            kernel.REPLACE_PERMISSION_TYPEHASH(), address(safe), address(perm), address(perm2), nonce
        ));
        bytes memory sig = _signerSig(sh);
        kernel.replacePermission(address(safe), address(perm), address(perm2), sig);
        assertFalse(kernel.isPermissionRegistered(address(safe), address(perm)));
        assertTrue(kernel.isPermissionRegistered(address(safe), address(perm2)));
        assertEq(kernel.getPermissions(address(safe)).length, 1);
    }

    function test_RevokeSession_DisablesDispatch() public {
        uint256 nonce = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(kernel.REVOKE_SESSION_TYPEHASH(), address(safe), nonce));
        bytes memory sig = _signerSig(sh);
        kernel.revokeSession(address(safe), sig);

        // Build sig before expectRevert — expectRevert intercepts the very next external call,
        // and _dispatch would consume it with a managerNonces() view call first.
        uint256 deadline     = block.timestamp + 1 hours;
        uint256 dispatchNonce = kernel.managerNonces(address(safe));
        bytes memory dispatchSig = _signDispatch(address(safe), address(0xABCD), 0, "", dispatchNonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.SessionInactive.selector, address(safe)));
        kernel.dispatch(address(safe), address(0xABCD), 0, "", dispatchSig, deadline);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 3. Manager dispatch
    // ─────────────────────────────────────────────────────────────────────────

    function test_Dispatch_RevertsWithNoPermissions() public {
        // Zero registered permissions → deny by default (allowlist semantics).
        // A manager cannot dispatch until at least one permission is registered.
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), address(0xABCD), 0, "", nonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.NoPermissionsRegistered.selector, address(safe)));
        kernel.dispatch(address(safe), address(0xABCD), 0, "", sig, deadline);
    }

    function test_Dispatch_SucceedsWithPassingPermission() public {
        _registerPermission(address(perm));
        perm.setResult(true);
        _dispatch(address(0xABCD), 0, abi.encodeWithSignature("go()"));
        assertEq(safe.callCount(), 1);
    }

    function test_Dispatch_RevertsIfPermissionDenies() public {
        _registerPermission(address(perm));
        perm.setResult(false);

        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory data = "";
        bytes memory sig  = _signDispatch(address(safe), address(0xABCD), 0, data, nonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(perm)));
        kernel.dispatch(address(safe), address(0xABCD), 0, data, sig, deadline);
    }

    function test_Dispatch_TreatsRevertingPermissionAsDenied() public {
        RevertingPermission rp = new RevertingPermission();
        _registerPermission(address(rp));

        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), address(0xABCD), 0, "", nonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(rp)));
        kernel.dispatch(address(safe), address(0xABCD), 0, "", sig, deadline);
    }

    function test_Dispatch_TreatsGasHogPermissionAsDenied() public {
        GasHogPermission hog = new GasHogPermission();
        _registerPermission(address(hog));

        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), address(0xABCD), 0, "", nonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(hog)));
        kernel.dispatch{gas: 5_000_000}(address(safe), address(0xABCD), 0, "", sig, deadline);
    }

    function test_Dispatch_RevertsOnExpiredDeadline() public {
        uint256 deadline = block.timestamp - 1;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), address(0xABCD), 0, "", nonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.DeadlineExpired.selector, deadline, block.timestamp));
        kernel.dispatch(address(safe), address(0xABCD), 0, "", sig, deadline);
    }

    function test_Dispatch_RevertsOnInvalidManagerSignature() public {
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        // Sign with wrong key
        bytes32 sh = keccak256(abi.encode(
            kernel.DISPATCH_TYPEHASH(), address(safe), address(0xABCD), uint256(0), keccak256(""), nonce, deadline
        ));
        bytes32 digest = kernel.hashTypedDataV4(sh);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBAD, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(SailKernel.InvalidManagerSignature.selector);
        kernel.dispatch(address(safe), address(0xABCD), 0, "", sig, deadline);
    }

    function test_Dispatch_NonceIncrements() public {
        _registerPermission(address(perm));
        assertEq(kernel.managerNonces(address(safe)), 0);
        _dispatch(address(0xABCD), 0, "");
        assertEq(kernel.managerNonces(address(safe)), 1);
        _dispatch(address(0xABCD), 0, "");
        assertEq(kernel.managerNonces(address(safe)), 2);
    }

    function test_Dispatch_RevertsOnReplay() public {
        _registerPermission(address(perm));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), address(0xABCD), 0, "", nonce, deadline);

        // First dispatch succeeds
        kernel.dispatch(address(safe), address(0xABCD), 0, "", sig, deadline);

        // Replay with same sig fails — nonce is now stale
        vm.expectRevert(SailKernel.InvalidManagerSignature.selector);
        kernel.dispatch(address(safe), address(0xABCD), 0, "", sig, deadline);
    }

    function test_Dispatch_RevertsIfSafeReturnsFalse() public {
        _registerPermission(address(perm));
        safe.setSuccess(false);
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), address(0xABCD), 0, "", nonce, deadline);

        vm.expectRevert(SailKernel.SafeExecutionFailed.selector);
        kernel.dispatch(address(safe), address(0xABCD), 0, "", sig, deadline);
    }

    function test_Dispatch_RevertsOnUnregisteredAccount() public {
        address unknown = address(new MockSafe());
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = 0;
        bytes memory sig = _signDispatch(unknown, address(0xABCD), 0, "", nonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.AccountNotRegistered.selector, unknown));
        kernel.dispatch(unknown, address(0xABCD), 0, "", sig, deadline);
    }

    function test_Dispatch_MultiplePermissionsAllMustPass() public {
        _registerPermission(address(perm));
        MockPermission perm2 = new MockPermission();
        _registerPermission(address(perm2));

        perm.setResult(true);
        perm2.setResult(false); // second one denies

        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), address(0xABCD), 0, "", nonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(perm2)));
        kernel.dispatch(address(safe), address(0xABCD), 0, "", sig, deadline);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 4. Fee accounting
    // ─────────────────────────────────────────────────────────────────────────

    function test_CollectFees_SplitsCorrectly() public {
        _govExec(abi.encodeCall(gov.setProtocolCutBps, (1_000)));

        uint256 grossFee     = 1_000_000;
        uint256 distBps      = 2_000; // 20% of remainder
        feePolicy.setFee(grossFee, DIST, distBps);

        // protocol_cut    = 1_000_000 * 1000 / 10000 = 100_000
        // remainder       = 900_000
        // distributor_cut = 900_000 * 2000 / 10000 = 180_000
        // manager_take    = 720_000

        address feeToken = address(0); // ETH
        vm.prank(manager);
        kernel.collectFees(address(safe), grossFee, 0, feeToken, manager);

        // Three ETH execTransactionFromModule calls
        assertEq(safe.callCount(), 3);
        (address to0, uint256 v0,,) = safe.getCall(0);
        (address to1, uint256 v1,,) = safe.getCall(1);
        (address to2, uint256 v2,,) = safe.getCall(2);
        assertEq(to0, TREASURY); assertEq(v0, 100_000);
        assertEq(to1, DIST);     assertEq(v1, 180_000);
        assertEq(to2, manager);  assertEq(v2, 720_000);
        assertTrue(feePolicy.recordCalled());
    }

    function test_CollectFees_ZeroProtocolCut() public {
        // governance cut = 0 (default)
        uint256 grossFee = 1_000_000;
        feePolicy.setFee(grossFee, address(0), 0);

        vm.prank(manager);
        kernel.collectFees(address(safe), grossFee, 0, address(0), manager);

        // Only manager transfer (no protocol cut, no distributor)
        assertEq(safe.callCount(), 1);
        (address to, uint256 v,,) = safe.getCall(0);
        assertEq(to, manager);
        assertEq(v, grossFee);
    }

    function test_CollectFees_SkipsZeroDistributor() public {
        _govExec(abi.encodeCall(gov.setProtocolCutBps, (500)));

        feePolicy.setFee(1_000_000, address(0), 1_000); // distributor = address(0)

        vm.prank(manager);
        kernel.collectFees(address(safe), 1_000_000, 0, address(0), manager);

        // Only protocol + manager (no distributor transfer since address(0))
        assertEq(safe.callCount(), 2);
        (address to0,,,) = safe.getCall(0);
        (address to1,,,) = safe.getCall(1);
        assertEq(to0, TREASURY);
        assertEq(to1, manager);
    }

    function test_CollectFees_ERC20Path() public {
        address token = address(0x1234567890123456789012345678901234567890);
        uint256 grossFee = 500;
        feePolicy.setFee(grossFee, address(0), 0);

        vm.prank(manager);
        kernel.collectFees(address(safe), grossFee, 0, token, manager);

        assertEq(safe.callCount(), 1);
        (address to, uint256 v, bytes memory d,) = safe.getCall(0);
        assertEq(to, token);
        assertEq(v, 0);
        // Encoded ERC-20 transfer call
        assertEq(d, abi.encodeWithSignature("transfer(address,uint256)", manager, grossFee));
    }

    function test_CollectFees_RevertsIfFeeTooLarge() public {
        feePolicy.setFee(1_000, address(0), 0);

        vm.prank(manager);
        vm.expectRevert(abi.encodeWithSelector(SailKernel.FeeTooLarge.selector, 2_000, 1_000));
        kernel.collectFees(address(safe), 2_000, 0, address(0), manager);
    }

    function test_CollectFees_RevertsIfNotManager() public {
        feePolicy.setFee(1_000, address(0), 0);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.NotManager.selector, address(this), manager));
        kernel.collectFees(address(safe), 1_000, 0, address(0), manager);
    }

    function test_CollectFees_RevertsIfNoPolicySet() public {
        MockSafe safe2 = new MockSafe();
        kernel.registerAccount(address(safe2), permSigner, manager, address(0)); // no feePolicy

        vm.prank(manager);
        vm.expectRevert(SailKernel.FeePolicyNotSet.selector);
        kernel.collectFees(address(safe2), 1_000, 0, address(0), manager);
    }

    function test_CollectFees_ProtocolCutCannotExceedCap() public {
        // Cap is enforced at timelock execution — above-cap call reverts
        bytes memory badData = abi.encodeCall(gov.setProtocolCutBps, (2_501));
        bytes32 salt = _govSchedule(badData);
        TimelockController tl = gov.timelock();
        vm.expectRevert(
            abi.encodeWithSelector(SailGovernance.ExceedsProtocolCutCap.selector, 2_501, 2_500)
        );
        vm.prank(TEAM);
        tl.execute(address(gov), 0, badData, bytes32(0), salt);

        // At the cap (25%): grossFee=10_000 → protocolCut=2_500, managerTake=7_500
        _govExec(abi.encodeCall(gov.setProtocolCutBps, (2_500)));

        feePolicy.setFee(10_000, address(0), 0);
        vm.prank(manager);
        kernel.collectFees(address(safe), 10_000, 0, address(0), manager);

        (,uint256 protocolV,,) = safe.getCall(0);
        assertEq(protocolV, 2_500);
        (,uint256 managerV,,) = safe.getCall(1);
        assertEq(managerV, 7_500);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 5. Principal tracking
    // ─────────────────────────────────────────────────────────────────────────

    function test_RecordDeposit_Accumulates() public {
        vm.startPrank(permSigner);
        kernel.recordDeposit(address(safe), 1_000);
        kernel.recordDeposit(address(safe), 500);
        vm.stopPrank();
        assertEq(kernel.cumulativeDeposits(address(safe)), 1_500);
    }

    function test_RecordWithdrawal_Accumulates() public {
        vm.startPrank(permSigner);
        kernel.recordWithdrawal(address(safe), 300);
        kernel.recordWithdrawal(address(safe), 700);
        vm.stopPrank();
        assertEq(kernel.cumulativeWithdrawals(address(safe)), 1_000);
    }

    function test_RecordDeposit_RevertsIfNotPermissionSigner() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(SailKernel.NotPermissionSigner.selector);
        kernel.recordDeposit(address(safe), 1_000);
    }

    function test_RecordWithdrawal_RevertsIfNotPermissionSigner() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(SailKernel.NotPermissionSigner.selector);
        kernel.recordWithdrawal(address(safe), 1_000);
    }

    function test_RecordDeposit_EmitsEvent() public {
        vm.expectEmit(true, false, false, true);
        emit SailKernel.DepositRecorded(address(safe), 1_000, 1_000);
        vm.prank(permSigner);
        kernel.recordDeposit(address(safe), 1_000);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Governance — setTreasury
    // ─────────────────────────────────────────────────────────────────────────

    function test_SetTreasury_UpdatesAddress() public {
        vm.prank(TEAM);
        kernel.setTreasury(address(0x5555));
        assertEq(kernel.treasury(), address(0x5555));
    }

    function test_SetTreasury_RevertsForNonGovernance() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(SailKernel.NotGovernance.selector);
        kernel.setTreasury(address(0x5555));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Protocol pause
    // ─────────────────────────────────────────────────────────────────────────

    function test_Dispatch_RevertsWhenPaused() public {
        _registerPermission(address(perm));
        perm.setResult(true);

        vm.prank(EMERGENCY_ADMIN);
        gov.pause();

        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), address(0xABCD), 0, "", nonce, deadline);

        vm.expectRevert(SailKernel.ProtocolPaused.selector);
        kernel.dispatch(address(safe), address(0xABCD), 0, "", sig, deadline);
    }

    function test_CollectFees_RevertsWhenPaused() public {
        feePolicy.setFee(1_000, address(0), 0);

        vm.prank(EMERGENCY_ADMIN);
        gov.pause();

        vm.prank(manager);
        vm.expectRevert(SailKernel.ProtocolPaused.selector);
        kernel.collectFees(address(safe), 1_000, 0, address(0), manager);
    }

    function test_RegisterPermission_RevertsWhenPaused() public {
        vm.prank(EMERGENCY_ADMIN);
        gov.pause();

        uint256 nonce = kernel.signerNonces(address(safe));
        bytes32 sh    = keccak256(abi.encode(
            kernel.REGISTER_PERMISSION_TYPEHASH(), address(safe), address(perm), nonce
        ));
        bytes memory sig = _signerSig(sh);

        vm.expectRevert(SailKernel.ProtocolPaused.selector);
        kernel.registerPermission(address(safe), address(perm), sig);
    }

    function test_PauseExpiry_AllowsDispatchAfter72h() public {
        _registerPermission(address(perm));
        perm.setResult(true);

        vm.prank(EMERGENCY_ADMIN);
        gov.pause();

        vm.warp(block.timestamp + 72 hours + 1);

        _dispatch(address(0xABCD), 0, abi.encodeWithSignature("go()"));
        assertEq(safe.callCount(), 1);
    }

    function test_Unpause_AllowsDispatch() public {
        _registerPermission(address(perm));
        perm.setResult(true);

        vm.prank(EMERGENCY_ADMIN);
        gov.pause();

        vm.prank(EMERGENCY_ADMIN);
        gov.unpause();

        _dispatch(address(0xABCD), 0, abi.encodeWithSignature("go()"));
        assertEq(safe.callCount(), 1);
    }
}
