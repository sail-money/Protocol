// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test}                    from "forge-std/Test.sol";
import {SailKernel}              from "../contracts/core/SailKernel.sol";
import {SailGovernance}          from "../contracts/governance/SailGovernance.sol";
import {TimelockController}      from "@openzeppelin/contracts/governance/TimelockController.sol";
import {IPermission, Context}    from "../contracts/interfaces/IPermission.sol";
import {IFeePolicy}              from "../contracts/interfaces/IFeePolicy.sol";
import {IOracle}                 from "../contracts/interfaces/IOracle.sol";
import {BoundedSwapPermission}   from "../contracts/templates/BoundedSwapPermission.sol";

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

    Call[] public calls;
    bool   public moduleCallSuccess = true;

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

    function isModuleEnabled(address) external pure returns (bool) { return true; }

    function setSuccess(bool s) external { moduleCallSuccess = s; }
    function clearCalls() external { delete calls; }

    receive() external payable {}
}

contract MockSafeFactory {
    function createProxyWithNonce(address, bytes calldata, uint256) external returns (address) {
        return address(new MockSafe());
    }
}

contract MockPermission is IPermission {
    bool public result = true;

    function setResult(bool r) external { result = r; }

    function evaluate(bytes calldata, Context calldata) external view returns (bool) {
        return result;
    }

    function discriminator() external pure returns (bytes32) { return bytes32(0); }
}

contract GasHogPermission is IPermission {
    function evaluate(bytes calldata, Context calldata) external view returns (bool) {
        uint256 x;
        while (true) { unchecked { x++; } }
        return true;
    }

    function discriminator() external pure returns (bytes32) { return bytes32(0); }
}

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
        grossFeeReturn       = gross;
        distributorReturn    = dist;
        distributorBpsReturn = distBps;
    }

    function computeFee(address, uint256) external view returns (uint256, address, uint256) {
        return (grossFeeReturn, distributorReturn, distributorBpsReturn);
    }

    function recordCollection(address, uint256, uint256) external {
        recordCalled = true;
    }
}

contract MockOracle is IOracle {
    struct PriceData { uint256 price; uint8 decimals; }
    mapping(address => mapping(address => PriceData)) private _prices;

    function setPrice(address base, address quote, uint256 price, uint8 decimals) external {
        _prices[base][quote] = PriceData(price, decimals);
    }

    function getPrice(address base, address quote) external view returns (uint256 price, uint8 decimals) {
        PriceData memory pd = _prices[base][quote];
        return (pd.price, pd.decimals);
    }
}

/// @dev ERC1271 contract signer: accepts signatures from a single backing EOA.
contract MockERC1271Signer {
    address public immutable owner;
    bytes4  private constant MAGIC = 0x1626ba7e;

    constructor(address _owner) { owner = _owner; }

    function isValidSignature(bytes32 digest, bytes memory sig) external view returns (bytes4) {
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        address recovered = ecrecover(digest, v, r, s);
        return recovered == owner ? MAGIC : bytes4(0);
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

        gov      = new SailGovernance(TEAM, 1 ether, EMERGENCY_ADMIN, 0, 0);
        kernel   = new SailKernel(address(gov), TREASURY);
        safe     = new MockSafe();
        perm     = new MockPermission();
        feePolicy = new MockFeePolicy();

        // Safe registers itself — msg.sender must be the Safe.
        vm.prank(address(safe));
        kernel.registerAccount(permSigner, manager, address(feePolicy));
    }

    // ── helpers ───────────────────────────────────────────────────────────────

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
            account, target, value, keccak256(data), nonce, deadline
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

    /// @dev Schedule and execute a call to `kernel` via the governance timelock.
    function _kernelTimelockExec(bytes memory data) internal {
        bytes32 salt = bytes32(_saltNonce++);
        TimelockController tl = gov.timelock();
        vm.prank(TEAM);
        tl.schedule(address(kernel), 0, data, bytes32(0), salt, 48 hours);
        vm.warp(block.timestamp + 48 hours + 1);
        vm.prank(TEAM);
        tl.execute(address(kernel), 0, data, bytes32(0), salt);
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
        vm.prank(address(safe));
        vm.expectRevert(abi.encodeWithSelector(SailKernel.AccountAlreadyRegistered.selector, address(safe)));
        kernel.registerAccount(permSigner, manager, address(0));
    }

    function test_RegisterAccount_RevertsOnZeroPermissionSigner() public {
        MockSafe newSafe = new MockSafe();
        vm.prank(address(newSafe));
        vm.expectRevert(SailKernel.ZeroAddress.selector);
        kernel.registerAccount(address(0), manager, address(0));
    }

    function test_RegisterAccount_RevertsOnZeroManager() public {
        MockSafe newSafe = new MockSafe();
        vm.prank(address(newSafe));
        vm.expectRevert(SailKernel.ZeroAddress.selector);
        kernel.registerAccount(permSigner, address(0), address(0));
    }

    function test_RegisterAccount_CallerBecomesAccount() public {
        MockSafe newSafe = new MockSafe();
        vm.prank(address(newSafe));
        kernel.registerAccount(permSigner, manager, address(feePolicy));
        assertTrue(kernel.registered(address(newSafe)));
        (address ps,,, ) = kernel.configs(address(newSafe));
        assertEq(ps, permSigner);
    }

    function test_RegisterAccount_DifferentCallerRegistersAsOwnAccount() public {
        // Two different callers register two separate accounts — no cross-contamination.
        MockSafe safe2 = new MockSafe();
        MockSafe safe3 = new MockSafe();

        vm.prank(address(safe2));
        kernel.registerAccount(permSigner, manager, address(0));

        vm.prank(address(safe3));
        kernel.registerAccount(permSigner, manager, address(0));

        assertTrue(kernel.registered(address(safe2)));
        assertTrue(kernel.registered(address(safe3)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 1b. createAccount
    // ─────────────────────────────────────────────────────────────────────────

    function test_CreateAccount_DeploysAndRegisters() public {
        MockSafeFactory factory = new MockSafeFactory();
        address singleton = address(0xBEEF);

        address account = kernel.createAccount(
            address(factory), singleton, "", 0, permSigner, manager, address(feePolicy)
        );

        assertTrue(kernel.registered(account));
        (address ps, address mgr,, bool active) = kernel.configs(account);
        assertEq(ps, permSigner);
        assertEq(mgr, manager);
        assertTrue(active);
    }

    function test_CreateAccount_RevertsOnZeroPermissionSigner() public {
        MockSafeFactory factory = new MockSafeFactory();
        vm.expectRevert(SailKernel.ZeroAddress.selector);
        kernel.createAccount(address(factory), address(0), "", 0, address(0), manager, address(0));
    }

    function test_CreateAccount_RevertsOnZeroManager() public {
        MockSafeFactory factory = new MockSafeFactory();
        vm.expectRevert(SailKernel.ZeroAddress.selector);
        kernel.createAccount(address(factory), address(0), "", 0, permSigner, address(0), address(0));
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
        assertEq(balBefore - caller.balance, 0.1 ether);
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

    function test_ReplacePermission_ChargesFee() public {
        _registerPermission(address(perm));
        _govExec(abi.encodeCall(gov.setBaseFee, (0.1 ether)));

        MockPermission perm2 = new MockPermission();
        uint256 nonce = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(
            kernel.REPLACE_PERMISSION_TYPEHASH(), address(safe), address(perm), address(perm2), nonce
        ));
        bytes memory sig = _signerSig(sh);

        uint256 treasuryBefore = TREASURY.balance;
        kernel.replacePermission{value: 0.1 ether}(address(safe), address(perm), address(perm2), sig);
        assertEq(TREASURY.balance - treasuryBefore, 0.1 ether);
    }

    function test_RevokeSession_DisablesDispatch() public {
        uint256 nonce = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(kernel.REVOKE_SESSION_TYPEHASH(), address(safe), nonce));
        bytes memory sig = _signerSig(sh);
        kernel.revokeSession(address(safe), sig);

        uint256 deadline      = block.timestamp + 1 hours;
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
        bytes memory sig = _signDispatch(address(safe), address(0xABCD), 0, "", nonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(perm)));
        kernel.dispatch(address(safe), address(0xABCD), 0, "", sig, deadline);
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
        bytes32 sh = keccak256(abi.encode(
            kernel.DISPATCH_TYPEHASH(), address(safe), address(0xABCD), uint256(0), keccak256(""), nonce, deadline
        ));
        bytes32 digest = kernel.hashTypedDataV4(sh);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBAD, digest);

        vm.expectRevert(SailKernel.InvalidManagerSignature.selector);
        kernel.dispatch(address(safe), address(0xABCD), 0, "", abi.encodePacked(r, s, v), deadline);
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

        kernel.dispatch(address(safe), address(0xABCD), 0, "", sig, deadline);

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
        bytes memory sig = _signDispatch(unknown, address(0xABCD), 0, "", 0, deadline);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.AccountNotRegistered.selector, unknown));
        kernel.dispatch(unknown, address(0xABCD), 0, "", sig, deadline);
    }

    function test_Dispatch_MultiplePermissionsAllMustPass() public {
        _registerPermission(address(perm));
        MockPermission perm2 = new MockPermission();
        _registerPermission(address(perm2));

        perm.setResult(true);
        perm2.setResult(false);

        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), address(0xABCD), 0, "", nonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(perm2)));
        kernel.dispatch(address(safe), address(0xABCD), 0, "", sig, deadline);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 3b. Integration: dispatch + BoundedSwapPermission
    // ─────────────────────────────────────────────────────────────────────────

    function test_Integration_Dispatch_BoundedSwap_Passes() public {
        // Deploy oracle + permission wired to the kernel's safe and manager.
        MockOracle oracle = new MockOracle();
        uint256 oraclePrice = 2e18;
        uint8   oracleDec   = 18;
        address tokenIn     = address(0xAAAA);
        address tokenOut    = address(0xBBBB);
        address router      = address(0xD111);
        oracle.setPrice(tokenIn, tokenOut, oraclePrice, oracleDec);

        address[] memory routers    = new address[](1); routers[0]    = router;
        address[] memory tIn        = new address[](1); tIn[0]        = tokenIn;
        address[] memory tOut       = new address[](1); tOut[0]       = tokenOut;
        uint256 maxAmt    = 1_000e18;
        uint256 slipBps   = 200; // 2%

        BoundedSwapPermission swapPerm = new BoundedSwapPermission(
            routers, tIn, tOut, maxAmt, slipBps, address(oracle), permSigner
        );

        _registerPermission(address(swapPerm));

        // Build a valid V3 exactInputSingle call within bounds.
        uint256 amtIn      = 100e18;
        uint256 expectedOut = 200e18;
        uint256 minOut     = expectedOut * (10_000 - slipBps) / 10_000; // 196e18

        bytes memory swapData = abi.encodeWithSelector(
            bytes4(0x414bf389),
            tokenIn, tokenOut, uint24(3000), address(safe),
            type(uint256).max, amtIn, minOut, uint160(0)
        );

        _dispatch(router, 0, swapData);
        assertEq(safe.callCount(), 1);
    }

    function test_Integration_Dispatch_BoundedSwap_BlocksSlippageViolation() public {
        MockOracle oracle = new MockOracle();
        address tokenIn  = address(0xAAAA);
        address tokenOut = address(0xBBBB);
        address router   = address(0xD111);
        oracle.setPrice(tokenIn, tokenOut, 2e18, 18);

        address[] memory routers = new address[](1); routers[0] = router;
        address[] memory tIn     = new address[](1); tIn[0]     = tokenIn;
        address[] memory tOut    = new address[](1); tOut[0]    = tokenOut;

        BoundedSwapPermission swapPerm = new BoundedSwapPermission(
            routers, tIn, tOut, 1_000e18, 200, address(oracle), permSigner
        );
        _registerPermission(address(swapPerm));

        // amountOutMin = 1 violates the oracle-derived floor (196e18).
        bytes memory swapData = abi.encodeWithSelector(
            bytes4(0x414bf389),
            tokenIn, tokenOut, uint24(3000), address(safe),
            type(uint256).max, uint256(100e18), uint256(1), uint160(0)
        );

        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), router, 0, swapData, nonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(swapPerm)));
        kernel.dispatch(address(safe), router, 0, swapData, sig, deadline);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 4. Fee accounting
    // ─────────────────────────────────────────────────────────────────────────

    function test_CollectFees_SplitsCorrectly() public {
        _govExec(abi.encodeCall(gov.setProtocolCutBps, (1_000)));

        uint256 grossFee = 1_000_000;
        feePolicy.setFee(grossFee, DIST, 2_000);

        vm.prank(manager);
        kernel.collectFees(address(safe), grossFee, 0, address(0), manager);

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
        uint256 grossFee = 1_000_000;
        feePolicy.setFee(grossFee, address(0), 0);

        vm.prank(manager);
        kernel.collectFees(address(safe), grossFee, 0, address(0), manager);

        assertEq(safe.callCount(), 1);
        (address to, uint256 v,,) = safe.getCall(0);
        assertEq(to, manager);
        assertEq(v, grossFee);
    }

    function test_CollectFees_SkipsZeroDistributor() public {
        _govExec(abi.encodeCall(gov.setProtocolCutBps, (500)));

        feePolicy.setFee(1_000_000, address(0), 1_000);

        vm.prank(manager);
        kernel.collectFees(address(safe), 1_000_000, 0, address(0), manager);

        assertEq(safe.callCount(), 2);
        (address to0,,,) = safe.getCall(0);
        (address to1,,,) = safe.getCall(1);
        assertEq(to0, TREASURY);
        assertEq(to1, manager);
    }

    function test_CollectFees_ZeroDistributorWithNonZeroBps_FoldsIntoManagerTake() public {
        // When distributor == address(0) but distributorBps > 0, the distributor share
        // must NOT be silently lost — it must be added to managerTake.
        uint256 grossFee       = 10_000;
        uint256 distributorBps = 2_000; // 20%
        // No protocol cut for simplicity
        _govExec(abi.encodeCall(gov.setProtocolCutBps, (0)));

        // distributor = address(0), but bps = 20%
        feePolicy.setFee(grossFee, address(0), distributorBps);

        vm.prank(manager);
        kernel.collectFees(address(safe), grossFee, 0, address(0), manager);

        // Only 1 transfer should happen (to manager — no protocol cut, no distributor)
        assertEq(safe.callCount(), 1);
        (address to, uint256 val,,) = safe.getCall(0);
        assertEq(to, manager);
        // Manager must receive the full grossFee (distributor share folded in)
        assertEq(val, grossFee);
    }

    function test_CollectFees_ERC20Path() public {
        address token    = address(0x1234567890123456789012345678901234567890);
        uint256 grossFee = 500;
        feePolicy.setFee(grossFee, address(0), 0);

        vm.prank(manager);
        kernel.collectFees(address(safe), grossFee, 0, token, manager);

        assertEq(safe.callCount(), 1);
        (address to, uint256 v, bytes memory d,) = safe.getCall(0);
        assertEq(to, token);
        assertEq(v, 0);
        // Verify the kernel uses transfer(address,uint256) encoding.
        bytes memory expected = abi.encodeWithSignature("transfer(address,uint256)", manager, grossFee);
        assertEq(d, expected);
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
        vm.prank(address(safe2));
        kernel.registerAccount(permSigner, manager, address(0));

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

        (, uint256 protocolV,,) = safe.getCall(0);
        assertEq(protocolV, 2_500);
        (, uint256 managerV,,) = safe.getCall(1);
        assertEq(managerV, 7_500);
    }


    function test_CollectFees_RevertsOnZeroRecipient() public {
        feePolicy.setFee(1_000, address(0), 0);
        vm.prank(manager);
        vm.expectRevert(SailKernel.ZeroAddress.selector);
        kernel.collectFees(address(safe), 1_000, 1e18, address(0), address(0));
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
        _kernelTimelockExec(abi.encodeCall(kernel.setTreasury, (address(0x5555))));
        assertEq(kernel.treasury(), address(0x5555));
    }

    function test_SetTreasury_RevertsForNonTimelock() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(SailKernel.NotTimelock.selector);
        kernel.setTreasury(address(0x5555));
    }

    function test_SetTreasury_RevertsForGovernanceDirect() public {
        // setTreasury now requires 48h timelock, even governance cannot call directly
        vm.prank(TEAM);
        vm.expectRevert(SailKernel.NotTimelock.selector);
        kernel.setTreasury(address(0x5555));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Protocol pause (via governance emergency admin)
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

    // ─────────────────────────────────────────────────────────────────────────
    // Session: revokeSession / activateSession
    // ─────────────────────────────────────────────────────────────────────────

    function test_ActivateSession_ReactivatesDispatch() public {
        _registerPermission(address(perm));

        // Revoke
        bytes32 revokeSh = keccak256(abi.encode(kernel.REVOKE_SESSION_TYPEHASH(), address(safe), kernel.signerNonces(address(safe))));
        kernel.revokeSession(address(safe), _signerSig(revokeSh));
        assertFalse(_sessionActive());

        // Activate
        bytes32 activateSh = keccak256(abi.encode(kernel.ACTIVATE_SESSION_TYPEHASH(), address(safe), kernel.signerNonces(address(safe))));
        kernel.activateSession(address(safe), _signerSig(activateSh));
        assertTrue(_sessionActive());

        // Dispatch now works
        _dispatch(address(0xABCD), 0, "");
        assertEq(safe.callCount(), 1);
    }

    function test_RevokeSession_Permanent_WithoutActivate() public {
        _registerPermission(address(perm));
        bytes32 sh = keccak256(abi.encode(kernel.REVOKE_SESSION_TYPEHASH(), address(safe), kernel.signerNonces(address(safe))));
        kernel.revokeSession(address(safe), _signerSig(sh));

        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), address(0xABCD), 0, "", nonce, deadline);
        vm.expectRevert(abi.encodeWithSelector(SailKernel.SessionInactive.selector, address(safe)));
        kernel.dispatch(address(safe), address(0xABCD), 0, "", sig, deadline);
    }

    function test_ActivateSession_RevertsOnBadSig() public {
        bytes32 sh = keccak256(abi.encode(kernel.ACTIVATE_SESSION_TYPEHASH(), address(safe), kernel.signerNonces(address(safe))));
        bytes32 digest = kernel.hashTypedDataV4(sh);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBAD, digest);
        vm.expectRevert(SailKernel.InvalidSignerSignature.selector);
        kernel.activateSession(address(safe), abi.encodePacked(r, s, v));
    }

    function test_ActivateSession_IdempotentOnAlreadyActiveSession() public {
        // Session is active by default — activating again should succeed and consume a nonce
        (,,, bool activeBefore) = kernel.configs(address(safe));
        assertTrue(activeBefore);
        uint256 nonceBefore = kernel.signerNonces(address(safe));

        bytes32 sh = keccak256(abi.encode(kernel.ACTIVATE_SESSION_TYPEHASH(), address(safe), nonceBefore));
        kernel.activateSession(address(safe), _signerSig(sh));

        (,,, bool activeAfter) = kernel.configs(address(safe));
        assertTrue(activeAfter, "session should remain active");
        assertEq(kernel.signerNonces(address(safe)), nonceBefore + 1, "nonce consumed");
    }

    function test_RevokeSession_IdempotentOnAlreadyInactiveSession() public {
        // Revoke once
        bytes32 sh1 = keccak256(abi.encode(kernel.REVOKE_SESSION_TYPEHASH(), address(safe), kernel.signerNonces(address(safe))));
        kernel.revokeSession(address(safe), _signerSig(sh1));

        (,,, bool activeAfterFirst) = kernel.configs(address(safe));
        assertFalse(activeAfterFirst);

        // Revoke again — should succeed and consume another nonce
        uint256 nonceBefore = kernel.signerNonces(address(safe));
        bytes32 sh2 = keccak256(abi.encode(kernel.REVOKE_SESSION_TYPEHASH(), address(safe), nonceBefore));
        kernel.revokeSession(address(safe), _signerSig(sh2));

        (,,, bool activeAfterSecond) = kernel.configs(address(safe));
        assertFalse(activeAfterSecond, "session should remain inactive");
        assertEq(kernel.signerNonces(address(safe)), nonceBefore + 1, "nonce consumed");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // setFeePolicy
    // ─────────────────────────────────────────────────────────────────────────

    function test_SetFeePolicy_UpdatesPolicy() public {
        MockFeePolicy newPolicy = new MockFeePolicy();
        bytes32 sh = keccak256(abi.encode(kernel.SET_FEE_POLICY_TYPEHASH(), address(safe), address(newPolicy), kernel.signerNonces(address(safe))));
        kernel.setFeePolicy(address(safe), address(newPolicy), _signerSig(sh));
        (,, address fp,) = kernel.configs(address(safe));
        assertEq(fp, address(newPolicy));
    }

    function test_SetFeePolicy_AllowsZeroAddress() public {
        bytes32 sh = keccak256(abi.encode(kernel.SET_FEE_POLICY_TYPEHASH(), address(safe), address(0), kernel.signerNonces(address(safe))));
        kernel.setFeePolicy(address(safe), address(0), _signerSig(sh));
        (,, address fp,) = kernel.configs(address(safe));
        assertEq(fp, address(0));
    }

    function test_SetFeePolicy_RevertsOnBadSig() public {
        bytes32 sh = keccak256(abi.encode(kernel.SET_FEE_POLICY_TYPEHASH(), address(safe), address(0), kernel.signerNonces(address(safe))));
        bytes32 digest = kernel.hashTypedDataV4(sh);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBAD, digest);
        vm.expectRevert(SailKernel.InvalidSignerSignature.selector);
        kernel.setFeePolicy(address(safe), address(0), abi.encodePacked(r, s, v));
    }

    function test_SetFeePolicy_EmitsEvent() public {
        MockFeePolicy newPolicy = new MockFeePolicy();
        bytes32 sh = keccak256(abi.encode(kernel.SET_FEE_POLICY_TYPEHASH(), address(safe), address(newPolicy), kernel.signerNonces(address(safe))));
        vm.expectEmit(true, true, false, false);
        emit SailKernel.FeePolicyUpdated(address(safe), address(newPolicy));
        kernel.setFeePolicy(address(safe), address(newPolicy), _signerSig(sh));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Permission count cap
    // ─────────────────────────────────────────────────────────────────────────

    function test_RegisterPermission_RevertsBeyondCap() public {
        uint256 cap = gov.maxPermissionsPerAccount();

        // Register up to the cap
        for (uint256 i = 0; i < cap; i++) {
            MockPermission p = new MockPermission();
            _registerPermission(address(p));
        }
        assertEq(kernel.getPermissions(address(safe)).length, cap);

        // One more should revert
        MockPermission extra = new MockPermission();
        uint256 nonce = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(kernel.REGISTER_PERMISSION_TYPEHASH(), address(safe), address(extra), nonce));
        bytes memory sig = _signerSig(sh);
        vm.expectRevert(abi.encodeWithSelector(SailKernel.TooManyPermissions.selector, address(safe), cap));
        kernel.registerPermission(address(safe), address(extra), sig);
    }

    function test_RegisterPermission_AfterRevokeAllowsNew() public {
        uint256 cap = gov.maxPermissionsPerAccount();

        // Fill to cap
        MockPermission[] memory perms = new MockPermission[](cap);
        for (uint256 i = 0; i < cap; i++) {
            perms[i] = new MockPermission();
            _registerPermission(address(perms[i]));
        }

        // Revoke one
        uint256 nonce = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(kernel.REVOKE_PERMISSION_TYPEHASH(), address(safe), address(perms[0]), nonce));
        kernel.revokePermission(address(safe), address(perms[0]), _signerSig(sh));
        assertEq(kernel.getPermissions(address(safe)).length, cap - 1);

        // Now can register one more
        MockPermission extra = new MockPermission();
        _registerPermission(address(extra));
        assertEq(kernel.getPermissions(address(safe)).length, cap);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Dispatch with non-zero ETH value
    // ─────────────────────────────────────────────────────────────────────────

    function test_Dispatch_WithNonZeroValue() public {
        _registerPermission(address(perm));
        uint256 ethValue = 1 ether;

        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), address(0xABCD), ethValue, "", nonce, deadline);
        kernel.dispatch(address(safe), address(0xABCD), ethValue, "", sig, deadline);

        assertEq(safe.callCount(), 1);
        (, uint256 v,,) = safe.getCall(0);
        assertEq(v, ethValue);
    }

    function test_Dispatch_ValueIncludedInEIP712Digest() public {
        _registerPermission(address(perm));

        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));

        // Sign with value = 0 but dispatch with value = 1 — must revert
        bytes memory sigForZero = _signDispatch(address(safe), address(0xABCD), 0, "", nonce, deadline);
        vm.expectRevert(SailKernel.InvalidManagerSignature.selector);
        kernel.dispatch(address(safe), address(0xABCD), 1 ether, "", sigForZero, deadline);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ERC1271 manager and permissionSigner
    // ─────────────────────────────────────────────────────────────────────────

    function test_ERC1271_Manager_SignatureAccepted() public {
        // Deploy a contract signer that validates signatures via backing EOA.
        uint256 backingKey = 0xC0DE;
        address backingEOA = vm.addr(backingKey);
        MockERC1271Signer contractManager = new MockERC1271Signer(backingEOA);

        // Register new safe with the contract as manager
        MockSafe safe2 = new MockSafe();
        vm.prank(address(safe2));
        kernel.registerAccount(permSigner, address(contractManager), address(feePolicy));

        // Register a permission
        uint256 sigNonce = kernel.signerNonces(address(safe2));
        bytes32 regSh = keccak256(abi.encode(kernel.REGISTER_PERMISSION_TYPEHASH(), address(safe2), address(perm), sigNonce));
        bytes32 regDigest = kernel.hashTypedDataV4(regSh);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(SIGNER_KEY, regDigest);
        kernel.registerPermission(address(safe2), address(perm), abi.encodePacked(r1, s1, v1));

        // Build dispatch sig using the backing EOA — kernel verifies via ERC1271
        uint256 deadline = block.timestamp + 1 hours;
        uint256 dispNonce = kernel.managerNonces(address(safe2));
        bytes32 dSh = keccak256(abi.encode(kernel.DISPATCH_TYPEHASH(), address(safe2), address(0xABCD), uint256(0), keccak256(""), dispNonce, deadline));
        bytes32 dDigest = kernel.hashTypedDataV4(dSh);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(backingKey, dDigest);
        bytes memory dispSig = abi.encodePacked(r2, s2, v2);

        kernel.dispatch(address(safe2), address(0xABCD), 0, "", dispSig, deadline);
        assertEq(safe2.callCount(), 1);
    }

    function test_ERC1271_Manager_WrongBackingKeyRejected() public {
        uint256 backingKey  = 0xC0DE;
        address backingEOA  = vm.addr(backingKey);
        MockERC1271Signer contractManager = new MockERC1271Signer(backingEOA);

        MockSafe safe2 = new MockSafe();
        vm.prank(address(safe2));
        kernel.registerAccount(permSigner, address(contractManager), address(feePolicy));

        uint256 sigNonce = kernel.signerNonces(address(safe2));
        bytes32 regSh = keccak256(abi.encode(kernel.REGISTER_PERMISSION_TYPEHASH(), address(safe2), address(perm), sigNonce));
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(SIGNER_KEY, kernel.hashTypedDataV4(regSh));
        kernel.registerPermission(address(safe2), address(perm), abi.encodePacked(r1, s1, v1));

        uint256 deadline = block.timestamp + 1 hours;
        uint256 dispNonce = kernel.managerNonces(address(safe2));
        bytes32 dSh = keccak256(abi.encode(kernel.DISPATCH_TYPEHASH(), address(safe2), address(0xABCD), uint256(0), keccak256(""), dispNonce, deadline));
        // Sign with WRONG key — ERC1271 returns 0 magic
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(0xBAD, kernel.hashTypedDataV4(dSh));

        vm.expectRevert(SailKernel.InvalidManagerSignature.selector);
        kernel.dispatch(address(safe2), address(0xABCD), 0, "", abi.encodePacked(r2, s2, v2), deadline);
    }

    function test_ERC1271_PermissionSigner_SignatureAccepted() public {
        uint256 backingKey = 0xBEAD;
        address backingEOA = vm.addr(backingKey);
        MockERC1271Signer contractSigner = new MockERC1271Signer(backingEOA);

        // Register new safe with the contract as permissionSigner
        MockSafe safe2 = new MockSafe();
        vm.prank(address(safe2));
        kernel.registerAccount(address(contractSigner), manager, address(feePolicy));

        // Register permission using backing EOA sig verified by ERC1271
        uint256 sigNonce = kernel.signerNonces(address(safe2));
        bytes32 sh = keccak256(abi.encode(kernel.REGISTER_PERMISSION_TYPEHASH(), address(safe2), address(perm), sigNonce));
        bytes32 digest = kernel.hashTypedDataV4(sh);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(backingKey, digest);
        kernel.registerPermission(address(safe2), address(perm), abi.encodePacked(r, s, v));

        assertTrue(kernel.isPermissionRegistered(address(safe2), address(perm)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    function _sessionActive() internal view returns (bool active) {
        (,,, active) = kernel.configs(address(safe));
    }
}
