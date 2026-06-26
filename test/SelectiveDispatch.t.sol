// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import {SailKernel}           from "../contracts/core/SailKernel.sol";
import {SailGovernance}       from "../contracts/governance/SailGovernance.sol";
import {TimelockDeployer}     from "./support/TimelockDeployer.sol";
import {IPermission, Context} from "../contracts/interfaces/IPermission.sol";
import {IBatchPermission, Call, BatchContext} from "../contracts/interfaces/IBatchPermission.sol";
import {ConfigurablePermission} from "../contracts/templates/ConfigurablePermission.sol";
import {SwapPermission}     from "../contracts/templates/SwapPermission.sol";
import {BorrowPermission}   from "../contracts/templates/BorrowPermission.sol";
import {TransferPermission}  from "../contracts/templates/TransferPermission.sol";
import {ApproveAndCallBatchPermission} from "../contracts/templates/ApproveAndCallBatchPermission.sol";
import {IOracle}              from "../contracts/interfaces/IOracle.sol";

// =============================================================================
// Mocks
// =============================================================================

/// @dev Simple mock Safe — records calls and always returns true.
contract MockSafe {
    // Octane group 1a test support: a finalized Safe reports nonce>=1 (setup never bumps it)
    // and exposes its trusted singleton via masterCopy() (intercepted by a real SafeProxy fallback).
    function nonce() external pure returns (uint256) { return 1; }
    function checkSignatures(bytes32, bytes calldata, bytes calldata) external view {}
    function masterCopy() external pure returns (address) { return address(0x5AFE); }

    struct CallEntry {
        address to;
        uint256 value;
        bytes   data;
        uint8   operation;
    }

    CallEntry[] private _calls;
    bool public moduleCallSuccess = true;

    receive() external payable {}

    function execTransactionFromModule(address to, uint256 value, bytes calldata data, uint8 op)
        external returns (bool)
    {
        _calls.push(CallEntry({to: to, value: value, data: data, operation: op}));
        return moduleCallSuccess;
    }

    function callCount() external view returns (uint256) { return _calls.length; }

    function getCall(uint256 i)
        external view
        returns (address to, uint256 value, bytes memory data, uint8 op)
    {
        CallEntry storage c = _calls[i];
        return (c.to, c.value, c.data, c.operation);
    }

    function isModuleEnabled(address) external pure returns (bool) { return true; }

    function setSuccess(bool s) external { moduleCallSuccess = s; }
    function clearCalls() external { delete _calls; }
}

/// @dev Simple allow-all IPermission (used as baseline mock)
contract MockPermission is IPermission {
    bool public result = true;
    function setResult(bool r) external { result = r; }
    function evaluate(bytes calldata, Context calldata) external view returns (bool) { return result; }
    function discriminator() external pure returns (bytes32) { return bytes32(0); }
}

/// @dev Allow-all IBatchPermission for batch backwards-compat test
contract AllowAllBatchPermission is IBatchPermission {
    function evaluateBatch(Call[] calldata, BatchContext calldata) external pure returns (bool) {
        return true;
    }
    function isBatchPermission() external pure returns (bool) { return true; }
    // IBatchPermission does not extend IPermission, so no evaluate() / discriminator() needed
}

/// @dev Minimal IOracle that returns fixed prices
contract MockOracle is IOracle {
    struct Price { uint256 p; uint8 d; }
    mapping(address => mapping(address => Price)) private _prices;

    function set(address base, address quote, uint256 p, uint8 d) external {
        _prices[base][quote] = Price(p, d);
    }

    function getPrice(address base, address quote)
        external view returns (uint256 price, uint8 decimals, uint256 updatedAt)
    {
        Price memory pd = _prices[base][quote];
        return (pd.p, pd.d, block.timestamp);
    }
}

// =============================================================================
// Helpers imported from FactoryTestBase / SailKernelTest patterns
// =============================================================================

// =============================================================================
// Main test contract
// =============================================================================
contract SelectiveDispatchTest is Test {
    // ── key constants ─────────────────────────────────────────────────────────
    uint256 internal constant PERM_SIGNER_KEY = 0xA11CE;
    uint256 internal constant MANAGER_KEY     = 0xB0B;

    address internal constant TREASURY = address(0xAAAA);
    // Governance: set BASE_FEE = 0 so registration fee is 0 by default,
    // but MAX_PERM_FEE = 0.001 ether as specified.
    uint256 internal constant BASE_FEE     = 0;
    uint256 internal constant MAX_PERM_FEE = 0.001 ether;

    // ── protocol ──────────────────────────────────────────────────────────────
    SailGovernance internal gov;
    SailKernel     internal kernel;
    MockSafe       internal safe;

    address internal permSigner;
    address internal manager;

    // ── DeFi addresses (deterministic placeholders) ───────────────────────────
    address constant UNI_ROUTER   = address(0xE001);  // allowed swap router
    address constant AAVE_POOL    = address(0xE002);  // allowed borrow protocol
    address constant TOKEN_IN     = address(0xE003);  // swap tokenIn
    address constant TOKEN_OUT    = address(0xE004);  // swap tokenOut
    address constant BORROW_ASSET = address(0xE005);  // borrow asset
    address constant TRANSFER_TKN = address(0xE006);  // transfer token (target)
    address constant RECIPIENT    = address(0xE007);  // allowed transfer recipient

    // ── selector constants ────────────────────────────────────────────────────
    bytes4 internal constant EXACT_INPUT_SINGLE_V1 = 0x414bf389;
    bytes4 internal constant AAVE_BORROW_SEL =
        bytes4(keccak256("borrow(address,uint256,uint256,uint16,address)"));
    bytes4 internal constant TRANSFER_SELECTOR = 0xa9059cbb;

    // ── deployed templates ────────────────────────────────────────────────────
    SwapPermission    internal swapPerm;
    BorrowPermission  internal borrowPerm;
    TransferPermission internal transferPerm;

    // ── setup ─────────────────────────────────────────────────────────────────

    function setUp() public {
        permSigner = vm.addr(PERM_SIGNER_KEY);
        manager    = vm.addr(MANAGER_KEY);

        vm.deal(address(this), 10 ether);

        gov    = new SailGovernance(address(this), MAX_PERM_FEE, address(this), BASE_FEE, TimelockDeployer.deploy(address(this)));
        kernel = new SailKernel(address(gov), TREASURY, address(0));
        safe   = new MockSafe();
        vm.deal(address(safe), 1 ether);

        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeProxyCodehash(address(safe).codehash, true);
        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeSingleton(address(0x5AFE), true); // Octane #9: trust the mock singleton

        vm.prank(address(safe));
        kernel.registerAccount(permSigner, manager, address(0), address(0), block.timestamp + 1 days, "");

        // Deploy templates (shared, multi-account)
        swapPerm     = new SwapPermission(address(kernel), address(0xA11CE));
        borrowPerm   = new BorrowPermission(address(kernel), address(0xA11CE));
        transferPerm = new TransferPermission(address(kernel), address(0xA11CE));
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    /// @dev EIP-712 registration sig from permSigner
    function _signerSig(bytes32 structHash) internal view returns (bytes memory) {
        bytes32 digest = kernel.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PERM_SIGNER_KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    function _registerPermission(address permission) internal {
        uint256 nonce = kernel.signerNonces(address(safe));
        uint256 deadline = block.timestamp + 1 days;
        bytes32 sh = keccak256(abi.encode(
            kernel.REGISTER_PERMISSION_TYPEHASH(), address(safe), permission, nonce, deadline
        ));
        uint256 fee = gov.permissionRegistrationFee();
        kernel.registerPermission{value: fee}(address(safe), permission, deadline, _signerSig(sh));
    }

    function _revokePermission(address permission) internal {
        uint256 nonce = kernel.signerNonces(address(safe));
        uint256 deadline = block.timestamp + 1 days;
        bytes32 sh = keccak256(abi.encode(
            kernel.REVOKE_PERMISSION_TYPEHASH(), address(safe), permission, nonce, deadline
        ));
        kernel.revokePermission(address(safe), permission, deadline, _signerSig(sh));
    }

    function _signDispatch(
        address account,
        address permission,
        address target,
        uint256 value,
        bytes memory data,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes32 sh = keccak256(abi.encode(
            kernel.DISPATCH_TYPEHASH(),
            account, permission, target, value, keccak256(data), nonce, deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(MANAGER_KEY, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }

    function _dispatch(address permission, address target, uint256 value, bytes memory data) internal {
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), permission, target, value, data, nonce, deadline);
        kernel.dispatch(address(safe), permission, target, value, data, sig, deadline);
    }

    /// @dev Sign a configure call for a shared template (ConfigurablePermission)
    function _signConfigure(
        ConfigurablePermission template,
        address account,
        bytes memory params,
        uint256 deadline
    ) internal view returns (bytes memory) {
        uint256 nonce = template.configNonces(account);
        uint256 epoch = template.kernel().registrationEpoch(account, address(template));
        bytes32 sh = keccak256(abi.encode(
            template.CONFIGURE_TYPEHASH(),
            account,
            keccak256(params),
            nonce,
            deadline,
            epoch
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PERM_SIGNER_KEY, template.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }

    // ── template configuration helpers ────────────────────────────────────────

    function _configureSwap(address account) internal {
        address[] memory routers   = new address[](1); routers[0]   = UNI_ROUTER;
        address[] memory tokensIn  = new address[](1); tokensIn[0]  = TOKEN_IN;
        address[] memory tokensOut = new address[](1); tokensOut[0] = TOKEN_OUT;
        // SwapPermission requires an oracle. These dispatch-selection tests exercise routing, not
        // the slippage band, so use a permissive 1:1 oracle with maximum tolerance; the success
        // swaps clear the resulting floor trivially. This is a full 7-field config; the prior
        // 6-field encode only decoded by ABI-layout coincidence on the now-removed no-oracle path.
        MockOracle oracle = new MockOracle();
        oracle.set(TOKEN_IN, TOKEN_OUT, 1, 0);
        bytes memory params = abi.encode(
            routers, tokensIn, tokensOut, uint256(1_000e18), uint256(9_999), address(oracle), uint256(3600)
        );
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _signConfigure(swapPerm, account, params, deadline);
        swapPerm.configure(account, params, deadline, sig);
    }

    function _configureBorrow(address account) internal {
        address[] memory protocols = new address[](1); protocols[0] = AAVE_POOL;
        address[] memory assets    = new address[](1); assets[0]    = BORROW_ASSET;
        bytes memory params = abi.encode(protocols, assets, uint256(1_000e18), uint256(0), address(0), address(0), uint256(0));
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _signConfigure(borrowPerm, account, params, deadline);
        borrowPerm.configure(account, params, deadline, sig);
    }

    function _configureTransfer(address account) internal {
        address[] memory recipients = new address[](1); recipients[0] = RECIPIENT;
        address[] memory tokens     = new address[](1); tokens[0]     = TRANSFER_TKN;
        bytes memory params = abi.encode(recipients, tokens, uint256(1_000e18));
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _signConfigure(transferPerm, account, params, deadline);
        transferPerm.configure(account, params, deadline, sig);
    }

    // ── calldata builders ──────────────────────────────────────────────────────

    /// @dev V3 exactInputSingle calldata (260 bytes)
    function _buildSwapData(uint256 amtIn, uint256 amtOutMin) internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            EXACT_INPUT_SINGLE_V1,
            TOKEN_IN, TOKEN_OUT, uint24(3000), address(safe),
            block.timestamp + 1 hours, amtIn, amtOutMin, uint160(0)
        );
    }

    /// @dev Aave borrow calldata (164 bytes)
    function _buildBorrowData(uint256 amount) internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            AAVE_BORROW_SEL, BORROW_ASSET, amount, uint256(2), uint16(0), address(safe)
        );
    }

    /// @dev ERC20 transfer calldata
    function _buildTransferData(uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(TRANSFER_SELECTOR, RECIPIENT, amount);
    }

    // =========================================================================
    // SECTION 1: MULTI-PERMISSION COEXISTENCE
    // =========================================================================

    /// @dev Test 1: Register swap, borrow, and transfer permissions on one account.
    function test_1_RegisterThreePermissions() public {
        _configureSwap(address(safe));
        _configureBorrow(address(safe));
        _configureTransfer(address(safe));

        _registerPermission(address(swapPerm));
        _registerPermission(address(borrowPerm));
        _registerPermission(address(transferPerm));

        assertTrue(kernel.isPermissionRegistered(address(safe), address(swapPerm)),    "swap not registered");
        assertTrue(kernel.isPermissionRegistered(address(safe), address(borrowPerm)),  "borrow not registered");
        assertTrue(kernel.isPermissionRegistered(address(safe), address(transferPerm)), "transfer not registered");
        assertEq(kernel.getPermissions(address(safe)).length, 3, "expected 3 permissions");
    }

    /// @dev Test 2: Dispatch a valid V3 swap selecting swapPerm → succeeds.
    function test_2_DispatchSwap_SelectingSwapPerm_Succeeds() public {
        _configureSwap(address(safe));
        _configureBorrow(address(safe));
        _configureTransfer(address(safe));
        _registerPermission(address(swapPerm));
        _registerPermission(address(borrowPerm));
        _registerPermission(address(transferPerm));

        bytes memory swapData = _buildSwapData(100e18, 100e18);
        _dispatch(address(swapPerm), UNI_ROUTER, 0, swapData);
        assertEq(safe.callCount(), 1, "swap call not executed");
    }

    /// @dev Test 3: Dispatch a valid Aave borrow selecting borrowPerm → succeeds.
    function test_3_DispatchBorrow_SelectingBorrowPerm_Succeeds() public {
        _configureSwap(address(safe));
        _configureBorrow(address(safe));
        _configureTransfer(address(safe));
        _registerPermission(address(swapPerm));
        _registerPermission(address(borrowPerm));
        _registerPermission(address(transferPerm));

        bytes memory borrowData = _buildBorrowData(500e18);
        _dispatch(address(borrowPerm), AAVE_POOL, 0, borrowData);
        assertEq(safe.callCount(), 1, "borrow call not executed");
    }

    /// @dev Test 4: Dispatch a valid ERC20 transfer selecting transferPerm → succeeds.
    function test_4_DispatchTransfer_SelectingTransferPerm_Succeeds() public {
        _configureSwap(address(safe));
        _configureBorrow(address(safe));
        _configureTransfer(address(safe));
        _registerPermission(address(swapPerm));
        _registerPermission(address(borrowPerm));
        _registerPermission(address(transferPerm));

        bytes memory transferData = _buildTransferData(100e18);
        _dispatch(address(transferPerm), TRANSFER_TKN, 0, transferData);
        assertEq(safe.callCount(), 1, "transfer call not executed");
    }

    /// @dev Test 5: After all three dispatches, all three permissions remain registered.
    function test_5_AllThreePermissionsRemainRegistered_AfterDispatch() public {
        _configureSwap(address(safe));
        _configureBorrow(address(safe));
        _configureTransfer(address(safe));
        _registerPermission(address(swapPerm));
        _registerPermission(address(borrowPerm));
        _registerPermission(address(transferPerm));

        _dispatch(address(swapPerm),    UNI_ROUTER,   0, _buildSwapData(100e18, 100e18));
        _dispatch(address(borrowPerm),  AAVE_POOL,    0, _buildBorrowData(500e18));
        _dispatch(address(transferPerm), TRANSFER_TKN, 0, _buildTransferData(100e18));

        assertTrue(kernel.isPermissionRegistered(address(safe), address(swapPerm)));
        assertTrue(kernel.isPermissionRegistered(address(safe), address(borrowPerm)));
        assertTrue(kernel.isPermissionRegistered(address(safe), address(transferPerm)));
        assertEq(kernel.getPermissions(address(safe)).length, 3);
    }

    // =========================================================================
    // SECTION 2: WRONG PERMISSION SELECTION
    // =========================================================================

    /// @dev Test 6: Dispatch a V3 swap selecting borrowPerm → PermissionDenied(borrowPerm).
    function test_6_WrongPermission_SwapViaBorowPerm_Reverts() public {
        _configureSwap(address(safe));
        _configureBorrow(address(safe));
        _registerPermission(address(swapPerm));
        _registerPermission(address(borrowPerm));

        bytes memory swapData = _buildSwapData(100e18, 100e18);
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), address(borrowPerm), UNI_ROUTER, 0, swapData, nonce, deadline);

        vm.expectRevert(
            abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(borrowPerm))
        );
        kernel.dispatch(address(safe), address(borrowPerm), UNI_ROUTER, 0, swapData, sig, deadline);
    }

    /// @dev Test 7: Dispatch with an unregistered permission address → PermissionNotRegistered.
    function test_7_UnregisteredPermission_Reverts() public {
        address unregistered = address(new MockPermission());
        bytes memory data    = _buildSwapData(100e18, 100e18);
        uint256 deadline     = block.timestamp + 1 hours;
        uint256 nonce        = kernel.managerNonces(address(safe));
        bytes memory sig     = _signDispatch(address(safe), unregistered, UNI_ROUTER, 0, data, nonce, deadline);

        vm.expectRevert(
            abi.encodeWithSelector(SailKernel.PermissionNotRegistered.selector, unregistered)
        );
        kernel.dispatch(address(safe), unregistered, UNI_ROUTER, 0, data, sig, deadline);
    }

    /// @dev Test 8: Dispatch with permission = address(0) → PermissionNotRegistered(address(0)).
    function test_8_ZeroPermission_Reverts() public {
        bytes memory data = _buildSwapData(100e18, 100e18);
        uint256 deadline  = block.timestamp + 1 hours;
        uint256 nonce     = kernel.managerNonces(address(safe));
        bytes memory sig  = _signDispatch(address(safe), address(0), UNI_ROUTER, 0, data, nonce, deadline);

        vm.expectRevert(
            abi.encodeWithSelector(SailKernel.PermissionNotRegistered.selector, address(0))
        );
        kernel.dispatch(address(safe), address(0), UNI_ROUTER, 0, data, sig, deadline);
    }

    // =========================================================================
    // SECTION 3: SIGNATURE BINDING
    // =========================================================================

    /// @dev Test 9: Build valid sig with permission=swapPerm. Replay that sig
    ///      with permission=borrowPerm in the call → InvalidManagerSignature.
    function test_9_SignatureBindsPermission_ReplayWithDifferentPerm_Reverts() public {
        _configureSwap(address(safe));
        _configureBorrow(address(safe));
        _registerPermission(address(swapPerm));
        _registerPermission(address(borrowPerm));

        bytes memory swapData = _buildSwapData(100e18, 100e18);
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));

        // Sign with permission=swapPerm
        bytes memory sig = _signDispatch(address(safe), address(swapPerm), UNI_ROUTER, 0, swapData, nonce, deadline);

        // Call with permission=borrowPerm — digest mismatch
        vm.expectRevert(SailKernel.InvalidManagerSignature.selector);
        kernel.dispatch(address(safe), address(borrowPerm), UNI_ROUTER, 0, swapData, sig, deadline);
    }

    /// @dev Test 10: Build a sig using OLD typehash fields (omitting `permission`).
    ///      Submit with new dispatch → InvalidManagerSignature.
    function test_10_OldTypehashFieldsOmittingPermission_Reverts() public {
        _configureSwap(address(safe));
        _registerPermission(address(swapPerm));

        bytes memory swapData = _buildSwapData(100e18, 100e18);
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));

        // Old typehash that did NOT include `permission` — simulate by using a custom
        // structHash that omits the permission field.
        bytes32 oldTypeHash = keccak256(
            "Dispatch(address account,address target,uint256 value,bytes32 dataHash,uint256 nonce,uint256 deadline)"
        );
        bytes32 badStructHash = keccak256(abi.encode(
            oldTypeHash,
            address(safe), UNI_ROUTER, uint256(0), keccak256(swapData), nonce, deadline
        ));
        bytes32 badDigest = kernel.hashTypedDataV4(badStructHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(MANAGER_KEY, badDigest);
        bytes memory badSig = abi.encodePacked(r, s, v);

        vm.expectRevert(SailKernel.InvalidManagerSignature.selector);
        kernel.dispatch(address(safe), address(swapPerm), UNI_ROUTER, 0, swapData, badSig, deadline);
    }

    // =========================================================================
    // SECTION 4: REGISTRATION RACE
    // =========================================================================

    /// @dev Test 11: Manager signs over swapPerm. Before dispatch, permSigner revokes
    ///      swapPerm. Dispatch reverts PermissionNotRegistered(address(swapPerm)).
    function test_11_RegistrationRace_PermRevokedBeforeDispatch_Reverts() public {
        _configureSwap(address(safe));
        _registerPermission(address(swapPerm));

        bytes memory swapData = _buildSwapData(100e18, 100e18);
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));

        // Manager builds the sig (signed before revoke)
        bytes memory sig = _signDispatch(address(safe), address(swapPerm), UNI_ROUTER, 0, swapData, nonce, deadline);

        // permSigner revokes swapPerm before dispatch
        _revokePermission(address(swapPerm));
        assertFalse(kernel.isPermissionRegistered(address(safe), address(swapPerm)));

        // Dispatch should now fail
        vm.expectRevert(
            abi.encodeWithSelector(SailKernel.PermissionNotRegistered.selector, address(swapPerm))
        );
        kernel.dispatch(address(safe), address(swapPerm), UNI_ROUTER, 0, swapData, sig, deadline);
    }

    // =========================================================================
    // SECTION 5: BATCH DISPATCH BACKWARDS COMPAT
    // =========================================================================

    /// @dev Test 12: Deploy a simple allow-all IBatchPermission, register it, call
    ///      dispatchBatch → succeeds.
    function test_12_BatchDispatch_AllowAllPermission_Succeeds() public {
        AllowAllBatchPermission batchPerm = new AllowAllBatchPermission();

        // Register the batch permission (uses standard IPermission registry path)
        uint256 sigNonce = kernel.signerNonces(address(safe));
        uint256 regDeadline = block.timestamp + 1 days;
        bytes32 sh = keccak256(abi.encode(
            kernel.REGISTER_PERMISSION_TYPEHASH(), address(safe), address(batchPerm), sigNonce, regDeadline
        ));
        uint256 fee = gov.permissionRegistrationFee();
        kernel.registerPermission{value: fee}(address(safe), address(batchPerm), regDeadline, _signerSig(sh));
        assertTrue(kernel.isPermissionRegistered(address(safe), address(batchPerm)));

        // Build a minimal batch (one inert call to a random address)
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(0xDEAD), value: 0, data: hex""});

        uint256 batchNonce = kernel.batchNonces(address(safe));
        uint256 deadline   = block.timestamp + 1 hours;

        bytes32 callsHash = keccak256(abi.encode(calls));
        bytes32 batchSh = keccak256(abi.encode(
            kernel.DISPATCH_BATCH_TYPEHASH(),
            address(safe), address(batchPerm), callsHash, batchNonce, deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(MANAGER_KEY, kernel.hashTypedDataV4(batchSh));
        bytes memory mgrSig = abi.encodePacked(r, s, v);

        kernel.dispatchBatch(address(safe), address(batchPerm), calls, mgrSig, deadline);
        assertEq(kernel.batchNonces(address(safe)), batchNonce + 1, "batch nonce did not advance");
    }

    // =========================================================================
    // SECTION 6: EXISTING TEMPLATES STILL WORK
    // =========================================================================

    /// @dev Test 13a: SwapPermission — dispatch valid V3 swap.
    function test_13a_Template_Swap_Dispatches() public {
        _configureSwap(address(safe));
        _registerPermission(address(swapPerm));

        bytes memory data = _buildSwapData(100e18, 100e18);
        _dispatch(address(swapPerm), UNI_ROUTER, 0, data);
        assertEq(safe.callCount(), 1, "swap dispatch failed");
    }

    /// @dev Test 13b: BorrowPermission — dispatch valid Aave borrow.
    function test_13b_Template_Borrow_Dispatches() public {
        _configureBorrow(address(safe));
        _registerPermission(address(borrowPerm));

        bytes memory data = _buildBorrowData(500e18);
        _dispatch(address(borrowPerm), AAVE_POOL, 0, data);
        assertEq(safe.callCount(), 1, "borrow dispatch failed");
    }

    /// @dev Test 13c: TransferPermission — dispatch valid ERC20 transfer.
    function test_13c_Template_Transfer_Dispatches() public {
        _configureTransfer(address(safe));
        _registerPermission(address(transferPerm));

        bytes memory data = _buildTransferData(100e18);
        _dispatch(address(transferPerm), TRANSFER_TKN, 0, data);
        assertEq(safe.callCount(), 1, "transfer dispatch failed");
    }

    /// @dev Test 13d: SwapPermission via configureDirect — dispatch valid V3 swap.
    function test_13d_Template_SwapPermission_Dispatches() public {
        SwapPermission swap = new SwapPermission(address(kernel), address(0xA11CE));

        address[] memory routers   = new address[](1); routers[0]   = UNI_ROUTER;
        address[] memory tokensIn   = new address[](1); tokensIn[0]   = TOKEN_IN;
        address[] memory tokensOut  = new address[](1); tokensOut[0]  = TOKEN_OUT;
        uint256 maxAmountPerTx = 1_000e18;
        // SwapPermission requires an oracle; this routing test is not about the band, so use a
        // permissive 1:1 oracle with maximum tolerance and a min-out that clears the floor.
        MockOracle oracle = new MockOracle();
        oracle.set(TOKEN_IN, TOKEN_OUT, 1, 0);
        uint256 maxSlippageBps = 9_999;
        address priceOracle    = address(oracle);
        uint256 maxPriceAgeSec = 3600;

        bytes memory params = abi.encode(
            routers, tokensIn, tokensOut, maxAmountPerTx, maxSlippageBps, priceOracle, maxPriceAgeSec
        );

        // configureDirect reads the permissionSigner from the kernel; caller must be it.
        vm.prank(permSigner);
        swap.configureDirect(address(safe), params);

        _registerPermissionFor(address(swap));

        // Valid Uniswap V3 exactInputSingle; recipient MUST equal the account.
        bytes memory data = abi.encodeWithSelector(
            EXACT_INPUT_SINGLE_V1,
            TOKEN_IN, TOKEN_OUT, uint24(3000), address(safe),
            uint256(block.timestamp + 1 hours), uint256(100e18), uint256(100e18), uint160(0)
        );

        _dispatch(address(swap), UNI_ROUTER, 0, data);
        assertEq(safe.callCount(), 1, "swap dispatch failed");
    }

    // =========================================================================
    // SECTION 7: GAS BENCHMARK
    // =========================================================================

    /// @dev Test 14: Record gas for a single dispatch with one registered permission.
    function test_14_GasBenchmark_SingleDispatch() public {
        MockPermission mockPerm = new MockPermission();
        _registerPermissionFor(address(mockPerm));

        bytes memory data    = abi.encodeWithSignature("go()");
        uint256 deadline     = block.timestamp + 1 hours;
        uint256 nonce        = kernel.managerNonces(address(safe));
        bytes memory sig     = _signDispatch(address(safe), address(mockPerm), address(0xABCD), 0, data, nonce, deadline);

        uint256 gasBefore = gasleft();
        kernel.dispatch(address(safe), address(mockPerm), address(0xABCD), 0, data, sig, deadline);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("dispatch gas (1 permission)", gasUsed);
        assertEq(safe.callCount(), 1, "dispatch did not execute");
        // Sanity bound: should be well under 500k
        assertLt(gasUsed, 500_000, "gas unreasonably high");
    }

    // =========================================================================
    // Additional coverage: Dispatched event
    // =========================================================================

    /// @dev The new Dispatched event includes the `permission` field. Verify it fires correctly.
    function test_Dispatched_EventIncludesPermission() public {
        _configureSwap(address(safe));
        _registerPermission(address(swapPerm));

        bytes memory swapData = _buildSwapData(100e18, 100e18);
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), address(swapPerm), UNI_ROUTER, 0, swapData, nonce, deadline);

        vm.expectEmit(true, true, false, true);
        emit SailKernel.Dispatched(address(safe), address(swapPerm), UNI_ROUTER, EXACT_INPUT_SINGLE_V1, 0);
        kernel.dispatch(address(safe), address(swapPerm), UNI_ROUTER, 0, swapData, sig, deadline);
    }

    // =========================================================================
    // Internal helpers (not test functions)
    // =========================================================================

    /// @dev Register a permission using the standard permSigner sig flow.
    function _registerPermissionFor(address permission) internal {
        uint256 nonce = kernel.signerNonces(address(safe));
        uint256 deadline = block.timestamp + 1 days;
        bytes32 sh = keccak256(abi.encode(
            kernel.REGISTER_PERMISSION_TYPEHASH(), address(safe), permission, nonce, deadline
        ));
        uint256 fee = gov.permissionRegistrationFee();
        kernel.registerPermission{value: fee}(address(safe), permission, deadline, _signerSig(sh));
    }
}
