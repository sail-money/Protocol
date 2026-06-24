// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "../contracts/core/SailKernel.sol";
import "../contracts/governance/SailGovernance.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {TimelockDeployer} from "./support/TimelockDeployer.sol";
import {SwapPermission} from "../contracts/templates/SwapPermission.sol";
import {IOracle} from "../contracts/interfaces/IOracle.sol";
import "../contracts/policies/StandardFeePolicy.sol";

// ─────────────────────────────────────────────────────────────────────────────
// MockOracle — permissive 1:1 reference (price 1, 0 decimals, always fresh). These
// integration tests exercise dispatch/fee mechanics, not the slippage band, so the
// band is configured at maximum tolerance and every swap clears it trivially.
// ─────────────────────────────────────────────────────────────────────────────
contract MockOracle is IOracle {
    function getPrice(address, address) external view returns (uint256, uint8, uint256) {
        return (1, 0, block.timestamp);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MockSafe — records every execTransactionFromModule call; forwards ETH
// transfers (value > 0, empty data) so fee splits land in real balances.
// ─────────────────────────────────────────────────────────────────────────────
contract MockSafe {
    struct Call {
        address to;
        uint256 value;
        bytes   data;
        uint8   operation;
    }

    Call[] private _calls;

    receive() external payable {}

    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation
    ) external returns (bool) {
        _calls.push(Call({to: to, value: value, data: data, operation: operation}));
        // Forward ETH for fee-split transfers (value present, no calldata).
        if (value > 0 && data.length == 0) {
            (bool ok,) = payable(to).call{value: value}("");
            return ok;
        }
        return true;
    }

    function callCount() external view returns (uint256) { return _calls.length; }

    function getCall(uint256 i) external view returns (address, uint256, bytes memory, uint8) {
        Call storage c = _calls[i];
        return (c.to, c.value, c.data, c.operation);
    }

    function isModuleEnabled(address) external pure returns (bool) { return true; }
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration test
// ─────────────────────────────────────────────────────────────────────────────
contract IntegrationTest is Test {
    // ── signing keys ─────────────────────────────────────────────────────────
    uint256 constant PERM_SIGNER_KEY = 0xA11CE;
    uint256 constant MANAGER_KEY     = 0xB0B;

    // ── well-known addresses ──────────────────────────────────────────────────
    address constant TREASURY          = address(0xAAAA);
    address constant DEAD              = address(0xDEAD);   // distributor
    address constant MANAGER_RECIPIENT = address(0xBBBB);
    address constant ROUTER            = address(0xCC01);
    address constant WETH              = address(0xCC02);
    address constant USDC              = address(0xCC03);
    address constant WBTC              = address(0xCC04);   // not on allowlist
    address constant FEE_MANAGER       = address(0xDD01);
    address constant EMERGENCY_ADMIN   = address(0xEEEE);

    // ── governance / fee parameters ───────────────────────────────────────────
    uint256 constant BASE_FEE           = 0.001 ether;
    uint256 constant MAX_PERM_FEE       = 0.001 ether;
    uint256 constant PROTOCOL_CUT_BPS   = 1_000;     // 10%
    uint256 constant MGMT_BPS           = 200;        // 2% annual
    uint256 constant PERF_BPS           = 2_000;      // 20%
    uint256 constant DIST_BPS           = 500;        // 5% of manager remainder

    uint256 constant T0 = 1_000_000;                  // non-zero genesis timestamp

    // ── deployed stack ────────────────────────────────────────────────────────
    SailGovernance       gov;
    SailKernel           kernel;
    MockSafe             mockSafe;
    SwapPermission       swap;
    StandardFeePolicy    feePolicy;

    // ── derived from keys ─────────────────────────────────────────────────────
    address permSigner;
    address manager;

    // ─────────────────────────────────────────────────────────────────────────
    // setUp — deploys and wires the full protocol stack
    // ─────────────────────────────────────────────────────────────────────────
    function setUp() public {
        permSigner = vm.addr(PERM_SIGNER_KEY);
        manager    = vm.addr(MANAGER_KEY);

        vm.warp(T0);
        vm.deal(address(this), 10 ether); // enough to pay registration fees

        // 1. Governance (test contract is initial governance)
        gov = new SailGovernance(address(this), MAX_PERM_FEE, EMERGENCY_ADMIN, 0, TimelockDeployer.deploy(address(this)));
        _govExec(abi.encodeCall(gov.setProtocolCutBps, (PROTOCOL_CUT_BPS)));
        _govExec(abi.encodeCall(gov.setPermissionRegistrationFee, (BASE_FEE)));
        vm.warp(T0); // reset after timelock warps so fee policy timestamps anchor at T0

        // 2. Kernel
        kernel = new SailKernel(address(gov), TREASURY);

        // 3. MockSafe
        mockSafe = new MockSafe();
        vm.deal(address(mockSafe), 100 ether); // ETH for fee-split transfers

        // registerAccount requires the caller's codehash to be allowlisted (Octane #4a).
        // All MockSafe instances share this codehash, so one seed covers safe2 etc.
        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeProxyCodehash(address(mockSafe).codehash, true);

        // 4. SwapPermission: shared multi-account deployment (config applied per-account
        //    after registration, below)
        address[] memory routers   = _arr1(ROUTER);
        address[] memory tokensIn  = _arr1(WETH);
        address[] memory tokensOut = _arr1(USDC);
        swap = new SwapPermission(address(kernel), address(0xA11CE));

        // 5. StandardFeePolicy: 2% mgmt / 20% perf / DEAD distributor / 5% dist share
        feePolicy = new StandardFeePolicy(
            MGMT_BPS, PERF_BPS, DEAD, DIST_BPS, address(kernel), FEE_MANAGER
        );
        vm.prank(address(gov.timelock()));
        gov.setTrustedFeePolicy(address(feePolicy), true);

        // 6. Register MockSafe with the kernel (must be called by the Safe itself)
        vm.prank(address(mockSafe));
        kernel.registerAccount(permSigner, manager, address(feePolicy), address(0));

        // 6b. Configure SwapPermission for this account: only ROUTER, WETH→USDC, 10 ETH cap.
        //     SwapPermission now requires an oracle; these dispatch/fee tests are not about the
        //     band, so use a permissive 1:1 oracle at maximum tolerance (full 7-field config).
        //     Must run after registerAccount (reads kernel.configs) and be sent by permissionSigner.
        MockOracle oracle = new MockOracle();
        vm.prank(permSigner);
        swap.configureDirect(
            address(mockSafe),
            abi.encode(routers, tokensIn, tokensOut, 10 ether, 9_999, address(oracle), uint256(3600))
        );

        // 7. Register SwapPermission (pays exact fee)
        uint256 fee = _calcFee(address(swap));
        uint256 regDeadline = block.timestamp + 1 days;
        kernel.registerPermission{value: fee}(
            address(mockSafe), address(swap), regDeadline,
            _signRegisterPermission(address(mockSafe), address(swap), 0, regDeadline)
        );

        // 8. Initialise fee policy: feeManager seeds HWM first (H-5 fix), then first collectFees
        vm.prank(FEE_MANAGER);
        feePolicy.seedHighWaterMark(address(mockSafe), 100 ether);
        // DELETED: zero-fee initial collectFees no longer needed; seedHighWaterMark now sets lastCollectionTimestamp
    }

    receive() external payable {} // accept refunds from registerPermission

    uint256 private _saltNonce;

    function _govExec(bytes memory data) internal {
        TimelockController tl = gov.timelock();
        bytes32 salt = bytes32(_saltNonce++);
        tl.schedule(address(gov), 0, data, bytes32(0), salt, 48 hours);
        vm.warp(block.timestamp + 48 hours + 1);
        tl.execute(address(gov), 0, data, bytes32(0), salt);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1 — Per-permission deployment fee against real bytecode
    // ─────────────────────────────────────────────────────────────────────────

    function test_Fee_CalculationIsFlatFee() public view {
        assertEq(_calcFee(address(swap)), BASE_FEE);
    }

    function test_Fee_ExactPaymentSucceeds() public {
        // Fresh account for a clean signerNonce
        MockSafe safe2 = new MockSafe();
        vm.prank(address(safe2));
        kernel.registerAccount(permSigner, manager, address(feePolicy), address(0));

        uint256 fee = _calcFee(address(swap));
        uint256 treasuryBefore = TREASURY.balance;
        uint256 regDeadline = block.timestamp + 1 days;

        kernel.registerPermission{value: fee}(
            address(safe2), address(swap), regDeadline,
            _signRegisterPermission(address(safe2), address(swap), 0, regDeadline)
        );

        assertTrue(kernel.isPermissionRegistered(address(safe2), address(swap)));
        assertEq(TREASURY.balance - treasuryBefore, fee, "treasury must receive exactly fee");
    }

    function test_Fee_InsufficientFeeReverts() public {
        MockSafe safe2 = new MockSafe();
        vm.prank(address(safe2));
        kernel.registerAccount(permSigner, manager, address(feePolicy), address(0));

        uint256 fee = _calcFee(address(swap));
        uint256 regDeadline = block.timestamp + 1 days;
        bytes memory sig = _signRegisterPermission(address(safe2), address(swap), 0, regDeadline);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.InsufficientFee.selector, fee, fee - 1));
        kernel.registerPermission{value: fee - 1}(address(safe2), address(swap), regDeadline, sig);
    }

    function test_Fee_ExcessRefundedToCaller() public {
        MockSafe safe2 = new MockSafe();
        vm.prank(address(safe2));
        kernel.registerAccount(permSigner, manager, address(feePolicy), address(0));

        uint256 fee = _calcFee(address(swap));
        uint256 overpay = fee + 1 ether;
        uint256 regDeadline = block.timestamp + 1 days;

        uint256 balBefore = address(this).balance;
        kernel.registerPermission{value: overpay}(
            address(safe2), address(swap), regDeadline,
            _signRegisterPermission(address(safe2), address(swap), 0, regDeadline)
        );

        // Caller paid `overpay`, should have had `1 ether` refunded → net cost = fee
        assertEq(balBefore - address(this).balance, fee, "excess must be refunded");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2 — Account setup
    // ─────────────────────────────────────────────────────────────────────────

    function test_AccountSetup_PermissionRegistered() public view {
        assertTrue(kernel.isPermissionRegistered(address(mockSafe), address(swap)));
        assertEq(kernel.getPermissions(address(mockSafe)).length, 1);
        assertEq(kernel.getPermissions(address(mockSafe))[0], address(swap));
    }

    function test_AccountSetup_FeePolicySet() public view {
        (,, address fp,,) = kernel.configs(address(mockSafe));
        assertEq(fp, address(feePolicy));
    }

    function test_AccountSetup_ManagerAndSignerSet() public view {
        (address ps, address mgr,,, bool active) = kernel.configs(address(mockSafe));
        assertEq(ps, permSigner);
        assertEq(mgr, manager);
        assertTrue(active);
        assertTrue(kernel.registered(address(mockSafe)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3 — Manager dispatch
    // ─────────────────────────────────────────────────────────────────────────

    function test_Dispatch_GoldenPath() public {
        bytes memory swapData = _v3Swap(WETH, USDC, address(mockSafe), 1 ether, 1 ether);
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(mockSafe));
        bytes memory sig = _signDispatch(address(mockSafe), address(swap), ROUTER, 0, swapData, nonce, deadline);

        kernel.dispatch(address(mockSafe), address(swap), ROUTER, 0, swapData, sig, deadline);

        // MockSafe must have received exactly one call with the swap calldata
        assertEq(mockSafe.callCount(), 1);
        (address to, uint256 val, bytes memory data,) = mockSafe.getCall(0);
        assertEq(to, ROUTER);
        assertEq(val, 0);
        assertEq(data, swapData);
    }

    function test_Dispatch_WrongRouter_Reverts() public {
        address badRouter = address(0xBAD1);
        bytes memory swapData = _v3Swap(WETH, USDC, address(mockSafe), 1 ether, 1 ether);
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(mockSafe));
        bytes memory sig = _signDispatch(address(mockSafe), address(swap), badRouter, 0, swapData, nonce, deadline);

        // BoundedSwapPermission: isAllowedRouter[badRouter] = false → PermissionDenied
        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(swap)));
        kernel.dispatch(address(mockSafe), address(swap), badRouter, 0, swapData, sig, deadline);
    }

    function test_Dispatch_WrongTokenIn_Reverts() public {
        bytes memory swapData = _v3Swap(WBTC, USDC, address(mockSafe), 1 ether, 1);
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(mockSafe));
        bytes memory sig = _signDispatch(address(mockSafe), address(swap), ROUTER, 0, swapData, nonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(swap)));
        kernel.dispatch(address(mockSafe), address(swap), ROUTER, 0, swapData, sig, deadline);
    }

    function test_Dispatch_WrongTokenOut_Reverts() public {
        bytes memory swapData = _v3Swap(WETH, WBTC, address(mockSafe), 1 ether, 1);
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(mockSafe));
        bytes memory sig = _signDispatch(address(mockSafe), address(swap), ROUTER, 0, swapData, nonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(swap)));
        kernel.dispatch(address(mockSafe), address(swap), ROUTER, 0, swapData, sig, deadline);
    }

    function test_Dispatch_WrongRecipient_Reverts() public {
        address badRecipient = address(0xBAD2);
        bytes memory swapData = _v3Swap(WETH, USDC, badRecipient, 1 ether, 1);
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(mockSafe));
        bytes memory sig = _signDispatch(address(mockSafe), address(swap), ROUTER, 0, swapData, nonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(swap)));
        kernel.dispatch(address(mockSafe), address(swap), ROUTER, 0, swapData, sig, deadline);
    }

    function test_Dispatch_Replay_Reverts() public {
        bytes memory swapData = _v3Swap(WETH, USDC, address(mockSafe), 1 ether, 1 ether);
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(mockSafe));
        bytes memory sig = _signDispatch(address(mockSafe), address(swap), ROUTER, 0, swapData, nonce, deadline);

        // First dispatch: succeeds (nonce = 0 → now 1)
        kernel.dispatch(address(mockSafe), address(swap), ROUTER, 0, swapData, sig, deadline);

        // Replay with stale nonce-0 signature → digest mismatch
        vm.expectRevert(SailKernel.InvalidManagerSignature.selector);
        kernel.dispatch(address(mockSafe), address(swap), ROUTER, 0, swapData, sig, deadline);
    }

    function test_Dispatch_RevokePermission_BlocksAllDispatch() public {
        // signerNonce = 1 after setUp's registerPermission
        uint256 sigNonce = kernel.signerNonces(address(mockSafe));
        uint256 revokeDeadline = block.timestamp + 1 days;
        kernel.revokePermission(
            address(mockSafe), address(swap), revokeDeadline,
            _signRevokePermission(address(mockSafe), address(swap), sigNonce, revokeDeadline)
        );
        assertEq(kernel.getPermissions(address(mockSafe)).length, 0);

        // After revocation _permissionIndex[account][swap] == 0, so PermissionNotRegistered fires
        bytes memory swapData = _v3Swap(WETH, USDC, address(mockSafe), 1 ether, 1 ether);
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(mockSafe));
        bytes memory sig = _signDispatch(address(mockSafe), address(swap), ROUTER, 0, swapData, nonce, deadline);

        vm.expectRevert(
            abi.encodeWithSelector(SailKernel.PermissionNotRegistered.selector, address(swap))
        );
        kernel.dispatch(address(mockSafe), address(swap), ROUTER, 0, swapData, sig, deadline);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 4 — Fee collection end-to-end with exact math
    //
    // setUp seeded HWM = 100 ether at T0.
    // After 365 days with currentNav = 120 ether:
    //   managementFee = 120e18 * 200 / 10_000              = 2.4 ether
    //   performanceFee = (120-100)e18 * 2000 / 10_000      = 4.0 ether
    //   grossFee                                            = 6.4 ether
    //   protocolCut   = 6.4e18 * 1000 / 10_000             = 0.64 ether
    //   remainder                                           = 5.76 ether
    //   distributorCut = 5.76e18 * 500 / 10_000            = 0.288 ether
    //   managerTake                                         = 5.472 ether
    // ─────────────────────────────────────────────────────────────────────────

    uint256 constant GROSS_FEE        = 6_400_000_000_000_000_000;  // 6.4 ether
    uint256 constant PROTOCOL_CUT_AMT = 640_000_000_000_000_000;    // 0.64 ether
    uint256 constant DIST_CUT_AMT     = 288_000_000_000_000_000;    // 0.288 ether
    uint256 constant MANAGER_TAKE_AMT = 5_472_000_000_000_000_000;  // 5.472 ether

    function test_FeeCollection_ComputeFeeExactMath() public {
        vm.warp(T0 + 365 days);
        (uint256 grossFee, address dist, uint256 distBps) =
            feePolicy.computeFee(address(mockSafe), 120 ether);

        assertEq(grossFee, GROSS_FEE,   "grossFee mismatch");
        assertEq(dist,     DEAD,        "distributor mismatch");
        assertEq(distBps,  DIST_BPS,    "distributorBps mismatch");
    }

    function test_FeeCollection_SplitsLandInCorrectWallets() public {
        vm.warp(T0 + 365 days);

        uint256 treasuryBefore   = TREASURY.balance;
        uint256 deadBefore       = DEAD.balance;
        uint256 feeManagerBefore = FEE_MANAGER.balance;

        vm.prank(manager);
        kernel.collectFees(address(mockSafe), GROSS_FEE, 120 ether, address(0));

        assertEq(TREASURY.balance   - treasuryBefore,  PROTOCOL_CUT_AMT, "protocol cut mismatch");
        assertEq(DEAD.balance       - deadBefore,       DIST_CUT_AMT,     "distributor cut mismatch");
        assertEq(FEE_MANAGER.balance - feeManagerBefore, MANAGER_TAKE_AMT, "manager take mismatch");
    }

    function test_FeeCollection_HWMRatchetsUp() public {
        vm.warp(T0 + 365 days);
        vm.prank(manager);
        kernel.collectFees(address(mockSafe), GROSS_FEE, 120 ether, address(0));

        assertEq(feePolicy.highWaterMark(address(mockSafe)), 120 ether);
        assertEq(feePolicy.lastCollectionTimestamp(address(mockSafe)), T0 + 365 days);
    }

    function test_FeeCollection_SecondYear_ManagementFeeOnly() public {
        // First collection: grossFee = 6.4 ether, HWM → 120 ether
        vm.warp(T0 + 365 days);
        vm.prank(manager);
        kernel.collectFees(address(mockSafe), GROSS_FEE, 120 ether, address(0));

        // Second year: currentNav still 120 ether (at the new HWM)
        vm.warp(T0 + 730 days);
        (uint256 grossFee,,) = feePolicy.computeFee(address(mockSafe), 120 ether);

        // Only management fee: 120 ether × 2% = 2.4 ether; performance fee = 0
        uint256 expectedMgmt = 120 ether * MGMT_BPS / 10_000; // 2.4 ether
        assertEq(grossFee, expectedMgmt, "second-year should have management fee only");

        // Confirm performance component is zero by verifying nav == hwm
        assertEq(feePolicy.highWaterMark(address(mockSafe)), 120 ether);
    }

    function test_FeeCollection_OvercollectReverts() public {
        vm.warp(T0 + 365 days);
        uint256 tooBig = GROSS_FEE + 1;

        vm.prank(manager);
        vm.expectRevert(abi.encodeWithSelector(SailKernel.FeeTooLarge.selector, tooBig, GROSS_FEE));
        kernel.collectFees(address(mockSafe), tooBig, 120 ether, address(0));
    }

    function test_FeeCollection_RecordDepositAccumulatesPrincipal() public {
        vm.prank(permSigner);
        kernel.recordDeposit(address(mockSafe), 100 ether);
        assertEq(kernel.cumulativeDeposits(address(mockSafe)), 100 ether);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 5 — Session revocation blocks all dispatch
    // ─────────────────────────────────────────────────────────────────────────

    function test_SessionRevoke_BlocksAllDispatch() public {
        uint256 sigNonce = kernel.signerNonces(address(mockSafe));
        uint256 sessionDeadline = block.timestamp + 1 days;
        kernel.revokeSession(
            address(mockSafe), sessionDeadline,
            _signRevokeSession(address(mockSafe), sigNonce, sessionDeadline)
        );

        assertFalse(_sessionActive(address(mockSafe)));

        bytes memory swapData = _v3Swap(WETH, USDC, address(mockSafe), 1 ether, 1 ether);
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(mockSafe));
        bytes memory sig = _signDispatch(address(mockSafe), address(swap), ROUTER, 0, swapData, nonce, deadline);

        vm.expectRevert(
            abi.encodeWithSelector(SailKernel.SessionInactive.selector, address(mockSafe))
        );
        kernel.dispatch(address(mockSafe), address(swap), ROUTER, 0, swapData, sig, deadline);
    }

    function test_SessionRevoke_AlreadyValidSwapNowBlocked() public {
        // First confirm the swap works
        bytes memory swapData = _v3Swap(WETH, USDC, address(mockSafe), 1 ether, 1 ether);
        {
            uint256 deadline = block.timestamp + 1 hours;
            uint256 nonce    = kernel.managerNonces(address(mockSafe));
            bytes memory sig = _signDispatch(address(mockSafe), address(swap), ROUTER, 0, swapData, nonce, deadline);
            kernel.dispatch(address(mockSafe), address(swap), ROUTER, 0, swapData, sig, deadline);
        }

        // Revoke the session
        uint256 sigNonce = kernel.signerNonces(address(mockSafe));
        uint256 sessionDeadline2 = block.timestamp + 1 days;
        kernel.revokeSession(
            address(mockSafe), sessionDeadline2,
            _signRevokeSession(address(mockSafe), sigNonce, sessionDeadline2)
        );

        // Same swap (with fresh nonce) now reverts
        uint256 deadline2 = block.timestamp + 1 hours;
        uint256 nonce2    = kernel.managerNonces(address(mockSafe));
        bytes memory sig2 = _signDispatch(address(mockSafe), address(swap), ROUTER, 0, swapData, nonce2, deadline2);

        vm.expectRevert(
            abi.encodeWithSelector(SailKernel.SessionInactive.selector, address(mockSafe))
        );
        kernel.dispatch(address(mockSafe), address(swap), ROUTER, 0, swapData, sig2, deadline2);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    function _calcFee(address) internal view returns (uint256) {
        return gov.permissionRegistrationFee();
    }

    function _signRegisterPermission(address account, address permission, uint256 nonce, uint256 deadline)
        internal view returns (bytes memory)
    {
        bytes32 sh = keccak256(abi.encode(
            kernel.REGISTER_PERMISSION_TYPEHASH(), account, permission, nonce, deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PERM_SIGNER_KEY, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }

    function _signRevokePermission(address account, address permission, uint256 nonce, uint256 deadline)
        internal view returns (bytes memory)
    {
        bytes32 sh = keccak256(abi.encode(
            kernel.REVOKE_PERMISSION_TYPEHASH(), account, permission, nonce, deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PERM_SIGNER_KEY, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }

    function _signRevokeSession(address account, uint256 nonce, uint256 deadline)
        internal view returns (bytes memory)
    {
        bytes32 sh = keccak256(abi.encode(
            kernel.REVOKE_SESSION_TYPEHASH(), account, nonce, deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PERM_SIGNER_KEY, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
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
            kernel.DISPATCH_TYPEHASH(), account, permission, target, value, keccak256(data), nonce, deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(MANAGER_KEY, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }

    /// @dev Encodes a Uniswap V3 exactInputSingle payload (260 bytes including selector).
    function _v3Swap(
        address tokenIn,
        address tokenOut,
        address recipient,
        uint256 amountIn,
        uint256 amountOutMin
    ) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(
            bytes4(0x414bf389), // exactInputSingle selector
            tokenIn,
            tokenOut,
            uint24(3000),
            recipient,
            type(uint256).max, // swap deadline — not checked by BoundedSwapPermission
            amountIn,
            amountOutMin,
            uint160(0)         // sqrtPriceLimitX96
        );
    }

    function _arr1(address a) internal pure returns (address[] memory arr) {
        arr = new address[](1);
        arr[0] = a;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // configs() struct accessor helper (named fields via destructuring)
    // ─────────────────────────────────────────────────────────────────────────

    function _sessionActive(address account) internal view returns (bool) {
        (,,,, bool active) = kernel.configs(account);
        return active;
    }
}
