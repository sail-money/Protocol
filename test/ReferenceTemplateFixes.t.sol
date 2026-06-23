// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import {Context}         from "../contracts/interfaces/IPermission.sol";
import {IOracle}         from "../contracts/interfaces/IOracle.sol";
import {SwapPermission}   from "../contracts/templates/SwapPermission.sol";
import {BorrowPermission} from "../contracts/templates/BorrowPermission.sol";

/// @dev Minimal kernel view stub: every account is registered and this test contract
///      is the permissionSigner, so `configureDirect` is accepted.
contract MockKernelView {
    address public immutable signer;
    constructor(address _signer) { signer = _signer; }
    function registered(address) external pure returns (bool) { return true; }
    function configs(address)
        external
        view
        returns (address permissionSigner, address manager, address feePolicy, bool sessionActive)
    {
        return (signer, address(0), address(0), true);
    }
}

/// @dev Fixed-return oracle. updatedAt is always fresh (block.timestamp).
contract MockOracle is IOracle {
    uint256 internal immutable p;
    uint8   internal immutable d;
    constructor(uint256 _p, uint8 _d) { p = _p; d = _d; }
    function getPrice(address, address) external view returns (uint256, uint8, uint256) {
        return (p, d, block.timestamp);
    }
}

/// @notice Regression guards for the PR3 reference-template fixes:
///         - SwapPermission: with NO oracle, amountOutMin == 0 must be DENIED (was fail-open).
///         - BorrowPermission: a non-zero-decimals collateral oracle that previously let a borrow
///           slip under maxLtvBps (raw-colValue bug) must now correctly DENY.
///         Plus a basic author-attribution check.
contract ReferenceTemplateFixesTest is Test {
    bytes4 internal constant EXACT_INPUT_SINGLE_V1 = 0x414bf389;
    bytes4 internal constant COMPOUND_BORROW       = bytes4(keccak256("borrow(uint256)"));

    address internal constant AUTHOR  = address(0xA11CE);
    address internal constant ACCOUNT = address(0xACC0);
    address internal constant ROUTER  = address(0x9000);
    address internal constant TOKIN   = address(0x100);
    address internal constant TOKOUT  = address(0x200);

    MockKernelView internal kernel;
    SwapPermission  internal swap;
    BorrowPermission internal borrow;

    function setUp() public {
        kernel = new MockKernelView(address(this)); // this contract is the permissionSigner
        swap   = new SwapPermission(address(kernel), AUTHOR);
        borrow = new BorrowPermission(address(kernel), AUTHOR);
    }

    function _ctx(address target, bytes4 selector) internal view returns (Context memory c) {
        c = Context({
            account:        ACCOUNT,
            manager:        address(0),
            submitter:      address(0),
            target:         target,
            selector:       selector,
            value:          0,
            blockTimestamp: block.timestamp,
            blockNumber:    block.number
        });
    }

    // ── Author attribution ─────────────────────────────────────────────────────

    function test_Author_IsRecordedFromConstructorArg() public view {
        assertEq(swap.author(),   AUTHOR);
        assertEq(borrow.author(), AUTHOR);
    }

    // ── SwapPermission: no-oracle slippage fail-closed ──────────────────────────

    function _configureSwapNoOracle() internal {
        address[] memory routers   = new address[](1); routers[0]   = ROUTER;
        address[] memory tokensIn  = new address[](1); tokensIn[0]  = TOKIN;
        address[] memory tokensOut = new address[](1); tokensOut[0] = TOKOUT;
        bytes memory params = abi.encode(
            routers, tokensIn, tokensOut,
            uint256(1000 ether), // maxAmountPerTx
            uint256(0),          // maxSlippageBps
            address(0),          // priceOracle — none
            uint256(0)           // maxPriceAgeSec
        );
        swap.configureDirect(ACCOUNT, params);
    }

    function _swapCalldata(uint256 amountOutMin) internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            EXACT_INPUT_SINGLE_V1,
            TOKIN, TOKOUT, uint24(3000), ACCOUNT, uint256(block.timestamp + 1),
            uint256(1 ether), amountOutMin, uint160(0)
        );
    }

    function test_Swap_NoOracle_AmountOutMinZero_IsDenied() public {
        _configureSwapNoOracle();
        // amountOutMin == 0 with no oracle: previously fail-open (true); now must be DENIED.
        assertFalse(swap.evaluate(_swapCalldata(0), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    function test_Swap_NoOracle_AmountOutMinNonZero_IsAllowed() public {
        _configureSwapNoOracle();
        // A non-zero caller-supplied minimum-out passes the no-oracle guard.
        assertTrue(swap.evaluate(_swapCalldata(1), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    // ── BorrowPermission: collateral-decimals LTV fix ───────────────────────────

    function _configureBorrow(uint256 maxLtvBps, address colOracle, address borOracle) internal {
        address cToken = ROUTER; // reuse as the Compound cToken (target == asset for Compound)
        address[] memory protocols = new address[](1); protocols[0] = cToken;
        address[] memory assets    = new address[](1); assets[0]    = cToken;
        bytes memory params = abi.encode(
            protocols, assets,
            uint256(1000 ether), // maxAmountPerTx
            maxLtvBps,
            colOracle, borOracle,
            uint256(1 days)      // maxPriceAgeSec
        );
        borrow.configureDirect(ACCOUNT, params);
    }

    function test_Borrow_NonZeroDecimalsCollateral_AboveLtv_IsDenied() public {
        // collateral oracle reports 100 units at 18 decimals (colValue = 100e18, colDec = 18).
        // borrow oracle: price 1 at 0 decimals. Borrow amount 80.
        //   correct LTV = 80 * 10_000 / (100e18 / 1e18=100) = 8000 bps = 80%.
        //   buggy (raw colValue) = 80 * 10_000 / 100e18 ≈ 0 bps → would have passed.
        // With maxLtvBps = 7000 (70%), the FIX must DENY.
        MockOracle col = new MockOracle(100e18, 18);
        MockOracle bor = new MockOracle(1, 0);
        _configureBorrow(7000, address(col), address(bor));

        bytes memory data = abi.encodeWithSelector(COMPOUND_BORROW, uint256(80));
        assertFalse(borrow.evaluate(data, _ctx(ROUTER, COMPOUND_BORROW)));
    }

    function test_Borrow_NonZeroDecimalsCollateral_WithinLtv_IsAllowed() public {
        // Same setup; with maxLtvBps = 8000 the 80% borrow is exactly at the ceiling → allowed.
        MockOracle col = new MockOracle(100e18, 18);
        MockOracle bor = new MockOracle(1, 0);
        _configureBorrow(8000, address(col), address(bor));

        bytes memory data = abi.encodeWithSelector(COMPOUND_BORROW, uint256(80));
        assertTrue(borrow.evaluate(data, _ctx(ROUTER, COMPOUND_BORROW)));
    }
}
