// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "./support/FactoryTestBase.sol";
import "../contracts/templates/shared/SharedDeFiBundlePermission.sol";
import "../contracts/interfaces/IOracle.sol";

/// @dev Minimal price oracle for bundle LTV tests.
contract BundleTestOracle is IOracle {
    mapping(bytes32 => uint256) private _price;
    mapping(bytes32 => uint8)   private _dec;

    function set(address base, address quote, uint256 price, uint8 dec) external {
        bytes32 k = keccak256(abi.encode(base, quote));
        _price[k] = price;
        _dec[k]   = dec;
    }

    function getPrice(address base, address quote) external view returns (uint256, uint8, uint256) {
        bytes32 k = keccak256(abi.encode(base, quote));
        return (_price[k], _dec[k], block.timestamp);
    }
}

contract SharedDeFiBundlePermissionTest is FactoryTestBase {
    SharedDeFiBundlePermission internal bundle;
    BundleTestOracle            internal colOracle;
    BundleTestOracle            internal borOracle;

    address constant ROUTER   = address(0xE592);
    address constant AAVE     = address(0xA11E);
    address constant USDC     = address(0xDC01);
    address constant WETH     = address(0xE711);
    address constant BOB      = address(0xB0B0);
    address constant STRANGER = address(0x9999);

    bytes4 constant SEL_AAVE     = bytes4(keccak256("borrow(address,uint256,uint256,uint16,address)"));
    bytes4 constant SEL_V3_SWAP  = bytes4(0x414bf389);
    bytes4 constant SEL_TRANSFER = bytes4(0xa9059cbb);

    uint256 constant MAX_SWAP   = 10 ether;
    uint256 constant MAX_BORROW = 100_000e18;
    uint256 constant MAX_LTV    = 7_500; // 75%

    function setUp() public override {
        super.setUp();
        bundle    = new SharedDeFiBundlePermission(address(kernel));
        colOracle = new BundleTestOracle();
        borOracle = new BundleTestOracle();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    function _arr1(address a) internal pure returns (address[] memory r) {
        r = new address[](1); r[0] = a;
    }

    function _empty() internal pure returns (address[] memory) {
        return new address[](0);
    }

    function _ctx(address account, address target, bytes4 sel) internal view returns (Context memory) {
        return Context({
            account:        account,
            manager:        address(0),
            submitter:      address(0),
            target:         target,
            selector:       sel,
            value:          0,
            blockTimestamp: block.timestamp,
            blockNumber:    block.number
        });
    }

    function _defaultSwapCfg() internal view returns (SharedDeFiBundlePermission.SwapConfig memory) {
        return SharedDeFiBundlePermission.SwapConfig({
            routers:        _arr1(ROUTER),
            tokensIn:       _arr1(WETH),
            tokensOut:      _arr1(USDC),
            maxAmountPerTx: MAX_SWAP,
            maxSlippageBps: 0,
            priceOracle:    address(0)
        });
    }

    function _defaultBorrowCfg() internal view returns (SharedDeFiBundlePermission.BorrowConfig memory) {
        return SharedDeFiBundlePermission.BorrowConfig({
            protocols:        _arr1(AAVE),
            assets:           _arr1(USDC),
            maxAmountPerTx:   MAX_BORROW,
            maxLtvBps:        MAX_LTV,
            collateralOracle: address(colOracle),
            borrowOracle:     address(borOracle)
        });
    }

    function _defaultTransferCfg() internal view returns (SharedDeFiBundlePermission.TransferConfig memory) {
        return SharedDeFiBundlePermission.TransferConfig({
            recipients:     _arr1(BOB),
            tokens:         _arr1(USDC),
            maxAmountPerTx: type(uint256).max
        });
    }

    function _configureFull(
        address account,
        SharedDeFiBundlePermission.SwapConfig memory swapCfg,
        SharedDeFiBundlePermission.BorrowConfig memory borrowCfg,
        SharedDeFiBundlePermission.TransferConfig memory transferCfg
    ) internal {
        bytes memory params = abi.encode(swapCfg, borrowCfg, transferCfg);
        uint256 deadline    = block.timestamp + 1 hours;
        bytes memory sig    = _signConfigure(bundle, account, params, deadline, PERM_SIGNER_KEY);
        bundle.configure(account, params, deadline, sig);
    }

    function _configureDefault(address account) internal {
        // Standard price setup: colValue=10_000, borPrice=1, borDec=0
        colOracle.set(account, address(0), 10_000, 0);
        borOracle.set(USDC, address(0), 1, 0);
        _configureFull(account, _defaultSwapCfg(), _defaultBorrowCfg(), _defaultTransferCfg());
    }

    function _aave(address asset, uint256 amount, address onBehalf) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(SEL_AAVE, asset, amount, uint256(1), uint16(0), onBehalf);
    }

    function _v3Swap(
        address tokenIn, address tokenOut, address to, uint256 amountIn, uint256 amountOutMin
    ) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(
            SEL_V3_SWAP,
            tokenIn, tokenOut, uint24(3000), to, type(uint256).max,
            amountIn, amountOutMin, uint160(0)
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Configure
    // ─────────────────────────────────────────────────────────────────────────

    function test_Configure_StoresConfig() public {
        _configureDefault(address(safe));
        assertTrue(bundle.isSwapRouter(address(safe), ROUTER));
        assertFalse(bundle.isSwapRouter(address(safe), STRANGER));
        assertTrue(bundle.isBorrowProtocol(address(safe), AAVE));
        assertTrue(bundle.isBorrowAsset(address(safe), USDC));
        assertTrue(bundle.isTransferRecipient(address(safe), BOB));
        assertFalse(bundle.isTransferRecipient(address(safe), STRANGER));
        assertEq(bundle.getBorrowConfig(address(safe)).maxLtvBps, MAX_LTV);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Swap domain
    // ─────────────────────────────────────────────────────────────────────────

    function test_Swap_AllowedRouter_Permitted() public {
        _configureDefault(address(safe));
        bytes memory data = _v3Swap(WETH, USDC, address(safe), 1 ether, 0);
        assertTrue(bundle.evaluate(data, _ctx(address(safe), ROUTER, SEL_V3_SWAP)));
    }

    function test_Swap_BlockedRouter_Denied() public {
        _configureDefault(address(safe));
        bytes memory data = _v3Swap(WETH, USDC, address(safe), 1 ether, 0);
        assertFalse(bundle.evaluate(data, _ctx(address(safe), STRANGER, SEL_V3_SWAP)));
    }

    function test_Swap_OverAmountCap_Denied() public {
        _configureDefault(address(safe));
        bytes memory data = _v3Swap(WETH, USDC, address(safe), MAX_SWAP + 1, 0);
        assertFalse(bundle.evaluate(data, _ctx(address(safe), ROUTER, SEL_V3_SWAP)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Borrow domain — LTV check
    // ─────────────────────────────────────────────────────────────────────────

    function test_Borrow_WithinLtv_Permitted() public {
        _configureDefault(address(safe));
        // colValue=10_000, borPrice=1, borDec=0, amount=7_500 → LTV = 75% = cap → pass
        bytes memory data = _aave(USDC, 7_500, address(safe));
        assertTrue(bundle.evaluate(data, _ctx(address(safe), AAVE, SEL_AAVE)));
    }

    function test_Borrow_OverLtv_Denied() public {
        _configureDefault(address(safe));
        // amount = 7_501 → LTV = 75.01% > 75% cap → blocked
        bytes memory data = _aave(USDC, 7_501, address(safe));
        assertFalse(bundle.evaluate(data, _ctx(address(safe), AAVE, SEL_AAVE)));
    }

    function test_Borrow_ZeroCollateralPrice_Denied() public {
        // colValue = 0 (unset oracle) → fail-closed
        borOracle.set(USDC, address(0), 1, 0);
        _configureFull(address(safe), _defaultSwapCfg(), _defaultBorrowCfg(), _defaultTransferCfg());
        bytes memory data = _aave(USDC, 1, address(safe));
        assertFalse(bundle.evaluate(data, _ctx(address(safe), AAVE, SEL_AAVE)));
    }

    /// @dev Regression for Fix 2: borPrice == 0 must be fail-closed (return false),
    ///      not fail-open (return true) as in the original buggy implementation.
    function test_Borrow_ZeroBorrowPrice_Denied() public {
        colOracle.set(address(safe), address(0), 10_000, 0);
        // borOracle returns (0, 0) for USDC — zero price
        _configureFull(address(safe), _defaultSwapCfg(), _defaultBorrowCfg(), _defaultTransferCfg());
        bytes memory data = _aave(USDC, 1, address(safe));
        assertFalse(bundle.evaluate(data, _ctx(address(safe), AAVE, SEL_AAVE)),
            "Zero borrow price must block the borrow (fail-closed)");
    }

    /// @dev Regression for Fix 1: borrowScaled must divide by 10^borDec (18 decimals).
    ///      With borDec=18 and borPrice=1e18 ($1/token):
    ///        correct:   borrowScaled = 50e18 * 1e18 / 10^18 = 50e18 → LTV = 5000 bps → pass
    ///        buggy:     borrowScaled = 50e18 * 1e18 / 1      = 50e36 → LTV >> cap    → blocked
    function test_Borrow_DecimalNormalization_18Dec_Permitted() public {
        colOracle.set(address(safe), address(0), 100e18, 0);
        borOracle.set(USDC, address(0), 1e18, 18);
        _configureFull(address(safe), _defaultSwapCfg(), _defaultBorrowCfg(), _defaultTransferCfg());
        bytes memory data = _aave(USDC, 50e18, address(safe));
        assertTrue(bundle.evaluate(data, _ctx(address(safe), AAVE, SEL_AAVE)),
            "50% LTV with 18-dec price must pass with correct decimal normalization");
    }

    /// @dev Regression for Fix 1: borrowScaled must divide by 10^borDec (6 decimals).
    ///      colValue=100, borPrice=1e6 (=$1 at 6-dec), borDec=6, amount=50:
    ///        correct:   borrowScaled = 50 * 1e6 / 10^6 = 50 → LTV = 5000 bps → pass
    ///        buggy:     borrowScaled = 50 * 1e6 / 1    = 50e6 → LTV >> cap   → blocked
    function test_Borrow_DecimalNormalization_6Dec_Permitted() public {
        colOracle.set(address(safe), address(0), 100, 0);
        borOracle.set(USDC, address(0), 1_000_000, 6);
        _configureFull(address(safe), _defaultSwapCfg(), _defaultBorrowCfg(), _defaultTransferCfg());
        bytes memory data = _aave(USDC, 50, address(safe));
        assertTrue(bundle.evaluate(data, _ctx(address(safe), AAVE, SEL_AAVE)),
            "50% LTV with 6-dec price must pass with correct decimal normalization");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Transfer domain
    // ─────────────────────────────────────────────────────────────────────────

    function test_Transfer_AllowedRecipient_Permitted() public {
        _configureDefault(address(safe));
        bytes memory data = abi.encodeWithSelector(SEL_TRANSFER, BOB, uint256(100e6));
        assertTrue(bundle.evaluate(data, _ctx(address(safe), USDC, SEL_TRANSFER)));
    }

    function test_Transfer_BlockedRecipient_Denied() public {
        _configureDefault(address(safe));
        bytes memory data = abi.encodeWithSelector(SEL_TRANSFER, STRANGER, uint256(100e6));
        assertFalse(bundle.evaluate(data, _ctx(address(safe), USDC, SEL_TRANSFER)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Multi-account isolation
    // ─────────────────────────────────────────────────────────────────────────

    function test_MultiAccount_SafeB_NotAffectedBySafeA_Config() public {
        // Register a second Safe
        MockSafe safeB = new MockSafe();
        vm.deal(address(safeB), 100 ether);
        vm.prank(address(safeB));
        kernel.registerAccount(permSigner, manager, address(0));

        // Configure bundle for Safe A only
        _configureDefault(address(safe));

        // Safe B has no config — swap router from Safe A's config must not bleed through
        bytes memory swapData = _v3Swap(WETH, USDC, address(safeB), 1 ether, 0);
        assertFalse(bundle.evaluate(swapData, _ctx(address(safeB), ROUTER, SEL_V3_SWAP)),
            "Safe B must not inherit Safe A's router allowlist");

        // Safe B borrow path also denied — no protocols in config
        bytes memory borrowData = _aave(USDC, 1, address(safeB));
        assertFalse(bundle.evaluate(borrowData, _ctx(address(safeB), AAVE, SEL_AAVE)),
            "Safe B must not inherit Safe A's borrow protocol allowlist");
    }
}
