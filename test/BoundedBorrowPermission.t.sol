// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {BoundedBorrowPermission} from "../contracts/templates/BoundedBorrowPermission.sol";
import {IOracle} from "../contracts/interfaces/IOracle.sol";
import {Context} from "../contracts/interfaces/IPermission.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

// ─────────────────────────────────────────────────────────────────────────────
// Mocks
// ─────────────────────────────────────────────────────────────────────────────

contract BorrowMockOracle is IOracle {
    struct PriceData { uint256 price; uint8 decimals; }
    mapping(address => mapping(address => PriceData)) private _prices;

    function setPrice(address base, address quote, uint256 price, uint8 dec) external {
        _prices[base][quote] = PriceData(price, dec);
    }

    function getPrice(address base, address quote) external view returns (uint256 price, uint8 decimals) {
        PriceData memory pd = _prices[base][quote];
        return (pd.price, pd.decimals);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test harness
// ─────────────────────────────────────────────────────────────────────────────

contract BoundedBorrowPermissionTest is Test {
    BoundedBorrowPermission perm;
    BorrowMockOracle        colOracle;
    BorrowMockOracle        borOracle;

    address constant SAFE      = address(0x5AFE);
    address constant AAVE      = address(0xA11E);
    address constant MORPHO    = address(0xA10F);
    address constant COMPOUND  = address(0xC011); // also used as cToken for Compound
    address constant USDC      = address(0xDC01);
    address constant WETH      = address(0xE711);
    address constant SIGNER    = address(0x5161);
    address constant STRANGER  = address(0x9999);

    uint256 constant MAX_AMOUNT = 10_000e18;
    uint256 constant MAX_LTV    = 7_500; // 75%

    // Oracle constants: raw values (dec=0 for simplicity in most tests)
    // collateral = 100 units, borrow price = 1 unit per token
    // → at 100 tokens: LTV = 100*1/100 = 100% → blocked
    // → at 75 tokens:  LTV = 75*1/100  = 75%  → exactly at cap
    // → at 74 tokens:  LTV = 74*1/100  = 74%  → passes
    uint256 constant COL_VALUE  = 100;
    uint256 constant BOR_PRICE  = 1;

    bytes4 constant SEL_AAVE     = bytes4(keccak256("borrow(address,uint256,uint256,uint16,address)"));
    bytes4 constant SEL_MORPHO   = bytes4(keccak256("borrow(address,uint256,address,address)"));
    bytes4 constant SEL_COMPOUND = bytes4(keccak256("borrow(uint256)"));

    // ── setup ─────────────────────────────────────────────────────────────────

    function setUp() public {
        colOracle = new BorrowMockOracle();
        borOracle = new BorrowMockOracle();

        // Collateral oracle: account → (100, 0)
        colOracle.setPrice(SAFE, address(0), COL_VALUE, 0);
        // Borrow oracle: USDC → (1, 0), WETH → (2, 0)
        borOracle.setPrice(USDC, address(0), BOR_PRICE, 0);
        borOracle.setPrice(WETH, address(0), 2, 0);
        // Compound cToken: same as COMPOUND address
        borOracle.setPrice(COMPOUND, address(0), BOR_PRICE, 0);

        address[] memory protocols = _arr3(AAVE, MORPHO, COMPOUND);
        address[] memory assets    = _arr3(USDC, WETH, COMPOUND);

        perm = new BoundedBorrowPermission(
            protocols, assets,
            MAX_AMOUNT, MAX_LTV,
            address(colOracle), address(borOracle),
            SIGNER
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    function _arr1(address a) internal pure returns (address[] memory r) {
        r = new address[](1); r[0] = a;
    }

    function _arr2(address a, address b) internal pure returns (address[] memory r) {
        r = new address[](2); r[0] = a; r[1] = b;
    }

    function _arr3(address a, address b, address c) internal pure returns (address[] memory r) {
        r = new address[](3); r[0] = a; r[1] = b; r[2] = c;
    }

    function _aave(
        address asset,
        uint256 amount,
        address onBehalfOf
    ) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(SEL_AAVE, asset, amount, uint256(1), uint16(0), onBehalfOf);
    }

    function _morpho(
        address asset,
        uint256 amount,
        address onBehalf,
        address receiver
    ) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(SEL_MORPHO, asset, amount, onBehalf, receiver);
    }

    function _compound(uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(SEL_COMPOUND, amount);
    }

    function _ctx(address target, bytes4 sel) internal pure returns (Context memory) {
        return Context({account: SAFE, manager: address(0), target: target, selector: sel, value: 0});
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────────────

    function test_Constructor_SetsValues() public view {
        assertEq(perm.permissionSigner(), SIGNER);
        assertEq(perm.maxAmountPerTx(),   MAX_AMOUNT);
        assertEq(perm.maxLtvBps(),        MAX_LTV);
        assertEq(perm.collateralOracle(), address(colOracle));
        assertEq(perm.borrowOracle(),     address(borOracle));
    }

    function test_Constructor_RegistersAllowlists() public view {
        assertTrue(perm.isAllowedProtocol(AAVE));
        assertTrue(perm.isAllowedProtocol(MORPHO));
        assertTrue(perm.isAllowedProtocol(COMPOUND));
        assertTrue(perm.isAllowedAsset(USDC));
        assertTrue(perm.isAllowedAsset(WETH));
        assertTrue(perm.isAllowedAsset(COMPOUND));
        assertFalse(perm.isAllowedProtocol(STRANGER));
        assertFalse(perm.isAllowedAsset(STRANGER));
    }

    function test_Constructor_RevertsZeroSigner() public {
        address[] memory e = new address[](0);
        vm.expectRevert(BoundedBorrowPermission.ZeroAddress.selector);
        new BoundedBorrowPermission(e, e, 0, 0, address(0), address(0), address(0));
    }

    function test_Constructor_RevertsLtvAboveCap() public {
        address[] memory e = new address[](0);
        vm.expectRevert(abi.encodeWithSelector(BoundedBorrowPermission.LtvBpsTooLarge.selector, 10_001));
        new BoundedBorrowPermission(e, e, 0, 10_001, address(0), address(0), SIGNER);
    }

    function test_Constructor_AtExactMaxLtv() public {
        address[] memory e = new address[](0);
        BoundedBorrowPermission p = new BoundedBorrowPermission(e, e, 0, 10_000, address(0), address(0), SIGNER);
        assertEq(p.maxLtvBps(), 10_000);
    }

    function test_Constructor_NoOracles() public {
        address[] memory e = new address[](0);
        BoundedBorrowPermission p = new BoundedBorrowPermission(e, e, MAX_AMOUNT, MAX_LTV, address(0), address(0), SIGNER);
        assertEq(p.collateralOracle(), address(0));
        assertEq(p.borrowOracle(),     address(0));
    }

    function test_Discriminator() public view {
        assertEq(perm.discriminator(), keccak256("BoundedBorrowPermission"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Aave V3 borrow — golden paths
    // ─────────────────────────────────────────────────────────────────────────

    function test_Aave_GoldenPath() public view {
        // borrow 50 USDC: LTV = 50*1/100 = 50% < 75% → pass
        bytes memory data = _aave(USDC, 50, SAFE);
        assertTrue(perm.evaluate(data, _ctx(AAVE, SEL_AAVE)));
    }

    function test_Aave_ExactlyAtAmountCap() public {
        // MAX_AMOUNT borrow, colOracle must be set high enough
        // Skip LTV by deploying no-oracle perm
        address[] memory protocols = _arr1(AAVE);
        address[] memory assets    = _arr1(USDC);
        BoundedBorrowPermission p = new BoundedBorrowPermission(
            protocols, assets, MAX_AMOUNT, MAX_LTV, address(0), address(0), SIGNER
        );
        bytes memory data = _aave(USDC, MAX_AMOUNT, SAFE);
        assertTrue(p.evaluate(data, _ctx(AAVE, SEL_AAVE)));
    }

    function test_Aave_ExactlyAtLtvCap() public view {
        // borrow 75: LTV = 75*1/100 = 7500 bps = exactly MAX_LTV → pass
        bytes memory data = _aave(USDC, 75, SAFE);
        assertTrue(perm.evaluate(data, _ctx(AAVE, SEL_AAVE)));
    }

    function test_Aave_WethTwoXPrice() public view {
        // WETH price = 2; borrow 37 WETH: LTV = 37*2/100 = 74% < 75% → pass
        bytes memory data = _aave(WETH, 37, SAFE);
        assertTrue(perm.evaluate(data, _ctx(AAVE, SEL_AAVE)));
    }

    function test_Aave_NoOracles_GoldenPath() public {
        address[] memory protocols = _arr1(AAVE);
        address[] memory assets    = _arr1(USDC);
        BoundedBorrowPermission p = new BoundedBorrowPermission(
            protocols, assets, MAX_AMOUNT, MAX_LTV, address(0), address(0), SIGNER
        );
        bytes memory data = _aave(USDC, MAX_AMOUNT, SAFE);
        assertTrue(p.evaluate(data, _ctx(AAVE, SEL_AAVE)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Aave V3 borrow — blocked cases
    // ─────────────────────────────────────────────────────────────────────────

    function test_Aave_WrongProtocol() public view {
        bytes memory data = _aave(USDC, 50, SAFE);
        assertFalse(perm.evaluate(data, _ctx(STRANGER, SEL_AAVE)));
    }

    function test_Aave_WrongAsset() public view {
        bytes memory data = _aave(STRANGER, 50, SAFE);
        assertFalse(perm.evaluate(data, _ctx(AAVE, SEL_AAVE)));
    }

    function test_Aave_AmountOverCap() public view {
        bytes memory data = _aave(USDC, MAX_AMOUNT + 1, SAFE);
        assertFalse(perm.evaluate(data, _ctx(AAVE, SEL_AAVE)));
    }

    function test_Aave_WrongOnBehalfOf() public view {
        bytes memory data = _aave(USDC, 50, STRANGER);
        assertFalse(perm.evaluate(data, _ctx(AAVE, SEL_AAVE)));
    }

    function test_Aave_OnBehalfOfZeroAddress() public view {
        bytes memory data = _aave(USDC, 50, address(0));
        assertFalse(perm.evaluate(data, _ctx(AAVE, SEL_AAVE)));
    }

    function test_Aave_LtvExceedsCap() public view {
        // borrow 76: LTV = 76*1/100 = 76% > 75% → blocked
        bytes memory data = _aave(USDC, 76, SAFE);
        assertFalse(perm.evaluate(data, _ctx(AAVE, SEL_AAVE)));
    }

    function test_Aave_LtvExceedsCap_WethDoublePrice() public view {
        // WETH price = 2; borrow 38 WETH: LTV = 38*2/100 = 76% > 75% → blocked
        bytes memory data = _aave(WETH, 38, SAFE);
        assertFalse(perm.evaluate(data, _ctx(AAVE, SEL_AAVE)));
    }

    function test_Aave_TooShort_163Bytes() public view {
        bytes memory full  = _aave(USDC, 50, SAFE);
        assertEq(full.length, 164);
        bytes memory short_ = new bytes(163);
        for (uint256 i; i < 163; i++) short_[i] = full[i];
        assertFalse(perm.evaluate(short_, _ctx(AAVE, SEL_AAVE)));
    }

    function test_Aave_ExactlyMinLength_164Bytes() public view {
        bytes memory data = _aave(USDC, 50, SAFE);
        assertEq(data.length, 164);
        assertTrue(perm.evaluate(data, _ctx(AAVE, SEL_AAVE)));
    }

    function test_Aave_ZeroAmountPasses() public view {
        bytes memory data = _aave(USDC, 0, SAFE);
        assertTrue(perm.evaluate(data, _ctx(AAVE, SEL_AAVE)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Morpho borrow — golden paths
    // ─────────────────────────────────────────────────────────────────────────

    function test_Morpho_GoldenPath() public view {
        bytes memory data = _morpho(USDC, 50, SAFE, SAFE);
        assertTrue(perm.evaluate(data, _ctx(MORPHO, SEL_MORPHO)));
    }

    function test_Morpho_ExactlyAtLtvCap() public view {
        bytes memory data = _morpho(USDC, 75, SAFE, SAFE);
        assertTrue(perm.evaluate(data, _ctx(MORPHO, SEL_MORPHO)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Morpho borrow — blocked cases
    // ─────────────────────────────────────────────────────────────────────────

    function test_Morpho_WrongProtocol() public view {
        bytes memory data = _morpho(USDC, 50, SAFE, SAFE);
        assertFalse(perm.evaluate(data, _ctx(STRANGER, SEL_MORPHO)));
    }

    function test_Morpho_WrongAsset() public view {
        bytes memory data = _morpho(STRANGER, 50, SAFE, SAFE);
        assertFalse(perm.evaluate(data, _ctx(MORPHO, SEL_MORPHO)));
    }

    function test_Morpho_AmountOverCap() public view {
        bytes memory data = _morpho(USDC, MAX_AMOUNT + 1, SAFE, SAFE);
        assertFalse(perm.evaluate(data, _ctx(MORPHO, SEL_MORPHO)));
    }

    function test_Morpho_WrongOnBehalf() public view {
        bytes memory data = _morpho(USDC, 50, STRANGER, SAFE);
        assertFalse(perm.evaluate(data, _ctx(MORPHO, SEL_MORPHO)));
    }

    function test_Morpho_WrongReceiver() public view {
        bytes memory data = _morpho(USDC, 50, SAFE, STRANGER);
        assertFalse(perm.evaluate(data, _ctx(MORPHO, SEL_MORPHO)));
    }

    function test_Morpho_BothWrong() public view {
        bytes memory data = _morpho(USDC, 50, STRANGER, STRANGER);
        assertFalse(perm.evaluate(data, _ctx(MORPHO, SEL_MORPHO)));
    }

    function test_Morpho_LtvExceedsCap() public view {
        bytes memory data = _morpho(USDC, 76, SAFE, SAFE);
        assertFalse(perm.evaluate(data, _ctx(MORPHO, SEL_MORPHO)));
    }

    function test_Morpho_TooShort_131Bytes() public view {
        bytes memory full  = _morpho(USDC, 50, SAFE, SAFE);
        assertEq(full.length, 132);
        bytes memory short_ = new bytes(131);
        for (uint256 i; i < 131; i++) short_[i] = full[i];
        assertFalse(perm.evaluate(short_, _ctx(MORPHO, SEL_MORPHO)));
    }

    function test_Morpho_ExactlyMinLength_132Bytes() public view {
        bytes memory data = _morpho(USDC, 50, SAFE, SAFE);
        assertEq(data.length, 132);
        assertTrue(perm.evaluate(data, _ctx(MORPHO, SEL_MORPHO)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Compound borrow — golden paths
    // ─────────────────────────────────────────────────────────────────────────

    function test_Compound_GoldenPath() public view {
        // ctx.target = COMPOUND (cToken); COMPOUND is in isAllowedAsset
        bytes memory data = _compound(50);
        assertTrue(perm.evaluate(data, _ctx(COMPOUND, SEL_COMPOUND)));
    }

    function test_Compound_ExactlyAtLtvCap() public view {
        bytes memory data = _compound(75);
        assertTrue(perm.evaluate(data, _ctx(COMPOUND, SEL_COMPOUND)));
    }

    function test_Compound_LtvExceedsCap() public view {
        bytes memory data = _compound(76);
        assertFalse(perm.evaluate(data, _ctx(COMPOUND, SEL_COMPOUND)));
    }

    function test_Compound_WrongProtocol() public view {
        bytes memory data = _compound(50);
        assertFalse(perm.evaluate(data, _ctx(STRANGER, SEL_COMPOUND)));
    }

    function test_Compound_CTokenNotInAssetList_Blocked() public view {
        // AAVE is in allowedProtocols but not in allowedAssets as cToken
        bytes memory data = _compound(50);
        assertFalse(perm.evaluate(data, _ctx(AAVE, SEL_COMPOUND)));
    }

    function test_Compound_AmountOverCap() public view {
        bytes memory data = _compound(MAX_AMOUNT + 1);
        assertFalse(perm.evaluate(data, _ctx(COMPOUND, SEL_COMPOUND)));
    }

    function test_Compound_TooShort_35Bytes() public view {
        bytes memory full  = _compound(50);
        assertEq(full.length, 36);
        bytes memory short_ = new bytes(35);
        for (uint256 i; i < 35; i++) short_[i] = full[i];
        assertFalse(perm.evaluate(short_, _ctx(COMPOUND, SEL_COMPOUND)));
    }

    function test_Compound_ExactlyMinLength_36Bytes() public view {
        bytes memory data = _compound(50);
        assertEq(data.length, 36);
        assertTrue(perm.evaluate(data, _ctx(COMPOUND, SEL_COMPOUND)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Oracle edge cases
    // ─────────────────────────────────────────────────────────────────────────

    function test_Oracle_ZeroCollateral_Blocked() public {
        colOracle.setPrice(SAFE, address(0), 0, 0); // no collateral
        bytes memory data = _aave(USDC, 1, SAFE);
        assertFalse(perm.evaluate(data, _ctx(AAVE, SEL_AAVE)));
    }

    function test_Oracle_ZeroCollateral_ZeroBorrow_Blocked() public {
        colOracle.setPrice(SAFE, address(0), 0, 0);
        bytes memory data = _aave(USDC, 0, SAFE);
        assertFalse(perm.evaluate(data, _ctx(AAVE, SEL_AAVE)));
    }

    function test_Oracle_ZeroBorrowPrice_Passes() public {
        // zero borrow price → zero borrow value → LTV = 0 → always passes
        borOracle.setPrice(USDC, address(0), 0, 0);
        bytes memory data = _aave(USDC, MAX_AMOUNT, SAFE);
        assertTrue(perm.evaluate(data, _ctx(AAVE, SEL_AAVE)));
    }

    function test_Oracle_DisabledBothAddressZero_Passes() public {
        // Deploy without oracles; any valid borrow amount passes LTV
        address[] memory protocols = _arr1(AAVE);
        address[] memory assets    = _arr1(USDC);
        BoundedBorrowPermission p = new BoundedBorrowPermission(
            protocols, assets, MAX_AMOUNT, MAX_LTV, address(0), address(0), SIGNER
        );
        bytes memory data = _aave(USDC, MAX_AMOUNT, SAFE);
        assertTrue(p.evaluate(data, _ctx(AAVE, SEL_AAVE)));
    }

    function test_Oracle_OnlyCollateralSet_LtvCheckSkipped() public {
        // Only collateralOracle set; borrowOracle = address(0) → LTV check disabled
        address[] memory protocols = _arr1(AAVE);
        address[] memory assets    = _arr1(USDC);
        BoundedBorrowPermission p = new BoundedBorrowPermission(
            protocols, assets, MAX_AMOUNT, MAX_LTV, address(colOracle), address(0), SIGNER
        );
        bytes memory data = _aave(USDC, MAX_AMOUNT, SAFE);
        assertTrue(p.evaluate(data, _ctx(AAVE, SEL_AAVE)));
    }

    function test_Oracle_OnlyBorrowSet_LtvCheckSkipped() public {
        address[] memory protocols = _arr1(AAVE);
        address[] memory assets    = _arr1(USDC);
        BoundedBorrowPermission p = new BoundedBorrowPermission(
            protocols, assets, MAX_AMOUNT, MAX_LTV, address(0), address(borOracle), SIGNER
        );
        bytes memory data = _aave(USDC, MAX_AMOUNT, SAFE);
        assertTrue(p.evaluate(data, _ctx(AAVE, SEL_AAVE)));
    }

    function test_Oracle_HighPrecision_18Decimals() public {
        // Use 18-decimal oracle values: colValue = 100e18, borPrice = 1e18
        BorrowMockOracle col18 = new BorrowMockOracle();
        BorrowMockOracle bor18 = new BorrowMockOracle();
        col18.setPrice(SAFE, address(0), 100e18, 18);
        bor18.setPrice(USDC, address(0), 1e18,   18);

        address[] memory protocols = _arr1(AAVE);
        address[] memory assets    = _arr1(USDC);
        BoundedBorrowPermission p = new BoundedBorrowPermission(
            protocols, assets, MAX_AMOUNT, MAX_LTV, address(col18), address(bor18), SIGNER
        );

        // ltvBps = amount * borPrice * 10_000 / colValue
        //        = amount * 1e18 * 10_000 / 100e18  (1e18 factors cancel → amount * 100)
        // amount=75 → ltvBps = 7500 → exactly at cap → passes
        bytes memory data = _aave(USDC, 75, SAFE);
        assertTrue(p.evaluate(data, _ctx(AAVE, SEL_AAVE)));

        // amount=76 → ltvBps = 7600 > 7500 → blocked
        bytes memory over = _aave(USDC, 76, SAFE);
        assertFalse(p.evaluate(over, _ctx(AAVE, SEL_AAVE)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Unknown calldata
    // ─────────────────────────────────────────────────────────────────────────

    function test_EmptyCalldata() public view {
        Context memory ctx = _ctx(AAVE, bytes4(0));
        assertFalse(perm.evaluate("", ctx));
    }

    function test_UnknownSelector_Transfer() public view {
        bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", SAFE, 1e18);
        Context memory ctx = _ctx(AAVE, bytes4(keccak256("transfer(address,uint256)")));
        assertFalse(perm.evaluate(data, ctx));
    }

    function testFuzz_UnknownSelector(bytes4 sel) public view {
        vm.assume(sel != SEL_AAVE && sel != SEL_MORPHO && sel != SEL_COMPOUND);
        bytes memory data = abi.encodePacked(
            sel,
            abi.encode(USDC, uint256(50), uint256(1), uint16(0), SAFE)
        );
        assertFalse(perm.evaluate(data, _ctx(AAVE, sel)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // setMaxAmountPerTx
    // ─────────────────────────────────────────────────────────────────────────

    function test_SetMaxAmountPerTx_Succeeds() public {
        vm.prank(SIGNER);
        perm.setMaxAmountPerTx(500e18);
        assertEq(perm.maxAmountPerTx(), 500e18);
    }

    function test_SetMaxAmountPerTx_EmitsEvent() public {
        vm.expectEmit(false, false, false, true);
        emit BoundedBorrowPermission.MaxAmountUpdated(MAX_AMOUNT, 200e18);
        vm.prank(SIGNER);
        perm.setMaxAmountPerTx(200e18);
    }

    function test_SetMaxAmountPerTx_RevertsForStranger() public {
        vm.prank(STRANGER);
        vm.expectRevert(BoundedBorrowPermission.NotPermissionSigner.selector);
        perm.setMaxAmountPerTx(500e18);
    }

    function test_SetMaxAmountPerTx_TakesEffect() public {
        // 50 <= MAX_AMOUNT → passes
        bytes memory data = _aave(USDC, 50, SAFE);
        assertTrue(perm.evaluate(data, _ctx(AAVE, SEL_AAVE)));

        vm.prank(SIGNER);
        perm.setMaxAmountPerTx(49); // tighten below 50

        assertFalse(perm.evaluate(data, _ctx(AAVE, SEL_AAVE)));
    }

    function testFuzz_SetMaxAmountPerTx_NonSigner(address caller) public {
        vm.assume(caller != SIGNER);
        vm.prank(caller);
        vm.expectRevert(BoundedBorrowPermission.NotPermissionSigner.selector);
        perm.setMaxAmountPerTx(1);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // setMaxLtvBps
    // ─────────────────────────────────────────────────────────────────────────

    function test_SetMaxLtvBps_Succeeds() public {
        vm.prank(SIGNER);
        perm.setMaxLtvBps(5_000);
        assertEq(perm.maxLtvBps(), 5_000);
    }

    function test_SetMaxLtvBps_EmitsEvent() public {
        vm.expectEmit(false, false, false, true);
        emit BoundedBorrowPermission.MaxLtvUpdated(MAX_LTV, 5_000);
        vm.prank(SIGNER);
        perm.setMaxLtvBps(5_000);
    }

    function test_SetMaxLtvBps_RevertsAboveCap() public {
        vm.prank(SIGNER);
        vm.expectRevert(abi.encodeWithSelector(BoundedBorrowPermission.LtvBpsTooLarge.selector, 10_001));
        perm.setMaxLtvBps(10_001);
    }

    function test_SetMaxLtvBps_AtExact10000_Passes() public {
        vm.prank(SIGNER);
        perm.setMaxLtvBps(10_000);
        assertEq(perm.maxLtvBps(), 10_000);
    }

    function test_SetMaxLtvBps_RevertsForStranger() public {
        vm.prank(STRANGER);
        vm.expectRevert(BoundedBorrowPermission.NotPermissionSigner.selector);
        perm.setMaxLtvBps(5_000);
    }

    function test_SetMaxLtvBps_TighterCapBlocksBorrow() public {
        // At 7500 bps, borrowing 75 passes
        bytes memory data = _aave(USDC, 75, SAFE);
        assertTrue(perm.evaluate(data, _ctx(AAVE, SEL_AAVE)));

        // Tighten to 50% (5000 bps)
        vm.prank(SIGNER);
        perm.setMaxLtvBps(5_000);

        // 75 borrow: LTV = 75% > 50% → now blocked
        assertFalse(perm.evaluate(data, _ctx(AAVE, SEL_AAVE)));

        // 50 borrow: LTV = 50% → exactly at new cap → passes
        bytes memory ok = _aave(USDC, 50, SAFE);
        assertTrue(perm.evaluate(ok, _ctx(AAVE, SEL_AAVE)));
    }

    function test_SetMaxLtvBps_ToZero_BlocksAllBorrows() public {
        vm.prank(SIGNER);
        perm.setMaxLtvBps(0);
        // Even 1 unit borrow: LTV = 1*1/100 * 10_000 = 100 bps > 0 → blocked
        bytes memory data = _aave(USDC, 1, SAFE);
        assertFalse(perm.evaluate(data, _ctx(AAVE, SEL_AAVE)));
    }

    function test_SetMaxLtvBps_ToZero_ZeroBorrowPasses() public {
        vm.prank(SIGNER);
        perm.setMaxLtvBps(0);
        // amount=0: LTV = 0 bps <= 0 → passes
        bytes memory data = _aave(USDC, 0, SAFE);
        assertTrue(perm.evaluate(data, _ctx(AAVE, SEL_AAVE)));
    }

    function testFuzz_SetMaxLtvBps_NonSigner(address caller) public {
        vm.assume(caller != SIGNER);
        vm.prank(caller);
        vm.expectRevert(BoundedBorrowPermission.NotPermissionSigner.selector);
        perm.setMaxLtvBps(5_000);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Fuzz: blocked cases across all protocols
    // ─────────────────────────────────────────────────────────────────────────

    function testFuzz_Aave_WrongOnBehalfOf(address onBehalf) public view {
        vm.assume(onBehalf != SAFE);
        bytes memory data = _aave(USDC, 50, onBehalf);
        assertFalse(perm.evaluate(data, _ctx(AAVE, SEL_AAVE)));
    }

    function testFuzz_Morpho_WrongReceiver(address receiver) public view {
        vm.assume(receiver != SAFE);
        bytes memory data = _morpho(USDC, 50, SAFE, receiver);
        assertFalse(perm.evaluate(data, _ctx(MORPHO, SEL_MORPHO)));
    }

    function testFuzz_Morpho_WrongOnBehalf(address onBehalf) public view {
        vm.assume(onBehalf != SAFE);
        bytes memory data = _morpho(USDC, 50, onBehalf, SAFE);
        assertFalse(perm.evaluate(data, _ctx(MORPHO, SEL_MORPHO)));
    }

    function testFuzz_Aave_WrongProtocol(address target) public view {
        vm.assume(target != AAVE && target != MORPHO && target != COMPOUND);
        bytes memory data = _aave(USDC, 50, SAFE);
        assertFalse(perm.evaluate(data, _ctx(target, SEL_AAVE)));
    }

    function testFuzz_Aave_WrongAsset(address asset) public view {
        vm.assume(asset != USDC && asset != WETH && asset != COMPOUND);
        bytes memory data = _aave(asset, 50, SAFE);
        assertFalse(perm.evaluate(data, _ctx(AAVE, SEL_AAVE)));
    }

    function testFuzz_Aave_AmountWithinCap(uint256 amount) public view {
        // Within cap and within LTV (colValue=100, borPrice=1, ltv cap 75%)
        amount = bound(amount, 0, 75);
        bytes memory data = _aave(USDC, amount, SAFE);
        assertTrue(perm.evaluate(data, _ctx(AAVE, SEL_AAVE)));
    }

    function testFuzz_Aave_AmountExceedsCap(uint256 excess) public view {
        excess = bound(excess, 1, type(uint256).max - MAX_AMOUNT);
        bytes memory data = _aave(USDC, MAX_AMOUNT + excess, SAFE);
        assertFalse(perm.evaluate(data, _ctx(AAVE, SEL_AAVE)));
    }

    function testFuzz_Compound_AmountWithinCap(uint256 amount) public view {
        amount = bound(amount, 0, 75);
        bytes memory data = _compound(amount);
        assertTrue(perm.evaluate(data, _ctx(COMPOUND, SEL_COMPOUND)));
    }

    function testFuzz_LtvBpsAboveCap(uint256 bps) public {
        bps = bound(bps, 10_001, type(uint256).max);
        vm.prank(SIGNER);
        vm.expectRevert(abi.encodeWithSelector(BoundedBorrowPermission.LtvBpsTooLarge.selector, bps));
        perm.setMaxLtvBps(bps);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // All checks interact correctly
    // ─────────────────────────────────────────────────────────────────────────

    function test_AllThreeChecks_AllFail() public view {
        // wrong protocol, wrong asset, wrong onBehalfOf, amount over cap, LTV over
        bytes memory data = _aave(STRANGER, MAX_AMOUNT + 1, STRANGER);
        assertFalse(perm.evaluate(data, _ctx(STRANGER, SEL_AAVE)));
    }

    function test_MorphoAndAaveUseSameAllowlists() public view {
        // USDC is allowed for both Aave and Morpho
        bytes memory aaveData   = _aave(USDC, 50, SAFE);
        bytes memory morphoData = _morpho(USDC, 50, SAFE, SAFE);
        assertTrue(perm.evaluate(aaveData,   _ctx(AAVE, SEL_AAVE)));
        assertTrue(perm.evaluate(morphoData, _ctx(MORPHO, SEL_MORPHO)));
    }

    function test_CompoundUsesTargetAsAssetId() public view {
        // COMPOUND is in isAllowedAsset; routing a borrow to COMPOUND target passes
        bytes memory data = _compound(50);
        assertTrue(perm.evaluate(data, _ctx(COMPOUND, SEL_COMPOUND)));

        // AAVE is in isAllowedProtocol but NOT added to isAllowedAsset as cToken
        assertFalse(perm.evaluate(data, _ctx(AAVE, SEL_COMPOUND)));
    }
}
