// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {Context} from "../../interfaces/IPermission.sol";
import {IOracle} from "../../interfaces/IOracle.sol";
import {BaseSharedPermission} from "./BaseSharedPermission.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

/// @notice Multi-account variant of BoundedBorrowPermission. One deployment serves any
///         number of accounts. Supports Aave V3, Morpho, and Compound V2 borrow selectors.
///
///         Config blob:
///             abi.encode(
///                 address[] protocols,
///                 address[] assets,
///                 uint256   maxAmountPerTx,
///                 uint256   maxLtvBps,
///                 address   collateralOracle,
///                 address   borrowOracle
///             )
contract SharedBoundedBorrowPermission is BaseSharedPermission {
    bytes4 private constant AAVE_BORROW     = bytes4(keccak256("borrow(address,uint256,uint256,uint16,address)"));
    bytes4 private constant MORPHO_BORROW   = bytes4(keccak256("borrow(address,uint256,address,address)"));
    bytes4 private constant COMPOUND_BORROW = bytes4(keccak256("borrow(uint256)"));

    uint256 private constant LEN_AAVE     = 164;
    uint256 private constant LEN_MORPHO   = 132;
    uint256 private constant LEN_COMPOUND = 36;

    struct Slot {
        address[] protocols;
        address[] assets;
        uint256   maxAmountPerTx;
        uint256   maxLtvBps;
        address   collateralOracle;
        address   borrowOracle;
    }

    mapping(address account => Slot) private _slots;
    mapping(address account => mapping(address => bool)) public isAllowedProtocol;
    mapping(address account => mapping(address => bool)) public isAllowedAsset;

    error LtvBpsTooLarge(uint256 bps);

    constructor(address _kernel)
        BaseSharedPermission(_kernel, "SharedBoundedBorrowPermission", "1")
    {}

    function getConfig(address account)
        external
        view
        returns (
            address[] memory protocols,
            address[] memory assets,
            uint256 maxAmountPerTx,
            uint256 maxLtvBps,
            address collateralOracle,
            address borrowOracle
        )
    {
        Slot storage s = _slots[account];
        return (s.protocols, s.assets, s.maxAmountPerTx, s.maxLtvBps, s.collateralOracle, s.borrowOracle);
    }

    function _applyConfig(address account, bytes calldata params) internal override {
        (
            address[] memory protocols,
            address[] memory assets,
            uint256 maxAmountPerTx,
            uint256 maxLtvBps,
            address collateralOracle,
            address borrowOracle
        ) = abi.decode(params, (address[], address[], uint256, uint256, address, address));

        if (maxLtvBps > 10_000) revert LtvBpsTooLarge(maxLtvBps);

        Slot storage s = _slots[account];
        for (uint256 i; i < s.protocols.length; i++) isAllowedProtocol[account][s.protocols[i]] = false;
        for (uint256 i; i < s.assets.length; i++)    isAllowedAsset[account][s.assets[i]]       = false;

        for (uint256 i; i < protocols.length; i++) isAllowedProtocol[account][protocols[i]] = true;
        for (uint256 i; i < assets.length; i++)    isAllowedAsset[account][assets[i]]       = true;

        s.protocols        = protocols;
        s.assets           = assets;
        s.maxAmountPerTx   = maxAmountPerTx;
        s.maxLtvBps        = maxLtvBps;
        s.collateralOracle = collateralOracle;
        s.borrowOracle     = borrowOracle;
    }

    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool) {
        if (!isAllowedProtocol[ctx.account][ctx.target]) return false;
        Slot storage s = _slots[ctx.account];

        if (ctx.selector == AAVE_BORROW) {
            if (txData.length < LEN_AAVE) return false;
            (address asset, uint256 amount, , , address onBehalfOf) =
                abi.decode(txData[4:], (address, uint256, uint256, uint16, address));
            if (!isAllowedAsset[ctx.account][asset]) return false;
            if (amount > s.maxAmountPerTx)           return false;
            if (onBehalfOf != ctx.account)           return false;
            return _ltvCheck(s, asset, amount, ctx.account);
        }

        if (ctx.selector == MORPHO_BORROW) {
            if (txData.length < LEN_MORPHO) return false;
            (address asset, uint256 amount, address onBehalf, address receiver) =
                abi.decode(txData[4:], (address, uint256, address, address));
            if (!isAllowedAsset[ctx.account][asset]) return false;
            if (amount > s.maxAmountPerTx)           return false;
            if (onBehalf != ctx.account)             return false;
            if (receiver != ctx.account)             return false;
            return _ltvCheck(s, asset, amount, ctx.account);
        }

        if (ctx.selector == COMPOUND_BORROW) {
            if (txData.length < LEN_COMPOUND) return false;
            uint256 amount = abi.decode(txData[4:], (uint256));
            if (!isAllowedAsset[ctx.account][ctx.target]) return false;
            if (amount > s.maxAmountPerTx)                return false;
            return _ltvCheck(s, ctx.target, amount, ctx.account);
        }

        return false;
    }

    function discriminator() external pure returns (bytes32) {
        return keccak256("SharedBoundedBorrowPermission");
    }

    function _ltvCheck(Slot storage s, address asset, uint256 amount, address account)
        internal
        view
        returns (bool)
    {
        if (s.collateralOracle == address(0) || s.borrowOracle == address(0)) return true;

        (uint256 colValue, uint8 colDec) = IOracle(s.collateralOracle).getPrice(account, address(0));
        (uint256 borPrice, uint8 borDec) = IOracle(s.borrowOracle).getPrice(asset, address(0));

        if (colDec > 77 || borDec > 77) return false;
        if (colValue == 0) return false;
        if (borPrice == 0) return false;

        uint256 borrowScaled = Math.mulDiv(amount, borPrice, 10 ** uint256(borDec));
        uint256 ltvBps       = Math.mulDiv(borrowScaled, 10_000, colValue);
        return ltvBps <= s.maxLtvBps;
    }
}
