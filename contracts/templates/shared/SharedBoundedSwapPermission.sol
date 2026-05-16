// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Context} from "../../interfaces/IPermission.sol";
import {IOracle} from "../../interfaces/IOracle.sol";
import {BaseSharedPermission} from "./BaseSharedPermission.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

/// @notice Multi-account variant of BoundedSwapPermission. One deployment serves any
///         number of accounts; each account stores its own routers, token allowlists,
///         amount cap, slippage tolerance, and oracle.
///
///         Config blob:
///             abi.encode(
///                 address[] routers,
///                 address[] tokensIn,
///                 address[] tokensOut,
///                 uint256   maxAmountPerTx,
///                 uint256   maxSlippageBps,
///                 address   priceOracle
///             )
contract SharedBoundedSwapPermission is BaseSharedPermission {
    // exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160)) — V3 SwapRouter (with deadline)
    bytes4 private constant EXACT_INPUT_SINGLE_V1 = 0x414bf389;
    // exactInputSingle((address,address,uint24,address,uint256,uint256,uint160)) — V3 SwapRouter02 (no deadline)
    bytes4 private constant EXACT_INPUT_SINGLE_V2 = 0x04e45aaf;
    // swapExactTokensForTokens(uint256,uint256,address[],address,uint256)
    bytes4 private constant SWAP_EXACT_TOKENS     = 0x38ed1739;

    uint256 private constant LEN_V3_V1  = 260;
    uint256 private constant LEN_V3_V2  = 228;
    uint256 private constant LEN_V2_MIN = 196;

    struct Slot {
        address[] routers;
        address[] tokensIn;
        address[] tokensOut;
        uint256   maxAmountPerTx;
        uint256   maxSlippageBps;
        address   priceOracle;
    }

    mapping(address account => Slot) private _slots;
    mapping(address account => mapping(address => bool)) public isAllowedRouter;
    mapping(address account => mapping(address => bool)) public isAllowedTokenIn;
    mapping(address account => mapping(address => bool)) public isAllowedTokenOut;

    error SlippageBpsTooLarge(uint256 bps);

    constructor(address _kernel)
        BaseSharedPermission(_kernel, "SharedBoundedSwapPermission", "1")
    {}

    // ── view helpers ──────────────────────────────────────────────────────────

    function getConfig(address account)
        external
        view
        returns (
            address[] memory routers,
            address[] memory tokensIn,
            address[] memory tokensOut,
            uint256 maxAmountPerTx,
            uint256 maxSlippageBps,
            address priceOracle
        )
    {
        Slot storage s = _slots[account];
        return (s.routers, s.tokensIn, s.tokensOut, s.maxAmountPerTx, s.maxSlippageBps, s.priceOracle);
    }

    // ── config application ────────────────────────────────────────────────────

    function _applyConfig(address account, bytes calldata params) internal override {
        (
            address[] memory routers,
            address[] memory tokensIn,
            address[] memory tokensOut,
            uint256 maxAmountPerTx,
            uint256 maxSlippageBps,
            address priceOracle
        ) = abi.decode(params, (address[], address[], address[], uint256, uint256, address));

        if (maxSlippageBps > 9_999) revert SlippageBpsTooLarge(maxSlippageBps);

        // Clear previous allowlists for this account
        Slot storage s = _slots[account];
        for (uint256 i; i < s.routers.length; i++)   isAllowedRouter[account][s.routers[i]] = false;
        for (uint256 i; i < s.tokensIn.length; i++)  isAllowedTokenIn[account][s.tokensIn[i]] = false;
        for (uint256 i; i < s.tokensOut.length; i++) isAllowedTokenOut[account][s.tokensOut[i]] = false;

        // Apply new
        for (uint256 i; i < routers.length; i++)   isAllowedRouter[account][routers[i]]     = true;
        for (uint256 i; i < tokensIn.length; i++)  isAllowedTokenIn[account][tokensIn[i]]   = true;
        for (uint256 i; i < tokensOut.length; i++) isAllowedTokenOut[account][tokensOut[i]] = true;

        s.routers        = routers;
        s.tokensIn       = tokensIn;
        s.tokensOut      = tokensOut;
        s.maxAmountPerTx = maxAmountPerTx;
        s.maxSlippageBps = maxSlippageBps;
        s.priceOracle    = priceOracle;
    }

    // ── IPermission ───────────────────────────────────────────────────────────

    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool) {
        if (!isAllowedRouter[ctx.account][ctx.target]) return false;
        Slot storage s = _slots[ctx.account];

        if (ctx.selector == EXACT_INPUT_SINGLE_V1) {
            if (txData.length < LEN_V3_V1) return false;
            (
                address tokenIn,
                address tokenOut,
                ,
                address recipient,
                ,
                uint256 amountIn,
                uint256 amountOutMinimum,
            ) = abi.decode(
                txData[4:],
                (address, address, uint24, address, uint256, uint256, uint256, uint160)
            );
            if (!isAllowedTokenIn[ctx.account][tokenIn])   return false;
            if (!isAllowedTokenOut[ctx.account][tokenOut]) return false;
            if (recipient != ctx.account)                  return false;
            if (amountIn > s.maxAmountPerTx)               return false;
            return _oracleCheck(s, tokenIn, tokenOut, amountIn, amountOutMinimum);
        }

        if (ctx.selector == EXACT_INPUT_SINGLE_V2) {
            if (txData.length < LEN_V3_V2) return false;
            (
                address tokenIn,
                address tokenOut,
                ,
                address recipient,
                uint256 amountIn,
                uint256 amountOutMinimum,
            ) = abi.decode(
                txData[4:],
                (address, address, uint24, address, uint256, uint256, uint160)
            );
            if (!isAllowedTokenIn[ctx.account][tokenIn])   return false;
            if (!isAllowedTokenOut[ctx.account][tokenOut]) return false;
            if (recipient != ctx.account)                  return false;
            if (amountIn > s.maxAmountPerTx)               return false;
            return _oracleCheck(s, tokenIn, tokenOut, amountIn, amountOutMinimum);
        }

        if (ctx.selector == SWAP_EXACT_TOKENS) {
            if (txData.length < LEN_V2_MIN) return false;
            (
                uint256 amountIn,
                uint256 amountOutMin,
                address[] memory path,
                address to,
            ) = abi.decode(txData[4:], (uint256, uint256, address[], address, uint256));
            if (path.length < 2)                                          return false;
            if (!isAllowedTokenIn[ctx.account][path[0]])                  return false;
            if (!isAllowedTokenOut[ctx.account][path[path.length - 1]])   return false;
            if (to != ctx.account)                                        return false;
            if (amountIn > s.maxAmountPerTx)                              return false;
            return _oracleCheck(s, path[0], path[path.length - 1], amountIn, amountOutMin);
        }

        return false;
    }

    function discriminator() external pure returns (bytes32) {
        return keccak256("SharedBoundedSwapPermission");
    }

    // ── internal ──────────────────────────────────────────────────────────────

    function _oracleCheck(
        Slot storage s,
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 amountOutMin
    ) internal view returns (bool) {
        if (s.priceOracle == address(0) || s.maxSlippageBps == 0) return true;
        (uint256 price, uint8 dec) = IOracle(s.priceOracle).getPrice(tokenIn, tokenOut);
        if (price == 0) return false;
        uint256 expectedOut  = Math.mulDiv(amountIn, price, 10 ** uint256(dec));
        uint256 oracleMinOut = Math.mulDiv(expectedOut, 10_000 - s.maxSlippageBps, 10_000);
        return amountOutMin >= oracleMinOut;
    }
}
