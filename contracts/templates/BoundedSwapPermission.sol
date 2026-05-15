// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IPermission, Context} from "../interfaces/IPermission.sol";
import {IOracle} from "../interfaces/IOracle.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

/// @notice Gates DEX swaps so the manager can only trade through approved routers,
///         with approved tokens, within an amount cap, and — when an oracle is
///         configured — within a slippage band derived from the on-chain price.
///
///         Supported selectors:
///           0x414bf389  exactInputSingle  (Uniswap V3 SwapRouter)
///           0x38ed1739  swapExactTokensForTokens  (Uniswap V2 Router)
contract BoundedSwapPermission is IPermission {
    // exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))
    bytes4 private constant EXACT_INPUT_SINGLE = 0x414bf389;
    // swapExactTokensForTokens(uint256,uint256,address[],address,uint256)
    bytes4 private constant SWAP_EXACT_TOKENS  = 0x38ed1739;

    // selector(4) + 8 static slots × 32 = 260
    uint256 private constant LEN_V3 = 260;
    // selector(4) + 5 head slots × 32 (amountIn, amountOutMin, pathOffset, to, deadline)
    //             + 1 tail slot  × 32 (path.length)  = 196  (minimum; path.length checked after decode)
    uint256 private constant LEN_V2_MIN = 196;

    // ── allowlists ────────────────────────────────────────────────────────────
    mapping(address router => bool) public isAllowedRouter;
    mapping(address token  => bool) public isAllowedTokenIn;
    mapping(address token  => bool) public isAllowedTokenOut;

    // ── tunable parameters ────────────────────────────────────────────────────
    uint256 public maxAmountPerTx;
    /// @notice Slippage tolerance in basis points. 0 = oracle check disabled.
    uint256 public maxSlippageBps;
    /// @notice Oracle address. address(0) = oracle check disabled.
    address public priceOracle;
    address public permissionSigner;

    // ── events ────────────────────────────────────────────────────────────────
    event MaxAmountUpdated(uint256 oldMax, uint256 newMax);
    event MaxSlippageUpdated(uint256 oldBps, uint256 newBps);

    // ── errors ────────────────────────────────────────────────────────────────
    error NotPermissionSigner();
    error ZeroAddress();
    error SlippageBpsTooLarge(uint256 bps);

    modifier onlyPermissionSigner() {
        if (msg.sender != permissionSigner) revert NotPermissionSigner();
        _;
    }

    constructor(
        address[] memory allowedRouters,
        address[] memory allowedTokensIn,
        address[] memory allowedTokensOut,
        uint256 _maxAmountPerTx,
        uint256 _maxSlippageBps,
        address _priceOracle,
        address _permissionSigner
    ) {
        if (_permissionSigner == address(0)) revert ZeroAddress();
        // 9_999 max: 10_000 would compute oracleMinOut = 0 when oracle is set,
        // silently bypassing the oracle floor. Use slippage = 0 to explicitly disable.
        if (_maxSlippageBps > 9_999) revert SlippageBpsTooLarge(_maxSlippageBps);

        maxAmountPerTx   = _maxAmountPerTx;
        maxSlippageBps   = _maxSlippageBps;
        priceOracle      = _priceOracle;
        permissionSigner = _permissionSigner;

        for (uint256 i; i < allowedRouters.length;   i++) isAllowedRouter[allowedRouters[i]]     = true;
        for (uint256 i; i < allowedTokensIn.length;  i++) isAllowedTokenIn[allowedTokensIn[i]]   = true;
        for (uint256 i; i < allowedTokensOut.length; i++) isAllowedTokenOut[allowedTokensOut[i]] = true;
    }

    // ── setters ───────────────────────────────────────────────────────────────

    function setMaxAmountPerTx(uint256 newMax) external onlyPermissionSigner {
        uint256 old = maxAmountPerTx;
        maxAmountPerTx = newMax;
        emit MaxAmountUpdated(old, newMax);
    }

    function setMaxSlippageBps(uint256 newBps) external onlyPermissionSigner {
        if (newBps > 9_999) revert SlippageBpsTooLarge(newBps);
        uint256 old = maxSlippageBps;
        maxSlippageBps = newBps;
        emit MaxSlippageUpdated(old, newBps);
    }

    // ── IPermission ───────────────────────────────────────────────────────────

    /// @inheritdoc IPermission
    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool) {
        if (!isAllowedRouter[ctx.target]) return false;

        // ── Uniswap V3 exactInputSingle ───────────────────────────────────────
        if (ctx.selector == EXACT_INPUT_SINGLE) {
            if (txData.length < LEN_V3) return false;

            // ExactInputSingleParams: tokenIn, tokenOut, fee, recipient, deadline,
            //                         amountIn, amountOutMinimum, sqrtPriceLimitX96
            (
                address tokenIn,
                address tokenOut,
                ,              // fee (uint24)
                address recipient,
                ,              // deadline (uint256)
                uint256 amountIn,
                uint256 amountOutMinimum,
            ) = abi.decode(
                txData[4:],
                (address, address, uint24, address, uint256, uint256, uint256, uint160)
            );

            if (!isAllowedTokenIn[tokenIn])   return false;
            if (!isAllowedTokenOut[tokenOut]) return false;
            if (recipient != ctx.account)     return false;
            if (amountIn > maxAmountPerTx)    return false;

            return _oracleCheck(tokenIn, tokenOut, amountIn, amountOutMinimum);
        }

        // ── Uniswap V2 swapExactTokensForTokens ──────────────────────────────
        if (ctx.selector == SWAP_EXACT_TOKENS) {
            if (txData.length < LEN_V2_MIN) return false;

            (
                uint256 amountIn,
                uint256 amountOutMin,
                address[] memory path,
                address to,
            ) = abi.decode(txData[4:], (uint256, uint256, address[], address, uint256));

            if (path.length < 2)                               return false;
            if (!isAllowedTokenIn[path[0]])                    return false;
            if (!isAllowedTokenOut[path[path.length - 1]])     return false;
            if (to != ctx.account)                             return false;
            if (amountIn > maxAmountPerTx)                     return false;

            return _oracleCheck(path[0], path[path.length - 1], amountIn, amountOutMin);
        }

        return false;
    }

    /// @inheritdoc IPermission
    function discriminator() external pure returns (bytes32) {
        return keccak256("BoundedSwapPermission");
    }

    // ── internal ──────────────────────────────────────────────────────────────

    /// @dev Passes immediately when oracle is disabled (address(0) or slippage = 0).
    ///      Otherwise checks amountOutMin >= oracle_price * amountIn * (1 - slippage).
    function _oracleCheck(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 amountOutMin
    ) internal view returns (bool) {
        if (priceOracle == address(0) || maxSlippageBps == 0) return true;

        (uint256 price, uint8 dec) = IOracle(priceOracle).getPrice(tokenIn, tokenOut);
        if (price == 0) return false;

        // expectedOut = amountIn × price / 10^dec   (overflow-safe via mulDiv)
        uint256 expectedOut  = Math.mulDiv(amountIn, price, 10 ** uint256(dec));
        // oracleMinOut = expectedOut × (10000 − slippage) / 10000
        uint256 oracleMinOut = Math.mulDiv(expectedOut, 10_000 - maxSlippageBps, 10_000);

        return amountOutMin >= oracleMinOut;
    }
}
