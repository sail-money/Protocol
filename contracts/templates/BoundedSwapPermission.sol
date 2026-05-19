// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {IPermission, Context} from "../interfaces/IPermission.sol";
import {IOracle} from "../interfaces/IOracle.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {CloneInitializable} from "./base/CloneInitializable.sol";

/// @title  BoundedSwapPermission
/// @notice Gates DEX swaps so the manager can only trade through approved routers,
///         with approved tokens, within an amount cap, and — when an oracle is
///         configured — within a slippage band derived from the on-chain price.
///
///         Supported selectors:
///           0x414bf389  exactInputSingle(ExactInputSingleParams)  — Uniswap V3 SwapRouter (with deadline)
///           0x04e45aaf  exactInputSingle(ExactInputSingleParams)  — Uniswap V3 SwapRouter02 (no deadline)
///           0x38ed1739  swapExactTokensForTokens(...)            — Uniswap V2 Router
///
/// @dev    Oracle check behaviour:
///           • `priceOracle == address(0)` OR `maxSlippageBps == 0` → oracle disabled,
///             no minimum output is enforced beyond the router's own slippage param.
///           • Setting `maxSlippageBps = 0` is an explicit opt-out, not "0% tolerance".
///             Use it only when you intend to remove slippage protection entirely.
///
///         Intermediate tokens in V2 multi-hop paths are NOT validated against
///         `isAllowedTokenIn`/`isAllowedTokenOut` — only path[0] and path[last] are
///         checked. Operators must ensure the full path is acceptable.
/// @custom:security-contact security@sail.money
/// @dev CLONE TEMPLATE: Deploy the logic contract once; use PermissionFactory.deployAndAttach to create per-account clones.
contract BoundedSwapPermission is IPermission, CloneInitializable {
    /// @notice Marks this as a single-account template (not a shared multi-account deployment).
    bool public constant IS_SINGLE_ACCOUNT = true;
    // -------------------------------------------------------------------------
    // Selectors
    // -------------------------------------------------------------------------

    /// @dev Uniswap V3 SwapRouter:
    ///      exactInputSingle((tokenIn,tokenOut,fee,recipient,deadline,amountIn,amountOutMinimum,sqrtPriceLimitX96))
    bytes4 private constant EXACT_INPUT_SINGLE_V1 = 0x414bf389;

    /// @dev Uniswap V3 SwapRouter02 (deadline dropped — checkout uses block.timestamp internally):
    ///      exactInputSingle((tokenIn,tokenOut,fee,recipient,amountIn,amountOutMinimum,sqrtPriceLimitX96))
    bytes4 private constant EXACT_INPUT_SINGLE_V2 = 0x04e45aaf;

    /// @dev swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] path, address to, uint256 deadline)
    bytes4 private constant SWAP_EXACT_TOKENS    = 0x38ed1739;

    // -------------------------------------------------------------------------
    // Calldata length constants
    // -------------------------------------------------------------------------

    /// @dev Minimum calldata length for V3 SwapRouter exactInputSingle:
    ///      selector(4) + 8 struct words × 32 = 260 bytes.
    uint256 private constant LEN_V3_V1 = 260;

    /// @dev Minimum calldata length for V3 SwapRouter02 exactInputSingle:
    ///      selector(4) + 7 struct words × 32 = 228 bytes.
    uint256 private constant LEN_V3_V2 = 228;

    /// @dev Minimum calldata length for V2 swapExactTokensForTokens structural check:
    ///      selector(4) + 5 head words × 32 (amountIn, amountOutMin, pathOffset, to, deadline)
    ///      + 1 path-length word × 32 = 196 bytes.
    ///      The actual minimum for a valid 2-element path is larger; path.length < 2 is checked
    ///      after decode.
    uint256 private constant LEN_V2_MIN = 196;

    // -------------------------------------------------------------------------
    // Allowlists
    // -------------------------------------------------------------------------

    /// @notice DEX router addresses the manager may route swaps through.
    mapping(address router => bool) public isAllowedRouter;

    /// @notice ERC-20 tokens the manager may sell (input token / path[0]).
    mapping(address token  => bool) public isAllowedTokenIn;

    /// @notice ERC-20 tokens the manager may buy (output token / path[last]).
    mapping(address token  => bool) public isAllowedTokenOut;

    // -------------------------------------------------------------------------
    // Mutable parameters
    // -------------------------------------------------------------------------

    /// @notice Per-transaction cap on `amountIn` (inclusive).
    uint256 public maxAmountPerTx;

    /// @notice Slippage tolerance in basis points (max 9 999).
    ///         0 = oracle check disabled entirely.
    /// @dev    Values up to 9 999 are accepted; 10 000 would compute oracleMinOut = 0
    ///         for any price, effectively disabling the floor. Use 0 to explicitly
    ///         opt out rather than setting 10 000.
    uint256 public maxSlippageBps;

    /// @notice Price oracle used for slippage validation. address(0) = oracle disabled.
    address public priceOracle;

    /// @notice Address authorised to update mutable settings.
    address public permissionSigner;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /// @notice Emitted when `maxAmountPerTx` is updated.
    /// @param  oldMax Previous cap value.
    /// @param  newMax New cap value.
    event MaxAmountUpdated(uint256 oldMax, uint256 newMax);

    /// @notice Emitted when `maxSlippageBps` is updated.
    /// @param  oldBps Previous slippage tolerance in basis points.
    /// @param  newBps New slippage tolerance in basis points.
    event MaxSlippageUpdated(uint256 oldBps, uint256 newBps);

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    /// @dev Thrown when a caller other than `permissionSigner` invokes a guarded setter.
    error NotPermissionSigner();

    /// @dev Thrown when a required address argument is the zero address.
    error ZeroAddress();

    /// @dev Thrown when a requested slippage value exceeds 9 999 basis points.
    error SlippageBpsTooLarge(uint256 bps);

    // -------------------------------------------------------------------------
    // Modifier
    // -------------------------------------------------------------------------

    /// @dev Reverts with NotPermissionSigner when caller is not `permissionSigner`.
    modifier onlyPermissionSigner() {
        if (msg.sender != permissionSigner) revert NotPermissionSigner();
        _;
    }

    // -------------------------------------------------------------------------
    // Constructor / Initialize
    // -------------------------------------------------------------------------

    constructor() {}

    /// @notice Called once by PermissionFactory after cloning the logic contract.
    /// @param  allowedRouters     DEX router addresses to pre-populate the router allowlist.
    /// @param  allowedTokensIn    Input token addresses to pre-populate `isAllowedTokenIn`.
    /// @param  allowedTokensOut   Output token addresses to pre-populate `isAllowedTokenOut`.
    /// @param  _maxAmountPerTx    Initial per-transaction amountIn cap.
    /// @param  _maxSlippageBps    Initial slippage tolerance (0–9 999 bps). 0 = oracle disabled.
    /// @param  _priceOracle       Oracle address; address(0) = oracle disabled.
    /// @param  _permissionSigner  Address permitted to update mutable settings.
    function initialize(
        address[] memory allowedRouters,
        address[] memory allowedTokensIn,
        address[] memory allowedTokensOut,
        uint256 _maxAmountPerTx,
        uint256 _maxSlippageBps,
        address _priceOracle,
        address _permissionSigner
    ) external initializer {
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

    // -------------------------------------------------------------------------
    // Setters
    // -------------------------------------------------------------------------

    /// @notice Update the per-transaction amountIn cap.
    /// @param  newMax New cap value (inclusive). Setting to 0 blocks all swaps.
    function setMaxAmountPerTx(uint256 newMax) external onlyPermissionSigner {
        uint256 old = maxAmountPerTx;
        maxAmountPerTx = newMax;
        emit MaxAmountUpdated(old, newMax);
    }

    /// @notice Update the oracle slippage tolerance.
    /// @param  newBps New tolerance in basis points. Must be ≤ 9 999. 0 = disable oracle check.
    function setMaxSlippageBps(uint256 newBps) external onlyPermissionSigner {
        if (newBps > 9_999) revert SlippageBpsTooLarge(newBps);
        uint256 old = maxSlippageBps;
        maxSlippageBps = newBps;
        emit MaxSlippageUpdated(old, newBps);
    }

    // -------------------------------------------------------------------------
    // IPermission
    // -------------------------------------------------------------------------

    /// @inheritdoc IPermission
    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool) {
        if (!isAllowedRouter[ctx.target]) return false;

        // ── Uniswap V3 SwapRouter (V1, with deadline) ─────────────────────────
        if (ctx.selector == EXACT_INPUT_SINGLE_V1) {
            if (txData.length < LEN_V3_V1) return false;

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

        // ── Uniswap V3 SwapRouter02 (V2, no deadline) ─────────────────────────
        if (ctx.selector == EXACT_INPUT_SINGLE_V2) {
            if (txData.length < LEN_V3_V2) return false;

            // ExactInputSingleParams (SwapRouter02): tokenIn, tokenOut, fee, recipient,
            //                                        amountIn, amountOutMinimum, sqrtPriceLimitX96
            (
                address tokenIn,
                address tokenOut,
                ,              // fee (uint24)
                address recipient,
                uint256 amountIn,
                uint256 amountOutMinimum,
            ) = abi.decode(
                txData[4:],
                (address, address, uint24, address, uint256, uint256, uint160)
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

    // -------------------------------------------------------------------------
    // Internal
    // -------------------------------------------------------------------------

    /// @dev Passes immediately when the oracle is disabled (address(0) or slippage = 0).
    ///      Otherwise checks amountOutMin >= oracle_price × amountIn × (1 − slippage).
    ///      Returns false (deny) when the oracle returns price = 0 or decimals > 77
    ///      (decimals > 77 would overflow 10^decimals beyond uint256 max).
    /// @param  tokenIn      ERC-20 address of the token being sold.
    /// @param  tokenOut     ERC-20 address of the token being bought.
    /// @param  amountIn     Amount of tokenIn being sold.
    /// @param  amountOutMin Minimum output specified in the swap calldata.
    /// @return              True if the slippage check passes or the oracle is disabled.
    function _oracleCheck(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 amountOutMin
    ) internal view returns (bool) {
        if (priceOracle == address(0) || maxSlippageBps == 0) return true;

        (uint256 price, uint8 dec,) = IOracle(priceOracle).getPrice(tokenIn, tokenOut);
        if (price == 0) return false;
        // 10^78 overflows uint256; treat as unsupported oracle configuration → deny.
        if (dec > 77) return false;

        // expectedOut = amountIn × price / 10^dec   (overflow-safe via mulDiv)
        uint256 expectedOut  = Math.mulDiv(amountIn, price, 10 ** uint256(dec));
        // oracleMinOut = expectedOut × (10000 − slippage) / 10000
        uint256 oracleMinOut = Math.mulDiv(expectedOut, 10_000 - maxSlippageBps, 10_000);

        return amountOutMin >= oracleMinOut;
    }
}
