// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {Context} from "../../interfaces/IPermission.sol";
import {IOracle} from "../../interfaces/IOracle.sol";
import {IPermissionIntrospection} from "../../interfaces/IPermissionIntrospection.sol";
import {SailCapabilities} from "../../interfaces/SailCapabilities.sol";
import {ConfigurablePermission} from "./ConfigurablePermission.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

/// @notice Reference swap permission (Uniswap V3 / V3-02 / V2). One deployment serves any
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
///                 address   priceOracle,
///                 uint256   maxPriceAgeSec
///             )
contract SwapPermission is ConfigurablePermission, IPermissionIntrospection {
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
        uint256   maxPriceAgeSec;
    }

    mapping(address account => Slot) private _slots;
    mapping(address account => mapping(address => bool)) public isAllowedRouter;
    mapping(address account => mapping(address => bool)) public isAllowedTokenIn;
    mapping(address account => mapping(address => bool)) public isAllowedTokenOut;

    /// @notice Tooling-layer attribution for the template author. The kernel never reads this.
    address public immutable author;

    error SlippageBpsTooLarge(uint256 bps);

    constructor(address _kernel, address _author)
        ConfigurablePermission(_kernel, "SwapPermission", "1")
    {
        author = _author;
    }

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
            address priceOracle,
            uint256 maxPriceAgeSec
        )
    {
        Slot storage s = _slots[account];
        return (s.routers, s.tokensIn, s.tokensOut, s.maxAmountPerTx, s.maxSlippageBps, s.priceOracle, s.maxPriceAgeSec);
    }

    // ── config application ────────────────────────────────────────────────────

    function _applyConfig(address account, bytes calldata params) internal override {
        (
            address[] memory routers,
            address[] memory tokensIn,
            address[] memory tokensOut,
            uint256 maxAmountPerTx,
            uint256 maxSlippageBps,
            address priceOracle,
            uint256 maxPriceAgeSec
        ) = abi.decode(params, (address[], address[], address[], uint256, uint256, address, uint256));

        if (maxSlippageBps > 9_999) revert SlippageBpsTooLarge(maxSlippageBps);
        // A configured oracle must come with a freshness bound; 0 would silently accept
        // arbitrarily stale prices and re-open the staleness gap the oracle is meant to close.
        if (priceOracle != address(0) && maxPriceAgeSec == 0) revert MissingPriceAge();

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
        s.maxPriceAgeSec = maxPriceAgeSec;
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
        return keccak256("SwapPermission");
    }

    // ── internal ──────────────────────────────────────────────────────────────

    function _oracleCheck(
        Slot storage s,
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 amountOutMin
    ) internal view returns (bool) {
        // No oracle configured: the template cannot derive a price floor on-chain. Rather than
        // fail open (which would let a manager pass amountOutMin = 0 and be sandwiched), require
        // a non-zero caller-supplied minimum-out. The manager remains responsible for choosing a
        // sane value; the template guarantees only that it is not zero.
        if (s.priceOracle == address(0)) {
            return amountOutMin > 0;
        }

        // Oracle configured: ALWAYS enforce the band. maxSlippageBps == 0 is treated as zero
        // tolerance (exact-out-or-better) — the strictest valid setting, never a bypass.
        // On L2s, check sequencer-uptime first.
        (uint256 price, uint8 dec, uint256 updatedAt) = IOracle(s.priceOracle).getPrice(tokenIn, tokenOut);
        if (s.maxPriceAgeSec > 0 && (updatedAt == 0 || block.timestamp - updatedAt > s.maxPriceAgeSec)) return false;
        if (price == 0) return false;
        if (dec > 77) return false;
        uint256 expectedOut  = Math.mulDiv(amountIn, price, 10 ** uint256(dec));
        uint256 oracleMinOut = Math.mulDiv(expectedOut, 10_000 - s.maxSlippageBps, 10_000);
        return amountOutMin >= oracleMinOut;
    }

    // ── IPermissionIntrospection ──────────────────────────────────────────────

    function permissionId() external pure override returns (bytes32) {
        return keccak256("sail.permission.SwapPermission.v1");
    }

    function permissionVersion() external pure override returns (bytes32) {
        return keccak256("v1");
    }

    function metadataURI() external pure override returns (string memory) {
        return "";
    }

    function capabilityIds() external pure override returns (bytes32[] memory ids) {
        ids = new bytes32[](1);
        ids[0] = SailCapabilities.BOUNDED_SWAP;
    }
}
