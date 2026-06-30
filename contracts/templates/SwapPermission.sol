// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {Context} from "../interfaces/IPermission.sol";
import {IOracle} from "../interfaces/IOracle.sol";
import {IPermissionIntrospection} from "../interfaces/IPermissionIntrospection.sol";
import {SailCapabilities} from "../interfaces/SailCapabilities.sol";
import {ConfigurablePermission} from "./ConfigurablePermission.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

/// @title  SwapPermission — oracle-gated bounded swap (recommended default)
/// @notice REFERENCE LAUNCH TEMPLATE — part of the hardened reference set, NOT part of the
///         trusted core. This is one of the seven hardened launch templates.
///         It is documented with the honest boundaries below
///         ("what this cannot protect against"). It sits OUTSIDE the trusted core
///         (SailKernel, SailGovernance, MandateFactory, StandardFeePolicy, SafeModuleEnabler):
///         a bug here cannot reach the kernel or accounts that have not registered it. The
///         kernel evaluates any permission safely under staticcall + a gas cap + fail-closed
///         semantics, but it does NOT verify that this permission's logic correctly enforces
///         what its NatSpec claims, so registrants remain responsible for reviewing it. The
///         loud "UNAUDITED — EXPERIMENTAL" banner is reserved for the future experimental template
///         set (currently empty), not this hardened launch set. See docs/SECURITY.md for the
///         reference-template documentation.
///
///         WHAT IT IS. The recommended default swap template. One deployment serves any number
///         of accounts; each account stores its own routers, token allowlists, per-tx amount cap,
///         slippage tolerance, and oracle. It gates a manager's swaps so that for every trade the
///         input/output tokens and the router are allowlisted, the input amount is within a per-tx
///         cap, the output recipient is the account itself, and the caller-supplied minimum-out
///         clears a slippage band derived from an injected price reference.
///
///         TRUST MODEL. An oracle is REQUIRED (see OracleRequired). The price reference is an
///         injected IOracle adapter — NOT the AMM pool being traded — so the band is measured
///         against an independent source rather than the same spot price an attacker can move.
///
///         VENUE BOUNDARY. Decodes standard AMM router ABIs only:
///           - V2  swapExactTokensForTokens(uint256,uint256,address[],address,uint256)
///           - V3  exactInputSingle(struct) — both the SwapRouter (with deadline) and the
///                 SwapRouter02 (no deadline) layouts.
///         These ABIs are shared byte-for-byte by Uniswap and its forks (PancakeSwap, SushiSwap,
///         Aerodrome-classic, etc.); cross-protocol/chain coverage comes from the router allowlist,
///         not from per-protocol code. It does NOT cover the Universal Router, Uniswap V4, or DEX
///         aggregators (1inch/Matcha/CoW): those carry swap parameters inside an opaque
///         command/bytes payload that cannot be decoded at a fixed offset.
///
///         HONEST BOUNDARY — what it does NOT do. The slippage band is only as strong as the
///         configured feed: it is only as good as the configured oracle's honesty and freshness and
///         does NOT protect against a manipulated or compromised oracle. The amount cap is
///         per-transaction, NOT cumulative — a manager may make many at-cap trades. The template
///         constrains the swap shape, not the wisdom of the trade.
///
///         NATIVE VALUE REJECTED. A dispatch carrying ctx.value != 0 is denied: this is an
///         allowance-based ERC-20 → ERC-20 template, so no ETH is ever forwarded to a router
///         (closing the payable-router / refundETH() ETH-sweep vector).
///
///         GAS BUDGET (operator note). This template's own evaluate cost is light — one oracle read
///         plus a decode and a couple of mulDivs — but the whole evaluation runs under the kernel's
///         150k PERMISSION_GAS_CAP. A heavy operator-supplied oracle adapter can push the evaluation
///         over that cap, which fails closed (deny). Operators must budget their adapter's gas.
///
///         CONFIG FRESHNESS (fail-closed). Evaluation denies unless this account is configured AND
///         its stored config epoch equals the kernel's current registration epoch for this
///         (account, permission). A configuration left over from a prior registration — e.g. after a
///         revoke / re-register cycle — is never honoured.
///
/// @dev    Config blob:
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

    /// @dev Cap on each config allowlist length, matching the other launch templates. Bounds the
    ///      gas of a later reconfigure so a too-large config cannot brick the permission.
    uint256 private constant MAX_ALLOWLIST_LENGTH = 50;

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
    /// @notice Thrown when an account is configured without a price oracle. The oracle is
    ///         mandatory by design: this template must never run reference-free. Accounts that
    ///         deliberately want no on-chain band must use SwapPermissionNoOracle instead.
    error OracleRequired();
    /// @notice Thrown when a config allowlist exceeds MAX_ALLOWLIST_LENGTH.
    error AllowlistTooLong();

    constructor(address _kernel, address _author)
        ConfigurablePermission(_kernel, "SwapPermission", "2")
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

        if (routers.length > MAX_ALLOWLIST_LENGTH
            || tokensIn.length > MAX_ALLOWLIST_LENGTH
            || tokensOut.length > MAX_ALLOWLIST_LENGTH) revert AllowlistTooLong();
        if (maxSlippageBps > 9_999) revert SlippageBpsTooLarge(maxSlippageBps);
        // The oracle is mandatory by design: without it the template would have no on-chain price
        // reference and could only fall back to trusting the manager's quote. That reference-free
        // mode lives in SwapPermissionNoOracle, never here — so reject a missing oracle outright.
        if (priceOracle == address(0)) revert OracleRequired();
        // A configured oracle must come with a freshness bound; 0 would silently accept
        // arbitrarily stale prices and re-open the staleness gap the oracle is meant to close.
        if (maxPriceAgeSec == 0) revert MissingPriceAge();

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
        // Fail closed unless the stored config is current for this registration epoch.
        if (!_configCurrent(ctx.account, ctx.configEpoch)) return false;
        // Swaps pull tokenIn via ERC-20 allowance; no supported router call needs native ETH.
        // A payable router (e.g. V3 exactInputSingle) would otherwise let an attached value be
        // forwarded to the router and swept via refundETH — reject nonzero value outright.
        if (ctx.value != 0) return false;
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
            // A token-for-itself swap is value-destroying by definition (no legitimate use) and,
            // with an oracle reporting a fresh base==quote price, would otherwise clear the band.
            if (tokenIn == tokenOut)                       return false;
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
            if (tokenIn == tokenOut)                       return false;
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
            // Load-bearing self-route guard: a round-trip path (e.g. [A,B,A]) executes and burns
            // AMM fees while the oracle's base==quote price clears the band. Reject equal endpoints.
            if (path[0] == path[path.length - 1])                         return false;
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
        // The oracle is guaranteed non-zero (enforced at configure() via OracleRequired), so the
        // band is ALWAYS enforced here. maxSlippageBps == 0 is treated as zero tolerance
        // (exact-out-or-better) — the strictest valid setting, never a bypass.
        // On L2s, check sequencer-uptime first.
        (uint256 price, uint8 dec, uint256 updatedAt) = IOracle(s.priceOracle).getPrice(tokenIn, tokenOut);
        if (s.maxPriceAgeSec > 0 && (updatedAt == 0 || block.timestamp - updatedAt > s.maxPriceAgeSec)) return false;
        if (price == 0) return false;
        if (dec > 77) return false;
        uint256 expectedOut  = Math.mulDiv(amountIn, price, 10 ** uint256(dec));
        uint256 oracleMinOut = Math.mulDiv(expectedOut, 10_000 - s.maxSlippageBps, 10_000);
        // Both mulDivs floor, so for very-low-decimal output tokens (especially 0-decimal) the
        // computed oracleMinOut floor can sit up to one base unit below the exact oracle-implied
        // minimum near an integer boundary — i.e. the band can be up to one base unit lax. This is
        // negligible for typical 6–18 decimal tokens and bounded to a single base unit. The oracle
        // band is a sanity bound; the manager-supplied amountOutMin remains the primary slippage floor.
        // Integer division floors: a small enough trade (low price / high-decimal token / tiny
        // amountIn) can truncate oracleMinOut to 0, at which point `amountOutMin >= 0` would wave
        // ANY minimum-out through — including 0 — silently defeating the band. Fail closed instead:
        // if there is no positive floor to enforce, deny rather than pretend to protect. Dust-sized
        // trades are denied under an oracle as a deliberate consequence.
        if (oracleMinOut == 0) return false;
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
