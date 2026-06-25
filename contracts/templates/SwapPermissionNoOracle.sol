// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {Context} from "../interfaces/IPermission.sol";
import {IPermissionIntrospection} from "../interfaces/IPermissionIntrospection.sol";
import {SailCapabilities} from "../interfaces/SailCapabilities.sol";
import {ConfigurablePermission} from "./ConfigurablePermission.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

/// @dev Minimal views needed to read a live price from an operator-named reference pool.
///      token0()/token1() share the same selectors on V2 and V3, so one interface covers both.
interface IPoolTokens {
    function token0() external view returns (address);
    function token1() external view returns (address);
}
interface IUniswapV2PairLike {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}
interface IUniswapV3PoolLike {
    function slot0()
        external
        view
        returns (uint160 sqrtPriceX96, int24 tick, uint16 obsIndex, uint16 obsCard, uint16 obsCardNext, uint8 feeProtocol, bool unlocked);
    function liquidity() external view returns (uint128);
}

/// @title  SwapPermissionNoOracle — bounded swap with a pool-referenced hallucination sanity band
/// @notice MINIMAL-GUARANTEE SHIPPING TEMPLATE — part of the launch template set.
///         It enforces only a non-zero minimum-out plus a pool-referenced hallucination
///         floor; it provides NO oracle-based, manipulation-resistant slippage protection —
///         use the oracle-gated SwapPermission for that. Read "WHAT IT DOES NOT PROTECT
///         AGAINST" below before relying on it. The kernel evaluates any permission safely
///         under staticcall + a gas cap + fail-closed semantics, but it does NOT verify that
///         this permission's logic correctly enforces what its NatSpec claims. Anyone
///         registering this permission is responsible for understanding its narrow guarantee.
///         See docs/SECURITY.md for the audit-scope documentation.
///
///         WHAT IT IS. A swap template for tokens that have NO oracle — i.e. no independent,
///         manipulation-resistant price feed. It is the non-oracle tier of the swap templates; for
///         manipulation-resistant price protection use the oracle-gated SwapPermission instead.
///         One deployment serves any number of accounts; each account stores its own routers, token
///         allowlists, per-tx cap, and a per-pair reference pool.
///
///         WHAT IT ENFORCES. For every trade: the input/output tokens and the router are
///         allowlisted; the input amount is within a per-tx cap; the output recipient is the
///         account itself; the caller-supplied minimum-out is non-zero; and — the sanity band — the
///         minimum-out is not more than the pair's operator-set toleranceBps below the output
///         implied by the live price of the operator-named reference pool for that pair. The check
///         fails closed (denies) if the reference pool is missing, unreadable, illiquid, or does not
///         correspond to the traded pair, or if the tolerance-adjusted floor rounds to zero.
///
///         WHAT THE SANITY BAND IS FOR. It is a HALLUCINATION GUARD: it catches an honest but
///         mistaken manager/agent that tries to trade at a wildly wrong price (a reasoning error, a
///         misparsed quote, a fabricated number). A confused agent is not also manipulating the
///         pool, so a live-pool comparison reliably flags the mistake.
///
///         WHAT IT DOES NOT PROTECT AGAINST — read this. The reference is a SINGLE pool's LIVE spot
///         price, which ANY party can move within the same transaction — a sandwich/MEV bot, a
///         malicious manager, or a compromised agent can flash-loan the pool to a price of their
///         choosing immediately before the gated swap. Against an in-transaction price manipulator
///         this check provides NO protection whatsoever; it is NOT a slippage defense and must not
///         be relied on as one. The operator-named pool is a convenience reference, NOT a trusted
///         or manipulation-resistant price source. For price protection that resists manipulation,
///         use the oracle-gated SwapPermission, which measures against an independent,
///         freshness-checked feed rather than a live pool. The cap is per-transaction, not
///         cumulative.
///
///         VENUE BOUNDARY. Decodes standard AMM router ABIs only:
///           - V2  swapExactTokensForTokens(uint256,uint256,address[],address,uint256)
///           - V3  exactInputSingle(struct) — both the SwapRouter (with deadline) and the
///                 SwapRouter02 (no deadline) layouts.
///         These ABIs are shared byte-for-byte by Uniswap and its forks (PancakeSwap, SushiSwap,
///         Aerodrome-classic, etc.); cross-protocol/chain coverage comes from the router allowlist,
///         not from per-protocol code. It does NOT cover the Universal Router, Uniswap V4, or DEX
///         aggregators (1inch/Matcha/CoW): those carry swap parameters inside an opaque
///         command/bytes payload that cannot be decoded at a fixed offset. The reference pool is a
///         V2 pair or a V3 pool, declared per pair by the operator.
///
/// @dev    The structural/decode region (the three selector decode blocks, the allowlist checks,
///         the size cap, and the recipient pin) is kept verbatim in sync with SwapPermission; the
///         only differences are the price judgement (a pool-referenced band here vs an oracle band
///         there) and the config blob. If either file's decode logic changes, BOTH must be updated.
///
///         Config blob:
///             abi.encode(
///                 address[]        routers,
///                 address[]        tokensIn,
///                 address[]        tokensOut,
///                 uint256          maxAmountPerTx,
///                 ReferencePool[]  referencePools   // one per allowed (tokenIn, tokenOut) pair
///             )
contract SwapPermissionNoOracle is ConfigurablePermission, IPermissionIntrospection {
    // exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160)) — V3 SwapRouter (with deadline)
    bytes4 private constant EXACT_INPUT_SINGLE_V1 = 0x414bf389;
    // exactInputSingle((address,address,uint24,address,uint256,uint256,uint160)) — V3 SwapRouter02 (no deadline)
    bytes4 private constant EXACT_INPUT_SINGLE_V2 = 0x04e45aaf;
    // swapExactTokensForTokens(uint256,uint256,address[],address,uint256)
    bytes4 private constant SWAP_EXACT_TOKENS     = 0x38ed1739;

    uint256 private constant LEN_V3_V1  = 260;
    uint256 private constant LEN_V3_V2  = 228;
    uint256 private constant LEN_V2_MIN = 196;

    uint256 private constant Q96 = 1 << 96;

    /// @dev Maximum sanity-band width. 50% — wide enough for a generous "catch a gross error" band,
    ///      narrow enough that the band still means something. A larger value would make the band
    ///      meaningless, so it is rejected at configure().
    uint256 private constant MAX_TOLERANCE_BPS = 5_000;

    enum PoolKind { V2, V3 }

    /// @notice Operator-declared reference pool for a directional (tokenIn, tokenOut) pair.
    struct ReferencePool {
        address  tokenIn;
        address  tokenOut;
        address  pool;
        PoolKind kind;
        uint256  toleranceBps;
    }

    /// @dev Stored, evaluate-time form: orientation is precomputed at configure() (pool tokens are
    ///      immutable), so evaluate never needs token0()/token1(). A zero `pool` means "no reference
    ///      configured for this pair" → deny.
    struct PoolRef {
        address  pool;
        PoolKind kind;
        uint256  toleranceBps;
        bool     tokenInIsToken0;
    }

    struct Slot {
        address[] routers;
        address[] tokensIn;
        address[] tokensOut;
        uint256   maxAmountPerTx;
        bytes32[] referencePairKeys; // keys written into poolFor, tracked so reconfigure can clear them
    }

    mapping(address account => Slot) private _slots;
    mapping(address account => mapping(address => bool)) public isAllowedRouter;
    mapping(address account => mapping(address => bool)) public isAllowedTokenIn;
    mapping(address account => mapping(address => bool)) public isAllowedTokenOut;
    /// @dev poolFor[account][keccak256(tokenIn, tokenOut)] — the per-pair reference pool.
    mapping(address account => mapping(bytes32 pairKey => PoolRef)) public poolFor;

    /// @notice Tooling-layer attribution for the template author. The kernel never reads this.
    address public immutable author;

    error ToleranceTooLarge(uint256 bps);
    error ZeroPool();
    error PairNotAllowlisted(address tokenIn, address tokenOut);
    error PoolTokenMismatch(address pool);
    error MissingReferencePool(address tokenIn, address tokenOut);

    constructor(address _kernel, address _author)
        ConfigurablePermission(_kernel, "SwapPermissionNoOracle", "2")
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
            uint256 maxAmountPerTx
        )
    {
        Slot storage s = _slots[account];
        return (s.routers, s.tokensIn, s.tokensOut, s.maxAmountPerTx);
    }

    /// @notice The reference pool configured for a directional pair (zero `pool` = none).
    function referencePoolFor(address account, address tokenIn, address tokenOut)
        external
        view
        returns (PoolRef memory)
    {
        return poolFor[account][_pairKey(tokenIn, tokenOut)];
    }

    // ── config application ────────────────────────────────────────────────────

    function _applyConfig(address account, bytes calldata params) internal override {
        (
            address[] memory routers,
            address[] memory tokensIn,
            address[] memory tokensOut,
            uint256 maxAmountPerTx,
            ReferencePool[] memory referencePools
        ) = abi.decode(params, (address[], address[], address[], uint256, ReferencePool[]));

        Slot storage s = _slots[account];

        // Clear previous allowlists and previous per-pair reference pools for this account.
        for (uint256 i; i < s.routers.length; i++)   isAllowedRouter[account][s.routers[i]] = false;
        for (uint256 i; i < s.tokensIn.length; i++)  isAllowedTokenIn[account][s.tokensIn[i]] = false;
        for (uint256 i; i < s.tokensOut.length; i++) isAllowedTokenOut[account][s.tokensOut[i]] = false;
        for (uint256 i; i < s.referencePairKeys.length; i++) delete poolFor[account][s.referencePairKeys[i]];
        delete s.referencePairKeys;

        // Apply allowlists.
        for (uint256 i; i < routers.length; i++)   isAllowedRouter[account][routers[i]]     = true;
        for (uint256 i; i < tokensIn.length; i++)  isAllowedTokenIn[account][tokensIn[i]]   = true;
        for (uint256 i; i < tokensOut.length; i++) isAllowedTokenOut[account][tokensOut[i]] = true;

        // Apply + validate reference pools.
        for (uint256 i; i < referencePools.length; i++) {
            ReferencePool memory r = referencePools[i];
            if (r.toleranceBps > MAX_TOLERANCE_BPS) revert ToleranceTooLarge(r.toleranceBps);
            if (r.pool == address(0)) revert ZeroPool();
            // (PoolKind is range-checked by abi.decode; an out-of-range enum reverts on decode.)
            if (!isAllowedTokenIn[account][r.tokenIn] || !isAllowedTokenOut[account][r.tokenOut]) {
                revert PairNotAllowlisted(r.tokenIn, r.tokenOut);
            }
            // Validate the named pool actually prices this pair, and precompute orientation. Pool
            // tokens are immutable on both venues, so a config-time check is sound and lets evaluate
            // trust pair membership.
            address t0 = IPoolTokens(r.pool).token0();
            address t1 = IPoolTokens(r.pool).token1();
            bool tokenInIsToken0;
            if (t0 == r.tokenIn && t1 == r.tokenOut)      tokenInIsToken0 = true;
            else if (t0 == r.tokenOut && t1 == r.tokenIn) tokenInIsToken0 = false;
            else revert PoolTokenMismatch(r.pool);

            bytes32 key = _pairKey(r.tokenIn, r.tokenOut);
            poolFor[account][key] =
                PoolRef({pool: r.pool, kind: r.kind, toleranceBps: r.toleranceBps, tokenInIsToken0: tokenInIsToken0});
            s.referencePairKeys.push(key);
        }

        // Strict coverage: every tradeable directional pair must have a reference pool. A swap is
        // tradeable when tokenIn ∈ tokensIn and tokenOut ∈ tokensOut, so require a pool for every
        // such combination. Degenerate self-pairs (tokenIn == tokenOut) are skipped — no pool can
        // price a token against itself, and such a swap denies at evaluate regardless. Surfacing a
        // gap at configure() is clearer than silent fail-closed denials later.
        for (uint256 i; i < tokensIn.length; i++) {
            for (uint256 j; j < tokensOut.length; j++) {
                if (tokensIn[i] == tokensOut[j]) continue;
                if (poolFor[account][_pairKey(tokensIn[i], tokensOut[j])].pool == address(0)) {
                    revert MissingReferencePool(tokensIn[i], tokensOut[j]);
                }
            }
        }

        s.routers        = routers;
        s.tokensIn       = tokensIn;
        s.tokensOut      = tokensOut;
        s.maxAmountPerTx = maxAmountPerTx;
    }

    // ── IPermission ───────────────────────────────────────────────────────────

    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool) {
        // Fail closed unless the stored config is current for this registration epoch (Octane #2/#8).
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
            if (!isAllowedTokenIn[ctx.account][tokenIn])   return false;
            if (!isAllowedTokenOut[ctx.account][tokenOut]) return false;
            if (recipient != ctx.account)                  return false;
            if (amountIn > s.maxAmountPerTx)               return false;
            return _sanityCheck(ctx.account, tokenIn, tokenOut, amountIn, amountOutMinimum);
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
            return _sanityCheck(ctx.account, tokenIn, tokenOut, amountIn, amountOutMinimum);
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
            return _sanityCheck(ctx.account, path[0], path[path.length - 1], amountIn, amountOutMin);
        }

        return false;
    }

    function discriminator() external pure returns (bytes32) {
        return keccak256("SwapPermissionNoOracle");
    }

    // ── internal ──────────────────────────────────────────────────────────────

    function _pairKey(address tokenIn, address tokenOut) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(tokenIn, tokenOut));
    }

    /// @dev The pool-referenced sanity band. Reads the live price of the operator-named reference
    ///      pool for this pair and requires amountOutMin to be within toleranceBps of the implied
    ///      output. Fail-closed on a missing/unreadable/illiquid pool or a zero floor. This is a
    ///      hallucination guard against an honest mistake — it is NOT manipulation-resistant (the
    ///      live pool price can be moved within the transaction; see the contract header).
    function _sanityCheck(address account, address tokenIn, address tokenOut, uint256 amountIn, uint256 amountOutMin)
        internal
        view
        returns (bool)
    {
        PoolRef storage rp = poolFor[account][_pairKey(tokenIn, tokenOut)];
        if (rp.pool == address(0)) return false; // no reference pool configured for this pair

        (bool ok, uint256 expectedOut) = _readExpectedOut(rp, amountIn);
        if (!ok || expectedOut == 0) return false; // unreadable/illiquid, or truncated to zero

        uint256 poolFloor = Math.mulDiv(expectedOut, 10_000 - rp.toleranceBps, 10_000);
        // Truncation-to-zero guard: a floor of zero would wave any minimum-out through, defeating
        // the band — fail closed instead.
        if (poolFloor == 0) return false;
        if (amountOutMin < poolFloor) return false;

        // Kept non-zero floor as cheap additional defense-in-depth (redundant while poolFloor > 0).
        return amountOutMin > 0;
    }

    /// @dev Reads the live price from the reference pool and returns the implied output for
    ///      amountIn, in tokenOut raw units (decimals cancel within the pair). Returns ok=false on
    ///      any read failure or illiquidity, so the caller fails closed.
    function _readExpectedOut(PoolRef storage rp, uint256 amountIn) internal view returns (bool ok, uint256 expectedOut) {
        if (rp.kind == PoolKind.V2) {
            try IUniswapV2PairLike(rp.pool).getReserves() returns (uint112 r0, uint112 r1, uint32) {
                if (r0 == 0 || r1 == 0) return (false, 0);
                (uint256 reserveIn, uint256 reserveOut) =
                    rp.tokenInIsToken0 ? (uint256(r0), uint256(r1)) : (uint256(r1), uint256(r0));
                return (true, Math.mulDiv(amountIn, reserveOut, reserveIn));
            } catch {
                return (false, 0);
            }
        } else {
            try IUniswapV3PoolLike(rp.pool).slot0() returns (uint160 sqrtP, int24, uint16, uint16, uint16, uint8, bool) {
                if (sqrtP == 0) return (false, 0);
                try IUniswapV3PoolLike(rp.pool).liquidity() returns (uint128 liq) {
                    if (liq == 0) return (false, 0);
                    if (rp.tokenInIsToken0) {
                        // price = (sqrtP / 2^96)^2 token1 per token0; out = in * price
                        uint256 tmp = Math.mulDiv(amountIn, sqrtP, Q96);
                        return (true, Math.mulDiv(tmp, sqrtP, Q96));
                    } else {
                        // out = in / price
                        uint256 tmp = Math.mulDiv(amountIn, Q96, sqrtP);
                        return (true, Math.mulDiv(tmp, Q96, sqrtP));
                    }
                } catch {
                    return (false, 0);
                }
            } catch {
                return (false, 0);
            }
        }
    }

    // ── IPermissionIntrospection ──────────────────────────────────────────────

    function permissionId() external pure override returns (bytes32) {
        return keccak256("sail.permission.SwapPermissionNoOracle.v1");
    }

    function permissionVersion() external pure override returns (bytes32) {
        return keccak256("v1");
    }

    function metadataURI() external pure override returns (string memory) {
        return "";
    }

    function capabilityIds() external pure override returns (bytes32[] memory ids) {
        ids = new bytes32[](1);
        ids[0] = SailCapabilities.SWAP_NO_ORACLE;
    }
}
