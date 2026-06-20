// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {Context} from "../interfaces/IPermission.sol";
import {IPermissionIntrospection} from "../interfaces/IPermissionIntrospection.sol";
import {SailCapabilities} from "../interfaces/SailCapabilities.sol";
import {ConfigurablePermission} from "../templates/shared/ConfigurablePermission.sol";

/// @notice Multi-account permission template that gates Pendle V2 Router V4 operations.
///         One deployment serves any number of accounts; each account stores its own
///         router address, market allowlist, amount cap, and per-domain feature flags.
///
///         Supported operation domains (each can be independently enabled/disabled):
///           • Liquidity — add/removeLiquidity* (10 selectors)
///           • PT swaps  — swapExact{Sy,Token}ForPt / swapExactPtFor{Sy,Token} (4 selectors)
///           • YT swaps  — swapExact{Sy,Token}ForYt / swapExactYtFor{Sy,Token} (4 selectors)
///           • Mint/Redeem — mintPyFrom* / redeemPyTo* (4 selectors)
///           • Claim yield — redeemDueInterestAndRewards (1 selector)
///
///         For mint/redeem operations, the second parameter is a YT address rather than
///         a market; isAllowedMarket is reused as an allowlist for both markets and YTs.
///
///         Config blob:
///             abi.encode(
///                 address   pendleRouter,
///                 address[] allowedMarkets,
///                 uint128   maxAmountPerTx,
///                 bool      allowLiquidityOps,
///                 bool      allowPtSwaps,
///                 bool      allowYtSwaps,
///                 bool      allowMintRedeem,
///                 bool      allowClaimYield
///             )
contract SharedPendlePermission is ConfigurablePermission, IPermissionIntrospection {
    // ── Pendle Router V4 selectors ────────────────────────────────────────────
    // Encoding key (structs expanded to tuple types):
    //   ApproxParams  = (uint256,uint256,uint256,uint256,uint256)
    //   SwapData      = (uint8,address,bytes,bool)
    //   TokenInput    = (address,uint256,address,address,(uint8,address,bytes,bool))
    //   TokenOutput   = (address,uint256,address,address,(uint8,address,bytes,bool))
    //   Order         = (uint256,uint256,uint256,uint8,address,address,address,address,uint256,uint256,uint256,bytes)
    //   FillOrderParams = (Order,bytes,uint256)
    //   LimitOrderData  = (address,uint256,FillOrderParams[],FillOrderParams[],bytes)

    // Liquidity — simple (no struct params in leading positions)
    bytes4 private constant SEL_ADD_DUAL_SY_PT     = bytes4(keccak256("addLiquidityDualSyAndPt(address,address,uint256,uint256,uint256)"));
    bytes4 private constant SEL_REMOVE_DUAL_SY_PT  = bytes4(keccak256("removeLiquidityDualSyAndPt(address,address,uint256,uint256,uint256)"));

    // Liquidity — with TokenInput / TokenOutput structs
    bytes4 private constant SEL_ADD_DUAL_TOK_PT    = 0x2756ce06; // addLiquidityDualTokenAndPt(address,address,(address,uint256,address,address,(uint8,address,bytes,bool)),uint256,uint256)
    bytes4 private constant SEL_REMOVE_DUAL_TOK_PT = 0xb00f09d7; // removeLiquidityDualTokenAndPt(address,address,uint256,(address,uint256,address,address,(uint8,address,bytes,bool)),uint256)
    bytes4 private constant SEL_REMOVE_SINGLE_TOK  = 0x60da0860; // removeLiquiditySingleToken(address,address,uint256,(address,uint256,address,address,(uint8,address,bytes,bool)),(address,uint256,...))
    bytes4 private constant SEL_ADD_SINGLE_TOK     = 0x12599ac6; // addLiquiditySingleToken(address,address,uint256,ApproxParams,TokenInput,LimitOrderData)

    // Liquidity — Sy / Pt amount-first (no struct in first 3 word slots)
    bytes4 private constant SEL_ADD_SINGLE_SY      = 0x58bda475; // addLiquiditySingleSy(address,address,uint256,uint256,ApproxParams,LimitOrderData)
    bytes4 private constant SEL_ADD_SINGLE_PT      = 0x4e390267; // addLiquiditySinglePt(address,address,uint256,uint256,ApproxParams,LimitOrderData)
    bytes4 private constant SEL_REMOVE_SINGLE_SY   = 0xd13b4fdc; // removeLiquiditySingleSy(address,address,uint256,uint256,LimitOrderData)
    bytes4 private constant SEL_REMOVE_SINGLE_PT   = 0x6b77ac9e; // removeLiquiditySinglePt(address,address,uint256,uint256,ApproxParams,LimitOrderData)

    // PT swaps
    bytes4 private constant SEL_SWAP_SY_FOR_PT     = 0x2a50917c; // swapExactSyForPt(address,address,uint256,uint256,ApproxParams,LimitOrderData)
    bytes4 private constant SEL_SWAP_PT_FOR_SY     = 0x3346d3a3; // swapExactPtForSy(address,address,uint256,uint256,LimitOrderData)
    bytes4 private constant SEL_SWAP_TOK_FOR_PT    = 0xc81f847a; // swapExactTokenForPt(address,address,uint256,ApproxParams,TokenInput,LimitOrderData)
    bytes4 private constant SEL_SWAP_PT_FOR_TOK    = 0x594a88cc; // swapExactPtForToken(address,address,uint256,TokenOutput,LimitOrderData)

    // YT swaps
    bytes4 private constant SEL_SWAP_SY_FOR_YT     = 0x7b8b4b95; // swapExactSyForYt(address,address,uint256,uint256,ApproxParams,LimitOrderData)
    bytes4 private constant SEL_SWAP_YT_FOR_SY     = 0x80c4d566; // swapExactYtForSy(address,address,uint256,uint256,LimitOrderData)
    bytes4 private constant SEL_SWAP_TOK_FOR_YT    = 0xed48907e; // swapExactTokenForYt(address,address,uint256,ApproxParams,TokenInput,LimitOrderData)
    bytes4 private constant SEL_SWAP_YT_FOR_TOK    = 0x05eb5327; // swapExactYtForToken(address,address,uint256,TokenOutput,LimitOrderData)

    // Mint / Redeem (YT address in param[1] doubles as market for allowlist check)
    bytes4 private constant SEL_MINT_PY_FROM_TOK   = 0xd0f42385; // mintPyFromToken(address,address,uint256,TokenInput)
    bytes4 private constant SEL_MINT_PY_FROM_SY    = bytes4(keccak256("mintPyFromSy(address,address,uint256,uint256)"));
    bytes4 private constant SEL_REDEEM_PY_TO_TOK   = 0x47f1de22; // redeemPyToToken(address,address,uint256,TokenOutput)
    bytes4 private constant SEL_REDEEM_PY_TO_SY    = bytes4(keccak256("redeemPyToSy(address,address,uint256,uint256)"));

    // Claim yield
    bytes4 private constant SEL_CLAIM_YIELD        = bytes4(keccak256("redeemDueInterestAndRewards(address,address[],address[],address[])"));

    // ── Per-account config ────────────────────────────────────────────────────

    struct Slot {
        address   pendleRouter;
        address[] allowedMarkets;
        uint128   maxAmountPerTx;
        bool      allowLiquidityOps;
        bool      allowPtSwaps;
        bool      allowYtSwaps;
        bool      allowMintRedeem;
        bool      allowClaimYield;
    }

    mapping(address account => Slot) private _slots;
    mapping(address account => mapping(address => bool)) public isAllowedMarket;

    // ── errors ────────────────────────────────────────────────────────────────

    error ZeroRouter();

    // ── constructor ───────────────────────────────────────────────────────────

    constructor(address _kernel)
        ConfigurablePermission(_kernel, "SharedPendlePermission", "1")
    {}

    // ── view helpers ──────────────────────────────────────────────────────────

    function getConfig(address account) external view returns (Slot memory) {
        return _slots[account];
    }

    // ── config application ────────────────────────────────────────────────────

    function _applyConfig(address account, bytes calldata params) internal override {
        (
            address pendleRouter,
            address[] memory allowedMarkets,
            uint128 maxAmountPerTx,
            bool allowLiquidityOps,
            bool allowPtSwaps,
            bool allowYtSwaps,
            bool allowMintRedeem,
            bool allowClaimYield
        ) = abi.decode(params, (address, address[], uint128, bool, bool, bool, bool, bool));

        // Clear previous market allowlist for this account
        Slot storage s = _slots[account];
        for (uint256 i; i < s.allowedMarkets.length; i++) {
            isAllowedMarket[account][s.allowedMarkets[i]] = false;
        }

        // Apply new market allowlist
        for (uint256 i; i < allowedMarkets.length; i++) {
            isAllowedMarket[account][allowedMarkets[i]] = true;
        }

        if (pendleRouter == address(0)) revert ZeroRouter();
        s.pendleRouter      = pendleRouter;
        s.allowedMarkets    = allowedMarkets;
        s.maxAmountPerTx    = maxAmountPerTx;
        s.allowLiquidityOps = allowLiquidityOps;
        s.allowPtSwaps      = allowPtSwaps;
        s.allowYtSwaps      = allowYtSwaps;
        s.allowMintRedeem   = allowMintRedeem;
        s.allowClaimYield   = allowClaimYield;
    }

    // ── IPermission ───────────────────────────────────────────────────────────

    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool) {
        Slot storage s = _slots[ctx.account];

        // Router must be set and must match the call target
        if (s.pendleRouter == address(0)) return false;
        if (ctx.target != s.pendleRouter) return false;

        bytes4 sel = ctx.selector;

        // Liquidity ops
        if (
            sel == SEL_ADD_DUAL_SY_PT     ||
            sel == SEL_ADD_DUAL_TOK_PT    ||
            sel == SEL_ADD_SINGLE_SY      ||
            sel == SEL_ADD_SINGLE_TOK     ||
            sel == SEL_ADD_SINGLE_PT      ||
            sel == SEL_REMOVE_DUAL_SY_PT  ||
            sel == SEL_REMOVE_DUAL_TOK_PT ||
            sel == SEL_REMOVE_SINGLE_SY   ||
            sel == SEL_REMOVE_SINGLE_TOK  ||
            sel == SEL_REMOVE_SINGLE_PT
        ) {
            return _evalLiquidity(txData, s, ctx.account, sel);
        }

        // PT swaps
        if (
            sel == SEL_SWAP_SY_FOR_PT  ||
            sel == SEL_SWAP_PT_FOR_SY  ||
            sel == SEL_SWAP_TOK_FOR_PT ||
            sel == SEL_SWAP_PT_FOR_TOK
        ) {
            return _evalPtSwap(txData, s, ctx.account, sel);
        }

        // YT swaps
        if (
            sel == SEL_SWAP_SY_FOR_YT  ||
            sel == SEL_SWAP_YT_FOR_SY  ||
            sel == SEL_SWAP_TOK_FOR_YT ||
            sel == SEL_SWAP_YT_FOR_TOK
        ) {
            return _evalYtSwap(txData, s, ctx.account, sel);
        }

        // Mint / Redeem
        if (
            sel == SEL_MINT_PY_FROM_TOK ||
            sel == SEL_MINT_PY_FROM_SY  ||
            sel == SEL_REDEEM_PY_TO_TOK ||
            sel == SEL_REDEEM_PY_TO_SY
        ) {
            return _evalMintRedeem(txData, s, ctx.account, sel);
        }

        // Claim yield
        if (sel == SEL_CLAIM_YIELD) {
            return _evalClaim(txData, s, ctx.account);
        }

        return false;
    }

    function discriminator() external pure returns (bytes32) {
        return keccak256("SharedPendlePermission");
    }

    // ── IPermissionIntrospection ──────────────────────────────────────────────

    function permissionId() external pure override returns (bytes32) {
        return keccak256("sail.permission.SharedPendlePermission.v1");
    }

    function permissionVersion() external pure override returns (bytes32) {
        return keccak256("v1");
    }

    function metadataURI() external pure override returns (string memory) {
        return "";
    }

    function capabilityIds() external pure override returns (bytes32[] memory ids) {
        ids = new bytes32[](1);
        ids[0] = SailCapabilities.PENDLE_YIELD;
    }

    // ── internal evaluators ───────────────────────────────────────────────────

    /// @dev WARNING: The byte offsets below are hardcoded for Pendle Router V4 ABI as of deployment.
    ///      If Pendle upgrades the router contract with a different ABI encoding, these offsets
    ///      MUST be updated and a new template deployed. Do not assume backward compatibility.
    ///      Verify against: https://github.com/pendle-finance/pendle-core-v2-public
    ///
    /// @dev Handles all add/removeLiquidity* selectors.
    ///      All liquidity functions have (address receiver, address market, ...) as their
    ///      first two parameters, followed by a uint256 amount in position [2] for most
    ///      variants, or a TokenInput/TokenOutput struct in position [2] for dual-token
    ///      and single-token variants.
    ///
    /// @dev NOTE: For removeLiquidity selectors, `maxAmountPerTx` is enforced against
    ///      `netLpToRemove` (LP token units), NOT underlying token units.
    ///      Operators MUST set maxAmountPerTx in LP token denomination for these selectors.
    function _evalLiquidity(
        bytes calldata txData,
        Slot storage s,
        address account,
        bytes4 sel
    ) internal view returns (bool) {
        if (!s.allowLiquidityOps) return false;
        if (txData.length < 68) return false; // 4 selector + 2 x 32 (receiver + market)

        (address receiver, address market) = abi.decode(txData[4:68], (address, address));
        if (receiver != account)                    return false;
        if (!isAllowedMarket[account][market])      return false;

        // Amount check: for variants that carry the amount as the third uint256 word
        // (addDualSyPt, removeDualSyPt, addSingleSy, addSinglePt, removeSingleSy,
        //  removeSinglePt, removeDualTokenPt, removeSingleToken) we decode it directly.
        // For variants with a struct in position [2] (addDualTokenPt, addSingleToken)
        // the TokenInput.netTokenIn is at offset [4 + 64 + 32] (after receiver+market+tokenIn).
        if (
            sel == SEL_ADD_DUAL_SY_PT    ||
            sel == SEL_REMOVE_DUAL_SY_PT ||
            sel == SEL_ADD_SINGLE_SY     ||
            sel == SEL_ADD_SINGLE_PT     ||
            sel == SEL_REMOVE_SINGLE_SY  ||
            sel == SEL_REMOVE_SINGLE_PT  ||
            sel == SEL_REMOVE_DUAL_TOK_PT||
            sel == SEL_REMOVE_SINGLE_TOK
        ) {
            if (txData.length < 100) return false; // 4 + 32*3
            (,, uint256 amount) = abi.decode(txData[4:100], (address, address, uint256));
            return amount <= uint256(s.maxAmountPerTx);
        }

        // addLiquidityDualTokenAndPt: (receiver, market, TokenInput, netPtDesired, minLpOut)
        // TokenInput starts at offset 68 (after 4+32+32). TokenInput layout:
        //   [0] tokenIn      (32 bytes, address)
        //   [1] netTokenIn   (32 bytes, uint256)  ← amount we check
        // So netTokenIn is at txData[4 + 64 + 32] = txData[100]
        if (sel == SEL_ADD_DUAL_TOK_PT) {
            // TokenInput is a static-sized inline struct when the dynamic SwapData.extCalldata
            // is empty; for the amount check we only need netTokenIn at word offset 3 (index 2
            // of the struct). However, because TokenInput contains a dynamic bytes field
            // (SwapData.extCalldata), the ABI encodes it as a reference. We decode the
            // head-only first two words after receiver+market to get the offset of the struct,
            // then read netTokenIn from the struct body.
            //
            // Simpler and safe: decode the whole (address, address, address, uint256) ignoring
            // struct wrapper — ABI puts tokenIn at word 3 and netTokenIn at word 4 after
            // the function selector when the struct offset is 0x60 (standard).
            // Robust approach: just enforce a min-length and decode via offset.
            if (txData.length < 196) return false;
            // The ABI head for (address,address,tuple,uint256,uint256):
            //   [0x04..0x24) receiver
            //   [0x24..0x44) market
            //   [0x44..0x64) offset to TokenInput (= 0xa0 = 160 from start of params = 5 words)
            //   [0x64..0x84) netPtDesired
            //   [0x84..0xa4) minLpOut
            //   [0xa4..0xc4) TokenInput.tokenIn
            //   [0xc4..0xe4) TokenInput.netTokenIn  ← here
            uint256 netTokenIn = abi.decode(txData[0xc4:0xe4], (uint256));
            return netTokenIn <= uint256(s.maxAmountPerTx);
        }

        // addLiquiditySingleToken: (receiver, market, minLpOut, ApproxParams, TokenInput, LimitOrderData)
        // ApproxParams = (uint256,uint256,uint256,uint256,uint256) — all static, encoded INLINE.
        // Head layout:
        //   [0x04) receiver        (address, inline)
        //   [0x24) market          (address, inline)
        //   [0x44) minLpOut        (uint256, inline)
        //   [0x64) ApproxParams[0..4] INLINE — 5 x uint256 = 160 bytes → [0x64..0x104)
        //   [0x104) offset to TokenInput   (value = 0x140)
        //   [0x124) offset to LimitOrderData
        // Head ends at 0x144; TokenInput body starts at params[0x140] = txData[0x144]
        // TokenInput.netTokenIn is at txData[0x144 + 0x20] = txData[0x164]
        if (sel == SEL_ADD_SINGLE_TOK) {
            if (txData.length < 0x184) return false;
            uint256 netTokenIn = abi.decode(txData[0x164:0x184], (uint256));
            return netTokenIn <= uint256(s.maxAmountPerTx);
        }

        return false;
    }

    /// @dev Handles swapExact{Sy,Token}ForPt and swapExactPtFor{Sy,Token}.
    ///      All PT swap functions lead with (address receiver, address market, ...).
    ///      - swapExactSyForPt:   (receiver, market, exactSyIn, ...)
    ///      - swapExactPtForSy:   (receiver, market, exactPtIn, ...)
    ///      - swapExactTokenForPt:(receiver, market, minPtOut,  ApproxParams, TokenInput, ...)
    ///        → amount is inside TokenInput.netTokenIn
    ///      - swapExactPtForToken:(receiver, market, exactPtIn, TokenOutput, ...)
    function _evalPtSwap(
        bytes calldata txData,
        Slot storage s,
        address account,
        bytes4 sel
    ) internal view returns (bool) {
        if (!s.allowPtSwaps) return false;
        if (txData.length < 68) return false;

        (address receiver, address market) = abi.decode(txData[4:68], (address, address));
        if (receiver != account)               return false;
        if (!isAllowedMarket[account][market]) return false;

        // Sy-in / Pt-in / Pt-out variants carry the primary amount as the 3rd word
        if (sel == SEL_SWAP_SY_FOR_PT || sel == SEL_SWAP_PT_FOR_SY || sel == SEL_SWAP_PT_FOR_TOK) {
            if (txData.length < 100) return false;
            (,, uint256 amount) = abi.decode(txData[4:100], (address, address, uint256));
            return amount <= uint256(s.maxAmountPerTx);
        }

        // swapExactTokenForPt: (receiver, market, minPtOut, ApproxParams, TokenInput, LimitOrderData)
        // Identical head layout to addLiquiditySingleToken — TokenInput.netTokenIn at txData[0x164]
        if (sel == SEL_SWAP_TOK_FOR_PT) {
            if (txData.length < 0x184) return false;
            uint256 netTokenIn = abi.decode(txData[0x164:0x184], (uint256));
            return netTokenIn <= uint256(s.maxAmountPerTx);
        }

        return false;
    }

    /// @dev Handles swapExact{Sy,Token}ForYt and swapExactYtFor{Sy,Token}.
    ///      Mirror of PT swap layout.
    function _evalYtSwap(
        bytes calldata txData,
        Slot storage s,
        address account,
        bytes4 sel
    ) internal view returns (bool) {
        if (!s.allowYtSwaps) return false;
        if (txData.length < 68) return false;

        (address receiver, address market) = abi.decode(txData[4:68], (address, address));
        if (receiver != account)               return false;
        if (!isAllowedMarket[account][market]) return false;

        if (sel == SEL_SWAP_SY_FOR_YT || sel == SEL_SWAP_YT_FOR_SY || sel == SEL_SWAP_YT_FOR_TOK) {
            if (txData.length < 100) return false;
            (,, uint256 amount) = abi.decode(txData[4:100], (address, address, uint256));
            return amount <= uint256(s.maxAmountPerTx);
        }

        // swapExactTokenForYt: (receiver, market, minYtOut, ApproxParams, TokenInput, LimitOrderData)
        // Identical head layout — TokenInput.netTokenIn at txData[0x164]
        if (sel == SEL_SWAP_TOK_FOR_YT) {
            if (txData.length < 0x184) return false;
            uint256 netTokenIn = abi.decode(txData[0x164:0x184], (uint256));
            return netTokenIn <= uint256(s.maxAmountPerTx);
        }

        return false;
    }

    /// @dev Handles mintPy* and redeemPyTo* selectors.
    ///      All use (address receiver, address YT, ...) — YT acts as the market key for
    ///      the allowlist check (same isAllowedMarket mapping).
    ///      - mintPyFromSy:    (receiver, YT, netSyIn, minPyOut)
    ///      - redeemPyToSy:    (receiver, YT, netPyIn, minSyOut)
    ///      - mintPyFromToken: (receiver, YT, minPyOut, TokenInput)  → amount in TokenInput
    ///      - redeemPyToToken: (receiver, YT, netPyIn, TokenOutput)  → amount = netPyIn
    function _evalMintRedeem(
        bytes calldata txData,
        Slot storage s,
        address account,
        bytes4 sel
    ) internal view returns (bool) {
        if (!s.allowMintRedeem) return false;
        if (txData.length < 68) return false;

        (address receiver, address yt) = abi.decode(txData[4:68], (address, address));
        if (receiver != account)            return false;
        if (!isAllowedMarket[account][yt])  return false;

        // mintPyFromSy / redeemPyToSy / redeemPyToToken — amount is the 3rd word
        if (sel == SEL_MINT_PY_FROM_SY || sel == SEL_REDEEM_PY_TO_SY || sel == SEL_REDEEM_PY_TO_TOK) {
            if (txData.length < 100) return false;
            (,, uint256 amount) = abi.decode(txData[4:100], (address, address, uint256));
            return amount <= uint256(s.maxAmountPerTx);
        }

        // mintPyFromToken: (receiver, YT, minPyOut, TokenInput)
        // Head: receiver[0x04], YT[0x24], minPyOut[0x44], offset-TokenInput[0x64](=0x80)
        // TokenInput body at [0x84]: tokenIn[0x84], netTokenIn[0xa4]
        if (sel == SEL_MINT_PY_FROM_TOK) {
            if (txData.length < 0xc4) return false;
            uint256 netTokenIn = abi.decode(txData[0xa4:0xc4], (uint256));
            return netTokenIn <= uint256(s.maxAmountPerTx);
        }

        return false;
    }

    /// @dev Handles redeemDueInterestAndRewards(address user, address[] sys, address[] yts, address[] markets).
    ///      Checks that the user field equals ctx.account and that every market in the
    ///      markets array is in the account's allowlist.
    function _evalClaim(
        bytes calldata txData,
        Slot storage s,
        address account
    ) internal view returns (bool) {
        if (!s.allowClaimYield) return false;
        if (txData.length < 36) return false; // 4 + 32 (user address word)

        // redeemDueInterestAndRewards(address user, address[] sys, address[] yts, address[] markets)
        // Decode all four parameters; validate user and each market entry.
        (address user,, , address[] memory markets) =
            abi.decode(txData[4:], (address, address[], address[], address[]));
        if (user != account) return false;
        for (uint256 i; i < markets.length; i++) {
            if (!isAllowedMarket[account][markets[i]]) return false;
        }
        return true;
    }
}
