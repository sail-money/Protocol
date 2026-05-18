// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {Context} from "../../interfaces/IPermission.sol";
import {IPermissionIntrospection} from "../../interfaces/IPermissionIntrospection.sol";
import {SailCapabilities} from "../../interfaces/SailCapabilities.sol";
import {BaseSharedPermission} from "./BaseSharedPermission.sol";

/// @notice Multi-account permission template that gates AMM liquidity operations across
///         Uniswap V3, Aerodrome Slipstream (concentrated), and Aerodrome Router (legacy v2).
///         One deployment serves any number of accounts; each account stores its own
///         target allowlist, token allowlist, amount cap, and per-operation feature flags.
///
///         Supported operation domains (each can be independently enabled/disabled):
///           • Mint / Open position    — mint (UniV3 + Aerodrome Slipstream NPM)
///           • Increase liquidity      — increaseLiquidity (UniV3 + Slipstream NPM)
///           • Decrease liquidity      — decreaseLiquidity (UniV3 + Slipstream NPM)
///           • Collect fees            — collect (UniV3 + Slipstream NPM)
///           • Burn position NFT       — burn (UniV3 + Slipstream NPM)
///           • Aerodrome add liquidity — addLiquidity / addLiquidityETH (legacy v2 Router)
///           • Aerodrome remove        — removeLiquidity / removeLiquidityETH (legacy v2 Router)
///
///         Note: Aerodrome add/remove operations are gated by allowMint / allowDecrease
///         respectively, treating add-liquidity as a mint-class operation.
///
///         Config blob:
///             abi.encode(
///                 address[] allowedTargets,
///                 address[] allowedTokens,
///                 uint128   maxAmountPerTokenPerTx,
///                 bool      allowMint,
///                 bool      allowIncrease,
///                 bool      allowDecrease,
///                 bool      allowCollect,
///                 bool      allowBurn
///             )
contract SharedAMMLiquidityPermission is BaseSharedPermission, IPermissionIntrospection {
    // ── Selector constants ────────────────────────────────────────────────────
    // UniV3 NonfungiblePositionManager (0x03a520b32C04BF3bEEf7BEb72E919cf822Ed34f1 on Base)
    // These selectors are also used for standard Uniswap V3 NPM deployments.
    //
    // MintParams tuple: (address,address,uint24,int24,int24,uint256,uint256,uint256,uint256,address,uint256)
    //   token0, token1, fee, tickLower, tickUpper,
    //   amount0Desired, amount1Desired, amount0Min, amount1Min, recipient, deadline
    bytes4 private constant MINT          = bytes4(keccak256("mint((address,address,uint24,int24,int24,uint256,uint256,uint256,uint256,address,uint256))"));
    // IncreaseLiquidityParams tuple: (uint256,uint256,uint256,uint256,uint256,uint256)
    //   tokenId, amount0Desired, amount1Desired, amount0Min, amount1Min, deadline
    bytes4 private constant INCREASE_LIQ  = bytes4(keccak256("increaseLiquidity((uint256,uint256,uint256,uint256,uint256,uint256))"));
    // DecreaseLiquidityParams tuple: (uint256,uint128,uint256,uint256,uint256)
    //   tokenId, liquidity, amount0Min, amount1Min, deadline
    bytes4 private constant DECREASE_LIQ  = bytes4(keccak256("decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))"));
    // CollectParams tuple: (uint256,address,uint128,uint128)
    //   tokenId, recipient, amount0Max, amount1Max
    bytes4 private constant COLLECT       = bytes4(keccak256("collect((uint256,address,uint128,uint128))"));
    bytes4 private constant BURN          = bytes4(keccak256("burn(uint256)"));

    // Aerodrome Slipstream NonfungiblePositionManager (0x827922686190790b37229fd06084350E74485b72 on Base)
    // MintParams DIFFERS from UniV3:
    //   - Field 3 is `int24 tickSpacing` instead of `uint24 fee`
    //   - Extra `uint160 sqrtPriceX96` appended as the final field
    // Tuple: (address,address,int24,int24,int24,uint256,uint256,uint256,uint256,address,uint256,uint160)
    //   token0, token1, tickSpacing, tickLower, tickUpper,
    //   amount0Desired, amount1Desired, amount0Min, amount1Min, recipient, deadline, sqrtPriceX96
    bytes4 private constant AERO_SLIPSTREAM_MINT = bytes4(keccak256("mint((address,address,int24,int24,int24,uint256,uint256,uint256,uint256,address,uint256,uint160))"));
    // increaseLiquidity / decreaseLiquidity / collect / burn share identical selectors with UniV3.

    // Aerodrome Router legacy v2 (0xcF77a3Ba9A5CA399B7c97c74d54e5b1Beb874E43 on Base)
    bytes4 private constant AERO_ADD_LIQ        = bytes4(keccak256("addLiquidity(address,address,bool,uint256,uint256,uint256,uint256,address,uint256)"));
    bytes4 private constant AERO_ADD_LIQ_ETH    = bytes4(keccak256("addLiquidityETH(address,bool,uint256,uint256,uint256,address,uint256)"));
    bytes4 private constant AERO_REMOVE_LIQ     = bytes4(keccak256("removeLiquidity(address,address,bool,uint256,uint256,uint256,address,uint256)"));
    bytes4 private constant AERO_REMOVE_LIQ_ETH = bytes4(keccak256("removeLiquidityETH(address,bool,uint256,uint256,uint256,address,uint256)"));

    // ── Constants ─────────────────────────────────────────────────────────────

    uint256 private constant MAX_ALLOWLIST_LENGTH = 50;

    // ── Errors ────────────────────────────────────────────────────────────────

    error AllowlistTooLong();

    // ── Per-account config ────────────────────────────────────────────────────

    struct Slot {
        address[] allowedTargets;
        address[] allowedTokens;
        uint128   maxAmountPerTokenPerTx;
        bool      allowMint;
        bool      allowIncrease;
        bool      allowDecrease;
        bool      allowCollect;
        bool      allowBurn;
    }

    mapping(address account => Slot) private _slots;
    mapping(address account => mapping(address => bool)) public isAllowedTarget;
    mapping(address account => mapping(address => bool)) public isAllowedToken;

    // ── constructor ───────────────────────────────────────────────────────────

    constructor(address _kernel)
        BaseSharedPermission(_kernel, "SharedAMMLiquidityPermission", "1")
    {}

    // ── view helpers ──────────────────────────────────────────────────────────

    function getConfig(address account) external view returns (Slot memory) {
        return _slots[account];
    }

    // ── config application ────────────────────────────────────────────────────

    function _applyConfig(address account, bytes calldata params) internal override {
        (
            address[] memory allowedTargets,
            address[] memory allowedTokens,
            uint128 maxAmountPerTokenPerTx,
            bool allowMint,
            bool allowIncrease,
            bool allowDecrease,
            bool allowCollect,
            bool allowBurn
        ) = abi.decode(params, (address[], address[], uint128, bool, bool, bool, bool, bool));

        if (allowedTargets.length > MAX_ALLOWLIST_LENGTH) revert AllowlistTooLong();
        if (allowedTokens.length  > MAX_ALLOWLIST_LENGTH) revert AllowlistTooLong();

        // Clear previous target and token allowlists for this account
        Slot storage s = _slots[account];
        for (uint256 i; i < s.allowedTargets.length; i++) {
            isAllowedTarget[account][s.allowedTargets[i]] = false;
        }
        for (uint256 i; i < s.allowedTokens.length; i++) {
            isAllowedToken[account][s.allowedTokens[i]] = false;
        }

        // Apply new allowlists
        for (uint256 i; i < allowedTargets.length; i++) {
            isAllowedTarget[account][allowedTargets[i]] = true;
        }
        for (uint256 i; i < allowedTokens.length; i++) {
            isAllowedToken[account][allowedTokens[i]] = true;
        }

        s.allowedTargets           = allowedTargets;
        s.allowedTokens            = allowedTokens;
        s.maxAmountPerTokenPerTx   = maxAmountPerTokenPerTx;
        s.allowMint                = allowMint;
        s.allowIncrease            = allowIncrease;
        s.allowDecrease            = allowDecrease;
        s.allowCollect             = allowCollect;
        s.allowBurn                = allowBurn;
    }

    // ── IPermission ───────────────────────────────────────────────────────────

    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool) {
        Slot storage s = _slots[ctx.account];

        if (!isAllowedTarget[ctx.account][ctx.target]) return false;

        bytes4 sel = ctx.selector;

        if (sel == MINT || sel == AERO_SLIPSTREAM_MINT) return _evalMint(txData, s, ctx.account, sel);
        if (sel == INCREASE_LIQ)                        return _evalIncrease(txData, s);
        if (sel == DECREASE_LIQ)                        return s.allowDecrease;
        if (sel == COLLECT)                             return _evalCollect(txData, s, ctx.account);
        if (sel == BURN)                                return s.allowBurn;
        if (sel == AERO_ADD_LIQ)                        return _evalAeroAdd(txData, s, ctx.account);
        if (sel == AERO_ADD_LIQ_ETH)                    return _evalAeroAddETH(txData, s, ctx.account, ctx.value);
        if (sel == AERO_REMOVE_LIQ)                     return _evalAeroRemove(txData, s, ctx.account);
        if (sel == AERO_REMOVE_LIQ_ETH)                 return _evalAeroRemoveETH(txData, s, ctx.account);

        return false;
    }

    function discriminator() external pure returns (bytes32) {
        return keccak256("SharedAMMLiquidityPermission");
    }

    // ── IPermissionIntrospection ──────────────────────────────────────────────

    function permissionId() external pure override returns (bytes32) {
        return keccak256("sail.permission.SharedAMMLiquidityPermission.v1");
    }

    function permissionVersion() external pure override returns (bytes32) {
        return keccak256("v1");
    }

    function metadataURI() external pure override returns (string memory) {
        return "";
    }

    function capabilityIds() external pure override returns (bytes32[] memory ids) {
        ids = new bytes32[](1);
        ids[0] = SailCapabilities.AMM_LIQUIDITY;
    }

    // ── internal evaluators ───────────────────────────────────────────────────

    /// @dev Handles mint for both UniV3 NPM and Aerodrome Slipstream NPM.
    ///
    ///      UniV3 MintParams (sel == MINT):
    ///        (address token0, address token1, uint24 fee, int24 tickLower, int24 tickUpper,
    ///         uint256 amount0Desired, uint256 amount1Desired, uint256 amount0Min, uint256 amount1Min,
    ///         address recipient, uint256 deadline)
    ///
    ///      Slipstream MintParams (sel == AERO_SLIPSTREAM_MINT) — note the different field layout:
    ///        (address token0, address token1, int24 tickSpacing, int24 tickLower, int24 tickUpper,
    ///         uint256 amount0Desired, uint256 amount1Desired, uint256 amount0Min, uint256 amount1Min,
    ///         address recipient, uint256 deadline, uint160 sqrtPriceX96)
    ///
    ///      Despite the different struct shape, both encode identically in the first 9 ABI words
    ///      (each field zero-extended to 32 bytes), so the token, amount, and recipient offsets
    ///      are the same for both variants. The only structural difference (uint24 fee vs int24
    ///      tickSpacing, and the trailing sqrtPriceX96) does not affect the words we read here.
    function _evalMint(
        bytes calldata txData,
        Slot storage s,
        address account,
        bytes4 sel
    ) internal view returns (bool) {
        if (!s.allowMint) return false;
        // 4 (selector) + 11 x 32 (UniV3) = 356 bytes minimum; Slipstream adds one more word (sqrtPriceX96)
        // Use the shorter bound — both variants carry at least 11 words after the selector.
        if (txData.length < 356) return false;

        // ABI layout after the 4-byte selector (each field in its own 32-byte slot):
        //   [  4.. 36) token0
        //   [ 36.. 68) token1
        //   [ 68..100) fee / tickSpacing  (unused here)
        //   [100..132) tickLower          (unused here)
        //   [132..164) tickUpper          (unused here)
        //   [164..196) amount0Desired
        //   [196..228) amount1Desired
        //   [228..260) amount0Min         (unused here)
        //   [260..292) amount1Min         (unused here)
        //   [292..324) recipient
        //   [324..356) deadline           (unused here)
        //   [356..388) sqrtPriceX96       (Slipstream only, sel == AERO_SLIPSTREAM_MINT)
        (address token0, address token1) = abi.decode(txData[4:68], (address, address));
        (, , , , , uint256 amount0Desired, uint256 amount1Desired) =
            abi.decode(txData[4:228], (address, address, uint256, uint256, uint256, uint256, uint256));
        address recipient = abi.decode(txData[292:324], (address));

        if (!isAllowedToken[account][token0])                   return false;
        if (!isAllowedToken[account][token1])                   return false;
        if (amount0Desired > s.maxAmountPerTokenPerTx)          return false;
        if (amount1Desired > s.maxAmountPerTokenPerTx)          return false;
        if (recipient != account)                               return false;

        // Suppress unused-variable warning for sel (both selectors follow the same path above)
        sel;
        return true;
    }

    /// @dev Handles increaseLiquidity for UniV3 and Slipstream NPM.
    ///      Token allowlist applies to new positions (mint) only; increaseLiquidity enforces
    ///      amount caps because the position's tokens are not available in calldata.
    ///
    ///      IncreaseLiquidityParams ABI layout:
    ///        [  4.. 36) tokenId        (unused here)
    ///        [ 36.. 68) amount0Desired
    ///        [ 68..100) amount1Desired
    function _evalIncrease(bytes calldata txData, Slot storage s) internal view returns (bool) {
        if (!s.allowIncrease) return false;
        if (txData.length < 100) return false; // 4 + 3 x 32

        (, uint256 amount0Desired, uint256 amount1Desired) =
            abi.decode(txData[4:100], (uint256, uint256, uint256));

        if (amount0Desired > s.maxAmountPerTokenPerTx) return false;
        if (amount1Desired > s.maxAmountPerTokenPerTx) return false;
        return true;
    }

    /// @dev Handles collect for UniV3 and Slipstream NPM.
    ///      CollectParams ABI layout:
    ///        [  4.. 36) tokenId    (unused here)
    ///        [ 36.. 68) recipient
    function _evalCollect(
        bytes calldata txData,
        Slot storage s,
        address account
    ) internal view returns (bool) {
        if (!s.allowCollect) return false;
        if (txData.length < 68) return false; // 4 + 2 x 32

        (, address recipient) = abi.decode(txData[4:68], (uint256, address));
        return recipient == account;
    }

    /// @dev Handles Aerodrome Router addLiquidity(address,address,bool,uint256,uint256,uint256,uint256,address,uint256).
    ///      Adding liquidity is treated as a mint-class operation (gated by allowMint).
    ///      ABI layout:
    ///        [  4.. 36) tokenA
    ///        [ 36.. 68) tokenB
    ///        [ 68..100) stable          (unused here)
    ///        [100..132) amountADesired
    ///        [132..164) amountBDesired
    ///        [164..196) amountAMin      (unused here)
    ///        [196..228) amountBMin      (unused here)
    ///        [228..260) to
    ///        [260..292) deadline        (unused here)
    function _evalAeroAdd(
        bytes calldata txData,
        Slot storage s,
        address account
    ) internal view returns (bool) {
        if (!s.allowMint) return false;
        if (txData.length < 292) return false; // 4 + 9 x 32

        (address tokenA, address tokenB, , uint256 amountADesired, uint256 amountBDesired, , , address to) =
            abi.decode(txData[4:], (address, address, bool, uint256, uint256, uint256, uint256, address));

        if (!isAllowedToken[account][tokenA])              return false;
        if (!isAllowedToken[account][tokenB])              return false;
        if (amountADesired > s.maxAmountPerTokenPerTx)     return false;
        if (amountBDesired > s.maxAmountPerTokenPerTx)     return false;
        if (to != account)                                 return false;
        return true;
    }

    /// @dev Handles Aerodrome Router addLiquidityETH(address,bool,uint256,uint256,uint256,address,uint256).
    ///      ABI layout:
    ///        [  4.. 36) token
    ///        [ 36.. 68) stable               (unused here)
    ///        [ 68..100) amountTokenDesired
    ///        [100..132) amountTokenMin        (unused here)
    ///        [132..164) amountETHMin          (unused here)
    ///        [164..196) to
    ///        [196..228) deadline              (unused here)
    function _evalAeroAddETH(
        bytes calldata txData,
        Slot storage s,
        address account,
        uint256 ethValue
    ) internal view returns (bool) {
        if (!s.allowMint) return false;
        if (txData.length < 228) return false; // 4 + 7 x 32

        (address token, , uint256 amountTokenDesired, , , address to) =
            abi.decode(txData[4:], (address, bool, uint256, uint256, uint256, address));

        if (!isAllowedToken[account][token])               return false;
        if (amountTokenDesired > s.maxAmountPerTokenPerTx) return false;
        if (ethValue > s.maxAmountPerTokenPerTx)           return false;
        if (to != account)                                 return false;
        return true;
    }

    /// @dev Handles Aerodrome Router removeLiquidity(address,address,bool,uint256,uint256,uint256,address,uint256).
    ///      ABI layout:
    ///        [  4.. 36) tokenA      (unused here)
    ///        [ 36.. 68) tokenB      (unused here)
    ///        [ 68..100) stable      (unused here)
    ///        [100..132) liquidity   (unused here)
    ///        [132..164) amountAMin  (unused here)
    ///        [164..196) amountBMin  (unused here)
    ///        [196..228) to
    ///        [228..260) deadline    (unused here)
    function _evalAeroRemove(
        bytes calldata txData,
        Slot storage s,
        address account
    ) internal view returns (bool) {
        if (!s.allowDecrease) return false;
        if (txData.length < 260) return false; // 4 + 8 x 32

        (, , , , , , address to) =
            abi.decode(txData[4:], (address, address, bool, uint256, uint256, uint256, address));

        return to == account;
    }

    /// @dev Handles Aerodrome Router removeLiquidityETH(address,bool,uint256,uint256,uint256,address,uint256).
    ///      ABI layout:
    ///        [  4.. 36) token          (unused here)
    ///        [ 36.. 68) stable         (unused here)
    ///        [ 68..100) liquidity      (unused here)
    ///        [100..132) amountTokenMin (unused here)
    ///        [132..164) amountETHMin   (unused here)
    ///        [164..196) to
    ///        [196..228) deadline       (unused here)
    function _evalAeroRemoveETH(
        bytes calldata txData,
        Slot storage s,
        address account
    ) internal view returns (bool) {
        if (!s.allowDecrease) return false;
        if (txData.length < 228) return false; // 4 + 7 x 32

        (, , , , , address to) =
            abi.decode(txData[4:], (address, bool, uint256, uint256, uint256, address));

        return to == account;
    }
}
