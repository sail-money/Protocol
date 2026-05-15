// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Context} from "../../interfaces/IPermission.sol";
import {IOracle} from "../../interfaces/IOracle.sol";
import {BaseSharedPermission} from "./BaseSharedPermission.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

/// @notice Composite multi-account template combining swap + borrow + transfer logic
///         into a single permission. One registered permission per account, one fee,
///         one configure signature — but the full DeFi action surface.
///
///         Dispatch is selector-routed inside evaluate(). Unknown selectors return false.
///         A sub-domain is effectively disabled by configuring empty allowlists for it.
///
///         Config blob (single ABI-encoded tuple of three structs):
///             abi.encode(SwapConfig, BorrowConfig, TransferConfig)
///
///         This is the recommended pattern for production Safes: build curated bundles
///         (e.g. "Conservative Yield", "Active Trading") and attach one bundle per Safe.
contract SharedDeFiBundlePermission is BaseSharedPermission {
    // -------------------------------------------------------------------------
    // Selectors
    // -------------------------------------------------------------------------
    // Uniswap V3 exactInputSingle / V2 swapExactTokensForTokens
    bytes4 private constant EXACT_INPUT_SINGLE = 0x414bf389;
    bytes4 private constant SWAP_EXACT_TOKENS  = 0x38ed1739;
    uint256 private constant LEN_V3     = 260;
    uint256 private constant LEN_V2_MIN = 196;

    // Aave V3 / Morpho / Compound borrow
    bytes4 private constant AAVE_BORROW     = bytes4(keccak256("borrow(address,uint256,uint256,uint16,address)"));
    bytes4 private constant MORPHO_BORROW   = bytes4(keccak256("borrow(address,uint256,address,address)"));
    bytes4 private constant COMPOUND_BORROW = bytes4(keccak256("borrow(uint256)"));
    uint256 private constant LEN_AAVE     = 164;
    uint256 private constant LEN_MORPHO   = 132;
    uint256 private constant LEN_COMPOUND = 36;

    // ERC-20 transfer / transferFrom
    bytes4 private constant TRANSFER_SELECTOR     = 0xa9059cbb;
    bytes4 private constant TRANSFERFROM_SELECTOR = 0x23b872dd;
    uint256 private constant LEN_TRANSFER     = 68;
    uint256 private constant LEN_TRANSFERFROM = 100;

    // -------------------------------------------------------------------------
    // Config structs — public so external encoders can construct typed configs
    // -------------------------------------------------------------------------
    struct SwapConfig {
        address[] routers;
        address[] tokensIn;
        address[] tokensOut;
        uint256   maxAmountPerTx;
        uint256   maxSlippageBps;
        address   priceOracle;
    }

    struct BorrowConfig {
        address[] protocols;
        address[] assets;
        uint256   maxAmountPerTx;
        uint256   maxLtvBps;
        address   collateralOracle;
        address   borrowOracle;
    }

    struct TransferConfig {
        address[] recipients;
        address[] tokens;
    }

    // -------------------------------------------------------------------------
    // Per-account storage
    // -------------------------------------------------------------------------
    mapping(address account => SwapConfig)     private _swap;
    mapping(address account => BorrowConfig)   private _borrow;
    mapping(address account => TransferConfig) private _transfer;

    // O(1) allowlist lookups
    mapping(address account => mapping(address => bool)) public isSwapRouter;
    mapping(address account => mapping(address => bool)) public isSwapTokenIn;
    mapping(address account => mapping(address => bool)) public isSwapTokenOut;
    mapping(address account => mapping(address => bool)) public isBorrowProtocol;
    mapping(address account => mapping(address => bool)) public isBorrowAsset;
    mapping(address account => mapping(address => bool)) public isTransferRecipient;
    mapping(address account => mapping(address => bool)) public isTransferToken;

    error SlippageBpsTooLarge(uint256 bps);
    error LtvBpsTooLarge(uint256 bps);

    constructor(address _kernel)
        BaseSharedPermission(_kernel, "SharedDeFiBundlePermission", "1")
    {}

    // -------------------------------------------------------------------------
    // View accessors
    // -------------------------------------------------------------------------

    function getSwapConfig(address account) external view returns (SwapConfig memory) {
        return _swap[account];
    }

    function getBorrowConfig(address account) external view returns (BorrowConfig memory) {
        return _borrow[account];
    }

    function getTransferConfig(address account) external view returns (TransferConfig memory) {
        return _transfer[account];
    }

    // -------------------------------------------------------------------------
    // Config application
    // -------------------------------------------------------------------------

    function _applyConfig(address account, bytes calldata params) internal override {
        (SwapConfig memory swap, BorrowConfig memory borrow, TransferConfig memory transfer) =
            abi.decode(params, (SwapConfig, BorrowConfig, TransferConfig));

        if (swap.maxSlippageBps > 10_000) revert SlippageBpsTooLarge(swap.maxSlippageBps);
        if (borrow.maxLtvBps    > 10_000) revert LtvBpsTooLarge(borrow.maxLtvBps);

        _applySwap(account, swap);
        _applyBorrow(account, borrow);
        _applyTransfer(account, transfer);
    }

    function _applySwap(address account, SwapConfig memory cfg) internal {
        SwapConfig storage s = _swap[account];
        for (uint256 i; i < s.routers.length; i++)   isSwapRouter[account][s.routers[i]]     = false;
        for (uint256 i; i < s.tokensIn.length; i++)  isSwapTokenIn[account][s.tokensIn[i]]   = false;
        for (uint256 i; i < s.tokensOut.length; i++) isSwapTokenOut[account][s.tokensOut[i]] = false;

        for (uint256 i; i < cfg.routers.length; i++)   isSwapRouter[account][cfg.routers[i]]     = true;
        for (uint256 i; i < cfg.tokensIn.length; i++)  isSwapTokenIn[account][cfg.tokensIn[i]]   = true;
        for (uint256 i; i < cfg.tokensOut.length; i++) isSwapTokenOut[account][cfg.tokensOut[i]] = true;

        _swap[account] = cfg;
    }

    function _applyBorrow(address account, BorrowConfig memory cfg) internal {
        BorrowConfig storage s = _borrow[account];
        for (uint256 i; i < s.protocols.length; i++) isBorrowProtocol[account][s.protocols[i]] = false;
        for (uint256 i; i < s.assets.length; i++)    isBorrowAsset[account][s.assets[i]]       = false;

        for (uint256 i; i < cfg.protocols.length; i++) isBorrowProtocol[account][cfg.protocols[i]] = true;
        for (uint256 i; i < cfg.assets.length; i++)    isBorrowAsset[account][cfg.assets[i]]       = true;

        _borrow[account] = cfg;
    }

    function _applyTransfer(address account, TransferConfig memory cfg) internal {
        TransferConfig storage s = _transfer[account];
        for (uint256 i; i < s.recipients.length; i++) isTransferRecipient[account][s.recipients[i]] = false;
        for (uint256 i; i < s.tokens.length; i++)     isTransferToken[account][s.tokens[i]]         = false;

        for (uint256 i; i < cfg.recipients.length; i++) isTransferRecipient[account][cfg.recipients[i]] = true;
        for (uint256 i; i < cfg.tokens.length; i++)     isTransferToken[account][cfg.tokens[i]]         = true;

        _transfer[account] = cfg;
    }

    // -------------------------------------------------------------------------
    // IPermission — selector-routed evaluate
    // -------------------------------------------------------------------------

    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool) {
        bytes4 sel = ctx.selector;

        if (sel == EXACT_INPUT_SINGLE || sel == SWAP_EXACT_TOKENS) {
            return _evalSwap(txData, ctx);
        }
        if (sel == AAVE_BORROW || sel == MORPHO_BORROW || sel == COMPOUND_BORROW) {
            return _evalBorrow(txData, ctx);
        }
        if (sel == TRANSFER_SELECTOR || sel == TRANSFERFROM_SELECTOR) {
            return _evalTransfer(txData, ctx);
        }
        return false;
    }

    function discriminator() external pure returns (bytes32) {
        return keccak256("SharedDeFiBundlePermission");
    }

    // -------------------------------------------------------------------------
    // Per-domain evaluators
    // -------------------------------------------------------------------------

    function _evalSwap(bytes calldata txData, Context calldata ctx) internal view returns (bool) {
        if (!isSwapRouter[ctx.account][ctx.target]) return false;
        SwapConfig storage s = _swap[ctx.account];

        if (ctx.selector == EXACT_INPUT_SINGLE) {
            if (txData.length < LEN_V3) return false;
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
            if (!isSwapTokenIn[ctx.account][tokenIn])   return false;
            if (!isSwapTokenOut[ctx.account][tokenOut]) return false;
            if (recipient != ctx.account)               return false;
            if (amountIn > s.maxAmountPerTx)            return false;
            return _swapOracleCheck(s, tokenIn, tokenOut, amountIn, amountOutMinimum);
        }

        // SWAP_EXACT_TOKENS
        if (txData.length < LEN_V2_MIN) return false;
        (
            uint256 v2AmountIn,
            uint256 v2AmountOutMin,
            address[] memory path,
            address v2To,
        ) = abi.decode(txData[4:], (uint256, uint256, address[], address, uint256));
        if (path.length < 2)                                        return false;
        if (!isSwapTokenIn[ctx.account][path[0]])                   return false;
        if (!isSwapTokenOut[ctx.account][path[path.length - 1]])    return false;
        if (v2To != ctx.account)                                    return false;
        if (v2AmountIn > s.maxAmountPerTx)                          return false;
        return _swapOracleCheck(s, path[0], path[path.length - 1], v2AmountIn, v2AmountOutMin);
    }

    function _swapOracleCheck(
        SwapConfig storage s,
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

    function _evalBorrow(bytes calldata txData, Context calldata ctx) internal view returns (bool) {
        if (!isBorrowProtocol[ctx.account][ctx.target]) return false;
        BorrowConfig storage s = _borrow[ctx.account];

        if (ctx.selector == AAVE_BORROW) {
            if (txData.length < LEN_AAVE) return false;
            (address asset, uint256 amount, , , address onBehalfOf) =
                abi.decode(txData[4:], (address, uint256, uint256, uint16, address));
            if (!isBorrowAsset[ctx.account][asset]) return false;
            if (amount > s.maxAmountPerTx)          return false;
            if (onBehalfOf != ctx.account)          return false;
            return _ltvCheck(s, asset, amount, ctx.account);
        }

        if (ctx.selector == MORPHO_BORROW) {
            if (txData.length < LEN_MORPHO) return false;
            (address asset, uint256 amount, address onBehalf, address receiver) =
                abi.decode(txData[4:], (address, uint256, address, address));
            if (!isBorrowAsset[ctx.account][asset]) return false;
            if (amount > s.maxAmountPerTx)          return false;
            if (onBehalf != ctx.account)            return false;
            if (receiver != ctx.account)            return false;
            return _ltvCheck(s, asset, amount, ctx.account);
        }

        // COMPOUND_BORROW
        if (txData.length < LEN_COMPOUND) return false;
        uint256 cAmount = abi.decode(txData[4:], (uint256));
        if (!isBorrowAsset[ctx.account][ctx.target]) return false;
        if (cAmount > s.maxAmountPerTx)              return false;
        return _ltvCheck(s, ctx.target, cAmount, ctx.account);
    }

    function _ltvCheck(BorrowConfig storage s, address asset, uint256 amount, address account)
        internal
        view
        returns (bool)
    {
        if (s.collateralOracle == address(0) || s.borrowOracle == address(0)) return true;

        (uint256 colValue,) = IOracle(s.collateralOracle).getPrice(account, address(0));
        (uint256 borPrice,) = IOracle(s.borrowOracle).getPrice(asset, address(0));

        if (colValue == 0) return false;
        if (borPrice == 0) return true;

        uint256 borrowScaled = Math.mulDiv(amount, borPrice, 1);
        uint256 ltvBps       = Math.mulDiv(borrowScaled, 10_000, colValue);
        return ltvBps <= s.maxLtvBps;
    }

    function _evalTransfer(bytes calldata txData, Context calldata ctx) internal view returns (bool) {
        if (ctx.value != 0) return false;
        if (!isTransferToken[ctx.account][ctx.target]) return false;

        if (ctx.selector == TRANSFER_SELECTOR) {
            if (txData.length < LEN_TRANSFER) return false;
            (address to,) = abi.decode(txData[4:], (address, uint256));
            return isTransferRecipient[ctx.account][to];
        }

        // TRANSFERFROM_SELECTOR
        if (txData.length < LEN_TRANSFERFROM) return false;
        (, address tfTo,) = abi.decode(txData[4:], (address, address, uint256));
        return isTransferRecipient[ctx.account][tfTo];
    }
}
