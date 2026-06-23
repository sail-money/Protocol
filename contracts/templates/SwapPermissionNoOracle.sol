// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {Context} from "../interfaces/IPermission.sol";
import {IPermissionIntrospection} from "../interfaces/IPermissionIntrospection.sol";
import {SailCapabilities} from "../interfaces/SailCapabilities.sol";
import {ConfigurablePermission} from "./ConfigurablePermission.sol";

/// @title  SwapPermissionNoOracle — bounded swap with NO on-chain price band
/// @notice UNAUDITED EXAMPLE — NOT PART OF THE TRUSTED CORE.
///         This permission is a reference example demonstrating how to express a bounded
///         mandate against the Sail kernel. It is provided as-is, is NOT covered by the
///         protocol audit of the trusted core (SailKernel, SailGovernance, MandateFactory,
///         StandardFeePolicy, SafeModuleEnabler), and carries no warranty. The kernel
///         evaluates any permission safely under staticcall + a gas cap + fail-closed
///         semantics, but it does NOT verify that this permission's logic correctly
///         enforces what its NatSpec claims. Anyone registering this permission is
///         responsible for reviewing it. See docs/SECURITY.md for the audit-scope documentation.
///
///         WHAT IT IS. A swap template for tokens that have no trustworthy price oracle. One
///         deployment serves any number of accounts; each account stores its own routers, token
///         allowlists, and per-tx amount cap. For every trade it enforces that the input/output
///         tokens and the router are allowlisted, the input amount is within a per-tx cap, the
///         output recipient is the account itself, and the caller-supplied minimum-out is non-zero.
///
///         WHAT IT ENFORCES. Token allowlist, router allowlist, per-trade size cap, and output
///         recipient pinned to the account.
///
///         WHAT IT DOES NOT ENFORCE — read this. It does NOT enforce any on-chain slippage or
///         price band. There is no oracle and no reference price of any kind. Price protection
///         depends ENTIRELY on the manager-supplied amountOutMin carried in the swap calldata,
///         exactly as in any direct AMM swap a user signs themselves. The template guarantees only
///         that this minimum-out is non-zero; it does NOT guarantee the minimum-out is reasonable.
///         A manager (or a sandwicher exploiting a loose minimum-out) can still receive far less
///         than fair value. Use this template only when no trustworthy oracle exists for the traded
///         token AND the operator accepts that price-honesty rides entirely on the manager's quote.
///         If a usable oracle exists, prefer SwapPermission (the oracle-gated default).
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
/// @dev    This file intentionally DUPLICATES the structural/decode region of SwapPermission
///         verbatim (the three selector decode blocks, the allowlist checks, the size cap, and the
///         recipient pin). The only differences from SwapPermission are (1) the config blob has 4
///         fields instead of 7 and (2) each evaluate branch ends in `amountOutMin > 0` instead of
///         an oracle band. The duplication is a deliberate trade for standalone simplicity: if
///         either file's decode logic ever changes, BOTH must be updated together to stay in sync.
///
///         Config blob:
///             abi.encode(
///                 address[] routers,
///                 address[] tokensIn,
///                 address[] tokensOut,
///                 uint256   maxAmountPerTx
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

    struct Slot {
        address[] routers;
        address[] tokensIn;
        address[] tokensOut;
        uint256   maxAmountPerTx;
    }

    mapping(address account => Slot) private _slots;
    mapping(address account => mapping(address => bool)) public isAllowedRouter;
    mapping(address account => mapping(address => bool)) public isAllowedTokenIn;
    mapping(address account => mapping(address => bool)) public isAllowedTokenOut;

    /// @notice Tooling-layer attribution for the template author. The kernel never reads this.
    address public immutable author;

    constructor(address _kernel, address _author)
        ConfigurablePermission(_kernel, "SwapPermissionNoOracle", "1")
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

    // ── config application ────────────────────────────────────────────────────

    function _applyConfig(address account, bytes calldata params) internal override {
        (
            address[] memory routers,
            address[] memory tokensIn,
            address[] memory tokensOut,
            uint256 maxAmountPerTx
        ) = abi.decode(params, (address[], address[], address[], uint256));

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
            // Non-zero floor only — NOT a slippage band; price protection rides on amountOutMin.
            return amountOutMinimum > 0;
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
            // Non-zero floor only — NOT a slippage band; price protection rides on amountOutMin.
            return amountOutMinimum > 0;
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
            // Non-zero floor only — NOT a slippage band; price protection rides on amountOutMin.
            return amountOutMin > 0;
        }

        return false;
    }

    function discriminator() external pure returns (bytes32) {
        return keccak256("SwapPermissionNoOracle");
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
