// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {Context} from "../interfaces/IPermission.sol";
import {IPermissionIntrospection} from "../interfaces/IPermissionIntrospection.sol";
import {SailCapabilities} from "../interfaces/SailCapabilities.sol";
import {ConfigurablePermission} from "./ConfigurablePermission.sol";

/// @title  WithdrawPermission — bounded vault / lending-pool exits paid to the account
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
///         set (currently empty), not this hardened launch set. See docs/SECURITY_MODEL.md for the
///         reference-template documentation.
///
///         WHAT IT IS. A reference withdraw (position-exit) template. One deployment serves any
///         number of accounts; each account stores its own vault/pool target allowlist, an asset
///         allowlist (consulted on the Aave path, where the asset is in calldata), and a per-tx
///         cap. It gates ERC-4626 vault exits and Aave v2/v3 pool withdrawals so redeemed funds
///         can only ever be paid to the account itself, and shares can only ever be burned from
///         the account's own position.
///
///         WHAT IT ENFORCES. For every call: the vault/pool (call target) is allowlisted; the
///         amount is within the per-tx cap; and every address argument naming a recipient or
///         position owner equals the account. On the ERC-4626 paths BOTH `receiver` AND `owner`
///         are pinned to the account: `receiver` keeps the proceeds in the account, and `owner`
///         stops the manager from burning a third party's shares through a share allowance
///         granted to the account (a third-party-position drain — the pin that is easy to omit).
///         On the Aave path `to` is pinned to the account and the withdrawn asset must be on the
///         asset allowlist. Calls carrying native ETH (msg.value != 0) are rejected.
///
///         SELECTOR BOUNDARY. Recognizes exactly three exit selectors:
///           - withdraw(uint256 assets, address receiver, address owner)  — ERC-4626 (0xb460af94)
///           - redeem(uint256 shares, address receiver, address owner)    — ERC-4626 (0xba087652)
///           - withdraw(address asset, uint256 amount, address to)        — Aave v2 LendingPool /
///             v3 Pool, identical signature on both, one branch covers both (0x69328dec)
///         Any other selector is denied. This gates protocol exits; it does NOT gate plain ERC-20
///         transfers — for a bounded ERC-20 move to a fixed recipient, use TransferPermission
///         with a one-entry recipient allowlist.
///
///         UNIFORM INVARIANT — why Aave v4 and Compound are OUT of scope. Every exit this
///         template permits carries its recipient IN CALLDATA, pinned to the account. Venues
///         whose exits pay `msg.sender` with no calldata recipient — Compound v2 `redeem` /
///         `redeemUnderlying`, Compound v3 `withdraw`, and Aave v4's Spoke
///         `withdraw(uint256 reserveId, uint256 amount, address onBehalfOf)` (funds are sent to
///         msg.sender; `onBehalfOf` names the debited position, not the destination) — cannot
///         satisfy that invariant by calldata inspection: their "funds stay with the account"
///         property is structural (msg.sender == account), not checkable here. Mixing them in
///         would weaken the uniform guarantee, so they are intentionally unrecognized (deny);
///         they need a dedicated permission if demanded.
///
///         HONEST BOUNDARY — what it does NOT do. An allowlisted vault or pool is not vetted —
///         the template constrains where proceeds go and how much exits per call, not the venue's
///         honesty or solvency. The cap on the `redeem(shares, ...)` path is denominated in
///         SHARES, not underlying assets — by design: `withdraw(assets, ...)` and the Aave path
///         cap the asset amount directly, while redeem bounds shares, whose underlying value
///         floats with the share price (these templates are intentionally oracle-free; operators
///         sizing a redeem cap must account for the share price). The cap is per-transaction, NOT
///         cumulative — a manager may make many at-cap exits. A maxAmountPerTx of 0 is accepted
///         and blocks every non-zero exit (fail-closed).
///
///         CONFIG FRESHNESS (fail-closed). Evaluation denies unless this account is configured AND
///         its stored config epoch equals the kernel's current registration epoch for this
///         (account, permission). A configuration left over from a prior registration — e.g. after a
///         revoke / re-register cycle — is never honoured.
///
/// @dev    Config blob:
///             abi.encode(
///                 address[] targets,
///                 address[] tokens,
///                 uint256   maxAmountPerTx
///             )
/// @custom:security-contact hello@sail.money
contract WithdrawPermission is ConfigurablePermission, IPermissionIntrospection {
    /// @dev withdraw(uint256 assets, address receiver, address owner) — ERC-4626. 0xb460af94.
    bytes4 private constant WITHDRAW_4626 = bytes4(keccak256("withdraw(uint256,address,address)"));
    /// @dev redeem(uint256 shares, address receiver, address owner) — ERC-4626. 0xba087652.
    bytes4 private constant REDEEM_4626   = bytes4(keccak256("redeem(uint256,address,address)"));
    /// @dev withdraw(address asset, uint256 amount, address to) — Aave v2 LendingPool AND v3 Pool
    ///      (identical signature, so one selector covers both). 0x69328dec.
    bytes4 private constant WITHDRAW_AAVE = bytes4(keccak256("withdraw(address,uint256,address)"));

    /// @dev All three recognized selectors take exactly three 32-byte words.
    uint256 private constant LEN_3ARG = 100; // selector(4) + 3 × 32

    uint256 private constant MAX_ALLOWLIST_LENGTH = 50;

    struct Slot {
        address[] targets;
        address[] tokens;
        uint256   maxAmountPerTx;
    }

    mapping(address account => Slot) private _slots;
    mapping(address account => mapping(address => bool)) public isAllowedTarget;
    mapping(address account => mapping(address => bool)) public isAllowedToken;

    /// @notice Tooling-layer attribution for the template author. The kernel never reads this.
    address public immutable author;

    error AllowlistTooLong();
    error EmptyAllowlist();

    constructor(address _kernel, address _author)
        ConfigurablePermission(_kernel, "WithdrawPermission", "2")
    {
        author = _author;
    }

    function getConfig(address account)
        external
        view
        returns (address[] memory targets, address[] memory tokens, uint256 maxAmountPerTx)
    {
        Slot storage s = _slots[account];
        return (s.targets, s.tokens, s.maxAmountPerTx);
    }

    function _applyConfig(address account, bytes calldata params) internal override {
        (address[] memory targets, address[] memory tokens, uint256 maxAmountPerTx) =
            abi.decode(params, (address[], address[], uint256));

        // Config validation (reference-grade): bound both allowlists, reject empty arrays,
        // and reject zero-address entries. maxAmountPerTx == 0 is allowed (fail-closed).
        if (targets.length > MAX_ALLOWLIST_LENGTH || tokens.length > MAX_ALLOWLIST_LENGTH) revert AllowlistTooLong();
        if (targets.length == 0 || tokens.length == 0) revert EmptyAllowlist();
        for (uint256 i; i < targets.length; i++) if (targets[i] == address(0)) revert ZeroAddress();
        for (uint256 i; i < tokens.length; i++)  if (tokens[i] == address(0))  revert ZeroAddress();

        Slot storage s = _slots[account];
        for (uint256 i; i < s.targets.length; i++) isAllowedTarget[account][s.targets[i]] = false;
        for (uint256 i; i < s.tokens.length; i++)  isAllowedToken[account][s.tokens[i]]   = false;

        for (uint256 i; i < targets.length; i++) isAllowedTarget[account][targets[i]] = true;
        for (uint256 i; i < tokens.length; i++)  isAllowedToken[account][tokens[i]]   = true;

        s.targets        = targets;
        s.tokens         = tokens;
        s.maxAmountPerTx = maxAmountPerTx;
    }

    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool) {
        // Fail closed unless the stored config is current for this registration epoch.
        if (!_configCurrent(ctx.account, ctx.configEpoch)) return false;
        // No supported exit selector is payable — reject native ETH.
        if (ctx.value != 0) return false;
        // Vault / pool must be on the account's target allowlist.
        if (!isAllowedTarget[ctx.account][ctx.target]) return false;
        Slot storage s = _slots[ctx.account];

        // ── withdraw(uint256 assets, address receiver, address owner) — ERC-4626 ──
        if (ctx.selector == WITHDRAW_4626) {
            if (txData.length < LEN_3ARG) return false;
            (uint256 assets, address receiver, address owner) =
                abi.decode(txData[4:], (uint256, address, address));
            if (assets > s.maxAmountPerTx) return false;
            // BOTH pins are required. `receiver` keeps the proceeds in the account; `owner`
            // stops the manager from burning a third party's shares through a share allowance
            // granted to the account (third-party-position drain).
            if (receiver != ctx.account) return false;
            return owner == ctx.account;
        }

        // ── redeem(uint256 shares, address receiver, address owner) — ERC-4626 ────
        if (ctx.selector == REDEEM_4626) {
            if (txData.length < LEN_3ARG) return false;
            (uint256 shares, address receiver, address owner) =
                abi.decode(txData[4:], (uint256, address, address));
            // NOTE: the cap on redeem() is denominated in SHARES, not underlying assets — its
            // asset/USD value floats with the share price. These templates are intentionally
            // oracle-free; operators sizing this cap must account for the share price.
            if (shares > s.maxAmountPerTx) return false;
            if (receiver != ctx.account) return false;
            return owner == ctx.account;
        }

        // ── withdraw(address asset, uint256 amount, address to) — Aave v2 / v3 ────
        if (ctx.selector == WITHDRAW_AAVE) {
            if (txData.length < LEN_3ARG) return false;
            (address asset, uint256 amount, address to) =
                abi.decode(txData[4:], (address, uint256, address));
            // Unlike the ERC-4626 paths (where only the vault is in calldata), the Aave asset
            // IS in calldata — allowlist it.
            if (!isAllowedToken[ctx.account][asset]) return false;
            if (amount > s.maxAmountPerTx) return false;
            return to == ctx.account;
        }

        return false;
    }

    function discriminator() external pure returns (bytes32) {
        return keccak256("WithdrawPermission");
    }

    // ── IPermissionIntrospection ──────────────────────────────────────────────

    function permissionId() external pure override returns (bytes32) {
        return keccak256("sail.permission.WithdrawPermission.v1");
    }

    function permissionVersion() external pure override returns (bytes32) {
        return keccak256("v1");
    }

    function metadataURI() external pure override returns (string memory) {
        return "";
    }

    function capabilityIds() external pure override returns (bytes32[] memory ids) {
        ids = new bytes32[](1);
        ids[0] = SailCapabilities.WITHDRAW;
    }
}
