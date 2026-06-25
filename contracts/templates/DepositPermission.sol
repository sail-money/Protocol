// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {Context} from "../interfaces/IPermission.sol";
import {IPermissionIntrospection} from "../interfaces/IPermissionIntrospection.sol";
import {SailCapabilities} from "../interfaces/SailCapabilities.sol";
import {ConfigurablePermission} from "./ConfigurablePermission.sol";

/// @title  DepositPermission — bounded ERC-20 deposit credited to the account
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
///         WHAT IT IS. A reference deposit template. One deployment serves any number of accounts;
///         each account stores its own target (protocol/vault) allowlist, token allowlist, and
///         per-tx amount cap. It gates a manager's ERC-20 deposits into vaults and lending pools so
///         the resulting position is always credited to the account itself.
///
///         WHAT IT ENFORCES. For every deposit: the target (call destination) is allowlisted; the
///         deposited token/asset is allowlisted; the amount is within the per-tx cap; and the
///         position recipient — receiver (ERC-4626) or onBehalfOf (Aave-style) — equals the
///         account, never an arbitrary address. Calls carrying native ETH (msg.value != 0) are
///         rejected: deposits are ERC-20 only (wrap to WETH first).
///
///         SELECTOR / VENUE BOUNDARY. Recognizes exactly four standard deposit shapes:
///           - deposit(uint256 assets, address receiver)                          — ERC-4626 / simple vault
///           - mint(uint256 shares, address receiver)                             — ERC-4626
///           - deposit(address asset, uint256 amount, address onBehalfOf, uint16) — Aave v2
///           - supply(address asset, uint256 amount, address onBehalfOf, uint16)  — Aave v3
///         Any other selector — or a non-standard / non-ERC-4626 / non-Aave-style deposit interface
///         — is denied. TOKEN ALLOWLIST ON ERC-4626 PATHS: deposit(assets,receiver) and
///         mint(shares,receiver) do NOT carry the underlying token in calldata — only the vault
///         (the call target). A given ERC-4626 vault accepts exactly one fixed underlying, so the
///         template requires the VAULT ADDRESS ITSELF to be in the token allowlist (in addition to
///         the target allowlist); allowlisting the vault thereby authorizes deposits of that one
///         token. For the Aave-style paths the asset is a calldata argument and is allowlisted
///         directly.
///
///         HONEST BOUNDARY — what it does NOT do. The cap on mint() is denominated in SHARES, not
///         underlying assets — its asset/USD value floats with the share price, and these templates
///         are oracle-free, so an operator sizing a mint cap must account for that. The cap is
///         per-transaction, NOT cumulative. An allowlisted-but-malicious vault or pool is not vetted
///         here; the template constrains the deposit shape and destination, not the venue's honesty.
///
/// @dev    Config blob:
///             abi.encode(
///                 address[] targets,
///                 address[] tokens,
///                 uint256   maxAmountPerTx
///             )
/// @custom:security-contact security@sail.money
contract DepositPermission is ConfigurablePermission, IPermissionIntrospection {
    /// @dev deposit(uint256 assets, address receiver) — ERC-4626 / simple vault.
    bytes4 private constant DEPOSIT_SIMPLE = bytes4(keccak256("deposit(uint256,address)"));
    /// @dev mint(uint256 shares, address receiver) — ERC-4626.
    bytes4 private constant MINT           = bytes4(keccak256("mint(uint256,address)"));
    /// @dev deposit(address asset, uint256 amount, address onBehalfOf, uint16) — Aave v2.
    bytes4 private constant DEPOSIT_AAVE   = bytes4(keccak256("deposit(address,uint256,address,uint16)"));
    /// @dev supply(address asset, uint256 amount, address onBehalfOf, uint16) — Aave v3.
    bytes4 private constant SUPPLY_AAVE    = bytes4(keccak256("supply(address,uint256,address,uint16)"));

    uint256 private constant LEN_2ARG = 68;  // selector(4) + 2 × 32
    uint256 private constant LEN_4ARG = 132; // selector(4) + 4 × 32

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
        ConfigurablePermission(_kernel, "DepositPermission", "2")
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
        // Fail closed unless the stored config is current for this registration epoch (Octane #2/#8).
        if (!_configCurrent(ctx.account, ctx.configEpoch)) return false;
        // No supported deposit selector is payable — reject native ETH.
        if (ctx.value != 0) return false;
        // Protocol / vault must be on the account's target allowlist.
        if (!isAllowedTarget[ctx.account][ctx.target]) return false;
        Slot storage s = _slots[ctx.account];

        // ── deposit(uint256 assets, address receiver) — ERC-4626 ──────────────
        if (ctx.selector == DEPOSIT_SIMPLE) {
            if (txData.length < LEN_2ARG) return false;
            (uint256 amount, address receiver) = abi.decode(txData[4:], (uint256, address));
            // Asset is not in calldata; require the vault itself to be token-allowlisted.
            if (!isAllowedToken[ctx.account][ctx.target]) return false;
            if (amount > s.maxAmountPerTx) return false;
            return receiver == ctx.account;
        }

        // ── mint(uint256 shares, address receiver) — ERC-4626 ─────────────────
        if (ctx.selector == MINT) {
            if (txData.length < LEN_2ARG) return false;
            (uint256 shares, address receiver) = abi.decode(txData[4:], (uint256, address));
            // Asset is not in calldata; require the vault itself to be token-allowlisted.
            if (!isAllowedToken[ctx.account][ctx.target]) return false;
            // NOTE: the cap on mint() is denominated in SHARES, not underlying assets — its
            // asset/USD value floats with the share price. These templates are intentionally
            // oracle-free; operators sizing this cap must account for the share price.
            if (shares > s.maxAmountPerTx) return false;
            return receiver == ctx.account;
        }

        // ── deposit(address asset, uint256 amount, address onBehalfOf, uint16) — Aave v2 ─
        if (ctx.selector == DEPOSIT_AAVE) {
            if (txData.length < LEN_4ARG) return false;
            (address asset, uint256 amount, address onBehalfOf,) =
                abi.decode(txData[4:], (address, uint256, address, uint16));
            if (!isAllowedToken[ctx.account][asset]) return false;
            if (amount > s.maxAmountPerTx) return false;
            return onBehalfOf == ctx.account;
        }

        // ── supply(address asset, uint256 amount, address onBehalfOf, uint16) — Aave v3 ─
        if (ctx.selector == SUPPLY_AAVE) {
            if (txData.length < LEN_4ARG) return false;
            (address asset, uint256 amount, address onBehalfOf,) =
                abi.decode(txData[4:], (address, uint256, address, uint16));
            if (!isAllowedToken[ctx.account][asset]) return false;
            if (amount > s.maxAmountPerTx) return false;
            return onBehalfOf == ctx.account;
        }

        return false;
    }

    function discriminator() external pure returns (bytes32) {
        return keccak256("DepositPermission");
    }

    // ── IPermissionIntrospection ──────────────────────────────────────────────

    function permissionId() external pure override returns (bytes32) {
        return keccak256("sail.permission.DepositPermission.v1");
    }

    function permissionVersion() external pure override returns (bytes32) {
        return keccak256("v1");
    }

    function metadataURI() external pure override returns (string memory) {
        return "";
    }

    function capabilityIds() external pure override returns (bytes32[] memory ids) {
        ids = new bytes32[](1);
        ids[0] = SailCapabilities.DEPOSIT;
    }
}
