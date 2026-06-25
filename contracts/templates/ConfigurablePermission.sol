// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {IPermission, Context} from "../interfaces/IPermission.sol";
import {IConfigurablePermission} from "../interfaces/IConfigurablePermission.sol";
import {AgentIdentityRef, IAccountAgentIdentityResolver} from "../interfaces/IAgentIdentityResolver.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @dev Subset of SailKernel that templates need to read.
///      `configs` declares only the field the templates actually use (permissionSigner,
///      ABI position 0). Declaring fewer return values than the kernel's full AccountConfig
///      getter is safe — the ABI decoder reads the first word and ignores trailing returndata —
///      and it cannot drift if the kernel struct later adds or reorders subsequent fields.
interface ISailKernelView {
    function registered(address account) external view returns (bool);
    function configs(address account) external view returns (address permissionSigner);
    /// @notice Current per-(account, permission) registration epoch. Bumped by the kernel whenever
    ///         the permission leaves the account's registry (revoke / replaced-out / manager-rotation
    ///         clear); NOT bumped on registration. Templates read it for `address(this)` to bind a
    ///         config to the registration it was signed against.
    function registrationEpoch(address account, address permission) external view returns (uint256);
}

/// @notice UNAUDITED EXAMPLE — NOT PART OF THE TRUSTED CORE.
///         Base class for the unaudited reference example permissions (SwapPermission,
///         BorrowPermission, TransferPermission, ApproveAndCallBatchPermission,
///         DepositPermission, WithdrawPermission). It is NOT part of the trusted core
///         (SailKernel, SailGovernance, MandateFactory, StandardFeePolicy, SafeModuleEnabler),
///         is not covered by the protocol audit of that core, and carries no warranty.
///         Anyone deploying a subclass is responsible for reviewing it. See docs/SECURITY.md
///         for the audit-scope documentation.
///
///         Abstract base for shared, multi-account permission templates.
///         One deployed instance serves any number of accounts; per-account config
///         is stored under `mapping(address => ...)` in concrete subclasses.
///
///         Auth: configure() requires an EIP-712 sig from the account's permissionSigner
///         (read from the kernel). configureDirect() requires msg.sender to equal the
///         permissionSigner. Both support ECDSA and ERC-1271 signers.
abstract contract ConfigurablePermission is IConfigurablePermission, IAccountAgentIdentityResolver, EIP712, ReentrancyGuard {
    bytes4 private constant ERC1271_MAGIC = 0x1626ba7e;

    bytes32 public constant CONFIGURE_TYPEHASH =
        keccak256("Configure(address account,bytes32 paramsHash,uint256 nonce,uint256 deadline,uint256 epoch)");

    bytes32 public constant SET_IDENTITY_TYPEHASH =
        keccak256("SetAgentIdentity(address account,bytes32 identityHash,uint256 nonce,uint256 deadline,uint256 epoch)");

    ISailKernelView public immutable kernel;

    mapping(address account => uint256) public configNonces;
    mapping(address account => bool)    public isConfigured;

    /// @notice The kernel registration epoch at which `account`'s config bounds were last applied
    ///         (via configure / configureDirect). Compared in evaluate() against the kernel's current
    ///         epoch (pushed as ctx.configEpoch) so a config that survived a revoke → re-register
    ///         cycle fails closed. Only the bound-applying paths write this; the identity paths do
    ///         NOT, so a fresh identity update cannot revive stale trading bounds.
    mapping(address account => uint256) public configuredEpoch;

    mapping(address account => AgentIdentityRef) private _agentIdentities;

    // ── events ────────────────────────────────────────────────────────────────
    event Configured(address indexed account, uint256 nonce, bytes32 paramsHash);
    event AgentIdentitySet(address indexed account, uint256 agentId, address agentWallet);

    // ── errors ────────────────────────────────────────────────────────────────
    error InvalidSignature();
    error DeadlineExpired(uint256 deadline, uint256 current);
    error AccountNotRegistered(address account);
    error NotPermissionSigner(address caller, address expected);
    error ZeroAddress();
    /// @notice Thrown when a price oracle is configured but no freshness bound is set.
    error MissingPriceAge();

    constructor(address _kernel, string memory name, string memory version)
        EIP712(name, version)
    {
        if (_kernel == address(0)) revert ZeroAddress();
        kernel = ISailKernelView(_kernel);
    }

    // ── IConfigurablePermission ───────────────────────────────────────────────

    /// @inheritdoc IConfigurablePermission
    function configure(
        address account,
        bytes calldata params,
        uint256 deadline,
        bytes calldata sig
    ) external nonReentrant {
        if (block.timestamp > deadline) revert DeadlineExpired(deadline, block.timestamp);
        if (!kernel.registered(account)) revert AccountNotRegistered(account);

        // Read nonce before incrementing — nonce is incremented AFTER signature verification
        // succeeds, preventing a failed verify from consuming the nonce.
        uint256 nonce = configNonces[account];
        // Bind the config to the CURRENT registration epoch. The signer signs `epoch` into the
        // typed data; the digest is rebuilt here with the on-chain value, so a signature produced
        // for a prior epoch (e.g. before a revoke that bumped the epoch) cannot verify — closing the
        // stale-config-signature replay (Octane #8). The domain-version bump invalidates any sig
        // predating this upgrade outright.
        uint256 epoch = kernel.registrationEpoch(account, address(this));
        bytes32 paramsHash = keccak256(params);
        bytes32 structHash = keccak256(abi.encode(
            CONFIGURE_TYPEHASH,
            account,
            paramsHash,
            nonce,
            deadline,
            epoch
        ));
        bytes32 digest = _hashTypedDataV4(structHash);

        address permSigner = kernel.configs(account);
        if (!_verifySig(permSigner, digest, sig)) revert InvalidSignature();

        // Increment nonce only after successful verification
        configNonces[account] = nonce + 1;
        _applyConfig(account, params);
        isConfigured[account] = true;
        configuredEpoch[account] = epoch;
        emit Configured(account, nonce, paramsHash);
    }

    /// @inheritdoc IConfigurablePermission
    function configureDirect(address account, bytes calldata params) external nonReentrant {
        if (!kernel.registered(account)) revert AccountNotRegistered(account);
        address permSigner = kernel.configs(account);
        if (msg.sender != permSigner) revert NotPermissionSigner(msg.sender, permSigner);

        uint256 nonce = configNonces[account]++;
        _applyConfig(account, params);
        isConfigured[account] = true;
        // No signature to bind, so stamp the current epoch unconditionally — keeps a direct config
        // current with the kernel's registration epoch.
        configuredEpoch[account] = kernel.registrationEpoch(account, address(this));
        emit Configured(account, nonce, keccak256(params));
    }

    /// @notice Exposed for off-chain sig construction.
    function hashTypedDataV4(bytes32 structHash) external view returns (bytes32) {
        return _hashTypedDataV4(structHash);
    }

    // ── IAccountAgentIdentityResolver ─────────────────────────────────────────

    /// @inheritdoc IAccountAgentIdentityResolver
    function agentIdentityFor(address account) external view returns (AgentIdentityRef memory) {
        return _agentIdentities[account];
    }

    /// @notice Set the agent identity for an account using an EIP-712 signature.
    /// @param  account  The registered Safe account.
    /// @param  ref      The AgentIdentityRef to store.
    /// @param  deadline Unix timestamp after which the signature is invalid.
    /// @param  sig      EIP-712 signature over SetAgentIdentity struct by permissionSigner.
    function setAgentIdentity(
        address account,
        AgentIdentityRef calldata ref,
        uint256 deadline,
        bytes calldata sig
    ) external nonReentrant {
        if (block.timestamp > deadline) revert DeadlineExpired(deadline, block.timestamp);
        if (!kernel.registered(account)) revert AccountNotRegistered(account);

        uint256 nonce = configNonces[account];
        // Bind identity writes to the current epoch too, so a stale identity signature cannot be
        // replayed across an epoch change. NOTE: identity writes do NOT stamp configuredEpoch —
        // they apply no trading bounds, so reviving a stale config via an identity update is
        // impossible by construction.
        uint256 epoch = kernel.registrationEpoch(account, address(this));
        bytes32 identityHash = keccak256(abi.encode(ref));
        bytes32 structHash = keccak256(abi.encode(SET_IDENTITY_TYPEHASH, account, identityHash, nonce, deadline, epoch));
        bytes32 digest = _hashTypedDataV4(structHash);

        address permSigner = kernel.configs(account);
        if (!_verifySig(permSigner, digest, sig)) revert InvalidSignature();

        configNonces[account] = nonce + 1;
        _agentIdentities[account] = ref;
        emit AgentIdentitySet(account, ref.agentId, ref.agentWallet);
    }

    /// @notice Set the agent identity for an account directly (no signature required).
    /// @dev    Caller must be the account's permissionSigner.
    /// @param  account  The registered Safe account.
    /// @param  ref      The AgentIdentityRef to store.
    /// @dev Increments `configNonces[account]` — callers must track nonce state if combining
    ///      with concurrent `configure` or `setAgentIdentity` calls for the same account.
    function setAgentIdentityDirect(address account, AgentIdentityRef calldata ref) external nonReentrant {
        if (!kernel.registered(account)) revert AccountNotRegistered(account);
        address permSigner = kernel.configs(account);
        if (msg.sender != permSigner) revert NotPermissionSigner(msg.sender, permSigner);

        configNonces[account]++;
        _agentIdentities[account] = ref;
        emit AgentIdentitySet(account, ref.agentId, ref.agentWallet);
    }

    // ── hooks for subclasses ──────────────────────────────────────────────────

    /// @dev Subclasses decode `params` and write to their per-account storage.
    function _applyConfig(address account, bytes calldata params) internal virtual;

    /// @dev Fail-closed freshness gate for evaluate()/evaluateBatch(). Returns true only when
    ///      `account` has applied config (isConfigured) AND the epoch it was stamped at matches the
    ///      kernel's current epoch for this permission (pushed by the kernel as `ctxEpoch`).
    ///      - isConfigured == false covers the never-configured / fresh-account (epoch 0) case.
    ///      - configuredEpoch != ctxEpoch covers a config left stale by a revoke → re-register cycle
    ///        (Octane #2 front-run and #8 replay): the re-register keeps the bumped epoch, so the old
    ///        stamp no longer matches until a fresh configure for the current epoch is applied.
    ///      Subclasses MUST call this as the first check in every evaluate path.
    function _configCurrent(address account, uint256 ctxEpoch) internal view returns (bool) {
        return isConfigured[account] && configuredEpoch[account] == ctxEpoch;
    }

    // ── internal ──────────────────────────────────────────────────────────────

    function _verifySig(address expected, bytes32 digest, bytes calldata sig)
        internal
        view
        returns (bool)
    {
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, sig);
        if (err == ECDSA.RecoverError.NoError && recovered == expected) return true;
        if (expected.code.length > 0) {
            try IERC1271(expected).isValidSignature(digest, sig) returns (bytes4 magic) {
                return magic == ERC1271_MAGIC;
            } catch {
                return false;
            }
        }
        return false;
    }
}
