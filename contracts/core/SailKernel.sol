// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {IPermission, Context}                from "../interfaces/IPermission.sol";
import {IBatchPermission, Call, BatchContext} from "../interfaces/IBatchPermission.sol";
import {IPermissionIntrospection}             from "../interfaces/IPermissionIntrospection.sol";
import {IFeePolicy}                            from "../interfaces/IFeePolicy.sol";
import {SailGovernance}        from "../governance/SailGovernance.sol";
import {ECDSA}                 from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712}                from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ReentrancyGuard}       from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC1271}              from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC20}                from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Math}                  from "@openzeppelin/contracts/utils/math/Math.sol";

/// @dev Minimal Safe factory interface — used only in `createAccount`.
interface ISafeFactory {
    function createProxyWithNonce(address singleton, bytes calldata initializer, uint256 saltNonce)
        external
        returns (address proxy);

    /// @notice The proxy creation bytecode the factory deploys (excludes the appended
    ///         singleton constructor arg). For Safe v1.4.1 this is `type(SafeProxy).creationCode`.
    /// @dev    The kernel uses this to predict the CREATE2 proxy address locally (see
    ///         `createAccount`), so it can adopt an already-deployed proxy (idempotency /
    ///         front-run resilience) without a factory-side predictor. Safe v1.4.1's factory
    ///         exposes `proxyCreationCode()` but NOT a view address predictor —
    ///         `calculateCreateProxyWithNonceAddress` was a revert-based simulator removed after v1.3.0.
    function proxyCreationCode() external pure returns (bytes memory);
}

/// @dev Minimal Safe module interface — used for executing transactions and fee transfers.
/// @dev DEPLOY ASSUMPTION: only Safe v1.4.1-style proxies may be governance-codehash-allowlisted —
///      i.e. proxies that (a) intercept masterCopy() (0xa619486e) from storage slot 0 in their own
///      fallback, (b) expose nonce(), and (c) implement Safe-core checkSignatures(bytes32,bytes,bytes).
///      registerAccount's #9 singleton pin and #4 owner-signature gate rely on all three.
interface ISafe {
    function execTransactionFromModule(address to, uint256 value, bytes calldata data, uint8 operation)
        external
        returns (bool success);

    function execTransactionFromModuleReturnData(address to, uint256 value, bytes calldata data, uint8 operation)
        external
        returns (bool success, bytes memory returnData);

    function isModuleEnabled(address module) external view returns (bool);

    /// @notice The Safe's transaction nonce. Incremented by `execTransaction` (before the inner
    ///         call runs) and never by `setup` — so a value of 0 proves the Safe has not yet
    ///         executed an owner-approved transaction (used to reject setup-time registration).
    function nonce() external view returns (uint256);

    /// @notice The Safe singleton (master copy) the proxy delegates to. On a genuine SafeProxy
    ///         v1.4.1 this is intercepted by the proxy's own fallback (selector 0xa619486e) and
    ///         read from storage slot 0, so it cannot be forged by a hostile singleton.
    function masterCopy() external view returns (address);

    /// @notice Validate `signatures` over `dataHash` against the Safe's owner set and threshold.
    ///         Safe-core method (not the fallback handler's ERC-1271 entrypoint), so it carries no
    ///         dependency on which fallbackHandler is configured. Reverts (GS0xx) on any failure;
    ///         returns nothing on success. `data` is only consulted for legacy contract-signature
    ///         (v==0) entries (requires keccak256(data)==dataHash); empty for EOA / approved-hash.
    function checkSignatures(bytes32 dataHash, bytes calldata data, bytes calldata signatures) external view;
}

/// @title  SailKernel
/// @notice Central execution kernel for the Sail protocol.
///
///         The kernel manages a registry of Safe accounts, each with a set of
///         permission contracts. When a manager submits a signed transaction, the
///         kernel:
///           1. Verifies the manager's EIP-712 signature and nonce.
///           2. Evaluates the named registered permission (only the selected permission must return true).
///           3. Executes the transaction via Safe's module interface.
///
///         Key design properties:
///           • Deny-by-default: accounts with no registered permissions cannot dispatch.
///           • Permission cap: governance-tunable limit (1–100) per account to bound
///             gas usage in the dispatch loop; read from SailGovernance at registration time.
///           • Salt binding: `createAccount` binds the CREATE2 salt to msg.sender to
///             prevent front-running attacks on Safe registration.
///           • Two-tier nonces: manager nonces gate dispatch; signer nonces gate
///             permission-registry operations, preventing cross-operation replay.
///           • ERC-1271 support: both manager and permissionSigner may be smart contracts.
///
/// @custom:security-contact security@sail.money
contract SailKernel is EIP712, ReentrancyGuard {
    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    /// @notice Gas budget allocated to each permission's `evaluate` staticcall.
    ///         A revert or gas exhaustion within a permission is treated as a false return.
    ///         Increased to 150_000 to accommodate templates (e.g. GMXPerpPermission,
    ///         AzuroPredictionPermission, LimitlessPredictionPermission) that use
    ///         `try this._decode*(...)` external calls within their evaluate paths.
    uint256 public constant PERMISSION_GAS_CAP = 150_000;

    /// @notice Maximum number of subcalls in a single batch dispatch.
    /// @dev    Bounds gas consumption in the subcall execution loop. A manager that needs
    ///         more than this can split into multiple consecutive batch dispatches.
    uint256 public constant MAX_BATCH_LENGTH = 16;

    /// @notice Gas budget allocated to a batch permission's `evaluateBatch` staticcall.
    /// @dev    Higher than PERMISSION_GAS_CAP because the batch evaluator must inspect
    ///         every subcall's calldata; a revert, OOG, or malformed return is treated
    ///         as a false return (fail-closed).
    uint256 public constant BATCH_EVAL_GAS_CAP = 1_000_000;

    /// @dev Gas budget for the `isBatchPermission()` type-detection staticcall. A view
    ///      function returning a bool should comfortably fit; a larger budget would
    ///      enlarge the attack surface without benefit.
    uint256 private constant BATCH_DETECT_GAS_CAP = 20_000;

    /// @dev Large nonce step applied to managerNonces/batchNonces when a signer restriction op
    ///      (revokePermission, replacePermission, revokeSession, revokePermissions) takes effect.
    ///      Invalidates any outstanding manager-signed dispatches that pre-date the restriction
    ///      without requiring separate nonce-rotation messages (Octane finding #7 related).
    uint256 private constant NONCE_EPOCH_INCREMENT = 1 << 128;

    /// @dev ERC-1271 magic value returned by `isValidSignature` for a valid signature.
    bytes4  private constant ERC1271_MAGIC              = 0x1626ba7e;

    /// @dev Exact calldata length of `setManager(address)`: selector (4) + 1 static arg (32).
    ///      Used by the W1 fallback-relay guard — a Safe FallbackManager relay appends the
    ///      original caller's 20 bytes, so any deviation from this length flags a relayed call.
    uint256 private constant SET_MANAGER_CALLDATA_LEN  = 36;

    /// @dev Exact calldata length of `collectFees(address,uint256,uint256,address)`:
    ///      selector (4) + 4 static args (128). See `SET_MANAGER_CALLDATA_LEN` for the W1 rationale.
    uint256 private constant COLLECT_FEES_CALLDATA_LEN = 132;

    // -------------------------------------------------------------------------
    // EIP-712 type hashes
    // -------------------------------------------------------------------------

    /// @notice EIP-712 type hash for manager dispatch authorisation.
    ///         Type string: "Dispatch(address account,address permission,address target,uint256 value,bytes32 dataHash,uint256 nonce,uint256 deadline)"
    /// @dev BREAKING CHANGE from v1: `permission` field added. Any pre-signed dispatch
    ///      messages created against the v1 typehash are permanently invalid after this upgrade.
    ///      Off-chain systems (keeper bots, SDK integrations) must re-generate signatures.
    bytes32 public constant DISPATCH_TYPEHASH = keccak256(
        "Dispatch(address account,address permission,address target,uint256 value,bytes32 dataHash,uint256 nonce,uint256 deadline)"
    );

    /// @notice EIP-712 type hash for single-permission registration.
    ///         Type string: "RegisterPermission(address account,address permission,uint256 nonce,uint256 deadline)"
    bytes32 public constant REGISTER_PERMISSION_TYPEHASH = keccak256(
        "RegisterPermission(address account,address permission,uint256 nonce,uint256 deadline)"
    );

    /// @notice EIP-712 type hash for single-permission revocation.
    ///         Type string: "RevokePermission(address account,address permission,uint256 nonce,uint256 deadline)"
    bytes32 public constant REVOKE_PERMISSION_TYPEHASH = keccak256(
        "RevokePermission(address account,address permission,uint256 nonce,uint256 deadline)"
    );

    /// @notice EIP-712 type hash for atomic permission replacement.
    ///         Type string: "ReplacePermission(address account,address oldPermission,address newPermission,uint256 nonce,uint256 deadline)"
    bytes32 public constant REPLACE_PERMISSION_TYPEHASH = keccak256(
        "ReplacePermission(address account,address oldPermission,address newPermission,uint256 nonce,uint256 deadline)"
    );

    /// @notice EIP-712 type hash for atomic batch permission replacement.
    ///         Type string: "ReplacePermissions(address account,address[] oldPermissions,address[] newPermissions,uint256 nonce,uint256 deadline)"
    bytes32 public constant REPLACE_PERMISSIONS_TYPEHASH = keccak256(
        "ReplacePermissions(address account,address[] oldPermissions,address[] newPermissions,uint256 nonce,uint256 deadline)"
    );

    /// @notice EIP-712 type hash for session revocation.
    ///         Type string: "RevokeSession(address account,uint256 nonce,uint256 deadline)"
    bytes32 public constant REVOKE_SESSION_TYPEHASH = keccak256(
        "RevokeSession(address account,uint256 nonce,uint256 deadline)"
    );

    /// @notice EIP-712 type hash for session re-activation.
    ///         Type string: "ActivateSession(address account,uint256 nonce,uint256 deadline)"
    bytes32 public constant ACTIVATE_SESSION_TYPEHASH = keccak256(
        "ActivateSession(address account,uint256 nonce,uint256 deadline)"
    );

    /// @notice EIP-712 type hash for fee policy updates.
    ///         Type string: "SetFeePolicy(address account,address newFeePolicy,address feeAsset,uint256 nonce,uint256 deadline)"
    bytes32 public constant SET_FEE_POLICY_TYPEHASH = keccak256(
        "SetFeePolicy(address account,address newFeePolicy,address feeAsset,uint256 nonce,uint256 deadline)"
    );

    /// @notice EIP-712 type hash for batch permission registration.
    ///         Type string: "RegisterPermissions(address account,address[] permissions,uint256 nonce,uint256 deadline)"
    ///         The `address[]` field is encoded as keccak256 of the ABI-packed padded addresses
    ///         per EIP-712 §4 (see `_hashAddressArray`).
    bytes32 public constant REGISTER_PERMISSIONS_TYPEHASH = keccak256(
        "RegisterPermissions(address account,address[] permissions,uint256 nonce,uint256 deadline)"
    );

    /// @notice EIP-712 type hash for batch permission revocation.
    ///         Type string: "RevokePermissions(address account,address[] permissions,uint256 nonce,uint256 deadline)"
    bytes32 public constant REVOKE_PERMISSIONS_TYPEHASH = keccak256(
        "RevokePermissions(address account,address[] permissions,uint256 nonce,uint256 deadline)"
    );

    /// @notice EIP-712 type hash for manager batch-dispatch authorisation.
    ///         Type string: "DispatchBatch(address account,address permission,bytes32 callsHash,uint256 nonce,uint256 deadline)"
    ///         `callsHash` = keccak256(abi.encode(calls)) — see `dispatchBatch` for the encoding.
    bytes32 public constant DISPATCH_BATCH_TYPEHASH = keccak256(
        "DispatchBatch(address account,address permission,bytes32 callsHash,uint256 nonce,uint256 deadline)"
    );

    /// @notice EIP-712 type hash for owner-authorised self-registration via `registerAccount`.
    ///         Type string: "RegisterAccount(address account,address permissionSigner,address manager,address feePolicy,address feeAsset,uint256 deadline)"
    /// @dev    The owner-set+threshold signature over this struct is the robust gate for the
    ///         self-registration path: it cannot be produced by a Safe.setup delegatecall helper
    ///         (which has no owner keys). No nonce field — registration is one-shot (the
    ///         `registered[account]` latch is never cleared, so a replayed signature reverts with
    ///         AccountAlreadyRegistered) and the EIP-712 domain pins chainId against cross-chain replay.
    bytes32 public constant REGISTER_ACCOUNT_TYPEHASH = keccak256(
        "RegisterAccount(address account,address permissionSigner,address manager,address feePolicy,address feeAsset,uint256 deadline)"
    );

    // -------------------------------------------------------------------------
    // Account state
    // -------------------------------------------------------------------------

    /// @notice Per-account configuration set at registration and updatable via signed ops.
    struct AccountConfig {
        /// @dev Address whose signatures authorise permission-registry operations.
        address permissionSigner;
        /// @dev Address whose signatures authorise dispatch calls.
        address manager;
        /// @dev Fee policy contract; address(0) means no fee policy is configured.
        address feePolicy;
        /// @dev Canonical fee settlement token; address(0) = native ETH.
        address feeAsset;
        /// @dev When false, all dispatch calls for this account are blocked.
        bool    sessionActive;
    }

    /// @notice Enriched permission descriptor returned by getPermissionsWithInfo.
    struct PermissionInfo {
        /// @dev Contract address of the permission.
        address permission;
        /// @dev True if the permission implements IBatchPermission.isBatchPermission().
        bool    isBatch;
        /// @dev True if the permission implements IPermissionIntrospection.
        bool    hasIntrospection;
        /// @dev From IPermissionIntrospection.permissionId(); bytes32(0) if not supported.
        bytes32 permissionId;
        /// @dev From IPermissionIntrospection.permissionVersion(); bytes32(0) if not supported.
        bytes32 permissionVersion;
    }

    /// @notice Per-account configuration.
    mapping(address account => AccountConfig)                          public  configs;

    /// @notice Whether an account has been registered with the kernel.
    mapping(address account => bool)                                   public  registered;

    /// @dev Ordered list of permission addresses per account. Maintained as a packed array
    ///      with swap-and-pop removal to keep indices compact. Max length: governance.maxPermissionsPerAccount().
    mapping(address account => address[])                              private _permissions;

    /// @dev Index-plus-one of each permission in `_permissions[account]`.
    ///      Zero means the permission is not registered. Stored as index+1 to distinguish
    ///      "registered at slot 0" from "not registered".
    mapping(address account => mapping(address permission => uint256)) private _permissionIndex;

    /// @notice Per-account nonces for manager dispatch signatures.
    ///         Separate from signerNonces to prevent cross-operation replay.
    mapping(address account => uint256) public managerNonces;

    /// @notice Per-account nonces for manager batch-dispatch signatures.
    /// @dev    Lives in a separate namespace from `managerNonces` so that single
    ///         dispatches and batch dispatches cannot replay across each other.
    ///         Consuming a batch nonce does not advance dispatch nonces, and vice versa.
    mapping(address account => uint256) public batchNonces;

    /// @notice Per-account nonces for permissionSigner operations
    ///         (register, revoke, replace, session, feePolicy).
    /// @dev    All signer operations share a single nonce counter per account.
    ///         Concurrent independent operations must use batch variants (registerPermissions,
    ///         revokePermissions) rather than multiple single-op calls. Submitting two
    ///         single-op calls simultaneously will cause one to fail due to nonce conflict.
    mapping(address account => uint256) public signerNonces;

    /// @notice Per-(account, permission) registration epoch. A plain monotonic counter, bumped
    ///         every time a permission LEAVES an account's registry (revoke, the removed side of a
    ///         replace, or a manager-rotation clear). It is NOT bumped on registration: a freshly
    ///         registered permission keeps its epoch so the configure-then-register flow (see
    ///         MandateFactory) stamps the same epoch the dispatch later reads.
    /// @dev    Pushed into Context/BatchContext at dispatch time so a ConfigurablePermission can
    ///         compare it against the epoch it stamped at configure() time and fail closed when a
    ///         stale configuration survives a revoke → re-register cycle (Octane #2 / #8). Distinct
    ///         from the packed manager/batch nonce epochs (NONCE_EPOCH_INCREMENT) — this is a clean
    ///         standalone +1 counter per (account, permission).
    mapping(address account => mapping(address permission => uint256)) public registrationEpoch;

    // -------------------------------------------------------------------------
    // Principal tracking
    // -------------------------------------------------------------------------

    /// @notice Cumulative deposit amount recorded for each account (informational).
    ///         Written by the permissionSigner via `recordDeposit`.
    mapping(address account => uint256) public cumulativeDeposits;

    /// @notice Cumulative withdrawal amount recorded for each account (informational).
    ///         Written by the permissionSigner via `recordWithdrawal`.
    mapping(address account => uint256) public cumulativeWithdrawals;

    /// @dev Records the single fee asset a policy instance has been bound to for an account.
    ///      `bound` is an explicit flag (not asset != 0) because address(0) is a valid fee
    ///      asset (native ETH), so it cannot double as the "unbound" sentinel.
    struct PolicyAssetBinding {
        bool    bound;
        address asset;
    }

    /// @notice Per-(account, policy) binding pinning a fee-policy instance to the single fee
    ///         asset it was first used with for that account. Reusing the SAME policy instance
    ///         with a DIFFERENT asset would leave the policy's persisted high-water mark in
    ///         stale units, inflating the next performance fee on a one-time over-collection.
    ///         To change the fee asset, point the account at a fresh policy instance, which
    ///         carries its own fresh per-account state.
    mapping(address account => mapping(address policy => PolicyAssetBinding)) private _policyAssetBinding;

    // -------------------------------------------------------------------------
    // Protocol references
    // -------------------------------------------------------------------------

    /// @notice The governance contract that stores fee parameters and the protocol cut.
    SailGovernance public immutable governance;

    /// @notice Runtime codehash of the audited, immutable SafeModuleEnabler this kernel pins as
    ///         the ONLY permissible Safe.setup delegatecall `to` target (W2). Captured at
    ///         construction from the deployed helper, so it matches the launch build by
    ///         construction — no hand-copied literal, no recompile-mismatch risk. `createAccount`
    ///         requires every non-zero `setupTarget` to carry exactly this codehash, so a
    ///         governance mistake allowlisting a mutable/look-alike helper cannot open the
    ///         setup-delegatecall takeover surface.
    bytes32        public immutable EXPECTED_SETUP_CODEHASH;

    /// @notice Address that receives the protocol's share of collected fees.
    address        public treasury;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /// @notice Emitted when a new account is registered.
    /// @param  account          The Safe address that was registered.
    /// @param  permissionSigner Address authorised to manage permissions.
    /// @param  manager          Address authorised to dispatch transactions.
    event AccountRegistered(address indexed account, address indexed permissionSigner, address indexed manager);

    /// @notice Emitted when a permission is added to an account.
    /// @param  account    The Safe account.
    /// @param  permission The permission contract address.
    event PermissionRegistered(address indexed account, address indexed permission);

    /// @notice Emitted when a permission is removed from an account.
    /// @param  account    The Safe account.
    /// @param  permission The permission contract address that was removed.
    event PermissionRevoked(address indexed account, address indexed permission);

    /// @notice Emitted when a permission is atomically replaced.
    /// @param  account        The Safe account.
    /// @param  oldPermission  Permission that was removed.
    /// @param  newPermission  Permission that was added in its place.
    event PermissionReplaced(address indexed account, address indexed oldPermission, address indexed newPermission);

    /// @notice Emitted when the manager session is suspended for an account.
    /// @param  account The Safe account whose session was revoked.
    event SessionRevoked(address indexed account);

    /// @notice Emitted when a previously revoked session is re-activated.
    /// @param  account The Safe account whose session was activated.
    event SessionActivated(address indexed account);

    /// @notice Emitted when the fee policy for an account is updated.
    /// @param  account       The Safe account.
    /// @param  newFeePolicy  The new fee policy contract address (address(0) = cleared).
    event FeePolicyUpdated(address indexed account, address indexed newFeePolicy);

    /// @notice Emitted when an account's manager (delegated signer) is rotated.
    /// @dev    Rotation clears the account's permission set, so a `ManagerChanged` is
    ///         accompanied by a `PermissionRevoked` for each previously-registered mandate.
    /// @param  account    The Safe account whose manager changed.
    /// @param  oldManager The previous manager address.
    /// @param  newManager The new manager address.
    event ManagerChanged(address indexed account, address indexed oldManager, address indexed newManager);

    /// @notice Emitted on each successful dispatch.
    /// @dev    `dataHash` is keccak256(calldata) — the raw bytes are recoverable from the tx.
    /// @param  account     The Safe account that executed the transaction.
    /// @param  permission  The registered permission that authorised the call.
    /// @param  target      The call target.
    /// @param  selector    Leading 4 bytes of calldata; bytes4(0) if calldata is shorter than 4 bytes.
    /// @param  value       Native ETH forwarded with the call (wei).
    event Dispatched(
        address indexed account,
        address indexed permission,
        address target,
        bytes4  selector,
        uint256 value
    );

    /// @notice Emitted on each successful batch dispatch.
    /// @param  account    The Safe account that executed the batch.
    /// @param  permission The batch-aware permission that authorised the batch.
    /// @param  batchHash  keccak256(abi.encode(calls)) — stable identifier for the call sequence.
    /// @param  callCount  Number of subcalls in the batch.
    event BatchDispatched(
        address indexed account,
        address indexed permission,
        bytes32 batchHash,
        uint256 callCount
    );

    /// @notice Emitted on each successful fee collection.
    /// @param  account        The Safe account that was charged.
    /// @param  feeToken       ERC-20 token used for fee payment; address(0) = native ETH.
    /// @param  grossFee       Total fee collected.
    /// @param  protocolCut    Portion forwarded to the treasury.
    /// @param  distributorCut Portion forwarded to the fee policy's distributor.
    /// @param  managerTake    Remainder forwarded to the manager's recipient.
    event FeesCollected(
        address indexed account,
        address indexed feeToken,
        uint256 grossFee,
        uint256 protocolCut,
        uint256 distributorCut,
        uint256 managerTake
    );

    /// @notice Emitted when a deposit is recorded for an account.
    /// @param  account    The Safe account.
    /// @param  amount     Amount deposited in this call.
    /// @param  cumulative Running cumulative deposit total after this call.
    event DepositRecorded(address indexed account, uint256 amount, uint256 cumulative);

    /// @notice Emitted when a withdrawal is recorded for an account.
    /// @param  account    The Safe account.
    /// @param  amount     Amount withdrawn in this call.
    /// @param  cumulative Running cumulative withdrawal total after this call.
    event WithdrawalRecorded(address indexed account, uint256 amount, uint256 cumulative);

    /// @notice Emitted when the treasury address is updated.
    /// @param  oldTreasury Previous treasury address.
    /// @param  newTreasury New treasury address.
    event TreasuryUpdated(address indexed oldTreasury, address indexed newTreasury);

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    /// @dev Thrown by `_registerAccount` when the account is already registered.
    error AccountAlreadyRegistered(address account);

    /// @dev Thrown by `_requireRegistered` when the account has not been registered.
    error AccountNotRegistered(address account);

    /// @dev Thrown by `dispatch` when `sessionActive` is false for the account.
    error SessionInactive(address account);

    /// @dev Thrown when `block.timestamp` exceeds the provided deadline.
    error DeadlineExpired(uint256 deadline, uint256 current);

    /// @dev Thrown when an EIP-712 manager signature cannot be verified.
    error InvalidManagerSignature();

    /// @dev Thrown when an EIP-712 permissionSigner signature cannot be verified.
    error InvalidSignerSignature();

    /// @dev Thrown when a permission returns false (or reverts) during dispatch.
    error PermissionDenied(address permission);

    /// @dev Thrown when `ISafe.execTransactionFromModule` returns false.
    error SafeExecutionFailed();

    /// @dev Thrown by `registerPermission` / `registerPermissions` when the permission
    ///      is already in the account's permission set.
    error PermissionAlreadyRegistered(address permission);

    /// @dev Thrown by operations that require a permission to be registered when it is not.
    error PermissionNotRegistered(address permission);

    /// @dev Thrown when adding permissions would exceed governance.maxPermissionsPerAccount().
    error TooManyPermissions(address account, uint256 limit);

    /// @dev Thrown when the ETH sent with a registration call is below the required fee.
    error InsufficientFee(uint256 required, uint256 provided);

    /// @dev Thrown by `collectFees` when no fee policy is set for the account.
    error FeePolicyNotSet();

    /// @dev Thrown by `collectFees` when `grossFee` exceeds the policy's computed maximum.
    error FeeTooLarge(uint256 requested, uint256 maxAllowed);

    /// @dev Thrown when an ETH or ERC-20 fee transfer via the Safe fails.
    error FeeTransferFailed();

    /// @dev Thrown when the caller of a manager-only function is not the account's manager.
    error NotManager(address caller, address expected);

    /// @dev Thrown by `onlyGovernance` when caller is not the current governance address.
    error NotGovernance();

    /// @dev Thrown by `onlyTimelock` when caller is not the governance 48-hour timelock.
    error NotTimelock();

    /// @dev Thrown when a caller other than the account's permissionSigner invokes a guarded op.
    error NotPermissionSigner();

    /// @dev Thrown when a required address argument is the zero address.
    error ZeroAddress();

    /// @dev Thrown by `setManager` when the new manager equals the current one — a no-op
    ///      rotation would needlessly clear mandates and bump the nonce epoch.
    error ManagerUnchanged();

    /// @dev Thrown by permission registration when the supplied address has no deployed code.
    error NotAContract(address addr);

    /// @dev Thrown by `collectFees` when `distributorBps` returned by the policy exceeds 10 000.
    error DistributorBpsTooLarge(uint256 bps);

    /// @dev Thrown by `collectFees` when the fee token does not match the account's configured canonical asset.
    error FeeTokenMismatch(address provided, address expected);

    /// @dev Thrown by `collectFees` when `grossFee` is zero.
    error ZeroFee();

    /// @dev Thrown by `dispatch` / `collectFees` when the protocol is paused.
    error ProtocolPaused();

    /// @dev Thrown when `createAccount` deploys a Safe that does not have this kernel enabled as a module.
    error ModuleNotEnabled();

    /// @dev Thrown by `registerAccount` when the caller Safe has not finalized setup (nonce == 0),
    ///      blocking a setup-delegatecall helper from registering attacker-chosen principals (Octane #4).
    error SetupNotFinalized();

    /// @dev Thrown by Safe-authorized functions (`registerAccount`, `setManager`, `collectFees`) when
    ///      msg.data is not the exact static length — a Safe fallback relay appends the caller's 20
    ///      bytes, so a length mismatch flags a fallbackHandler-relayed call (Octane W1).
    error UnexpectedCalldataLength();

    /// @dev Thrown by `createAccount` when the provided Safe factory is not in governance's trusted allowlist.
    error UntrustedFactory(address factory);

    /// @dev Thrown by `createAccount` when the provided Safe singleton is not in governance's trusted allowlist.
    error UntrustedSingleton(address singleton);

    /// @dev Thrown by `createAccount` when `safeInitializer` is too short to contain the
    ///      Safe.setup `to` field (selector + owners offset + threshold + to = 100 bytes).
    error InvalidInitializer();

    /// @dev Thrown by `createAccount` when the Safe.setup delegatecall `to` target is not
    ///      in governance's trusted module-setup allowlist.
    error UntrustedModuleSetup(address setup);

    /// @dev Thrown by `createAccount` when the Safe.setup delegatecall `to` target's runtime
    ///      codehash does not match the immutable, audited SafeModuleEnabler pinned at deploy
    ///      (`EXPECTED_SETUP_CODEHASH`). Defends against a governance mistake allowlisting a
    ///      MUTABLE helper at a trusted address: even an address-allowlisted target is rejected
    ///      unless its deployed bytecode is byte-identical to the pinned immutable helper (W2).
    error UntrustedModuleSetupCodehash(address setup);

    /// @dev Thrown by `registerAccount` when the caller's runtime codehash is not in
    ///      governance's trusted Safe-proxy-codehash allowlist.
    error UntrustedProxyCodehash(bytes32 codehash);

    /// @dev Thrown by `registerAccount` when `ownerSig` carries a Safe approved-hash entry (v == 1).
    ///      Inside `checkSignatures` msg.sender is this kernel, so Safe accepts a v==1 entry whose
    ///      r-field encodes the kernel as "owner" (msg.sender == currentOwner) — letting a malicious
    ///      Safe.setup delegatecall helper register with NO genuine owner key. Honest owners never
    ///      need the shortcut: EOAs sign ECDSA and contract owners use the v==0 path.
    error ApprovedHashSignatureNotAllowed();

    /// @dev Thrown by `dispatchBatch` when the calls array is empty.
    error EmptyBatch();

    /// @dev Thrown by `dispatchBatch` when the calls array exceeds MAX_BATCH_LENGTH.
    error BatchTooLong(uint256 length);

    /// @dev Thrown by `dispatchBatch` when the named permission does not implement IBatchPermission
    ///      (detected via try/catch on `isBatchPermission()`).
    error PermissionNotBatchAware(address permission);

    /// @dev Thrown by `dispatchBatch` when the named permission's `evaluateBatch`
    ///      returns false, reverts, runs out of gas, or returns malformed data.
    error BatchPermissionDenied();

    /// @dev Thrown by `dispatchBatch` when one of the batched subcalls reverts
    ///      (Safe's execTransactionFromModule returns false).
    error BatchSubcallFailed(uint256 index, address target);

    /// @dev Thrown by `dispatchBatch` when a subcall targets the kernel itself —
    ///      a defensive guard preventing self-targeted reentrancy attempts.
    error KernelSelfTarget(uint256 index);

    /// @dev Thrown by `dispatchBatch` when a subcall targets the zero address.
    error BatchZeroTarget(uint256 index);

    /// @dev Thrown by `dispatch`/`dispatchBatch` when a call targets the Safe account itself.
    ///      Prevents module-triggered self-calls that satisfy Safe's onlySelf guard and could
    ///      enable owner/threshold changes, module manipulation, or guard/fallback overwrites.
    error AccountSelfTarget();

    /// @dev Thrown by `_registerAccount` or `setFeePolicy` when the provided fee policy is not
    ///      in governance's trusted allowlist.  Prevents upgradeable/metamorphic policies.
    error UntrustedFeePolicy(address policy);

    /// @dev Thrown by `setFeePolicy` when a fee-policy instance already used for an account
    ///      with one fee asset is reused with a different asset. Reusing an instance across
    ///      denominations would leave its persisted high-water mark in stale units. To change
    ///      the fee asset, point the account at a fresh policy instance.
    error FeePolicyAssetMismatch(address policy, address expected, address provided);

    /// @dev Thrown by `replacePermissions` when `oldPermissions` and `newPermissions` have different lengths.
    error ArrayLengthMismatch();

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    /// @notice Deploy the kernel with a governance contract, treasury, and the Safe.setup helper.
    /// @param  _governance    Address of the deployed SailGovernance contract.
    /// @param  _treasury      Address that will receive the protocol's share of fees.
    /// @param  _setupEnabler  The deployed, immutable SafeModuleEnabler. Its runtime codehash is
    ///                        captured into `EXPECTED_SETUP_CODEHASH` and pinned as the only
    ///                        permissible Safe.setup delegatecall target (W2). MUST be the genuine
    ///                        immutable helper at launch; it must already be deployed when the
    ///                        kernel is constructed so its codehash can be read here.
    constructor(address _governance, address _treasury, address _setupEnabler) EIP712("SailKernel", "1") {
        if (_governance == address(0) || _treasury == address(0) || _treasury == address(this)) revert ZeroAddress();
        governance             = SailGovernance(_governance);
        treasury               = _treasury;
        EXPECTED_SETUP_CODEHASH = _setupEnabler.codehash;
    }

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------

    /// @dev Reverts with NotGovernance when caller is not the current governance address.
    modifier onlyGovernance() {
        if (msg.sender != governance.governance()) revert NotGovernance();
        _;
    }

    /// @dev Reverts with NotTimelock when caller is not the governance timelock.
    ///      Used for high-impact setters that must observe the 48-hour delay.
    modifier onlyTimelock() {
        if (msg.sender != address(governance.timelock())) revert NotTimelock();
        _;
    }

    /// @dev Reverts with ProtocolPaused when governance.isPaused() returns true.
    modifier whenNotPaused() {
        if (governance.isPaused()) revert ProtocolPaused();
        _;
    }

    // -------------------------------------------------------------------------
    // Governance
    // -------------------------------------------------------------------------

    /// @notice Update the treasury address that receives the protocol's fee share.
    /// @dev    Enforces the 48-hour timelock so that a compromised governance key cannot
    ///         instantly redirect all protocol fee flows. Schedule via governance.timelock().
    /// @param  newTreasury New treasury address. Must not be the zero address.
    function setTreasury(address newTreasury) external onlyTimelock {
        if (newTreasury == address(0)) revert ZeroAddress();
        if (newTreasury == address(this)) revert ZeroAddress();
        address old = treasury;
        treasury = newTreasury;
        emit TreasuryUpdated(old, newTreasury);
    }

    // -------------------------------------------------------------------------
    // 1. Account instantiation
    // -------------------------------------------------------------------------

    /// @notice Deploy a new Safe via factory and register it with the kernel in one transaction.
    /// @dev    The salt passed to the factory is derived from `keccak256(saltNonce, msg.sender,
    ///         permissionSigner, manager, feePolicy)` so that a front-runner supplying different
    ///         principals lands at a different CREATE2 address and cannot squat the registration
    ///         (Octane #4 / #16). The Safe.setup delegatecall `to` target embedded in
    ///         `safeInitializer` is validated against the trusted module-setup allowlist, removing
    ///         the arbitrary-delegatecall surface (Octane #1). If a proxy already exists at the
    ///         predicted address (legitimate pre-deploy or retry) the factory call is skipped.
    /// @param  safeFactory       Address of the Safe proxy factory contract.
    /// @param  safeSingleton     Address of the Safe singleton (implementation) contract.
    /// @param  safeInitializer   Calldata for the Safe's `setup` call during deployment.
    /// @param  saltNonce         Caller-chosen nonce; combined with msg.sender + principals into the salt.
    /// @param  permissionSigner  Address that will sign permission-registry operations.
    /// @param  manager           Address that will sign dispatch calls.
    /// @param  feePolicy         Fee policy contract; address(0) = no fee policy.
    /// @param  feeAsset          Canonical fee settlement token; address(0) = native ETH.
    /// @return account           Address of the deployed (or pre-existing) Safe proxy.
    function createAccount(
        address safeFactory,
        address safeSingleton,
        bytes calldata safeInitializer,
        uint256 saltNonce,
        address permissionSigner,
        address manager,
        address feePolicy,
        address feeAsset
    ) external returns (address account) {
        if (!governance.trustedSafeFactory(safeFactory))     revert UntrustedFactory(safeFactory);
        if (!governance.trustedSafeSingleton(safeSingleton)) revert UntrustedSingleton(safeSingleton);

        // Enforce that the delegatecall target inside Safe.setup is an allowlisted helper.
        // setup() ABI layout: selector(4) + owners_offset(32) + threshold(32) + to(32) + ...
        // 'to' is at bytes [68:100].
        if (safeInitializer.length < 100) revert InvalidInitializer();
        address setupTarget = address(uint160(uint256(bytes32(safeInitializer[68:100]))));
        // address(0) means no delegatecall (vanilla Safe.setup) — always safe, no allowlist check needed.
        if (setupTarget != address(0) && !governance.trustedModuleSetup(setupTarget)) revert UntrustedModuleSetup(setupTarget);
        // W2: address-allowlisting alone is not enough — pin the target's runtime codehash to the
        // audited immutable SafeModuleEnabler captured at deploy. This converts the operational rule
        // ("only ever allowlist an IMMUTABLE helper") into a code guarantee: a governance mistake
        // allowlisting a mutable/upgradeable look-alike at a trusted address cannot satisfy the pin.
        // Gated on setupTarget != address(0) exactly like the address check, so the no-setup path
        // (vanilla Safe.setup) is unaffected.
        if (setupTarget != address(0) && setupTarget.codehash != EXPECTED_SETUP_CODEHASH) {
            revert UntrustedModuleSetupCodehash(setupTarget);
        }

        uint256 boundSalt = uint256(keccak256(abi.encode(saltNonce, msg.sender, permissionSigner, manager, feePolicy)));

        // Predict the proxy address with the same CREATE2 formula SafeProxyFactory uses, so a
        // proxy already deployed at that address (a retry, or a same-config front-runner) is
        // adopted instead of reverting. Computed locally rather than via a factory predictor:
        // Safe v1.4.1's factory exposes no view predictor (only proxyCreationCode()).
        //   salt           = keccak256(keccak256(initializer), saltNonce)
        //   deploymentData = proxyCreationCode() ++ uint256(uint160(singleton))
        bytes32 create2Salt = keccak256(abi.encodePacked(keccak256(safeInitializer), boundSalt));
        bytes32 initCodeHash = keccak256(
            abi.encodePacked(ISafeFactory(safeFactory).proxyCreationCode(), uint256(uint160(safeSingleton)))
        );
        address predicted = address(
            uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), safeFactory, create2Salt, initCodeHash))))
        );
        if (predicted.code.length == 0) {
            account = ISafeFactory(safeFactory).createProxyWithNonce(safeSingleton, safeInitializer, boundSalt);
        } else {
            account = predicted;
        }

        if (!ISafe(account).isModuleEnabled(address(this))) revert ModuleNotEnabled();

        // Parity with registerAccount: the resulting proxy must carry an allowlisted Safe-proxy
        // runtime codehash. The trusted factory + CREATE2 prediction path already implies this,
        // so the check is redundant for a legitimately-created proxy — it makes the codehash trust
        // anchor explicit and symmetric across both account-entry paths.
        bytes32 accountCodehash;
        assembly { accountCodehash := extcodehash(account) }
        if (!governance.trustedSafeProxyCodehash(accountCodehash)) revert UntrustedProxyCodehash(accountCodehash);

        _registerAccount(account, permissionSigner, manager, feePolicy, feeAsset);
    }

    /// @notice Register an existing Safe that has already added this kernel as a module.
    /// @dev    MUST be called by the Safe itself (msg.sender == Safe). The caller must be a
    ///         genuine Safe proxy (verified by runtime codehash against the trusted allowlist,
    ///         blocking arbitrary-contract self-registration — finding #4a) and must already
    ///         have this kernel enabled as a module.
    ///
    ///         #4 OWNER AUTHORISATION (the robust gate): registration is bound to an EIP-712
    ///         signature over the principals, verified through the Safe's own owner-set+threshold
    ///         check (`checkSignatures`). This defeats the Safe.setup-delegatecall attack that a
    ///         view-only heuristic could not: during setup every Safe-storage signal (nonce, module
    ///         state, slot-0 singleton) is attacker-forgeable, but a setup helper cannot produce the
    ///         owners' signatures over this digest. If an attacker rewrites the owner set to sign with
    ///         their own key, they own the Safe — there is no victim. (The same setup-controlling
    ///         attacker could also enable a draining module of their own, so this boundary is the most
    ///         a registration check can defend; see the PR notes.) The `nonce()==0` check below is
    ///         kept purely as cheap defense-in-depth on top of the signature.
    ///
    ///         createAccount does NOT carry an owner signature: it routes through the internal
    ///         `_registerAccount` (never this public function), is kernel-orchestrated, validates the
    ///         singleton/factory/setup-target against governance allowlists, and binds the principals
    ///         into the CREATE2 salt — so it is protected by construction and unaffected by this gate.
    ///
    ///         INVOCATION: owners sign the RegisterAccount digest off-chain; an owner-approved Safe
    ///         `execTransaction` then calls this function (so msg.sender == the Safe, satisfying the
    ///         codehash gate) carrying that signature. msg.sender == account is preserved.
    /// @dev    OWNER SIGNATURE TYPES: EOA owners sign ECDSA over the digest (Safe's v>1 path). Contract
    ///         owners (ERC-1271 / nested Safe) use Safe's v==0 path — `checkSignatures` is given the
    ///         EIP-712 preimage as `data`, so its keccak256(data)==digest check passes and contract-owner
    ///         self-registration works. The v==1 approved-hash shortcut is rejected
    ///         (`ApprovedHashSignatureNotAllowed`): inside `checkSignatures` msg.sender is the kernel, so
    ///         a v==1 entry encoding the kernel as owner would let a setup-delegatecall helper register
    ///         with no genuine owner key.
    /// @param  permissionSigner  Address that will sign permission-registry operations.
    /// @param  manager           Address that will sign dispatch calls.
    /// @param  feePolicy         Fee policy contract; address(0) = no fee policy.
    /// @param  feeAsset          Canonical fee settlement token; address(0) = native ETH.
    /// @param  deadline          Unix timestamp after which the owner signature is invalid.
    /// @param  ownerSig          Safe owner-set+threshold signature(s) over the RegisterAccount digest.
    function registerAccount(
        address permissionSigner,
        address manager,
        address feePolicy,
        address feeAsset,
        uint256 deadline,
        bytes calldata ownerSig
    ) external {
        // No exact-length W1 guard here (cf. setManager/collectFees): `ownerSig` is dynamic, so an
        // exact length is undefined and a minimum-length check would not catch a +20-byte fallback
        // relay. The owner-signature requirement closes the W1 fallback vector for this function
        // directly — a relay cannot produce the owners' signature over the digest.

        // 1. Codehash (cheap/static; uses extcodehash, not an ISafe method call). Pins genuine
        //    SafeProxy bytecode before any call into the proxy.
        bytes32 codehash;
        assembly { codehash := extcodehash(caller()) }
        if (!governance.trustedSafeProxyCodehash(codehash)) revert UntrustedProxyCodehash(codehash);

        // 2. #9 trusted singleton — checked BEFORE any other ISafe method runs. The codehash above
        //    only pins proxy bytecode; a genuine proxy can still delegate to a hostile singleton that
        //    forges module execution/return data. masterCopy() is the one ISafe call that may precede
        //    this check: the proxy answers 0xa619486e from storage slot 0 in its own fallback, so a
        //    malicious singleton cannot forge it. Confirming the singleton here means nonce(),
        //    isModuleEnabled(), and checkSignatures() below are never invoked on an unverified singleton.
        address singleton = ISafe(msg.sender).masterCopy();
        if (!governance.trustedSafeSingleton(singleton)) revert UntrustedSingleton(singleton);

        // 3. #4 defense-in-depth: setup() never bumps the Safe nonce; execTransaction increments it
        //    before the inner call runs. A value of 0 therefore flags a not-yet-finalized Safe. This is
        //    forgeable by a setup-delegatecall helper (nonce lives in slot 5), so it is NOT the gate —
        //    the owner signature below is. Kept as a cheap early reject.
        if (ISafe(msg.sender).nonce() == 0) revert SetupNotFinalized();

        // 4. Module must be enabled.
        if (!ISafe(msg.sender).isModuleEnabled(address(this))) revert ModuleNotEnabled();

        // 5. #4 owner authorisation (the robust gate). Bind the principals to an owner-set+threshold
        //    signature so a setup helper — which holds no owner keys — cannot register. chainId is in
        //    the EIP-712 domain; no nonce is needed because registration is one-shot (`registered[]`
        //    never clears, so a replay reverts AccountAlreadyRegistered in _registerAccount).
        if (block.timestamp > deadline) revert DeadlineExpired(deadline, block.timestamp);
        bytes32 structHash = keccak256(abi.encode(
            REGISTER_ACCOUNT_TYPEHASH,
            msg.sender,
            permissionSigner,
            manager,
            feePolicy,
            feeAsset,
            deadline
        ));
        bytes32 digest = _hashTypedDataV4(structHash);

        // Reject the Safe v==1 approved-hash shortcut: it lets a malicious setup helper authorize
        //    registration without a genuine owner signature. Safe encodes `ownerSig` as 65-byte entries
        //    (r|s|v, v at byte 64); threshold entries form the static region [0, threshold*65), and a
        //    v==0 contract owner appends its signature in a dynamic tail beginning at that entry's `s`
        //    pointer — which, for the first such entry, equals threshold*65 (Safe appends tails in the
        //    order it parses entries). We scan only the static region so a tail byte is never misread
        //    as a phantom v==1: start with the whole sig, and the first v==0 entry shrinks the limit to
        //    its `s` (the static-region end). Bounding to the static region keeps the contract-owner
        //    path working. (Over-scanning could only over-reject, never miss a static v==1.)
        uint256 limit = ownerSig.length;
        for (uint256 i; i * 65 + 64 < limit; ++i) {
            uint256 base = i * 65;
            uint8 v;
            assembly { v := byte(0, calldataload(add(ownerSig.offset, add(base, 64)))) }
            if (v == 1) revert ApprovedHashSignatureNotAllowed();
            if (v == 0) {
                uint256 s;
                assembly { s := calldataload(add(ownerSig.offset, add(base, 32))) }
                if (s < limit) limit = s;
            }
        }

        // Pass the EIP-712 preimage as `data` so a contract owner (ERC-1271 / nested Safe) can
        //    validate via Safe's v==0 contract-signature path: Safe requires keccak256(data) == digest,
        //    which holds by construction because digest == keccak256(0x1901 ‖ domainSeparator ‖
        //    structHash). The ECDSA path ignores `data`.
        bytes memory preimage = abi.encodePacked(hex"1901", _domainSeparatorV4(), structHash);
        // Reverts (GS0xx) unless `ownerSig` satisfies the Safe's owner set + threshold.
        ISafe(msg.sender).checkSignatures(digest, preimage, ownerSig);

        _registerAccount(msg.sender, permissionSigner, manager, feePolicy, feeAsset);
    }

    /// @dev Shared registration logic for `createAccount` and `registerAccount`.
    function _registerAccount(address account, address permissionSigner, address manager, address feePolicy, address feeAsset)
        internal
    {
        if (registered[account]) revert AccountAlreadyRegistered(account);
        if (permissionSigner == address(0) || manager == address(0)) revert ZeroAddress();
        if (feePolicy != address(0) && !governance.trustedFeePolicy(feePolicy)) revert UntrustedFeePolicy(feePolicy);
        registered[account] = true;
        configs[account] = AccountConfig({
            permissionSigner: permissionSigner,
            manager:          manager,
            feePolicy:        feePolicy,
            feeAsset:         feeAsset,
            sessionActive:    true
        });
        emit AccountRegistered(account, permissionSigner, manager);
    }

    /// @notice Rotate the manager (delegated signer) for an account, clearing every
    ///         attached mandate in the same transaction.
    /// @dev    AUTHORIZATION: MUST be called by the Safe itself (`msg.sender == account`).
    ///         Authorization therefore flows through the Safe's own owner threshold — the
    ///         custody anchor — and replay protection comes from the Safe's nonce, so no
    ///         kernel signature or nonce is needed. This mirrors `registerAccount`'s
    ///         `msg.sender == Safe` trust model. `_requireRegistered` ensures only an
    ///         already-registered account (a genuine Safe proxy, vetted at registration)
    ///         can reach this path, and an account can only rotate its own manager.
    ///
    ///         MANDATE RESET: A rotated signer must never silently inherit authority the
    ///         owner approved for the old one. Rather than leave mandates attached but
    ///         inert, this clears the permission set outright (fail-closed: subsequent
    ///         dispatches revert with `PermissionNotRegistered` until the owner re-approves
    ///         each mandate via the normal `registerPermission(s)` flow — which binds them
    ///         to the new manager). A `PermissionRevoked` is emitted per cleared mandate.
    ///
    ///         IN-FLIGHT OPS: `managerNonces`, `batchNonces`, and `signerNonces` are all
    ///         bumped by `NONCE_EPOCH_INCREMENT` so any dispatch the old manager pre-signed,
    ///         and any permission-signer op pre-signed against the old epoch, is invalidated —
    ///         consistent with every other mandate-mutating op.
    ///
    ///         PAUSE: Intentionally exempt from `whenNotPaused` — losing the agent key is
    ///         exactly the kind of incident during which recovery must remain possible, and
    ///         rotation moves no funds. (See `revokeSession`/`revokePermission`.)
    /// @param  newManager New address authorised to sign dispatches. Must be non-zero and
    ///                    different from the current manager.
    function setManager(address newManager) external nonReentrant {
        // W1: reject Safe-fallback-relayed calls. A direct call is exactly selector + 1 static arg;
        // a fallback relay appends the caller's 20 bytes (see SET_MANAGER_CALLDATA_LEN).
        if (msg.data.length != SET_MANAGER_CALLDATA_LEN) revert UnexpectedCalldataLength();
        address account = msg.sender;
        _requireRegistered(account);
        if (newManager == address(0)) revert ZeroAddress();
        address oldManager = configs[account].manager;
        if (newManager == oldManager) revert ManagerUnchanged();

        configs[account].manager = newManager;
        _clearPermissions(account);
        managerNonces[account] += NONCE_EPOCH_INCREMENT;
        batchNonces[account]   += NONCE_EPOCH_INCREMENT;
        signerNonces[account]  += NONCE_EPOCH_INCREMENT;

        emit ManagerChanged(account, oldManager, newManager);
    }

    /// @notice The address currently authorised to sign dispatches for an account.
    /// @param  account The Safe account to query.
    /// @return         The account's manager (delegated signer); address(0) if unregistered.
    function getManager(address account) external view returns (address) {
        return configs[account].manager;
    }

    // -------------------------------------------------------------------------
    // 2. Permission registry
    // -------------------------------------------------------------------------

    /// @notice Register a single permission for an account.
    ///         Requires a permissionSigner EIP-712 signature and an ETH registration fee.
    /// @dev    PERMISSION TRUST: The kernel binds authorization to a permission address only.
    ///         If a registered permission is upgradeable or uses a proxy, a change to its
    ///         implementation requires no new kernel signature. Operators are responsible for
    ///         registering only non-upgradeable or audited permission contracts.
    ///         See Sail Protocol whitepaper §8.2.
    /// @param  account    The registered Safe account.
    /// @param  permission Address of the permission contract to register.
    /// @param  deadline   Unix timestamp after which the signature is invalid.
    /// @param  sig        EIP-712 signature over RegisterPermission struct by permissionSigner.
    function registerPermission(address account, address permission, uint256 deadline, bytes calldata sig)
        external
        payable
        nonReentrant
        whenNotPaused
    {
        _requireRegistered(account);
        if (block.timestamp > deadline) revert DeadlineExpired(deadline, block.timestamp);
        if (permission == address(0)) revert ZeroAddress();
        if (permission.code.length == 0) revert NotAContract(permission);
        if (_permissionIndex[account][permission] != 0) revert PermissionAlreadyRegistered(permission);
        uint256 limit = governance.maxPermissionsPerAccount();
        if (_permissions[account].length >= limit)
            revert TooManyPermissions(account, limit);

        uint256 nonce = signerNonces[account];
        _verifySignerSig(
            account,
            keccak256(abi.encode(REGISTER_PERMISSION_TYPEHASH, account, permission, nonce, deadline)),
            sig
        );
        signerNonces[account] = nonce + 1;

        uint256 fee = _calcPermissionFee();
        if (msg.value < fee) revert InsufficientFee(fee, msg.value);

        _permissions[account].push(permission);
        _permissionIndex[account][permission] = _permissions[account].length; // stored as index + 1

        _collectRegistrationFee(fee);
        emit PermissionRegistered(account, permission);
    }

    /// @notice Revoke a single permission from an account.
    ///         Requires a permissionSigner EIP-712 signature.
    /// @dev    Intentionally exempt from whenNotPaused — users must be able to revoke
    ///         permissions even during a protocol pause to reduce their exposure.
    /// @param  account    The registered Safe account.
    /// @param  permission Address of the permission contract to revoke.
    /// @param  deadline   Unix timestamp after which the signature is invalid.
    /// @param  sig        EIP-712 signature over RevokePermission struct by permissionSigner.
    function revokePermission(address account, address permission, uint256 deadline, bytes calldata sig) external nonReentrant {
        _requireRegistered(account);
        if (block.timestamp > deadline) revert DeadlineExpired(deadline, block.timestamp);
        uint256 nonce = signerNonces[account];
        _verifySignerSig(
            account,
            keccak256(abi.encode(REVOKE_PERMISSION_TYPEHASH, account, permission, nonce, deadline)),
            sig
        );
        signerNonces[account] = nonce + 1;
        _removePermission(account, permission);
        registrationEpoch[account][permission] += 1;
        managerNonces[account] += NONCE_EPOCH_INCREMENT;
        batchNonces[account]   += NONCE_EPOCH_INCREMENT;
        emit PermissionRevoked(account, permission);
    }

    /// @notice Atomically replace one permission with another in a single signed operation.
    ///         Requires a permissionSigner EIP-712 signature and an ETH registration fee.
    /// @dev    PERMISSION TRUST: The kernel binds authorization to a permission address only.
    ///         If a registered permission is upgradeable or uses a proxy, a change to its
    ///         implementation requires no new kernel signature. Operators are responsible for
    ///         registering only non-upgradeable or audited permission contracts.
    ///         See Sail Protocol whitepaper §8.2.
    /// @param  account        The registered Safe account.
    /// @param  oldPermission  Permission to remove.
    /// @param  newPermission  Permission to add in its place.
    /// @param  deadline       Unix timestamp after which the signature is invalid.
    /// @param  sig            EIP-712 signature over ReplacePermission struct by permissionSigner.
    function replacePermission(
        address account,
        address oldPermission,
        address newPermission,
        uint256 deadline,
        bytes calldata sig
    ) external payable nonReentrant whenNotPaused {
        _requireRegistered(account);
        if (block.timestamp > deadline) revert DeadlineExpired(deadline, block.timestamp);
        if (newPermission == address(0)) revert ZeroAddress();
        if (newPermission.code.length == 0) revert NotAContract(newPermission);
        if (_permissionIndex[account][newPermission] != 0) revert PermissionAlreadyRegistered(newPermission);

        uint256 nonce = signerNonces[account];
        _verifySignerSig(
            account,
            keccak256(abi.encode(REPLACE_PERMISSION_TYPEHASH, account, oldPermission, newPermission, nonce, deadline)),
            sig
        );
        signerNonces[account] = nonce + 1;

        uint256 idx = _permissionIndex[account][oldPermission];
        if (idx == 0) revert PermissionNotRegistered(oldPermission);

        uint256 fee = _calcPermissionFee();
        if (msg.value < fee) revert InsufficientFee(fee, msg.value);

        _permissions[account][idx - 1] = newPermission;
        delete _permissionIndex[account][oldPermission];
        _permissionIndex[account][newPermission] = idx;
        // Bump the REMOVED side only. newPermission is register-like (its config is applied just
        // before this call in the bundled flow); bumping it would strand that fresh config.
        registrationEpoch[account][oldPermission] += 1;

        _collectRegistrationFee(fee);
        managerNonces[account] += NONCE_EPOCH_INCREMENT;
        batchNonces[account]   += NONCE_EPOCH_INCREMENT;
        emit PermissionReplaced(account, oldPermission, newPermission);
    }

    /// @notice Atomically replace N permissions with N new ones in a single signed operation.
    ///         Eliminates the front-running overlap window that arises when separate
    ///         `registerPermissions` + `revokePermissions` calls are used for N→N migrations.
    ///         Requires a permissionSigner EIP-712 signature and a fee per swap.
    /// @dev    PERMISSION TRUST: The kernel binds authorization to a permission address only.
    ///         If a registered permission is upgradeable or uses a proxy, a change to its
    ///         implementation requires no new kernel signature. Operators are responsible for
    ///         registering only non-upgradeable or audited permission contracts.
    ///         See Sail Protocol whitepaper §8.2.
    /// @param  account         The registered Safe account.
    /// @param  oldPermissions  Permissions to remove (parallel to `newPermissions`).
    /// @param  newPermissions  Permissions to add in their place.
    /// @param  deadline        Unix timestamp after which the signature is invalid.
    /// @param  sig             EIP-712 signature over ReplacePermissions struct by permissionSigner.
    function replacePermissions(
        address account,
        address[] calldata oldPermissions,
        address[] calldata newPermissions,
        uint256 deadline,
        bytes calldata sig
    ) external payable nonReentrant whenNotPaused {
        if (oldPermissions.length != newPermissions.length) revert ArrayLengthMismatch();
        if (oldPermissions.length == 0) {
            if (msg.value > 0) _collectRegistrationFee(0); // refunds full msg.value to caller
            return;
        }
        _requireRegistered(account);
        if (block.timestamp > deadline) revert DeadlineExpired(deadline, block.timestamp);

        uint256 nonce = signerNonces[account];
        _verifySignerSig(
            account,
            keccak256(abi.encode(
                REPLACE_PERMISSIONS_TYPEHASH,
                account,
                _hashAddressArray(oldPermissions),
                _hashAddressArray(newPermissions),
                nonce,
                deadline
            )),
            sig
        );
        signerNonces[account] = nonce + 1;

        uint256 fee = _calcPermissionFee() * oldPermissions.length;
        if (msg.value < fee) revert InsufficientFee(fee, msg.value);

        for (uint256 i; i < oldPermissions.length; i++) {
            address oldPerm = oldPermissions[i];
            address newPerm = newPermissions[i];
            if (newPerm == address(0)) revert ZeroAddress();
            if (newPerm.code.length == 0) revert NotAContract(newPerm);
            uint256 idx = _permissionIndex[account][oldPerm];
            if (idx == 0) revert PermissionNotRegistered(oldPerm);
            if (_permissionIndex[account][newPerm] != 0) revert PermissionAlreadyRegistered(newPerm);
            _permissions[account][idx - 1] = newPerm;
            delete _permissionIndex[account][oldPerm];
            _permissionIndex[account][newPerm] = idx;
            registrationEpoch[account][oldPerm] += 1; // bump the removed side only (see replacePermission)
            emit PermissionReplaced(account, oldPerm, newPerm);
        }

        _collectRegistrationFee(fee);
        managerNonces[account] += NONCE_EPOCH_INCREMENT;
        batchNonces[account]   += NONCE_EPOCH_INCREMENT;
    }

    /// @notice Suspend the manager session for an account. All `dispatch` calls will
    ///         revert with `SessionInactive` until `activateSession` is called.
    /// @param  account  The registered Safe account.
    /// @param  deadline Unix timestamp after which the signature is invalid.
    /// @param  sig      EIP-712 signature over RevokeSession struct by permissionSigner.
    function revokeSession(address account, uint256 deadline, bytes calldata sig) external nonReentrant {
        _requireRegistered(account);
        if (block.timestamp > deadline) revert DeadlineExpired(deadline, block.timestamp);
        uint256 nonce = signerNonces[account];
        _verifySignerSig(
            account,
            keccak256(abi.encode(REVOKE_SESSION_TYPEHASH, account, nonce, deadline)),
            sig
        );
        signerNonces[account] = nonce + 1;
        configs[account].sessionActive = false;
        managerNonces[account] += NONCE_EPOCH_INCREMENT;
        batchNonces[account]   += NONCE_EPOCH_INCREMENT;
        emit SessionRevoked(account);
    }

    /// @notice Re-activate a previously suspended session. Requires a fresh permissionSigner
    ///         signature to prove the key is still under the operator's control.
    /// @param  account  The registered Safe account.
    /// @param  deadline Unix timestamp after which the signature is invalid.
    /// @param  sig      EIP-712 signature over ActivateSession struct by permissionSigner.
    function activateSession(address account, uint256 deadline, bytes calldata sig) external nonReentrant {
        _requireRegistered(account);
        if (block.timestamp > deadline) revert DeadlineExpired(deadline, block.timestamp);
        uint256 nonce = signerNonces[account];
        _verifySignerSig(
            account,
            keccak256(abi.encode(ACTIVATE_SESSION_TYPEHASH, account, nonce, deadline)),
            sig
        );
        signerNonces[account] = nonce + 1;
        configs[account].sessionActive = true;
        // Rotate manager/batch nonce epochs on reactivation so any dispatch the manager
        // pre-signed while the session was suspended (current epoch) cannot execute once
        // the session is live again. Mirrors revokeSession's epoch bump — a session cycle
        // is a clean kill switch for outstanding signatures in both directions.
        managerNonces[account] += NONCE_EPOCH_INCREMENT;
        batchNonces[account]   += NONCE_EPOCH_INCREMENT;
        emit SessionActivated(account);
    }

    /// @notice Replace the fee policy for an account. Requires a permissionSigner signature.
    ///         Setting `newFeePolicy = address(0)` clears the policy and blocks fee collection.
    /// @param  account      The registered Safe account.
    /// @param  newFeePolicy New fee policy contract address; address(0) = no fee policy.
    /// @param  feeAsset     Canonical fee settlement token for the new policy; address(0) = native ETH.
    /// @param  deadline     Unix timestamp after which the signature is invalid.
    /// @param  sig          EIP-712 signature over SetFeePolicy struct by permissionSigner.
    function setFeePolicy(address account, address newFeePolicy, address feeAsset, uint256 deadline, bytes calldata sig) external nonReentrant {
        _requireRegistered(account);
        // Allow clearing (newFeePolicy == 0) during pause so permissionSigner can disarm a compromised policy
        // before the pause lifts and collectFees becomes callable again.  Block non-zero updates while paused.
        if (governance.isPaused() && newFeePolicy != address(0)) revert ProtocolPaused();
        if (newFeePolicy != address(0) && !governance.trustedFeePolicy(newFeePolicy)) revert UntrustedFeePolicy(newFeePolicy);
        if (block.timestamp > deadline) revert DeadlineExpired(deadline, block.timestamp);
        uint256 nonce = signerNonces[account];
        _verifySignerSig(
            account,
            keccak256(abi.encode(SET_FEE_POLICY_TYPEHASH, account, newFeePolicy, feeAsset, nonce, deadline)),
            sig
        );
        signerNonces[account] = nonce + 1;

        // Pin a policy instance to the single fee asset it is used with for this account, so the
        // policy's persisted (per-account) high-water mark can never be mixed across denominations.
        // First lazily bind the currently configured policy (e.g. one set at registration) to its
        // current asset, so a later swap to a different asset on the SAME instance is caught even
        // on the first setFeePolicy call.
        address currentPolicy = configs[account].feePolicy;
        if (currentPolicy != address(0)) {
            PolicyAssetBinding storage current = _policyAssetBinding[account][currentPolicy];
            if (!current.bound) { current.bound = true; current.asset = configs[account].feeAsset; }
        }
        // Then enforce the binding for the incoming policy: bind on first use, else require a match.
        if (newFeePolicy != address(0)) {
            PolicyAssetBinding storage binding = _policyAssetBinding[account][newFeePolicy];
            if (!binding.bound) { binding.bound = true; binding.asset = feeAsset; }
            else if (binding.asset != feeAsset) revert FeePolicyAssetMismatch(newFeePolicy, binding.asset, feeAsset);
        }

        configs[account].feePolicy = newFeePolicy;
        configs[account].feeAsset  = (newFeePolicy == address(0)) ? address(0) : feeAsset;
        emit FeePolicyUpdated(account, newFeePolicy);

        // Lifecycle hook (after all kernel state writes — CEI): tell the new policy it has been
        // attached so it can re-anchor its per-account accounting. This closes the detach→reattach
        // over-collection (the same instance would otherwise bill management fees over the dormant
        // interval). The call passes ONLY `account` — the kernel never learns NAV/valuation; that
        // stays the policy/manager's responsibility. The new policy is governance-trusted (checked
        // above) and setFeePolicy is nonReentrant, so the external call is safe here.
        if (newFeePolicy != address(0)) IFeePolicy(newFeePolicy).onAttach(account);
    }

    /// @notice Register multiple permissions atomically. One signer nonce is consumed for the
    ///         entire batch; the total fee equals the sum of individual permission fees.
    ///         Reverts atomically if any permission in the batch is already registered,
    ///         the cap would be exceeded, the fee is insufficient, or the signature is invalid.
    /// @dev    The `permissions` array is EIP-712 encoded as keccak256 of the ABI-packed
    ///         zero-padded addresses (see `_hashAddressArray`). Empty arrays are a no-op
    ///         and do not consume a nonce.
    /// @dev    PERMISSION TRUST: The kernel binds authorization to a permission address only.
    ///         If a registered permission is upgradeable or uses a proxy, a change to its
    ///         implementation requires no new kernel signature. Operators are responsible for
    ///         registering only non-upgradeable or audited permission contracts.
    ///         See Sail Protocol whitepaper §8.2.
    /// @param  account     The registered Safe account.
    /// @param  permissions Addresses of permission contracts to register.
    /// @param  deadline    Unix timestamp after which the signature is invalid.
    /// @param  sig         EIP-712 signature over RegisterPermissions struct by permissionSigner.
    function registerPermissions(
        address account,
        address[] calldata permissions,
        uint256 deadline,
        bytes calldata sig
    ) external payable nonReentrant whenNotPaused {
        if (permissions.length == 0) {
            if (msg.value > 0) _collectRegistrationFee(0); // refunds full msg.value to caller
            return;
        }
        _requireRegistered(account);
        if (block.timestamp > deadline) revert DeadlineExpired(deadline, block.timestamp);

        // Enforce the cap before consuming the nonce to avoid nonce burns on revert.
        uint256 limit = governance.maxPermissionsPerAccount();
        if (_permissions[account].length + permissions.length > limit)
            revert TooManyPermissions(account, limit);

        uint256 nonce = signerNonces[account];
        _verifySignerSig(
            account,
            keccak256(abi.encode(
                REGISTER_PERMISSIONS_TYPEHASH,
                account,
                _hashAddressArray(permissions),
                nonce,
                deadline
            )),
            sig
        );
        signerNonces[account] = nonce + 1;

        // Compute total fee before any state changes
        uint256 totalFee = _calcPermissionFee() * permissions.length;
        if (msg.value < totalFee) revert InsufficientFee(totalFee, msg.value);

        // Add all permissions atomically — reverts if any duplicate or invalid address found
        for (uint256 i; i < permissions.length; i++) {
            address perm = permissions[i];
            if (perm == address(0)) revert ZeroAddress();
            if (perm.code.length == 0) revert NotAContract(perm);
            if (_permissionIndex[account][perm] != 0) revert PermissionAlreadyRegistered(perm);
            _permissions[account].push(perm);
            _permissionIndex[account][perm] = _permissions[account].length;
            emit PermissionRegistered(account, perm);
        }

        _collectRegistrationFee(totalFee);
    }

    /// @notice Revoke multiple permissions atomically. One signer nonce is consumed for
    ///         the entire batch; no ETH fee is required.
    ///         Empty arrays are a no-op and do not consume a nonce.
    /// @dev    Intentionally exempt from whenNotPaused — users must be able to revoke
    ///         permissions even during a protocol pause to reduce their exposure.
    /// @param  account     The registered Safe account.
    /// @param  permissions Addresses of permission contracts to revoke.
    /// @param  deadline    Unix timestamp after which the signature is invalid.
    /// @param  sig         EIP-712 signature over RevokePermissions struct by permissionSigner.
    function revokePermissions(
        address account,
        address[] calldata permissions,
        uint256 deadline,
        bytes calldata sig
    ) external nonReentrant {
        if (permissions.length == 0) return;
        _requireRegistered(account);
        if (block.timestamp > deadline) revert DeadlineExpired(deadline, block.timestamp);

        uint256 nonce = signerNonces[account];
        _verifySignerSig(
            account,
            keccak256(abi.encode(
                REVOKE_PERMISSIONS_TYPEHASH,
                account,
                _hashAddressArray(permissions),
                nonce,
                deadline
            )),
            sig
        );
        signerNonces[account] = nonce + 1;

        for (uint256 i; i < permissions.length; i++) {
            _removePermission(account, permissions[i]);
            registrationEpoch[account][permissions[i]] += 1;
            emit PermissionRevoked(account, permissions[i]);
        }
        managerNonces[account] += NONCE_EPOCH_INCREMENT;
        batchNonces[account]   += NONCE_EPOCH_INCREMENT;
    }

    /// @notice Return the full list of registered permission addresses for an account.
    /// @param  account The Safe account to query.
    /// @return         Array of registered permission contract addresses.
    function getPermissions(address account) external view returns (address[] memory) {
        return _permissions[account];
    }

    /// @notice Check whether a specific permission is registered for an account.
    /// @param  account    The Safe account to query.
    /// @param  permission The permission contract address to look up.
    /// @return            True if the permission is currently registered.
    function isPermissionRegistered(address account, address permission) external view returns (bool) {
        return _permissionIndex[account][permission] != 0;
    }

    // -------------------------------------------------------------------------
    // 3. Manager dispatch
    // -------------------------------------------------------------------------

    /// @notice Verify a manager signature, evaluate the named permission, and
    ///         execute the transaction via the Safe module interface.
    ///
    // SELECTIVE authorization semantics: the manager signature names one
    // registered permission, and only that permission evaluates the call.
    // Changed from the prior conjunctive (AND) model where all registered
    // permissions had to approve. The new model enables multi-permission SMAs
    // where unrelated permissions (e.g., Uniswap, Aave, Transfer) coexist
    // on one account without falsely denying each other's calls. Layered
    // defense via permission composition is not supported here — a separate
    // guard mechanism may be added later if needed.
    ///
    /// @dev    The manager nonce is incremented before external interaction; however, any revert
    ///         will roll back this write, so failed attempts do not consume the nonce. To achieve
    ///         strict single-use semantics, convert post-nonce failures to non-reverting denials
    ///         or add an explicit cancel-nonce operation. The permission is evaluated via
    ///         staticcall with PERMISSION_GAS_CAP gas; a revert or gas exhaustion inside a
    ///         permission is treated as denial. The named permission must be pre-registered
    ///         on the account; this is the permissionSigner's trust anchor.
    /// @dev    CONFIG SEQUENCING: Dispatch authorizes by permission address only, not by
    ///         configuration state. To atomically tighten a permission's rules, use
    ///         replacePermission rather than reconfiguring in place. An in-place configure
    ///         is subject to a front-run window while the transaction is pending.
    /// @param  account     The registered Safe account to execute through.
    /// @param  permission  The registered permission that must authorise this call.
    /// @param  target      Call target address.
    /// @param  value       Native ETH to forward with the call (wei).
    /// @param  data        Calldata for the target call.
    /// @param  managerSig  EIP-712 signature over Dispatch struct by the account's manager.
    /// @param  deadline    Unix timestamp after which the signature is invalid.
    function dispatch(
        address account,
        address permission,
        address target,
        uint256 value,
        bytes calldata data,
        bytes calldata managerSig,
        uint256 deadline
    ) external nonReentrant whenNotPaused {
        _requireRegistered(account);

        AccountConfig storage cfg = configs[account];
        if (!cfg.sessionActive) revert SessionInactive(account);
        // Deadline is a user-supplied expiry, intentionally compared against block.timestamp.
        // Matches the pattern used by every other deadline-checking entry point in this contract.
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp > deadline) revert DeadlineExpired(deadline, block.timestamp);

        // O(1) membership check — revert if the named permission is not registered.
        if (_permissionIndex[account][permission] == 0) revert PermissionNotRegistered(permission);

        uint256 nonce    = managerNonces[account];
        bytes32 dataHash = keccak256(data);
        bytes32 digest   = _hashTypedDataV4(keccak256(abi.encode(
            DISPATCH_TYPEHASH,
            account,
            permission,
            target,
            value,
            dataHash,
            nonce,
            deadline
        )));
        if (!_recoverOrERC1271(cfg.manager, digest, managerSig)) revert InvalidManagerSignature();
        managerNonces[account] = nonce + 1;

        // Prevent module-triggered self-calls: a call targeting the Safe itself satisfies
        // Safe's onlySelf guard, enabling enableModule/setGuard/owner changes without permission.
        if (target == account) revert AccountSelfTarget();
        // Parity with dispatchBatch's per-subcall guards: a single dispatch may not target the
        // zero address or the kernel itself. Re-entry is already blocked by nonReentrant; rejecting
        // these targets closes the class at the dispatch boundary. Single dispatch has no subcall
        // index, so it reuses the batch errors with index 0.
        if (target == address(0))    revert BatchZeroTarget(0);
        if (target == address(this)) revert KernelSelfTarget(0);

        bytes4 sel = data.length >= 4 ? bytes4(data[:4]) : bytes4(0);
        Context memory ctx = Context({
            account:        account,
            manager:        cfg.manager,
            submitter:      msg.sender,
            target:         target,
            selector:       sel,
            value:          value,
            blockTimestamp: block.timestamp,
            blockNumber:    block.number,
            configEpoch:    registrationEpoch[account][permission]
        });
        if (!_evaluatePermission(permission, data, ctx)) revert PermissionDenied(permission);

        if (!ISafe(account).execTransactionFromModule(target, value, data, 0)) revert SafeExecutionFailed();

        emit Dispatched(account, permission, target, sel, value);
    }

    /// @dev Invoke a single permission via staticcall with the configured gas cap.
    ///      Returns false on revert, out-of-gas, or malformed return data.
    function _evaluatePermission(address permission, bytes calldata data, Context memory ctx)
        internal
        view
        returns (bool)
    {
        bytes memory callData = abi.encodeCall(IPermission.evaluate, (data, ctx));
        (bool success, bytes memory ret) = permission.staticcall{gas: PERMISSION_GAS_CAP}(callData);
        if (!success || ret.length < 32) return false;
        // Decode as uint256 to avoid abi.decode revert on non-canonical bool words (e.g. 0x02).
        return abi.decode(ret, (uint256)) == 1;
    }

    // -------------------------------------------------------------------------
    // 3b. Batch dispatch
    // -------------------------------------------------------------------------

    /// @notice Execute a sequence of Safe module calls as a single atomic transaction,
    ///         gated by ONE named batch-aware permission.
    ///
    /// @dev    DIVERGENCE FROM `dispatch`: only the named `permission` is evaluated.
    ///         Other IPermissions registered on the account are NOT consulted during
    ///         batch dispatch. The batch-aware permission owns full responsibility for
    ///         validating every subcall and any cross-call invariants (e.g. matching
    ///         approve/consume amounts, mandatory reset-to-zero cleanup).
    ///
    ///         The `permission` MUST still be registered on the account — registration
    ///         is the permissionSigner's trust anchor. Choosing it for a batch then
    ///         requires only the manager's signature.
    ///
    ///         Atomicity: if any subcall returns false from execTransactionFromModule,
    ///         the entire dispatch reverts, rolling back all prior subcalls in the batch.
    ///
    ///         Operation type: every subcall executes with `operation = 0` (CALL).
    ///         DELEGATECALL is never used. The kernel does not depend on Safe MultiSend.
    ///
    ///         Self-target guard: no subcall may target this kernel. This is a defensive
    ///         measure — re-entry through public functions is already blocked by
    ///         nonReentrant, but rejecting kernel-targeted subcalls eliminates the
    ///         entire class of self-targeted attacks at the dispatch boundary.
    ///
    /// @dev    CONFIG SEQUENCING: Dispatch authorizes by permission address only, not by
    ///         configuration state. To atomically tighten a permission's rules, use
    ///         replacePermission rather than reconfiguring in place. An in-place configure
    ///         is subject to a front-run window while the transaction is pending.
    ///
    /// @param  account     The registered Safe account to execute through.
    /// @param  permission  The batch-aware permission that authorises this batch.
    ///                     Must be registered on the account and implement IBatchPermission.
    /// @param  calls       Ordered subcall sequence (length 1..MAX_BATCH_LENGTH).
    /// @param  managerSig  EIP-712 signature over DispatchBatch struct by the account's manager.
    /// @param  deadline    Unix timestamp after which the signature is invalid.
    function dispatchBatch(
        address account,
        address permission,
        Call[] calldata calls,
        bytes calldata managerSig,
        uint256 deadline
    ) external nonReentrant whenNotPaused {
        // 1. Account / session / deadline validation
        _requireRegistered(account);
        AccountConfig storage cfg = configs[account];
        if (!cfg.sessionActive) revert SessionInactive(account);
        if (block.timestamp > deadline) revert DeadlineExpired(deadline, block.timestamp);

        // 2. Batch length bounds
        uint256 len = calls.length;
        if (len == 0) revert EmptyBatch();
        if (len > MAX_BATCH_LENGTH) revert BatchTooLong(len);

        // 3. Permission must be registered for this account
        if (_permissionIndex[account][permission] == 0) revert PermissionNotRegistered(permission);

        // 4. Verify manager signature over the canonical callsHash
        bytes32 callsHash = keccak256(abi.encode(calls));
        uint256 nonce     = batchNonces[account];
        bytes32 digest    = _hashTypedDataV4(keccak256(abi.encode(
            DISPATCH_BATCH_TYPEHASH,
            account,
            permission,
            callsHash,
            nonce,
            deadline
        )));
        if (!_recoverOrERC1271(cfg.manager, digest, managerSig)) revert InvalidManagerSignature();
        // NOTE: Nonce is incremented here, but any subsequent revert will roll back this write;
        // failed attempts do not consume the nonce. To enforce single-use semantics, convert
        // post-nonce failures to non-reverting denials or add an explicit cancel-nonce operation.
        batchNonces[account] = nonce + 1;

        // 5. Permission must implement IBatchPermission. Detection via staticcall
        //    is stricter than try/catch — guarantees no state mutation regardless of
        //    what the target claims about its function modifiers.
        {
            (bool detOk, bytes memory detRet) = permission.staticcall{gas: BATCH_DETECT_GAS_CAP}(
                abi.encodeWithSelector(IBatchPermission.isBatchPermission.selector)
            );
            if (!detOk || detRet.length < 32 || abi.decode(detRet, (uint256)) != 1) {
                revert PermissionNotBatchAware(permission);
            }
        }

        // 6. Pre-flight: no subcall may target the zero address or the kernel itself
        for (uint256 i = 0; i < len;) {
            if (calls[i].target == address(0))    revert BatchZeroTarget(i);
            if (calls[i].target == address(this)) revert KernelSelfTarget(i);
            if (calls[i].target == account)       revert AccountSelfTarget();
            unchecked { ++i; }
        }

        // 7. Build BatchContext and evaluate the batch permission
        BatchContext memory ctx = BatchContext({
            account:        account,
            manager:        cfg.manager,
            submitter:      msg.sender,
            permission:     permission,
            batchHash:      callsHash,
            blockTimestamp: block.timestamp,
            blockNumber:    block.number,
            configEpoch:    registrationEpoch[account][permission]
        });
        if (!_evaluateBatchPermission(permission, calls, ctx)) revert BatchPermissionDenied();

        // 8. Execute each subcall in order via Safe module CALL (operation = 0).
        //    Any failure reverts the entire transaction, rolling back earlier subcalls.
        for (uint256 i = 0; i < len;) {
            Call calldata c = calls[i];
            bool ok = ISafe(account).execTransactionFromModule(c.target, c.value, c.data, 0);
            if (!ok) revert BatchSubcallFailed(i, c.target);
            unchecked { ++i; }
        }

        emit BatchDispatched(account, permission, callsHash, len);
    }

    /// @dev Invoke `evaluateBatch` on the named permission via staticcall with the
    ///      batch gas cap. Returns false on revert, OOG, or malformed return data.
    ///      Pattern mirrors `_evaluatePermission` for consistency.
    function _evaluateBatchPermission(
        address permission,
        Call[] calldata calls,
        BatchContext memory ctx
    ) internal view returns (bool) {
        bytes memory callData = abi.encodeCall(IBatchPermission.evaluateBatch, (calls, ctx));
        (bool success, bytes memory ret) = permission.staticcall{gas: BATCH_EVAL_GAS_CAP}(callData);
        if (!success || ret.length < 32) return false;
        return abi.decode(ret, (uint256)) == 1;
    }

    // -------------------------------------------------------------------------
    // 3c. Permission introspection views
    // -------------------------------------------------------------------------

    /// @notice Return the full permission list for an account with enriched metadata.
    /// @dev    Reads IPermissionIntrospection and IBatchPermission.isBatchPermission()
    ///         on each registered permission via try/catch. A non-implementing permission
    ///         returns zero/false for the corresponding fields.
    ///
    ///         `hasIntrospection` is true when `permissionId()` succeeds AND returns
    ///         a non-zero value (a zero permissionId indicates a non-compliant or unset
    ///         implementation; see IPermissionIntrospection.permissionId()).
    ///
    ///         Intended for off-chain use only. Each permission may make up to 3 external
    ///         view calls; call with a generous gas limit on accounts with many permissions.
    ///         MUST NOT be called from dispatch — use isPermissionRegistered() for O(1) checks.
    ///
    /// @dev    External calls to user-deployed permission contracts are NOT gas-capped here.
    ///         Off-chain consumers (indexers, dashboards) should apply their own gas limit or
    ///         timeout when calling this function over RPC; a buggy or malicious permission can
    ///         consume large amounts of gas or return large data. The kernel omits a cap because
    ///         this is a view with no on-chain impact; the dispatch-path already gas-caps each
    ///         permission evaluation via the protocol's per-permission gas isolation guarantee.
    /// @param  account The Safe account to query.
    /// @return infos   Array of PermissionInfo, one per registered permission, in registration order.
    function getPermissionsWithInfo(address account) external view returns (PermissionInfo[] memory infos) {
        address[] storage perms = _permissions[account];
        uint256 len = perms.length;
        infos = new PermissionInfo[](len);
        for (uint256 i; i < len; i++) {
            address perm = perms[i];
            infos[i].permission = perm;
            try IBatchPermission(perm).isBatchPermission() returns (bool b) {
                infos[i].isBatch = b;
            } catch {}
            try IPermissionIntrospection(perm).permissionId() returns (bytes32 pid) {
                if (pid != bytes32(0)) {
                    infos[i].hasIntrospection = true;
                    infos[i].permissionId = pid;
                    try IPermissionIntrospection(perm).permissionVersion() returns (bytes32 pv) {
                        infos[i].permissionVersion = pv;
                    } catch {}
                }
            } catch {}
        }
    }

    /// @notice Simulate whether a batch dispatch would be approved without executing it.
    /// @dev    Runs the same validation as dispatchBatch EXCEPT signature verification
    ///         (no sig available in a simulation context) and Safe module execution.
    ///         Useful for off-chain pre-flight checks (keeper bots, UI previews).
    ///
    ///         Return values:
    ///           approved = true  → batch would pass evaluateBatch
    ///           approved = false → batch would be denied; `reason` has a short descriptor
    ///
    ///         Does NOT check: session active, deadline, or sig.
    ///         Callers must verify those separately.
    ///         DOES check: account registration and permission registration; returns
    ///         (false, "AccountNotRegistered") or (false, "PermissionNotRegistered") accordingly.
    ///
    /// @param  account    The registered Safe account.
    /// @param  permission The batch-aware permission to evaluate.
    /// @param  calls      The call sequence to evaluate.
    /// @return approved   True if the batch permission would authorise the call sequence.
    /// @return reason     Short denial reason string; empty if approved.
    function previewBatch(
        address account,
        address permission,
        Call[] calldata calls
    ) external view returns (bool approved, string memory reason) {
        if (calls.length == 0)               return (false, "EmptyBatch");
        if (calls.length > MAX_BATCH_LENGTH) return (false, "BatchTooLong");
        if (!registered[account])            return (false, "AccountNotRegistered");
        if (_permissionIndex[account][permission] == 0) return (false, "PermissionNotRegistered");

        for (uint256 i; i < calls.length; i++) {
            if (calls[i].target == address(0))    return (false, "BatchZeroTarget");
            if (calls[i].target == address(this)) return (false, "KernelSelfTarget");
            if (calls[i].target == account)       return (false, "AccountSelfTarget");
        }

        (bool detOk, bytes memory detRet) = permission.staticcall{gas: BATCH_DETECT_GAS_CAP}(
            abi.encodeWithSelector(IBatchPermission.isBatchPermission.selector)
        );
        if (!detOk || detRet.length < 32 || abi.decode(detRet, (uint256)) != 1) {
            return (false, "PermissionNotBatchAware");
        }

        bytes32 callsHash = keccak256(abi.encode(calls));
        BatchContext memory ctx = BatchContext({
            account:        account,
            manager:        configs[account].manager,
            submitter:      address(0),   // no submitter in simulation; permissions enforcing submitter whitelists will return false
            permission:     permission,
            batchHash:      callsHash,
            blockTimestamp: block.timestamp,
            blockNumber:    block.number,
            configEpoch:    registrationEpoch[account][permission]
        });

        if (!_evaluateBatchPermission(permission, calls, ctx)) {
            return (false, "BatchPermissionDenied");
        }
        return (true, "");
    }

    // -------------------------------------------------------------------------
    // 4. Fee accounting
    // -------------------------------------------------------------------------

    /// @notice Collect fees earned by the manager. The kernel validates the requested amount
    ///         against the registered fee policy and enforces the protocol/distributor split.
    /// @dev    TRUST ASSUMPTION: `currentNav` is provided by the manager and is not verified
    ///         on-chain. The fee policy is the sole guard against inflated NAV inputs.
    ///
    /// @dev    DENOMINATION WARNING: `currentNav` and `feeToken` must use consistent units.
    ///         The fee policy computes maxFee from currentNav — if NAV is USD-denominated
    ///         but feeToken is WETH, the fee ceiling will be wildly incorrect.
    ///         Deployers must ensure their fee policy validates or denominates in feeToken units.
    ///         The actual tokens transferred equal `grossFee` — not a function of `currentNav` —
    ///         but a dishonest manager could inflate `currentNav` to unlock a larger `maxFee`
    ///         ceiling and then pass a correspondingly large `grossFee`. Deployers must use a
    ///         fee policy that validates NAV independently if the manager is not trusted.
    ///
    /// @dev Fee collection is atomic: any failed transfer reverts the entire call.
    ///      ETH mode (feeToken == address(0)) requires all recipients to be payable.
    ///      To avoid DoS on non-payable recipients, prefer ERC-20 fee tokens.
    /// @param  account    The registered Safe account from which fees are collected.
    /// @param  grossFee   Requested fee amount. Must not exceed the policy's computed maximum.
    /// @param  currentNav Current net asset value reported by the manager.
    /// @param  feeToken   ERC-20 token for fee payment; address(0) = native ETH.
    /// @dev DENOMINATION WARNING: `grossFee` and `currentNav` must be expressed in the same
    ///      token units as the fee token (or ETH wei if feeToken==address(0)). Mixing
    ///      denominations between grossFee and currentNav will silently produce incorrect fee
    ///      calculations inside the policy.
    function collectFees(
        address account,
        uint256 grossFee,
        uint256 currentNav,
        address feeToken
    ) external nonReentrant whenNotPaused {
        // W1: reject Safe-fallback-relayed calls. collectFees also accepts msg.sender == account,
        // so a fallbackHandler==kernel Safe could otherwise force its own fee outflows. A direct
        // call is exactly selector + 4 static args (see COLLECT_FEES_CALLDATA_LEN).
        if (msg.data.length != COLLECT_FEES_CALLDATA_LEN) revert UnexpectedCalldataLength();
        _requireRegistered(account);
        AccountConfig storage cfg = configs[account];
        if (!cfg.sessionActive) revert SessionInactive(account);
        // Fee collection is a fund-moving operation, so it is restricted to the manager or
        // the Safe account itself (the latter covers non-forwarding ERC-1271 managers, and is
        // the owner-controlled backstop). The permissionSigner manages the permission registry
        // and never moves funds, so it is intentionally excluded.
        if (msg.sender != cfg.manager && msg.sender != account) {
            revert NotManager(msg.sender, cfg.manager);
        }
        address feePolicy = cfg.feePolicy;
        if (feePolicy == address(0)) revert FeePolicyNotSet();
        if (grossFee == 0) revert ZeroFee();
        if (feeToken != cfg.feeAsset) revert FeeTokenMismatch(feeToken, cfg.feeAsset);

        // Recipient is always pulled from the policy — prevents manager from redirecting fees.
        address recipient = IFeePolicy(feePolicy).feeRecipient();
        if (recipient == address(0)) revert ZeroAddress();

        (uint256 maxFee, address distributor, uint256 distributorBps) =
            IFeePolicy(feePolicy).computeFee(account, currentNav);
        if (grossFee > maxFee) revert FeeTooLarge(grossFee, maxFee);
        if (distributorBps > 10_000) revert DistributorBpsTooLarge(distributorBps);

        // Prevent payout targets from being the kernel itself: ETH transfers would revert
        // (no receive/fallback) blocking all collections; ERC-20 transfers would permanently
        // trap tokens since the kernel has no sweep mechanism.
        if (treasury == address(this) || distributor == address(this) || recipient == address(this)) {
            revert ZeroAddress();
        }

        uint256 protocolCut    = Math.mulDiv(grossFee, governance.currentProtocolCutBps(), 10_000);
        uint256 remainder      = grossFee - protocolCut;
        uint256 distributorCut = Math.mulDiv(remainder, distributorBps, 10_000);
        // If the policy returns a non-zero distributorBps but a zero distributor address,
        // fold the distributor share into managerTake rather than silently dropping it.
        if (distributor == address(0)) distributorCut = 0;
        uint256 managerTake    = remainder - distributorCut;

        // Record state update BEFORE external transfers (CEI pattern).
        // This prevents a policy that reverts after transfers from leaving funds extracted
        // but state un-updated, which would allow a second collection over the same period.
        IFeePolicy(feePolicy).recordCollection(account, grossFee, currentNav);

        if (feeToken == address(0)) {
            if (protocolCut    > 0) _safeTransferETH(account, treasury,    protocolCut);
            if (distributorCut > 0) _safeTransferETH(account, distributor, distributorCut);
            if (managerTake    > 0) _safeTransferETH(account, recipient,   managerTake);
        } else {
            if (protocolCut    > 0) _safeTransferERC20(account, feeToken, treasury,    protocolCut);
            if (distributorCut > 0) _safeTransferERC20(account, feeToken, distributor, distributorCut);
            if (managerTake    > 0) _safeTransferERC20(account, feeToken, recipient,   managerTake);
        }

        emit FeesCollected(account, feeToken, grossFee, protocolCut, distributorCut, managerTake);
    }

    /// @dev Execute a native ETH transfer out of the Safe via module call.
    /// @dev Reverts the entire fee collection if the Safe call returns false.
    ///      Intentional design: partial payouts would leave split invariants broken.
    ///      Use ERC-20 tokens where recipient payability cannot be guaranteed.
    function _safeTransferETH(address account, address to, uint256 value) internal {
        if (!ISafe(account).execTransactionFromModule(to, value, "", 0)) revert FeeTransferFailed();
    }

    /// @dev Execute an ERC-20 transfer out of the Safe via module call, verifying BOTH the
    ///      Safe module's success bool AND the token's own return value (SafeERC20 semantics).
    ///      The module-only bool is true whenever the inner `transfer` does not revert, so a
    ///      token that returns `false` without reverting — or returns malformed data — would
    ///      otherwise be recorded as a collected fee while no tokens moved. This reverts on
    ///      that case. A compliant token that returns nothing (non-standard, e.g. some USDT
    ///      deployments) is tolerated as success, matching SafeERC20.
    ///      The return value is decoded as a uint256 compared to 1 (rather than abi.decode to
    ///      bool) so a non-canonical word reverts cleanly with FeeTransferFailed instead of a
    ///      decode panic, consistent with the permission-evaluation decode elsewhere.
    /// @dev OUT OF SCOPE: fee-on-transfer shortfall. A fee-on-transfer token returns `true`
    ///      and does move tokens, just fewer than `amount`; this check does not guarantee the
    ///      recipient received `amount`. That risk is bounded by the account's feeAsset choice.
    function _safeTransferERC20(address account, address token, address to, uint256 amount) internal {
        bytes memory data = abi.encodeCall(IERC20.transfer, (to, amount));
        (bool ok, bytes memory ret) = ISafe(account).execTransactionFromModuleReturnData(token, 0, data, 0);
        if (!ok) revert FeeTransferFailed();
        if (ret.length != 0 && (ret.length < 32 || abi.decode(ret, (uint256)) != 1)) revert FeeTransferFailed();
    }

    // -------------------------------------------------------------------------
    // 5. Principal tracking
    // -------------------------------------------------------------------------

    /// @notice Record a deposit into the account. Only the permissionSigner may call.
    /// @dev    These values are informational. They are not used to constrain fee
    ///         collection on-chain, but may be used by off-chain tooling and future policy
    ///         contracts to derive context-aware fee limits.
    /// @param  account The registered Safe account.
    /// @param  amount  Deposit amount to record (in the account's base currency units).
    function recordDeposit(address account, uint256 amount) external nonReentrant {
        _requireRegistered(account);
        if (msg.sender != configs[account].permissionSigner) revert NotPermissionSigner();
        uint256 newDeposits = cumulativeDeposits[account] += amount;
        emit DepositRecorded(account, amount, newDeposits);
    }

    /// @notice Record a withdrawal from the account. Only the permissionSigner may call.
    /// @param  account The registered Safe account.
    /// @param  amount  Withdrawal amount to record (in the account's base currency units).
    function recordWithdrawal(address account, uint256 amount) external nonReentrant {
        _requireRegistered(account);
        if (msg.sender != configs[account].permissionSigner) revert NotPermissionSigner();
        uint256 newWithdrawals = cumulativeWithdrawals[account] += amount;
        emit WithdrawalRecorded(account, amount, newWithdrawals);
    }

    // -------------------------------------------------------------------------
    // Public helpers
    // -------------------------------------------------------------------------

    /// @notice Compute the EIP-712 digest for a given struct hash.
    /// @dev    Exposed for off-chain tooling, frontends, and tests.
    /// @param  structHash The EIP-712 struct hash (output of `keccak256(abi.encode(TYPEHASH, ...))`).
    /// @return            The final EIP-712 digest including domain separator.
    function hashTypedDataV4(bytes32 structHash) external view returns (bytes32) {
        return _hashTypedDataV4(structHash);
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /// @dev Reverts with AccountNotRegistered when the account has not been registered.
    function _requireRegistered(address account) internal view {
        if (!registered[account]) revert AccountNotRegistered(account);
    }

    /// @dev Return the flat registration fee for a permission.
    function _calcPermissionFee() internal view returns (uint256) {
        return governance.permissionRegistrationFee();
    }

    /// @dev Forward `fee` to the treasury and refund any ETH overpayment to msg.sender.
    ///      All callers (registerPermission, replacePermission, registerPermissions) complete
    ///      every state mutation (nonce increment, permission array update) before invoking
    ///      this function. The refund callback to msg.sender therefore occurs after all
    ///      state is settled; re-entry into any nonReentrant function is blocked. Any
    ///      re-entry into non-guarded functions (revokeSession, activateSession) still
    ///      requires a valid permissionSigner signature, preventing unauthorised mutations.
    function _collectRegistrationFee(uint256 fee) internal {
        if (fee > 0) {
            (bool ok,) = treasury.call{value: fee}("");
            if (!ok) revert FeeTransferFailed();
        }
        uint256 excess = msg.value - fee;
        if (excess > 0) {
            (bool ok,) = msg.sender.call{value: excess}("");
            if (!ok) revert FeeTransferFailed();
        }
    }

    /// @dev Remove a permission from the account's list using swap-and-pop to preserve
    ///      packed storage. Updates `_permissionIndex` for the swapped element.
    function _removePermission(address account, address permission) internal {
        uint256 idx = _permissionIndex[account][permission];
        if (idx == 0) revert PermissionNotRegistered(permission);
        address[] storage perms = _permissions[account];
        uint256 lastIdx = perms.length - 1;
        if (idx - 1 != lastIdx) {
            address last = perms[lastIdx];
            perms[idx - 1] = last;
            _permissionIndex[account][last] = idx;
        }
        perms.pop();
        delete _permissionIndex[account][permission];
    }

    /// @dev Remove every permission registered for an account, clearing both the ordered
    ///      list and the index mapping, and emitting `PermissionRevoked` for each. Used by
    ///      `setManager` to reset mandates on signer rotation. Bounded by
    ///      governance.maxPermissionsPerAccount(). Unlike `_removePermission`, this does not
    ///      swap-and-pop per element: it reads each entry, clears its index, then deletes the
    ///      whole array in one shot — so the array is never mutated mid-iteration.
    function _clearPermissions(address account) internal {
        address[] storage perms = _permissions[account];
        uint256 len = perms.length;
        for (uint256 i; i < len;) {
            address perm = perms[i];
            delete _permissionIndex[account][perm];
            registrationEpoch[account][perm] += 1;
            emit PermissionRevoked(account, perm);
            unchecked { ++i; }
        }
        delete _permissions[account];
    }

    /// @dev EIP-712-compliant encoding of `address[]`:
    ///      keccak256 of the concatenation of each address zero-padded to 32 bytes,
    ///      which is the ABI encoding of `address[]` per EIP-712 §4.
    /// @param  arr The address array to hash.
    /// @return     The EIP-712 hash of the array.
    function _hashAddressArray(address[] calldata arr) internal pure returns (bytes32) {
        bytes32[] memory buf = new bytes32[](arr.length);
        for (uint256 i; i < arr.length; i++) {
            buf[i] = bytes32(uint256(uint160(arr[i])));
        }
        return keccak256(abi.encodePacked(buf));
    }

    /// @dev Verify an EIP-712 permissionSigner signature against a struct hash.
    ///      Supports both EOA (ECDSA) and smart-contract (ERC-1271) signers.
    function _verifySignerSig(address account, bytes32 structHash, bytes memory sig) internal view {
        bytes32 digest = _hashTypedDataV4(structHash);
        if (!_recoverOrERC1271(configs[account].permissionSigner, digest, sig)) revert InvalidSignerSignature();
    }

    /// @dev Verify a signature against `expected`, supporting both ECDSA and ERC-1271.
    ///      ECDSA is tried first regardless of code presence; this handles EIP-7702 accounts
    ///      that install transient code but do not implement ERC-1271.  If ECDSA recovery
    ///      succeeds and the recovered address matches, the signature is accepted immediately.
    ///      Otherwise, falls back to ERC-1271 when `expected` is a contract.
    /// @param  expected Address expected to have produced the signature.
    /// @param  digest   EIP-712 digest to verify against.
    /// @param  sig      Signature bytes.
    /// @return          True if the signature is valid for `expected`.
    function _recoverOrERC1271(address expected, bytes32 digest, bytes memory sig) internal view returns (bool) {
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
