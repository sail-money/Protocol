// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IPermission, Context} from "../interfaces/IPermission.sol";
import {IFeePolicy}            from "../interfaces/IFeePolicy.sol";
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
}

/// @dev Minimal Safe module interface — used for executing transactions and fee transfers.
interface ISafe {
    function execTransactionFromModule(address to, uint256 value, bytes calldata data, uint8 operation)
        external
        returns (bool success);
}

/// @title  SailKernel
/// @notice Central execution kernel for the Sail protocol.
///
///         The kernel manages a registry of Safe accounts, each with a set of
///         permission contracts. When a manager submits a signed transaction, the
///         kernel:
///           1. Verifies the manager's EIP-712 signature and nonce.
///           2. Evaluates every registered permission (all must return true).
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
    uint256 public constant PERMISSION_GAS_CAP = 100_000;

    /// @dev ERC-1271 magic value returned by `isValidSignature` for a valid signature.
    bytes4  private constant ERC1271_MAGIC              = 0x1626ba7e;

    // -------------------------------------------------------------------------
    // EIP-712 type hashes
    // -------------------------------------------------------------------------

    /// @notice EIP-712 type hash for manager dispatch authorisation.
    ///         Type string: "Dispatch(address account,address target,uint256 value,bytes32 dataHash,uint256 nonce,uint256 deadline)"
    bytes32 public constant DISPATCH_TYPEHASH = keccak256(
        "Dispatch(address account,address target,uint256 value,bytes32 dataHash,uint256 nonce,uint256 deadline)"
    );

    /// @notice EIP-712 type hash for single-permission registration.
    ///         Type string: "RegisterPermission(address account,address permission,uint256 nonce)"
    bytes32 public constant REGISTER_PERMISSION_TYPEHASH = keccak256(
        "RegisterPermission(address account,address permission,uint256 nonce)"
    );

    /// @notice EIP-712 type hash for single-permission revocation.
    ///         Type string: "RevokePermission(address account,address permission,uint256 nonce)"
    bytes32 public constant REVOKE_PERMISSION_TYPEHASH = keccak256(
        "RevokePermission(address account,address permission,uint256 nonce)"
    );

    /// @notice EIP-712 type hash for atomic permission replacement.
    ///         Type string: "ReplacePermission(address account,address oldPermission,address newPermission,uint256 nonce)"
    bytes32 public constant REPLACE_PERMISSION_TYPEHASH = keccak256(
        "ReplacePermission(address account,address oldPermission,address newPermission,uint256 nonce)"
    );

    /// @notice EIP-712 type hash for session revocation.
    ///         Type string: "RevokeSession(address account,uint256 nonce)"
    bytes32 public constant REVOKE_SESSION_TYPEHASH = keccak256(
        "RevokeSession(address account,uint256 nonce)"
    );

    /// @notice EIP-712 type hash for session re-activation.
    ///         Type string: "ActivateSession(address account,uint256 nonce)"
    bytes32 public constant ACTIVATE_SESSION_TYPEHASH = keccak256(
        "ActivateSession(address account,uint256 nonce)"
    );

    /// @notice EIP-712 type hash for fee policy updates.
    ///         Type string: "SetFeePolicy(address account,address newFeePolicy,uint256 nonce)"
    bytes32 public constant SET_FEE_POLICY_TYPEHASH = keccak256(
        "SetFeePolicy(address account,address newFeePolicy,uint256 nonce)"
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
        /// @dev When false, all dispatch calls for this account are blocked.
        bool    sessionActive;
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

    /// @notice Per-account nonces for permissionSigner operations
    ///         (register, revoke, replace, session, feePolicy).
    mapping(address account => uint256) public signerNonces;

    // -------------------------------------------------------------------------
    // Principal tracking
    // -------------------------------------------------------------------------

    /// @notice Cumulative deposit amount recorded for each account (informational).
    ///         Written by the permissionSigner via `recordDeposit`.
    mapping(address account => uint256) public cumulativeDeposits;

    /// @notice Cumulative withdrawal amount recorded for each account (informational).
    ///         Written by the permissionSigner via `recordWithdrawal`.
    mapping(address account => uint256) public cumulativeWithdrawals;

    // -------------------------------------------------------------------------
    // Protocol references
    // -------------------------------------------------------------------------

    /// @notice The governance contract that stores fee parameters and the protocol cut.
    SailGovernance public immutable governance;

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

    /// @notice Emitted on each successful dispatch.
    /// @dev    `dataHash` is keccak256(calldata) — the raw bytes are recoverable from the tx.
    /// @param  account   The Safe account that executed the transaction.
    /// @param  target    The call target.
    /// @param  value     Native ETH forwarded with the call (wei).
    /// @param  dataHash  keccak256 of the dispatched calldata.
    event Dispatched(address indexed account, address indexed target, uint256 value, bytes32 dataHash);

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

    /// @dev Thrown by `collectFees` when `distributorBps` returned by the policy exceeds 10 000.
    error DistributorBpsTooLarge(uint256 bps);

    /// @dev Thrown by `dispatch` when no permissions are registered (deny-by-default).
    error NoPermissionsRegistered(address account);
    /// @dev Thrown by `dispatch` / `collectFees` when the protocol is paused.
    error ProtocolPaused();

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    /// @notice Deploy the kernel with a governance contract and initial treasury address.
    /// @param  _governance  Address of the deployed SailGovernance contract.
    /// @param  _treasury    Address that will receive the protocol's share of fees.
    constructor(address _governance, address _treasury) EIP712("SailKernel", "1") {
        if (_governance == address(0) || _treasury == address(0)) revert ZeroAddress();
        governance = SailGovernance(_governance);
        treasury   = _treasury;
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
        address old = treasury;
        treasury = newTreasury;
        emit TreasuryUpdated(old, newTreasury);
    }

    // -------------------------------------------------------------------------
    // 1. Account instantiation
    // -------------------------------------------------------------------------

    /// @notice Deploy a new Safe via factory and register it with the kernel in one transaction.
    /// @dev    The salt passed to the factory is derived from `keccak256(saltNonce, msg.sender)`
    ///         to bind the CREATE2 address to the caller, preventing front-running attacks where
    ///         an observer could claim registration of a Safe they did not deploy.
    ///         Off-chain pre-computation: `boundSalt = uint256(keccak256(abi.encode(saltNonce, msg.sender)))`.
    /// @param  safeFactory       Address of the Safe proxy factory contract.
    /// @param  safeSingleton     Address of the Safe singleton (implementation) contract.
    /// @param  safeInitializer   Calldata for the Safe's `setup` call during deployment.
    /// @param  saltNonce         Caller-chosen nonce; combined with msg.sender to form the CREATE2 salt.
    /// @param  permissionSigner  Address that will sign permission-registry operations.
    /// @param  manager           Address that will sign dispatch calls.
    /// @param  feePolicy         Fee policy contract; address(0) = no fee policy.
    /// @return account           Address of the newly deployed Safe proxy.
    function createAccount(
        address safeFactory,
        address safeSingleton,
        bytes calldata safeInitializer,
        uint256 saltNonce,
        address permissionSigner,
        address manager,
        address feePolicy
    ) external returns (address account) {
        uint256 boundSalt = uint256(keccak256(abi.encode(saltNonce, msg.sender)));
        account = ISafeFactory(safeFactory).createProxyWithNonce(safeSingleton, safeInitializer, boundSalt);
        _registerAccount(account, permissionSigner, manager, feePolicy);
    }

    /// @notice Register an existing Safe that has already added this kernel as a module.
    /// @dev    MUST be called by the Safe itself via a Safe transaction (msg.sender == Safe).
    ///         This prevents front-running: only the Safe's own signers can authorise
    ///         registration by executing a transaction through the Safe's threshold mechanism.
    /// @param  permissionSigner  Address that will sign permission-registry operations.
    /// @param  manager           Address that will sign dispatch calls.
    /// @param  feePolicy         Fee policy contract; address(0) = no fee policy.
    function registerAccount(address permissionSigner, address manager, address feePolicy) external {
        _registerAccount(msg.sender, permissionSigner, manager, feePolicy);
    }

    /// @dev Shared registration logic for `createAccount` and `registerAccount`.
    function _registerAccount(address account, address permissionSigner, address manager, address feePolicy)
        internal
    {
        if (registered[account]) revert AccountAlreadyRegistered(account);
        if (permissionSigner == address(0) || manager == address(0)) revert ZeroAddress();
        registered[account] = true;
        configs[account] = AccountConfig({
            permissionSigner: permissionSigner,
            manager:          manager,
            feePolicy:        feePolicy,
            sessionActive:    true
        });
        emit AccountRegistered(account, permissionSigner, manager);
    }

    // -------------------------------------------------------------------------
    // 2. Permission registry
    // -------------------------------------------------------------------------

    /// @notice Register a single permission for an account.
    ///         Requires a permissionSigner EIP-712 signature and an ETH registration fee.
    /// @param  account    The registered Safe account.
    /// @param  permission Address of the permission contract to register.
    /// @param  sig        EIP-712 signature over RegisterPermission struct by permissionSigner.
    function registerPermission(address account, address permission, bytes calldata sig)
        external
        payable
        nonReentrant
        whenNotPaused
    {
        _requireRegistered(account);
        if (_permissionIndex[account][permission] != 0) revert PermissionAlreadyRegistered(permission);
        uint256 limit = governance.maxPermissionsPerAccount();
        if (_permissions[account].length >= limit)
            revert TooManyPermissions(account, limit);

        uint256 nonce = signerNonces[account]++;
        _verifySignerSig(
            account,
            keccak256(abi.encode(REGISTER_PERMISSION_TYPEHASH, account, permission, nonce)),
            sig
        );

        uint256 fee = _calcPermissionFee(permission);
        if (msg.value < fee) revert InsufficientFee(fee, msg.value);

        _permissions[account].push(permission);
        _permissionIndex[account][permission] = _permissions[account].length; // stored as index + 1

        _collectRegistrationFee(fee);
        emit PermissionRegistered(account, permission);
    }

    /// @notice Revoke a single permission from an account.
    ///         Requires a permissionSigner EIP-712 signature.
    /// @param  account    The registered Safe account.
    /// @param  permission Address of the permission contract to revoke.
    /// @param  sig        EIP-712 signature over RevokePermission struct by permissionSigner.
    function revokePermission(address account, address permission, bytes calldata sig) external nonReentrant {
        _requireRegistered(account);
        uint256 nonce = signerNonces[account]++;
        _verifySignerSig(
            account,
            keccak256(abi.encode(REVOKE_PERMISSION_TYPEHASH, account, permission, nonce)),
            sig
        );
        _removePermission(account, permission);
        emit PermissionRevoked(account, permission);
    }

    /// @notice Atomically replace one permission with another in a single signed operation.
    ///         Requires a permissionSigner EIP-712 signature and an ETH registration fee.
    /// @param  account        The registered Safe account.
    /// @param  oldPermission  Permission to remove.
    /// @param  newPermission  Permission to add in its place.
    /// @param  sig            EIP-712 signature over ReplacePermission struct by permissionSigner.
    function replacePermission(
        address account,
        address oldPermission,
        address newPermission,
        bytes calldata sig
    ) external payable nonReentrant {
        _requireRegistered(account);
        if (_permissionIndex[account][newPermission] != 0) revert PermissionAlreadyRegistered(newPermission);

        uint256 nonce = signerNonces[account]++;
        _verifySignerSig(
            account,
            keccak256(abi.encode(REPLACE_PERMISSION_TYPEHASH, account, oldPermission, newPermission, nonce)),
            sig
        );

        uint256 idx = _permissionIndex[account][oldPermission];
        if (idx == 0) revert PermissionNotRegistered(oldPermission);

        uint256 fee = _calcPermissionFee(newPermission);
        if (msg.value < fee) revert InsufficientFee(fee, msg.value);

        _permissions[account][idx - 1] = newPermission;
        delete _permissionIndex[account][oldPermission];
        _permissionIndex[account][newPermission] = idx;

        _collectRegistrationFee(fee);
        emit PermissionReplaced(account, oldPermission, newPermission);
    }

    /// @notice Suspend the manager session for an account. All `dispatch` calls will
    ///         revert with `SessionInactive` until `activateSession` is called.
    /// @param  account The registered Safe account.
    /// @param  sig     EIP-712 signature over RevokeSession struct by permissionSigner.
    function revokeSession(address account, bytes calldata sig) external nonReentrant {
        _requireRegistered(account);
        uint256 nonce = signerNonces[account]++;
        _verifySignerSig(
            account,
            keccak256(abi.encode(REVOKE_SESSION_TYPEHASH, account, nonce)),
            sig
        );
        configs[account].sessionActive = false;
        emit SessionRevoked(account);
    }

    /// @notice Re-activate a previously suspended session. Requires a fresh permissionSigner
    ///         signature to prove the key is still under the operator's control.
    /// @param  account The registered Safe account.
    /// @param  sig     EIP-712 signature over ActivateSession struct by permissionSigner.
    function activateSession(address account, bytes calldata sig) external nonReentrant {
        _requireRegistered(account);
        uint256 nonce = signerNonces[account]++;
        _verifySignerSig(
            account,
            keccak256(abi.encode(ACTIVATE_SESSION_TYPEHASH, account, nonce)),
            sig
        );
        configs[account].sessionActive = true;
        emit SessionActivated(account);
    }

    /// @notice Replace the fee policy for an account. Requires a permissionSigner signature.
    ///         Setting `newFeePolicy = address(0)` clears the policy and blocks fee collection.
    /// @param  account      The registered Safe account.
    /// @param  newFeePolicy New fee policy contract address; address(0) = no fee policy.
    /// @param  sig          EIP-712 signature over SetFeePolicy struct by permissionSigner.
    function setFeePolicy(address account, address newFeePolicy, bytes calldata sig) external nonReentrant {
        _requireRegistered(account);
        uint256 nonce = signerNonces[account]++;
        _verifySignerSig(
            account,
            keccak256(abi.encode(SET_FEE_POLICY_TYPEHASH, account, newFeePolicy, nonce)),
            sig
        );
        configs[account].feePolicy = newFeePolicy;
        emit FeePolicyUpdated(account, newFeePolicy);
    }

    /// @notice Register multiple permissions atomically. One signer nonce is consumed for the
    ///         entire batch; the total fee equals the sum of individual permission fees.
    ///         Reverts atomically if any permission in the batch is already registered,
    ///         the cap would be exceeded, the fee is insufficient, or the signature is invalid.
    /// @dev    The `permissions` array is EIP-712 encoded as keccak256 of the ABI-packed
    ///         zero-padded addresses (see `_hashAddressArray`). Empty arrays are a no-op
    ///         and do not consume a nonce.
    /// @param  account     The registered Safe account.
    /// @param  permissions Addresses of permission contracts to register.
    /// @param  deadline    Unix timestamp after which the signature is invalid.
    /// @param  sig         EIP-712 signature over RegisterPermissions struct by permissionSigner.
    function registerPermissions(
        address account,
        address[] calldata permissions,
        uint256 deadline,
        bytes calldata sig
    ) external payable nonReentrant {
        if (permissions.length == 0) return;
        _requireRegistered(account);
        if (block.timestamp > deadline) revert DeadlineExpired(deadline, block.timestamp);

        // Enforce the cap before consuming the nonce to avoid nonce burns on revert.
        uint256 limit = governance.maxPermissionsPerAccount();
        if (_permissions[account].length + permissions.length > limit)
            revert TooManyPermissions(account, limit);

        uint256 nonce = signerNonces[account]++;
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

        // Compute total fee before any state changes
        uint256 totalFee;
        for (uint256 i; i < permissions.length; i++) {
            totalFee += _calcPermissionFee(permissions[i]);
        }
        if (msg.value < totalFee) revert InsufficientFee(totalFee, msg.value);

        // Add all permissions atomically — reverts if any duplicate found
        for (uint256 i; i < permissions.length; i++) {
            address perm = permissions[i];
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

        uint256 nonce = signerNonces[account]++;
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

        for (uint256 i; i < permissions.length; i++) {
            _removePermission(account, permissions[i]);
            emit PermissionRevoked(account, permissions[i]);
        }
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

    /// @notice Verify a manager signature, evaluate all registered permissions, and
    ///         execute the transaction via the Safe module interface.
    /// @dev    The manager nonce is consumed before any external interaction to prevent
    ///         replay even if the Safe call reverts. Permissions are evaluated via staticcall
    ///         with PERMISSION_GAS_CAP gas; a revert or gas exhaustion inside a permission
    ///         is treated as denial. Zero registered permissions → deny (allowlist semantics).
    /// @param  account     The registered Safe account to execute through.
    /// @param  target      Call target address.
    /// @param  value       Native ETH to forward with the call (wei).
    /// @param  data        Calldata for the target call.
    /// @param  managerSig  EIP-712 signature over Dispatch struct by the account's manager.
    /// @param  deadline    Unix timestamp after which the signature is invalid.
    function dispatch(
        address account,
        address target,
        uint256 value,
        bytes calldata data,
        bytes calldata managerSig,
        uint256 deadline
    ) external nonReentrant whenNotPaused {
        _requireRegistered(account);

        AccountConfig storage cfg = configs[account];
        if (!cfg.sessionActive) revert SessionInactive(account);
        if (block.timestamp > deadline) revert DeadlineExpired(deadline, block.timestamp);

        uint256 nonce = managerNonces[account]++;
        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
            DISPATCH_TYPEHASH,
            account,
            target,
            value,
            keccak256(data),
            nonce,
            deadline
        )));
        if (!_recoverOrERC1271(cfg.manager, digest, managerSig)) revert InvalidManagerSignature();

        // Walk permissions — each evaluated via staticcall with gas cap.
        // Zero registered permissions means deny by default (allowlist semantics).
        address[] storage perms = _permissions[account];
        uint256 len = perms.length;
        if (len == 0) revert NoPermissionsRegistered(account);
        Context memory ctx = Context({
            account:        account,
            manager:        cfg.manager,
            submitter:      msg.sender,
            target:         target,
            selector:       data.length >= 4 ? bytes4(data[:4]) : bytes4(0),
            value:          value,
            blockTimestamp: block.timestamp,
            blockNumber:    block.number
        });
        for (uint256 i = 0; i < len; i++) {
            if (!_evaluatePermission(perms[i], data, ctx)) revert PermissionDenied(perms[i]);
        }

        if (!ISafe(account).execTransactionFromModule(target, value, data, 0)) revert SafeExecutionFailed();

        emit Dispatched(account, target, value, keccak256(data));
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
        return abi.decode(ret, (bool));
    }

    // -------------------------------------------------------------------------
    // 4. Fee accounting
    // -------------------------------------------------------------------------

    /// @notice Collect fees earned by the manager. The kernel validates the requested amount
    ///         against the registered fee policy and enforces the protocol/distributor split.
    /// @dev    TRUST ASSUMPTION: `currentNav` is provided by the manager and is not verified
    ///         on-chain. The fee policy is the sole guard against inflated NAV inputs.
    ///         The actual tokens transferred equal `grossFee` — not a function of `currentNav` —
    ///         but a dishonest manager could inflate `currentNav` to unlock a larger `maxFee`
    ///         ceiling and then pass a correspondingly large `grossFee`. Deployers must use a
    ///         fee policy that validates NAV independently if the manager is not trusted.
    /// @param  account    The registered Safe account from which fees are collected.
    /// @param  grossFee   Requested fee amount. Must not exceed the policy's computed maximum.
    /// @param  currentNav Current net asset value reported by the manager.
    /// @param  feeToken   ERC-20 token for fee payment; address(0) = native ETH.
    /// @param  recipient  Address that receives the manager's net share after splits.
    ///                    Must not be the zero address.
    function collectFees(
        address account,
        uint256 grossFee,
        uint256 currentNav,
        address feeToken,
        address recipient
    ) external nonReentrant whenNotPaused {
        _requireRegistered(account);
        if (recipient == address(0)) revert ZeroAddress();
        AccountConfig storage cfg = configs[account];
        if (msg.sender != cfg.manager) revert NotManager(msg.sender, cfg.manager);
        if (cfg.feePolicy == address(0)) revert FeePolicyNotSet();

        (uint256 maxFee, address distributor, uint256 distributorBps) =
            IFeePolicy(cfg.feePolicy).computeFee(account, currentNav);
        if (grossFee > maxFee) revert FeeTooLarge(grossFee, maxFee);
        if (distributorBps > 10_000) revert DistributorBpsTooLarge(distributorBps);

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
        IFeePolicy(cfg.feePolicy).recordCollection(account, grossFee, currentNav);

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
    function _safeTransferETH(address account, address to, uint256 value) internal {
        if (!ISafe(account).execTransactionFromModule(to, value, "", 0)) revert FeeTransferFailed();
    }

    /// @dev Execute an ERC-20 transfer out of the Safe via module call.
    function _safeTransferERC20(address account, address token, address to, uint256 amount) internal {
        bytes memory data = abi.encodeCall(IERC20.transfer, (to, amount));
        if (!ISafe(account).execTransactionFromModule(token, 0, data, 0)) revert FeeTransferFailed();
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
    function recordDeposit(address account, uint256 amount) external {
        _requireRegistered(account);
        if (msg.sender != configs[account].permissionSigner) revert NotPermissionSigner();
        cumulativeDeposits[account] += amount;
        emit DepositRecorded(account, amount, cumulativeDeposits[account]);
    }

    /// @notice Record a withdrawal from the account. Only the permissionSigner may call.
    /// @param  account The registered Safe account.
    /// @param  amount  Withdrawal amount to record (in the account's base currency units).
    function recordWithdrawal(address account, uint256 amount) external {
        _requireRegistered(account);
        if (msg.sender != configs[account].permissionSigner) revert NotPermissionSigner();
        cumulativeWithdrawals[account] += amount;
        emit WithdrawalRecorded(account, amount, cumulativeWithdrawals[account]);
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

    /// @dev Compute the registration fee for a permission based on its bytecode size.
    ///      Each component is individually capped at MAX_PERMISSION_FEE_WEI before summing
    ///      to prevent overflow when both components are near the cap.
    function _calcPermissionFee(address permission) internal view returns (uint256) {
        uint256 cap  = governance.MAX_PERMISSION_FEE_WEI();
        uint256 base        = Math.min(governance.baseFee(), cap);
        uint256 sizeContrib = Math.min(Math.mulDiv(permission.code.length, governance.complexityRate(), 1), cap);
        return Math.min(base + sizeContrib, cap);
    }

    /// @dev Forward `fee` to the treasury and refund any ETH overpayment to msg.sender.
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
    ///      For EOAs: recovers the signer via `ECDSA.tryRecover`.
    ///      For contracts: calls `isValidSignature` and checks for the ERC-1271 magic value.
    /// @param  expected Address expected to have produced the signature.
    /// @param  digest   EIP-712 digest to verify against.
    /// @param  sig      Signature bytes (65 bytes for ECDSA; arbitrary for ERC-1271).
    /// @return          True if the signature is valid for `expected`.
    function _recoverOrERC1271(address expected, bytes32 digest, bytes memory sig) internal view returns (bool) {
        if (expected.code.length == 0) {
            (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, sig);
            return err == ECDSA.RecoverError.NoError && recovered == expected;
        }
        try IERC1271(expected).isValidSignature(digest, sig) returns (bytes4 magic) {
            return magic == ERC1271_MAGIC;
        } catch {
            return false;
        }
    }
}
