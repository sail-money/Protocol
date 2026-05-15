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

interface ISafeFactory {
    function createProxyWithNonce(address singleton, bytes calldata initializer, uint256 saltNonce)
        external
        returns (address proxy);
}

interface ISafe {
    function execTransactionFromModule(address to, uint256 value, bytes calldata data, uint8 operation)
        external
        returns (bool success);
}

contract SailKernel is EIP712, ReentrancyGuard {
    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------
    uint256 public constant PERMISSION_GAS_CAP        = 100_000;
    uint256 public constant MAX_PERMISSIONS_PER_ACCOUNT = 20;
    bytes4  private constant ERC1271_MAGIC            = 0x1626ba7e;

    // -------------------------------------------------------------------------
    // EIP-712 type hashes
    // -------------------------------------------------------------------------
    bytes32 public constant DISPATCH_TYPEHASH = keccak256(
        "Dispatch(address account,address target,uint256 value,bytes32 dataHash,uint256 nonce,uint256 deadline)"
    );
    bytes32 public constant REGISTER_PERMISSION_TYPEHASH = keccak256(
        "RegisterPermission(address account,address permission,uint256 nonce)"
    );
    bytes32 public constant REVOKE_PERMISSION_TYPEHASH = keccak256(
        "RevokePermission(address account,address permission,uint256 nonce)"
    );
    bytes32 public constant REPLACE_PERMISSION_TYPEHASH = keccak256(
        "ReplacePermission(address account,address oldPermission,address newPermission,uint256 nonce)"
    );
    bytes32 public constant REVOKE_SESSION_TYPEHASH = keccak256(
        "RevokeSession(address account,uint256 nonce)"
    );
    bytes32 public constant ACTIVATE_SESSION_TYPEHASH = keccak256(
        "ActivateSession(address account,uint256 nonce)"
    );
    bytes32 public constant SET_FEE_POLICY_TYPEHASH = keccak256(
        "SetFeePolicy(address account,address newFeePolicy,uint256 nonce)"
    );

    // -------------------------------------------------------------------------
    // Account state
    // -------------------------------------------------------------------------
    struct AccountConfig {
        address permissionSigner;
        address manager;
        address feePolicy;
        bool    sessionActive;
    }

    mapping(address account => AccountConfig)                          public  configs;
    mapping(address account => bool)                                   public  registered;
    mapping(address account => address[])                              private _permissions;
    mapping(address account => mapping(address permission => uint256)) private _permissionIndex;

    // Separate nonces: manager nonces for dispatch, signer nonces for registry ops.
    mapping(address account => uint256) public managerNonces;
    mapping(address account => uint256) public signerNonces;

    // -------------------------------------------------------------------------
    // Principal tracking
    // -------------------------------------------------------------------------
    mapping(address account => uint256) public cumulativeDeposits;
    mapping(address account => uint256) public cumulativeWithdrawals;

    // -------------------------------------------------------------------------
    // Protocol references
    // -------------------------------------------------------------------------
    SailGovernance public immutable governance;
    address        public treasury;

    // -------------------------------------------------------------------------
    // Emergency pause
    // -------------------------------------------------------------------------
    bool public paused;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------
    event AccountRegistered(address indexed account, address indexed permissionSigner, address indexed manager);
    event PermissionRegistered(address indexed account, address indexed permission);
    event PermissionRevoked(address indexed account, address indexed permission);
    event PermissionReplaced(address indexed account, address indexed oldPermission, address indexed newPermission);
    event SessionRevoked(address indexed account);
    event SessionActivated(address indexed account);
    event FeePolicyUpdated(address indexed account, address indexed newFeePolicy);
    /// @dev `dataHash` is keccak256(calldata) — the raw bytes are recoverable from the tx itself.
    event Dispatched(address indexed account, address indexed target, uint256 value, bytes32 dataHash);
    event FeesCollected(
        address indexed account,
        address indexed feeToken,
        uint256 grossFee,
        uint256 protocolCut,
        uint256 distributorCut,
        uint256 managerTake
    );
    event DepositRecorded(address indexed account, uint256 amount, uint256 cumulative);
    event WithdrawalRecorded(address indexed account, uint256 amount, uint256 cumulative);
    event TreasuryUpdated(address indexed oldTreasury, address indexed newTreasury);
    event Paused(address indexed by);
    event Unpaused(address indexed by);

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------
    error AccountAlreadyRegistered(address account);
    error AccountNotRegistered(address account);
    error SessionInactive(address account);
    error DeadlineExpired(uint256 deadline, uint256 current);
    error InvalidManagerSignature();
    error InvalidSignerSignature();
    error PermissionDenied(address permission);
    error SafeExecutionFailed();
    error PermissionAlreadyRegistered(address permission);
    error PermissionNotRegistered(address permission);
    error TooManyPermissions(address account, uint256 limit);
    error InsufficientFee(uint256 required, uint256 provided);
    error FeePolicyNotSet();
    error FeeTooLarge(uint256 requested, uint256 maxAllowed);
    error FeeTransferFailed();
    error NotManager(address caller, address expected);
    error NotGovernance();
    error NotPermissionSigner();
    error ZeroAddress();
    error DistributorBpsTooLarge(uint256 bps);
    error NoPermissionsRegistered(address account);
    error ProtocolPaused();

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------
    constructor(address _governance, address _treasury) EIP712("SailKernel", "1") {
        if (_governance == address(0) || _treasury == address(0)) revert ZeroAddress();
        governance = SailGovernance(_governance);
        treasury   = _treasury;
    }

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------
    modifier onlyGovernance() {
        if (msg.sender != governance.governance()) revert NotGovernance();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert ProtocolPaused();
        _;
    }

    // -------------------------------------------------------------------------
    // Governance
    // -------------------------------------------------------------------------
    function setTreasury(address newTreasury) external onlyGovernance {
        if (newTreasury == address(0)) revert ZeroAddress();
        address old = treasury;
        treasury = newTreasury;
        emit TreasuryUpdated(old, newTreasury);
    }

    /// @notice Halt all dispatches and fee collections.
    function pause() external onlyGovernance {
        paused = true;
        emit Paused(msg.sender);
    }

    /// @notice Resume normal protocol operation.
    function unpause() external onlyGovernance {
        paused = false;
        emit Unpaused(msg.sender);
    }

    // -------------------------------------------------------------------------
    // 1. Account instantiation
    // -------------------------------------------------------------------------

    /// @notice Deploy a new Safe via factory and register it with the kernel in one transaction.
    /// @dev    The salt passed to the factory is derived from `keccak256(saltNonce, msg.sender)`
    ///         to bind the CREATE2 address to the caller and prevent front-running attacks where
    ///         an observer could claim registration of a Safe they did not deploy.
    ///         Callers wishing to pre-compute the Safe address must use the same binding:
    ///         `boundSalt = uint256(keccak256(abi.encode(saltNonce, msg.sender)))`.
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
    ///         This prevents front-running: only the Safe's own signers can authorise registration
    ///         by executing a transaction through the Safe's own threshold mechanism.
    function registerAccount(address permissionSigner, address manager, address feePolicy) external {
        _registerAccount(msg.sender, permissionSigner, manager, feePolicy);
    }

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

    /// @notice Register a permission for an account. Requires a permission-signer signature and ETH fee.
    function registerPermission(address account, address permission, bytes calldata sig)
        external
        payable
        nonReentrant
    {
        _requireRegistered(account);
        if (_permissionIndex[account][permission] != 0) revert PermissionAlreadyRegistered(permission);
        if (_permissions[account].length >= MAX_PERMISSIONS_PER_ACCOUNT)
            revert TooManyPermissions(account, MAX_PERMISSIONS_PER_ACCOUNT);

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

    /// @notice Revoke a single permission. Requires a permission-signer signature.
    function revokePermission(address account, address permission, bytes calldata sig) external {
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

    /// @notice Atomically replace one permission with another. Requires a permission-signer signature and ETH fee.
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

    /// @notice Revoke the entire manager session. Dispatch is blocked until activateSession is called.
    function revokeSession(address account, bytes calldata sig) external {
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

    /// @notice Re-activate a previously revoked session. Requires a fresh permissionSigner signature.
    function activateSession(address account, bytes calldata sig) external {
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
    function setFeePolicy(address account, address newFeePolicy, bytes calldata sig) external {
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

    function getPermissions(address account) external view returns (address[] memory) {
        return _permissions[account];
    }

    function isPermissionRegistered(address account, address permission) external view returns (bool) {
        return _permissionIndex[account][permission] != 0;
    }

    // -------------------------------------------------------------------------
    // 3. Manager dispatch
    // -------------------------------------------------------------------------

    /// @notice Verify manager signature, evaluate all permissions, execute via Safe.
    /// @dev    Nonce is consumed before any external interaction to prevent replay even if the
    ///         Safe call reverts. Permissions are evaluated via staticcall with a per-permission
    ///         gas cap; a revert or gas exhaustion inside a permission is treated as denial.
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

    /// @notice Manager calls this to collect earned fees. The kernel validates the amount
    ///         against the registered fee policy and enforces the protocol/distributor split.
    /// @dev    TRUST ASSUMPTION: `currentNav` is provided by the manager. The fee policy is
    ///         the sole on-chain guard against inflated NAV inputs. Deployers must use a fee
    ///         policy that validates NAV independently (e.g., via an oracle) if the manager
    ///         is not trusted to report NAV accurately.
    /// @param feeToken  ERC-20 token address, or address(0) for native ETH.
    /// @param recipient Address that receives the manager's net share.
    function collectFees(
        address account,
        uint256 grossFee,
        uint256 currentNav,
        address feeToken,
        address recipient
    ) external nonReentrant whenNotPaused {
        _requireRegistered(account);
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
        uint256 managerTake    = remainder - distributorCut;

        if (feeToken == address(0)) {
            if (protocolCut    > 0)                              _safeTransferETH(account, treasury,    protocolCut);
            if (distributorCut > 0 && distributor != address(0)) _safeTransferETH(account, distributor, distributorCut);
            if (managerTake    > 0)                              _safeTransferETH(account, recipient,   managerTake);
        } else {
            if (protocolCut    > 0)                              _safeTransferERC20(account, feeToken, treasury,    protocolCut);
            if (distributorCut > 0 && distributor != address(0)) _safeTransferERC20(account, feeToken, distributor, distributorCut);
            if (managerTake    > 0)                              _safeTransferERC20(account, feeToken, recipient,   managerTake);
        }

        IFeePolicy(cfg.feePolicy).recordCollection(account, grossFee, currentNav);
        emit FeesCollected(account, feeToken, grossFee, protocolCut, distributorCut, managerTake);
    }

    function _safeTransferETH(address account, address to, uint256 value) internal {
        if (!ISafe(account).execTransactionFromModule(to, value, "", 0)) revert FeeTransferFailed();
    }

    function _safeTransferERC20(address account, address token, address to, uint256 amount) internal {
        bytes memory data = abi.encodeCall(IERC20.transfer, (to, amount));
        if (!ISafe(account).execTransactionFromModule(token, 0, data, 0)) revert FeeTransferFailed();
    }

    // -------------------------------------------------------------------------
    // 5. Principal tracking
    // -------------------------------------------------------------------------

    /// @notice Record a deposit into the account. Only the permission signer may call.
    function recordDeposit(address account, uint256 amount) external {
        _requireRegistered(account);
        if (msg.sender != configs[account].permissionSigner) revert NotPermissionSigner();
        cumulativeDeposits[account] += amount;
        emit DepositRecorded(account, amount, cumulativeDeposits[account]);
    }

    /// @notice Record a withdrawal from the account. Only the permission signer may call.
    function recordWithdrawal(address account, uint256 amount) external {
        _requireRegistered(account);
        if (msg.sender != configs[account].permissionSigner) revert NotPermissionSigner();
        cumulativeWithdrawals[account] += amount;
        emit WithdrawalRecorded(account, amount, cumulativeWithdrawals[account]);
    }

    // -------------------------------------------------------------------------
    // Public helpers
    // -------------------------------------------------------------------------

    /// @notice Exposed for frontend and test use — computes the EIP-712 digest for a struct hash.
    function hashTypedDataV4(bytes32 structHash) external view returns (bytes32) {
        return _hashTypedDataV4(structHash);
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    function _requireRegistered(address account) internal view {
        if (!registered[account]) revert AccountNotRegistered(account);
    }

    function _calcPermissionFee(address permission) internal view returns (uint256) {
        uint256 cap  = governance.MAX_PERMISSION_FEE_WEI();
        // Cap each component before summing to prevent overflow when both are near cap.
        uint256 base        = Math.min(governance.baseFee(), cap);
        uint256 sizeContrib = Math.min(Math.mulDiv(permission.code.length, governance.complexityRate(), 1), cap);
        return Math.min(base + sizeContrib, cap);
    }

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

    function _verifySignerSig(address account, bytes32 structHash, bytes memory sig) internal view {
        bytes32 digest = _hashTypedDataV4(structHash);
        if (!_recoverOrERC1271(configs[account].permissionSigner, digest, sig)) revert InvalidSignerSignature();
    }

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
