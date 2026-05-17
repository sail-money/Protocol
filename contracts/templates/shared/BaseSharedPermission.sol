// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {IPermission, Context} from "../../interfaces/IPermission.sol";
import {IConfigurablePermission} from "../../interfaces/IConfigurablePermission.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

/// @dev Subset of SailKernel that templates need to read.
interface ISailKernelView {
    function registered(address account) external view returns (bool);
    function configs(address account)
        external
        view
        returns (address permissionSigner, address manager, address feePolicy, bool sessionActive);
}

/// @notice Abstract base for shared, multi-account permission templates.
///         One deployed instance serves any number of accounts; per-account config
///         is stored under `mapping(address => ...)` in concrete subclasses.
///
///         Auth: configure() requires an EIP-712 sig from the account's permissionSigner
///         (read from the kernel). configureDirect() requires msg.sender to equal the
///         permissionSigner. Both support ECDSA and ERC-1271 signers.
abstract contract BaseSharedPermission is IConfigurablePermission, EIP712 {
    bytes4 private constant ERC1271_MAGIC = 0x1626ba7e;

    bytes32 public constant CONFIGURE_TYPEHASH =
        keccak256("Configure(address account,bytes32 paramsHash,uint256 nonce,uint256 deadline)");

    ISailKernelView public immutable kernel;

    mapping(address account => uint256) public configNonces;
    mapping(address account => bool)    public isConfigured;

    // ── events ────────────────────────────────────────────────────────────────
    event Configured(address indexed account, uint256 nonce, bytes32 paramsHash);

    // ── errors ────────────────────────────────────────────────────────────────
    error InvalidSignature();
    error DeadlineExpired(uint256 deadline, uint256 current);
    error AccountNotRegistered(address account);
    error NotPermissionSigner(address caller, address expected);
    error ZeroAddress();

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
    ) external {
        if (block.timestamp > deadline) revert DeadlineExpired(deadline, block.timestamp);
        if (!kernel.registered(account)) revert AccountNotRegistered(account);

        // Read nonce before incrementing — nonce is incremented AFTER signature verification
        // succeeds, preventing a failed verify from consuming the nonce.
        uint256 nonce = configNonces[account];
        bytes32 paramsHash = keccak256(params);
        bytes32 structHash = keccak256(abi.encode(
            CONFIGURE_TYPEHASH,
            account,
            paramsHash,
            nonce,
            deadline
        ));
        bytes32 digest = _hashTypedDataV4(structHash);

        (address permSigner,,,) = kernel.configs(account);
        if (!_verifySig(permSigner, digest, sig)) revert InvalidSignature();

        // Increment nonce only after successful verification
        configNonces[account] = nonce + 1;
        _applyConfig(account, params);
        isConfigured[account] = true;
        emit Configured(account, nonce, paramsHash);
    }

    /// @inheritdoc IConfigurablePermission
    function configureDirect(address account, bytes calldata params) external {
        if (!kernel.registered(account)) revert AccountNotRegistered(account);
        (address permSigner,,,) = kernel.configs(account);
        if (msg.sender != permSigner) revert NotPermissionSigner(msg.sender, permSigner);

        uint256 nonce = configNonces[account]++;
        _applyConfig(account, params);
        isConfigured[account] = true;
        emit Configured(account, nonce, keccak256(params));
    }

    /// @notice Exposed for off-chain sig construction.
    function hashTypedDataV4(bytes32 structHash) external view returns (bytes32) {
        return _hashTypedDataV4(structHash);
    }

    // ── hooks for subclasses ──────────────────────────────────────────────────

    /// @dev Subclasses decode `params` and write to their per-account storage.
    function _applyConfig(address account, bytes calldata params) internal virtual;

    // ── internal ──────────────────────────────────────────────────────────────

    function _verifySig(address expected, bytes32 digest, bytes calldata sig)
        internal
        view
        returns (bool)
    {
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
