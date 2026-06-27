// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {Clones}                  from "@openzeppelin/contracts/proxy/Clones.sol";
import {ReentrancyGuard}         from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IConfigurablePermission} from "../interfaces/IConfigurablePermission.sol";
import {CloneInitializable}      from "../utils/CloneInitializable.sol";

interface ISailKernelFactory {
    function registerPermission(address account, address permission, uint256 deadline, bytes calldata sig)
        external
        payable;
    function registerPermissions(
        address account,
        address[] calldata permissions,
        uint256 deadline,
        bytes calldata sig
    ) external payable;
    function replacePermission(
        address account,
        address oldPermission,
        address newPermission,
        uint256 deadline,
        bytes calldata sig
    ) external payable;
    function revokePermission(address account, address permission, uint256 deadline, bytes calldata sig) external;
    function revokePermissions(
        address account,
        address[] calldata permissions,
        uint256 deadline,
        bytes calldata sig
    ) external;
}

/// @notice Orchestrator that bundles (configure → register) into a single transaction.
///
///         The factory holds no trust: each inner call (template.configure and
///         kernel.registerPermission) is independently signature-authenticated. The
///         factory's value is UX bundling, fee forwarding with excess refund, and a
///         canonical entry point for off-chain tooling.
///
///         Anyone can deploy a template that implements IConfigurablePermission and have
///         it work with this factory immediately — no allowlist, no registry. Reputation
///         is an off-chain concern.
///
/// @dev    Force-sent ETH (via selfdestruct or coinbase) accrues to `address(this).balance`
///         and is unrecoverable — no sweep function exists. This is an accepted residual
///         given that `receive()` already blocks direct ETH deposits.
contract MandateFactory is ReentrancyGuard {
    ISailKernelFactory public immutable kernel;

    event Attached(address indexed account, address indexed permission, bytes32 paramsHash);
    event Reconfigured(address indexed account, address indexed permission, bytes32 paramsHash);
    event BatchAttached(address indexed account, address[] permissions);
    event Replaced(address indexed account, address indexed oldPermission, address indexed newPermission);
    event Detached(address indexed account, address indexed permission);
    event BatchDetached(address indexed account, address[] permissions);
    /// @notice Emitted when a clone template is deployed and registered in a single transaction.
    /// @param account    The Safe account the clone is registered for.
    /// @param impl       The logic contract that was cloned.
    /// @param clone      The freshly deployed EIP-1167 proxy instance.
    /// @param salt       The salt used for deterministic cloning.
    event CloneDeployedAndAttached(
        address indexed account,
        address indexed impl,
        address indexed clone,
        bytes32 salt
    );

    error LengthMismatch();
    error RefundFailed();
    error ZeroAddress();
    error InitDataTooShort();
    error CloneInitFailed();

    constructor(address _kernel) {
        if (_kernel == address(0)) revert ZeroAddress();
        kernel = ISailKernelFactory(_kernel);
    }

    /// @dev Accept ETH only from the kernel (excess refund from registration fee).
    ///      Rejecting ETH from arbitrary senders prevents balance inflation attacks
    ///      that could manipulate the `_refundExcess` accounting.
    receive() external payable {
        if (msg.sender != address(kernel)) revert RefundFailed();
    }

    // -------------------------------------------------------------------------
    // attach: configure template + register with kernel, one tx
    // -------------------------------------------------------------------------

    function attach(
        address account,
        address template,
        bytes calldata params,
        uint256 configureDeadline,
        bytes calldata configureSig,
        uint256 kernelDeadline,
        bytes calldata kernelSig
    ) external payable nonReentrant {
        uint256 preBalance = address(this).balance - msg.value;
        IConfigurablePermission(template).configure(account, params, configureDeadline, configureSig);
        kernel.registerPermission{value: msg.value}(account, template, kernelDeadline, kernelSig);
        _refundExcess(preBalance);
        emit Attached(account, template, keccak256(params));
    }

    // -------------------------------------------------------------------------
    // attachBatch: configure N templates + register all atomically with kernel
    // -------------------------------------------------------------------------

    function attachBatch(
        address account,
        address[] calldata templates,
        bytes[] calldata params,
        uint256[] calldata configureDeadlines,
        bytes[] calldata configureSigs,
        uint256 kernelDeadline,
        bytes calldata kernelBatchSig
    ) external payable nonReentrant {
        uint256 n = templates.length;
        if (n != params.length)             revert LengthMismatch();
        if (n != configureDeadlines.length) revert LengthMismatch();
        if (n != configureSigs.length)      revert LengthMismatch();

        uint256 preBalance = address(this).balance - msg.value;

        _batchConfigure(account, templates, params, configureDeadlines, configureSigs);
        kernel.registerPermissions{value: msg.value}(account, templates, kernelDeadline, kernelBatchSig);
        _refundExcess(preBalance);
        emit BatchAttached(account, templates);
    }

    function _batchConfigure(
        address account,
        address[] calldata templates,
        bytes[] calldata params,
        uint256[] memory configureDeadlines,
        bytes[] calldata configureSigs
    ) private {
        for (uint256 i; i < templates.length; i++) {
            IConfigurablePermission(templates[i]).configure(
                account, params[i], configureDeadlines[i], configureSigs[i]
            );
        }
    }

    // -------------------------------------------------------------------------
    // reconfigure: update a template's params for an account (no kernel touch)
    // -------------------------------------------------------------------------

    function reconfigure(
        address account,
        address template,
        bytes calldata params,
        uint256 deadline,
        bytes calldata configureSig
    ) external {
        IConfigurablePermission(template).configure(account, params, deadline, configureSig);
        emit Reconfigured(account, template, keccak256(params));
    }

    // -------------------------------------------------------------------------
    // replace: atomic kernel swap of one template for another, with config
    // -------------------------------------------------------------------------

    function replace(
        address account,
        address oldTemplate,
        address newTemplate,
        bytes calldata newParams,
        uint256 configureDeadline,
        bytes calldata configureSig,
        uint256 kernelReplaceDeadline,
        bytes calldata kernelReplaceSig
    ) external payable nonReentrant {
        uint256 preBalance = address(this).balance - msg.value;
        IConfigurablePermission(newTemplate).configure(
            account, newParams, configureDeadline, configureSig
        );
        kernel.replacePermission{value: msg.value}(account, oldTemplate, newTemplate, kernelReplaceDeadline, kernelReplaceSig);
        _refundExcess(preBalance);
        emit Replaced(account, oldTemplate, newTemplate);
    }

    // -------------------------------------------------------------------------
    // deployAndAttach: clone a standalone template, initialize, register — one tx
    //
    // For standalone (single-account) templates that use initialize() instead of
    // configure(). The caller supplies:
    //   - impl:      the logic contract address of the standalone template to clone
    //   - salt:      caller-chosen entropy; the factory namespaces it internally as
    //                keccak256(abi.encode(msg.sender, account, salt, keccak256(initData))).
    //                Binding the caller and the target account mirrors the kernel's bound-salt
    //                doctrine (SailKernel.createAccount folds msg.sender + principals into the
    //                CREATE2 salt) so each (caller, account) pair owns its own clone address
    //                space and no counterfactual address can be squatted across callers or
    //                accounts — including a shared relayer caller serving many accounts.
    //                Binding keccak256(initData) additionally ties the predicted clone address
    //                to the exact initialization payload: a registration signature authorizes
    //                one specific address, and substituting different initData resolves to a
    //                different address that the signature does not cover.
    //   - initData:  ABI-encoded initialize(...) call (selector + args)
    //   - kernelSig: permission-signer signature for kernel.registerPermission
    //
    // The clone address is deterministic and can be predicted off-chain via
    // predictCloneAddress(impl, account, salt, initData) — call it from the same EOA that will
    // send deployAndAttach, with the same account and the same initData, because the factory
    // namespaces by msg.sender, account, and the init-data hash.
    // -------------------------------------------------------------------------

    /// @notice Deploy an EIP-1167 clone of `impl`, call `initData` on it, then
    ///         register it with the kernel for `account` — all in one transaction.
    /// @dev    Salt is namespaced by (msg.sender, account, keccak256(initData)) to prevent
    ///         cross-caller and cross-account squatting of the predicted address and to bind
    ///         the address to the exact initialization payload. Because the address commits to
    ///         keccak256(initData), a registration signature cannot be reused with substituted
    ///         initData — different init bytes resolve to a different address the signature does
    ///         not authorize. Call `predictCloneAddress` with the same EOA, account, and
    ///         initData before signing `kernelSig`.
    ///         `initialized()` is a liveness guard only — third-party `impl` contracts
    ///         that implement `initialized()` incorrectly can still pass this check
    ///         while remaining misconfigured. Verify `initData` correctness off-chain.
    function deployAndAttach(
        address account,
        address impl,
        bytes32 salt,
        bytes calldata initData,
        uint256 kernelDeadline,
        bytes calldata kernelSig
    ) external payable nonReentrant returns (address clone) {
        if (impl == address(0)) revert ZeroAddress();
        if (initData.length < 4) revert InitDataTooShort();

        uint256 preBalance = address(this).balance - msg.value;

        bytes32 namespacedSalt = keccak256(abi.encode(msg.sender, account, salt, keccak256(initData)));
        clone = Clones.cloneDeterministic(impl, namespacedSalt);

        (bool ok, bytes memory retdata) = clone.call(initData);
        if (!ok) _bubbleCloneInitRevert(retdata);

        try CloneInitializable(clone).initialized() returns (bool isInitialized) {
            if (!isInitialized) revert CloneInitFailed();
        } catch {
            revert CloneInitFailed();
        }

        kernel.registerPermission{value: msg.value}(account, clone, kernelDeadline, kernelSig);
        _refundExcess(preBalance);

        emit CloneDeployedAndAttached(account, impl, clone, namespacedSalt);
    }

    /// @notice Predict the address of a clone before it is deployed.
    ///         Must be called from the same EOA that will call `deployAndAttach`,
    ///         with the same `account` and the same `initData`, because the factory
    ///         namespaces the salt by msg.sender, account, and keccak256(initData).
    ///         Passing different `initData` here yields a different address — prediction
    ///         and deployment match only when the init payload is identical.
    function predictCloneAddress(address impl, address account, bytes32 salt, bytes calldata initData)
        external
        view
        returns (address)
    {
        bytes32 namespacedSalt = keccak256(abi.encode(msg.sender, account, salt, keccak256(initData)));
        return Clones.predictDeterministicAddress(impl, namespacedSalt, address(this));
    }

    // -------------------------------------------------------------------------
    // detach: revoke from kernel (config remains in template; can be re-attached)
    // -------------------------------------------------------------------------

    function detach(address account, address template, uint256 kernelDeadline, bytes calldata kernelSig) external {
        kernel.revokePermission(account, template, kernelDeadline, kernelSig);
        emit Detached(account, template);
    }

    function detachBatch(
        address account,
        address[] calldata templates,
        uint256 kernelDeadline,
        bytes calldata kernelBatchSig
    ) external {
        kernel.revokePermissions(account, templates, kernelDeadline, kernelBatchSig);
        emit BatchDetached(account, templates);
    }

    // -------------------------------------------------------------------------
    // internal
    // -------------------------------------------------------------------------

    function _refundExcess(uint256 preBalance) internal {
        uint256 excess = address(this).balance - preBalance;
        if (excess == 0) return;
        (bool ok,) = msg.sender.call{value: excess}("");
        if (!ok) revert RefundFailed();
    }

    function _bubbleCloneInitRevert(bytes memory retdata) private pure {
        if (retdata.length == 0) revert CloneInitFailed();
        assembly {
            revert(add(retdata, 0x20), mload(retdata))
        }
    }
}
