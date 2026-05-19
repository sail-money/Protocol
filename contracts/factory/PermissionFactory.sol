// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {Clones}                  from "@openzeppelin/contracts/proxy/Clones.sol";
import {IConfigurablePermission} from "../interfaces/IConfigurablePermission.sol";
import {CloneInitializable}      from "../templates/base/CloneInitializable.sol";

interface ISailKernelFactory {
    function registerPermission(address account, address permission, bytes calldata sig)
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
        bytes calldata sig
    ) external payable;
    function revokePermission(address account, address permission, bytes calldata sig) external;
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
contract PermissionFactory {
    ISailKernelFactory public immutable kernel;

    event Attached(address indexed account, address indexed template, bytes32 paramsHash);
    event Reconfigured(address indexed account, address indexed template, bytes32 paramsHash);
    event BatchAttached(address indexed account, address[] templates);
    event Replaced(address indexed account, address indexed oldTemplate, address indexed newTemplate);
    event Detached(address indexed account, address indexed template);
    event BatchDetached(address indexed account, address[] templates);
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
        bytes calldata kernelSig
    ) external payable {
        uint256 preBalance = address(this).balance - msg.value;
        IConfigurablePermission(template).configure(account, params, configureDeadline, configureSig);
        kernel.registerPermission{value: msg.value}(account, template, kernelSig);
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
    ) external payable {
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
        bytes calldata kernelReplaceSig
    ) external payable {
        uint256 preBalance = address(this).balance - msg.value;
        IConfigurablePermission(newTemplate).configure(
            account, newParams, configureDeadline, configureSig
        );
        kernel.replacePermission{value: msg.value}(account, oldTemplate, newTemplate, kernelReplaceSig);
        _refundExcess(preBalance);
        emit Replaced(account, oldTemplate, newTemplate);
    }

    // -------------------------------------------------------------------------
    // deployAndAttach: clone a standalone template, initialize, register — one tx
    //
    // For standalone (single-account) templates that use initialize() instead of
    // configure(). The caller supplies:
    //   - impl:      the logic contract address (from deployments/<chainId>/templates.standalone.json)
    //   - salt:      deterministic salt; recommended:
    //                keccak256(abi.encode(account, impl, perAccountNonce))
    //                to give each account its own salt space and avoid collisions.
    //   - initData:  ABI-encoded initialize(...) call (selector + args)
    //   - kernelSig: permission-signer signature for kernel.registerPermission
    //
    // The clone address is deterministic and can be predicted off-chain via
    // predictCloneAddress(impl, salt) before the transaction is sent.
    // -------------------------------------------------------------------------

    /// @notice Deploy an EIP-1167 clone of `impl`, call `initData` on it, then
    ///         register it with the kernel for `account` — all in one transaction.
    function deployAndAttach(
        address account,
        address impl,
        bytes32 salt,
        bytes calldata initData,
        bytes calldata kernelSig
    ) external payable returns (address clone) {
        if (impl == address(0)) revert ZeroAddress();
        if (initData.length < 4) revert InitDataTooShort();

        uint256 preBalance = address(this).balance - msg.value;

        clone = Clones.cloneDeterministic(impl, salt);

        (bool ok, bytes memory retdata) = clone.call(initData);
        if (!ok) _bubbleCloneInitRevert(retdata);

        try CloneInitializable(clone).initialized() returns (bool isInitialized) {
            if (!isInitialized) revert CloneInitFailed();
        } catch {
            revert CloneInitFailed();
        }

        kernel.registerPermission{value: msg.value}(account, clone, kernelSig);
        _refundExcess(preBalance);

        emit CloneDeployedAndAttached(account, impl, clone, salt);
    }

    /// @notice Predict the address of a clone before it is deployed.
    ///         Use this off-chain to pre-compute the permission address for signing.
    function predictCloneAddress(address impl, bytes32 salt) external view returns (address) {
        return Clones.predictDeterministicAddress(impl, salt, address(this));
    }

    // -------------------------------------------------------------------------
    // detach: revoke from kernel (config remains in template; can be re-attached)
    // -------------------------------------------------------------------------

    function detach(address account, address template, bytes calldata kernelSig) external {
        kernel.revokePermission(account, template, kernelSig);
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
