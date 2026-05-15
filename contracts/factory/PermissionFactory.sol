// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IConfigurablePermission} from "../interfaces/IConfigurablePermission.sol";

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

    error LengthMismatch();
    error RefundFailed();
    error ZeroAddress();

    constructor(address _kernel) {
        if (_kernel == address(0)) revert ZeroAddress();
        kernel = ISailKernelFactory(_kernel);
    }

    receive() external payable {}

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

        for (uint256 i; i < n; i++) {
            IConfigurablePermission(templates[i]).configure(
                account, params[i], configureDeadlines[i], configureSigs[i]
            );
        }
        kernel.registerPermissions{value: msg.value}(account, templates, kernelDeadline, kernelBatchSig);
        _refundExcess(preBalance);
        emit BatchAttached(account, templates);
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
    // detach: revoke from kernel (config remains in template; can be re-attached)
    // -------------------------------------------------------------------------

    function detach(address account, address template, bytes calldata kernelSig) external {
        kernel.revokePermission(account, template, kernelSig);
    }

    function detachBatch(
        address account,
        address[] calldata templates,
        uint256 kernelDeadline,
        bytes calldata kernelBatchSig
    ) external {
        kernel.revokePermissions(account, templates, kernelDeadline, kernelBatchSig);
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
}
