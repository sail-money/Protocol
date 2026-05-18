// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {IPermission, Context}              from "../../contracts/interfaces/IPermission.sol";
import {IPermissionIntrospection}          from "../../contracts/interfaces/IPermissionIntrospection.sol";
import {IAgentIdentityResolver,
        IAccountAgentIdentityResolver,
        AgentIdentityRef}                  from "../../contracts/interfaces/IAgentIdentityResolver.sol";
import {SailCapabilities}                  from "../../contracts/interfaces/SailCapabilities.sol";

// ─────────────────────────────────────────────────────────────────────────────
// MockAgentIdentityPermission
// ─────────────────────────────────────────────────────────────────────────────

/// @notice Configurable mock implementing IPermission + IAgentIdentityResolver +
///         IPermissionIntrospection. Used in tests to verify that:
///           - agentIdentity() surfaces the expected identity without kernel involvement.
///           - evaluate() continues to work normally (returns shouldApprove).
///           - capabilityIds() declares AGENT_IDENTITY.
///
/// @dev    The kernel never calls agentIdentity() — this is purely for off-chain
///         consumers and for templates that read identity inside evaluate().
contract MockAgentIdentityPermission is IPermission, IAgentIdentityResolver, IPermissionIntrospection {
    AgentIdentityRef private _identity;
    bool             private _shouldApprove;

    constructor(AgentIdentityRef memory identity, bool shouldApprove) {
        _identity      = identity;
        _shouldApprove = shouldApprove;
    }

    // ── IPermission ───────────────────────────────────────────────────────────

    /// @notice Returns the configured approval result. Ignores txData and ctx.
    function evaluate(bytes calldata, Context calldata) external view override returns (bool) {
        return _shouldApprove;
    }

    function discriminator() external pure override returns (bytes32) {
        return keccak256("MockAgentIdentityPermission");
    }

    // ── IAgentIdentityResolver ────────────────────────────────────────────────

    /// @notice Returns the agent identity supplied at construction.
    function agentIdentity() external view override returns (AgentIdentityRef memory) {
        return _identity;
    }

    // ── IPermissionIntrospection ──────────────────────────────────────────────

    function permissionId() external pure override returns (bytes32) {
        return keccak256("sail.permission.MockAgentIdentityPermission.v1");
    }

    function permissionVersion() external pure override returns (bytes32) {
        return keccak256("v1");
    }

    function metadataURI() external pure override returns (string memory) {
        return "";
    }

    function capabilityIds() external pure override returns (bytes32[] memory ids) {
        ids = new bytes32[](1);
        ids[0] = SailCapabilities.AGENT_IDENTITY;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MockAccountAgentIdentityPermission
// ─────────────────────────────────────────────────────────────────────────────

/// @notice Configurable mock implementing IPermission + IAccountAgentIdentityResolver +
///         IPermissionIntrospection. Stores a per-account identity mapping supplied
///         at construction. Useful for testing shared-template patterns where different
///         Safe accounts may be managed by different agents.
///
/// @dev    agentIdentityFor(unknown) returns a zero-filled AgentIdentityRef and does
///         NOT revert, matching the interface contract.
contract MockAccountAgentIdentityPermission is IPermission, IAccountAgentIdentityResolver, IPermissionIntrospection {
    mapping(address account => AgentIdentityRef) private _identities;
    mapping(address account => bool)             private _hasIdentity;
    bool private _shouldApprove;

    /// @param accounts    Accounts to pre-configure.
    /// @param identities  Identities parallel to `accounts`.
    /// @param shouldApprove  evaluate() return value.
    constructor(
        address[] memory accounts,
        AgentIdentityRef[] memory identities,
        bool shouldApprove
    ) {
        require(accounts.length == identities.length, "length mismatch");
        for (uint256 i; i < accounts.length; i++) {
            _identities[accounts[i]] = identities[i];
            _hasIdentity[accounts[i]] = true;
        }
        _shouldApprove = shouldApprove;
    }

    // ── IPermission ───────────────────────────────────────────────────────────

    function evaluate(bytes calldata, Context calldata) external view override returns (bool) {
        return _shouldApprove;
    }

    function discriminator() external pure override returns (bytes32) {
        return keccak256("MockAccountAgentIdentityPermission");
    }

    // ── IAccountAgentIdentityResolver ─────────────────────────────────────────

    /// @notice Returns the configured identity for `account`, or a zero struct if absent.
    function agentIdentityFor(address account) external view override returns (AgentIdentityRef memory ref) {
        if (_hasIdentity[account]) {
            return _identities[account];
        }
        // Zero-filled struct for unknown accounts — must not revert.
        return ref;
    }

    // ── IPermissionIntrospection ──────────────────────────────────────────────

    function permissionId() external pure override returns (bytes32) {
        return keccak256("sail.permission.MockAccountAgentIdentityPermission.v1");
    }

    function permissionVersion() external pure override returns (bytes32) {
        return keccak256("v1");
    }

    function metadataURI() external pure override returns (string memory) {
        return "";
    }

    function capabilityIds() external pure override returns (bytes32[] memory ids) {
        ids = new bytes32[](1);
        ids[0] = SailCapabilities.AGENT_IDENTITY;
    }
}
