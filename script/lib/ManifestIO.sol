// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Vm} from "forge-std/Vm.sol";

/// @notice Shared helpers for reading and writing per-chain deployment manifests.
///
///         Manifests live at `deployments/<chainId>/<target>.json`. Each deploy
///         script owns one target file. Sibling scripts can read addresses from
///         peer manifests so post-core targets stay independently runnable.
library ManifestIO {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    error ManifestExists(string path);
    error ManifestMissing(string path);

    /// @return dir Absolute-relative path to `deployments/<chainId>`.
    function chainDir(uint256 chainId) internal pure returns (string memory dir) {
        return string.concat("deployments/", vm.toString(chainId));
    }

    /// @return path Full path for a target manifest.
    function manifestPath(uint256 chainId, string memory target)
        internal
        pure
        returns (string memory path)
    {
        return string.concat(chainDir(chainId), "/", target, ".json");
    }

    /// @notice Ensure the chain directory exists.
    function ensureChainDir(uint256 chainId) internal {
        vm.createDir(chainDir(chainId), true);
    }

    /// @notice Refuse to overwrite an existing manifest unless `fresh` is true.
    ///         Callers should snapshot existing manifests under
    ///         `deployments/<chainId>/_archive/<date>/` (handled by deploy.sh).
    function guardOverwrite(uint256 chainId, string memory target, bool fresh) internal view {
        string memory path = manifestPath(chainId, target);
        if (!fresh && vm.exists(path)) revert ManifestExists(path);
    }

    /// @notice Persist a built JSON blob to the target path.
    function write(uint256 chainId, string memory target, string memory json) internal {
        ensureChainDir(chainId);
        string memory path = manifestPath(chainId, target);
        vm.writeFile(path, json);
    }

    /// @notice Read an address field from a peer manifest on the same chain.
    function readAddress(uint256 chainId, string memory target, string memory jsonPath)
        internal
        view
        returns (address)
    {
        string memory path = manifestPath(chainId, target);
        if (!vm.exists(path)) revert ManifestMissing(path);
        string memory json = vm.readFile(path);
        return vm.parseJsonAddress(json, jsonPath);
    }

    /// @notice Serialise the common header fields into the JSON object identified by `k`.
    ///         Every manifest starts with the same provenance block so audits can pin
    ///         a deploy to a commit + chain + deployer without grepping scripts.
    function serializeHeader(string memory k, string memory schema, address deployer)
        internal
    {
        vm.serializeString(k, "schema", schema);
        vm.serializeUint(k, "chainId", block.chainid);
        vm.serializeUint(k, "blockNumber", block.number);
        vm.serializeUint(k, "timestamp", block.timestamp);
        vm.serializeAddress(k, "deployer", deployer);
        vm.serializeString(k, "gitCommit", _envOrEmpty("GIT_COMMIT"));
        vm.serializeString(k, "solcVersion", "0.8.26");
    }

    function _envOrEmpty(string memory key) private view returns (string memory) {
        try vm.envString(key) returns (string memory v) { return v; }
        catch { return ""; }
    }
}
