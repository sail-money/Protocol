// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script, console2} from "forge-std/Script.sol";
import {ManifestIO}       from "../lib/ManifestIO.sol";

import {BoundedDepositPermission}        from "../../contracts/templates/BoundedDepositPermission.sol";
import {BoundedWithdrawPermission}       from "../../contracts/templates/BoundedWithdrawPermission.sol";

/// @notice Standalone (single-account clone) template logic deployment.
///
///         Each contract here is a logic / implementation contract for an EIP-1167
///         minimal proxy. The logic contracts themselves carry NO per-user state —
///         their constructors call `_disableInitializers()`, permanently locking them.
///         Per-account clones are created at runtime via `MandateFactory.deployAndAttach`.
///
///         Because there are no constructor arguments to record, verification is
///         trivial: no --constructor-args needed.
///
///         Writes `deployments/<chainId>/templates.standalone.json`.
contract DeployStandaloneTemplates is Script {
    string internal constant SCHEMA = "sail.deploy.templates.standalone";
    string internal constant TARGET = "templates.standalone";

    struct Deployment {
        BoundedDepositPermission        boundedDeposit;
        BoundedWithdrawPermission       boundedWithdraw;
    }

    function run() external returns (Deployment memory d) {
        address deployer = vm.envAddress("DEPLOYER_ADDRESS");
        bool fresh       = _boolEnv("SAIL_DEPLOY_FRESH");
        ManifestIO.guardOverwrite(block.chainid, TARGET, fresh);

        console2.log("=== Sail standalone-templates deploy ===");
        console2.log("deployer :", deployer);

        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(pk);

        d.boundedDeposit      = new BoundedDepositPermission();
        d.boundedWithdraw     = new BoundedWithdrawPermission();

        vm.stopBroadcast();

        console2.log("BoundedDepositPermission      :", address(d.boundedDeposit));
        console2.log("BoundedWithdrawPermission     :", address(d.boundedWithdraw));

        _writeManifest(deployer, d);
    }

    function _writeManifest(address deployer, Deployment memory d) internal {
        string memory k = "sail-standalone-templates";
        ManifestIO.serializeHeader(k, SCHEMA, deployer);
        vm.serializeAddress(k, "boundedDeposit",      address(d.boundedDeposit));
        string memory json =
            vm.serializeAddress(k, "boundedWithdraw",     address(d.boundedWithdraw));

        ManifestIO.write(block.chainid, TARGET, json);
        console2.log("wrote", ManifestIO.manifestPath(block.chainid, TARGET));
    }

    function _boolEnv(string memory key) internal view returns (bool) {
        try vm.envString(key) returns (string memory v) {
            return bytes(v).length > 0 && keccak256(bytes(v)) != keccak256(bytes("0"));
        } catch { return false; }
    }
}
