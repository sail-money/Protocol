// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script, console2} from "forge-std/Script.sol";
import {ManifestIO}       from "../lib/ManifestIO.sol";

import {SharedApproveAndCallBatchPermission}  from "../../contracts/templates/shared/SharedApproveAndCallBatchPermission.sol";
import {SharedBoundedBorrowPermission}        from "../../contracts/templates/shared/SharedBoundedBorrowPermission.sol";
import {SharedBoundedSwapPermission}          from "../../contracts/templates/shared/SharedBoundedSwapPermission.sol";
import {SharedTransferTargetPermission}       from "../../contracts/templates/shared/SharedTransferTargetPermission.sol";

/// @notice Shared permission template deployment.
///
///         Every shared template is a singleton bound to the kernel. Accounts opt in
///         per-instance via `configure(account, params, deadline, sig)`. Deploying
///         these once per chain gives every Sail account a canonical, audited set
///         of permission shapes to attach to.
///
///         Reads the kernel address from `deployments/<chainId>/core.json` so this
///         script can be re-run independently after a core redeploy.
///
///         Writes `deployments/<chainId>/templates.shared.json`.
contract DeploySharedTemplates is Script {
    string internal constant SCHEMA = "sail.deploy.templates.shared";
    string internal constant TARGET = "templates.shared";

    struct Deployment {
        address kernel;
        SharedApproveAndCallBatchPermission approveAndCallBatch;
        SharedBoundedBorrowPermission       boundedBorrow;
        SharedBoundedSwapPermission         boundedSwap;
        SharedTransferTargetPermission      transferTarget;
    }

    function run() external returns (Deployment memory d) {
        address deployer = vm.envAddress("DEPLOYER_ADDRESS");
        bool fresh       = _boolEnv("SAIL_DEPLOY_FRESH");
        ManifestIO.guardOverwrite(block.chainid, TARGET, fresh);

        d.kernel = ManifestIO.readAddress(block.chainid, "core", ".kernel");
        console2.log("=== Sail shared-templates deploy ===");
        console2.log("deployer :", deployer);
        console2.log("kernel   :", d.kernel);

        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(pk);

        d.approveAndCallBatch = new SharedApproveAndCallBatchPermission(d.kernel);
        d.boundedBorrow       = new SharedBoundedBorrowPermission(d.kernel);
        d.boundedSwap         = new SharedBoundedSwapPermission(d.kernel);
        d.transferTarget      = new SharedTransferTargetPermission(d.kernel);

        vm.stopBroadcast();

        console2.log("SharedApproveAndCallBatchPermission :", address(d.approveAndCallBatch));
        console2.log("SharedBoundedBorrowPermission       :", address(d.boundedBorrow));
        console2.log("SharedBoundedSwapPermission         :", address(d.boundedSwap));
        console2.log("SharedTransferTargetPermission      :", address(d.transferTarget));

        _writeManifest(deployer, d);
    }

    function _writeManifest(address deployer, Deployment memory d) internal {
        string memory k = "sail-shared-templates";
        ManifestIO.serializeHeader(k, SCHEMA, deployer);
        vm.serializeAddress(k, "kernel", d.kernel);
        vm.serializeAddress(k, "sharedApproveAndCallBatch", address(d.approveAndCallBatch));
        vm.serializeAddress(k, "sharedBoundedBorrow",       address(d.boundedBorrow));
        vm.serializeAddress(k, "sharedBoundedSwap",         address(d.boundedSwap));
        string memory json =
            vm.serializeAddress(k, "sharedTransferTarget",  address(d.transferTarget));

        ManifestIO.write(block.chainid, TARGET, json);
        console2.log("wrote", ManifestIO.manifestPath(block.chainid, TARGET));
    }

    function _boolEnv(string memory key) internal view returns (bool) {
        try vm.envString(key) returns (string memory v) {
            return bytes(v).length > 0 && keccak256(bytes(v)) != keccak256(bytes("0"));
        } catch { return false; }
    }
}
