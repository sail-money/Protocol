// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script, console2} from "forge-std/Script.sol";
import {ManifestIO}       from "../lib/ManifestIO.sol";

import {AzuroPredictionPermission}       from "../../contracts/templates/AzuroPredictionPermission.sol";
import {BoundedApprovePermission}        from "../../contracts/templates/BoundedApprovePermission.sol";
import {BoundedBorrowPermission}         from "../../contracts/templates/BoundedBorrowPermission.sol";
import {BoundedDepositPermission}        from "../../contracts/templates/BoundedDepositPermission.sol";
import {BoundedLiFiPermission}           from "../../contracts/templates/BoundedLiFiPermission.sol";
import {BoundedSwapPermission}           from "../../contracts/templates/BoundedSwapPermission.sol";
import {BoundedWithdrawPermission}       from "../../contracts/templates/BoundedWithdrawPermission.sol";
import {GMXPerpPermission}               from "../../contracts/templates/GMXPerpPermission.sol";
import {GainsNetworkPerpPermission}      from "../../contracts/templates/GainsNetworkPerpPermission.sol";
import {LimitlessPredictionPermission}   from "../../contracts/templates/LimitlessPredictionPermission.sol";
import {SynthetixPerpPermission}         from "../../contracts/templates/SynthetixPerpPermission.sol";
import {TransferTargetPermission}        from "../../contracts/templates/TransferTargetPermission.sol";

/// @notice Standalone (single-account clone) template logic deployment.
///
///         Each contract here is a logic / implementation contract for an EIP-1167
///         minimal proxy. The logic contracts themselves carry NO per-user state —
///         their constructors call `_disableInitializers()`, permanently locking them.
///         Per-account clones are created at runtime via `PermissionFactory.deployAndAttach`.
///
///         Because there are no constructor arguments to record, verification is
///         trivial: no --constructor-args needed.
///
///         Writes `deployments/<chainId>/templates.standalone.json`.
contract DeployStandaloneTemplates is Script {
    string internal constant SCHEMA = "sail.deploy.templates.standalone";
    string internal constant TARGET = "templates.standalone";

    struct Deployment {
        AzuroPredictionPermission       azuroPrediction;
        BoundedApprovePermission        boundedApprove;
        BoundedBorrowPermission         boundedBorrow;
        BoundedDepositPermission        boundedDeposit;
        BoundedLiFiPermission           boundedLiFi;
        BoundedSwapPermission           boundedSwap;
        BoundedWithdrawPermission       boundedWithdraw;
        GMXPerpPermission               gmxPerp;
        GainsNetworkPerpPermission      gainsNetworkPerp;
        LimitlessPredictionPermission   limitlessPrediction;
        SynthetixPerpPermission         synthetixPerp;
        TransferTargetPermission        transferTarget;
    }

    function run() external returns (Deployment memory d) {
        address deployer = vm.envAddress("DEPLOYER_ADDRESS");
        bool fresh       = _boolEnv("SAIL_DEPLOY_FRESH");
        ManifestIO.guardOverwrite(block.chainid, TARGET, fresh);

        console2.log("=== Sail standalone-templates deploy ===");
        console2.log("deployer :", deployer);

        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(pk);

        d.azuroPrediction     = new AzuroPredictionPermission();
        d.boundedApprove      = new BoundedApprovePermission();
        d.boundedBorrow       = new BoundedBorrowPermission();
        d.boundedDeposit      = new BoundedDepositPermission();
        d.boundedLiFi         = new BoundedLiFiPermission();
        d.boundedSwap         = new BoundedSwapPermission();
        d.boundedWithdraw     = new BoundedWithdrawPermission();
        d.gmxPerp             = new GMXPerpPermission();
        d.gainsNetworkPerp    = new GainsNetworkPerpPermission();
        d.limitlessPrediction = new LimitlessPredictionPermission();
        d.synthetixPerp       = new SynthetixPerpPermission();
        d.transferTarget      = new TransferTargetPermission();

        vm.stopBroadcast();

        console2.log("AzuroPredictionPermission     :", address(d.azuroPrediction));
        console2.log("BoundedApprovePermission      :", address(d.boundedApprove));
        console2.log("BoundedBorrowPermission       :", address(d.boundedBorrow));
        console2.log("BoundedDepositPermission      :", address(d.boundedDeposit));
        console2.log("BoundedLiFiPermission         :", address(d.boundedLiFi));
        console2.log("BoundedSwapPermission         :", address(d.boundedSwap));
        console2.log("BoundedWithdrawPermission     :", address(d.boundedWithdraw));
        console2.log("GMXPerpPermission             :", address(d.gmxPerp));
        console2.log("GainsNetworkPerpPermission    :", address(d.gainsNetworkPerp));
        console2.log("LimitlessPredictionPermission :", address(d.limitlessPrediction));
        console2.log("SynthetixPerpPermission       :", address(d.synthetixPerp));
        console2.log("TransferTargetPermission      :", address(d.transferTarget));

        _writeManifest(deployer, d);
    }

    function _writeManifest(address deployer, Deployment memory d) internal {
        string memory k = "sail-standalone-templates";
        ManifestIO.serializeHeader(k, SCHEMA, deployer);
        vm.serializeAddress(k, "azuroPrediction",     address(d.azuroPrediction));
        vm.serializeAddress(k, "boundedApprove",      address(d.boundedApprove));
        vm.serializeAddress(k, "boundedBorrow",       address(d.boundedBorrow));
        vm.serializeAddress(k, "boundedDeposit",      address(d.boundedDeposit));
        vm.serializeAddress(k, "boundedLiFi",         address(d.boundedLiFi));
        vm.serializeAddress(k, "boundedSwap",         address(d.boundedSwap));
        vm.serializeAddress(k, "boundedWithdraw",     address(d.boundedWithdraw));
        vm.serializeAddress(k, "gmxPerp",             address(d.gmxPerp));
        vm.serializeAddress(k, "gainsNetworkPerp",    address(d.gainsNetworkPerp));
        vm.serializeAddress(k, "limitlessPrediction", address(d.limitlessPrediction));
        vm.serializeAddress(k, "synthetixPerp",       address(d.synthetixPerp));
        string memory json =
            vm.serializeAddress(k, "transferTarget",  address(d.transferTarget));

        ManifestIO.write(block.chainid, TARGET, json);
        console2.log("wrote", ManifestIO.manifestPath(block.chainid, TARGET));
    }

    function _boolEnv(string memory key) internal view returns (bool) {
        try vm.envString(key) returns (string memory v) {
            return bytes(v).length > 0 && keccak256(bytes(v)) != keccak256(bytes("0"));
        } catch { return false; }
    }
}
