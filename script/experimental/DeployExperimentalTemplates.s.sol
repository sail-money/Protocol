// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script, console2} from "forge-std/Script.sol";
import {ManifestIO}       from "../lib/ManifestIO.sol";

// Standalone (single-account clone) experimental templates — no constructor args.
import {AzuroPredictionPermission}       from "../../contracts/experimental/AzuroPredictionPermission.sol";
import {BoundedApprovePermission}        from "../../contracts/experimental/BoundedApprovePermission.sol";
import {BoundedBorrowPermission}         from "../../contracts/experimental/BoundedBorrowPermission.sol";
import {BoundedLiFiPermission}           from "../../contracts/experimental/BoundedLiFiPermission.sol";
import {BoundedSwapPermission}           from "../../contracts/experimental/BoundedSwapPermission.sol";
import {GMXPerpPermission}               from "../../contracts/experimental/GMXPerpPermission.sol";
import {GainsNetworkPerpPermission}      from "../../contracts/experimental/GainsNetworkPerpPermission.sol";
import {LimitlessPredictionPermission}   from "../../contracts/experimental/LimitlessPredictionPermission.sol";
import {SynthetixPerpPermission}         from "../../contracts/experimental/SynthetixPerpPermission.sol";
import {TransferTargetPermission}        from "../../contracts/experimental/TransferTargetPermission.sol";

// Shared (kernel-bound singleton) experimental templates — take the kernel address.
import {SharedAMMLiquidityPermission}    from "../../contracts/experimental/SharedAMMLiquidityPermission.sol";
import {SharedDeFiBundlePermission}      from "../../contracts/experimental/SharedDeFiBundlePermission.sol";
import {SharedPendlePermission}          from "../../contracts/experimental/SharedPendlePermission.sol";

/// @notice Deployment of the EXPERIMENTAL permission templates.
///
///         These contracts are unaudited and NOT part of the trusted core. They are
///         NOT deployed at launch — this script exists only to deploy them for future
///         verification or controlled experiments. See contracts/experimental/README.md.
///
///         Reads the kernel address from `deployments/<chainId>/core.json` for the
///         kernel-bound shared templates. Writes
///         `deployments/<chainId>/templates.experimental.json`.
contract DeployExperimentalTemplates is Script {
    string internal constant SCHEMA = "sail.deploy.templates.experimental";
    string internal constant TARGET = "templates.experimental";

    struct Deployment {
        address kernel;
        // standalone
        AzuroPredictionPermission       azuroPrediction;
        BoundedApprovePermission        boundedApprove;
        BoundedBorrowPermission         boundedBorrow;
        BoundedLiFiPermission           boundedLiFi;
        BoundedSwapPermission           boundedSwap;
        GMXPerpPermission               gmxPerp;
        GainsNetworkPerpPermission      gainsNetworkPerp;
        LimitlessPredictionPermission   limitlessPrediction;
        SynthetixPerpPermission         synthetixPerp;
        TransferTargetPermission        transferTarget;
        // shared (kernel-bound)
        SharedAMMLiquidityPermission    ammLiquidity;
        SharedDeFiBundlePermission      defiBundle;
        SharedPendlePermission          pendle;
    }

    function run() external returns (Deployment memory d) {
        address deployer = vm.envAddress("DEPLOYER_ADDRESS");
        bool fresh       = _boolEnv("SAIL_DEPLOY_FRESH");
        ManifestIO.guardOverwrite(block.chainid, TARGET, fresh);

        d.kernel = ManifestIO.readAddress(block.chainid, "core", ".kernel");
        console2.log("=== Sail EXPERIMENTAL-templates deploy (unaudited, not launch) ===");
        console2.log("deployer :", deployer);
        console2.log("kernel   :", d.kernel);

        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(pk);

        d.azuroPrediction     = new AzuroPredictionPermission();
        d.boundedApprove      = new BoundedApprovePermission();
        d.boundedBorrow       = new BoundedBorrowPermission();
        d.boundedLiFi         = new BoundedLiFiPermission();
        d.boundedSwap         = new BoundedSwapPermission();
        d.gmxPerp             = new GMXPerpPermission();
        d.gainsNetworkPerp    = new GainsNetworkPerpPermission();
        d.limitlessPrediction = new LimitlessPredictionPermission();
        d.synthetixPerp       = new SynthetixPerpPermission();
        d.transferTarget      = new TransferTargetPermission();

        d.ammLiquidity        = new SharedAMMLiquidityPermission(d.kernel);
        d.defiBundle          = new SharedDeFiBundlePermission(d.kernel);
        d.pendle              = new SharedPendlePermission(d.kernel);

        vm.stopBroadcast();

        console2.log("AzuroPredictionPermission     :", address(d.azuroPrediction));
        console2.log("BoundedApprovePermission      :", address(d.boundedApprove));
        console2.log("BoundedBorrowPermission       :", address(d.boundedBorrow));
        console2.log("BoundedLiFiPermission         :", address(d.boundedLiFi));
        console2.log("BoundedSwapPermission         :", address(d.boundedSwap));
        console2.log("GMXPerpPermission             :", address(d.gmxPerp));
        console2.log("GainsNetworkPerpPermission    :", address(d.gainsNetworkPerp));
        console2.log("LimitlessPredictionPermission :", address(d.limitlessPrediction));
        console2.log("SynthetixPerpPermission       :", address(d.synthetixPerp));
        console2.log("TransferTargetPermission      :", address(d.transferTarget));
        console2.log("SharedAMMLiquidityPermission  :", address(d.ammLiquidity));
        console2.log("SharedDeFiBundlePermission    :", address(d.defiBundle));
        console2.log("SharedPendlePermission        :", address(d.pendle));

        _writeManifest(deployer, d);
    }

    function _writeManifest(address deployer, Deployment memory d) internal {
        string memory k = "sail-experimental-templates";
        ManifestIO.serializeHeader(k, SCHEMA, deployer);
        vm.serializeAddress(k, "kernel", d.kernel);
        vm.serializeAddress(k, "azuroPrediction",     address(d.azuroPrediction));
        vm.serializeAddress(k, "boundedApprove",      address(d.boundedApprove));
        vm.serializeAddress(k, "boundedBorrow",       address(d.boundedBorrow));
        vm.serializeAddress(k, "boundedLiFi",         address(d.boundedLiFi));
        vm.serializeAddress(k, "boundedSwap",         address(d.boundedSwap));
        vm.serializeAddress(k, "gmxPerp",             address(d.gmxPerp));
        vm.serializeAddress(k, "gainsNetworkPerp",    address(d.gainsNetworkPerp));
        vm.serializeAddress(k, "limitlessPrediction", address(d.limitlessPrediction));
        vm.serializeAddress(k, "synthetixPerp",       address(d.synthetixPerp));
        vm.serializeAddress(k, "transferTarget",      address(d.transferTarget));
        vm.serializeAddress(k, "sharedAmmLiquidity",  address(d.ammLiquidity));
        vm.serializeAddress(k, "sharedDeFiBundle",    address(d.defiBundle));
        string memory json =
            vm.serializeAddress(k, "sharedPendle",    address(d.pendle));

        ManifestIO.write(block.chainid, TARGET, json);
        console2.log("wrote", ManifestIO.manifestPath(block.chainid, TARGET));
    }

    function _boolEnv(string memory key) internal view returns (bool) {
        try vm.envString(key) returns (string memory v) {
            return bytes(v).length > 0 && keccak256(bytes(v)) != keccak256(bytes("0"));
        } catch { return false; }
    }
}
