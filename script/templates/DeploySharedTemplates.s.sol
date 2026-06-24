// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script, console2} from "forge-std/Script.sol";
import {ManifestIO}       from "../lib/ManifestIO.sol";

import {ApproveAndCallBatchPermission} from "../../contracts/templates/ApproveAndCallBatchPermission.sol";
import {BorrowPermission}              from "../../contracts/templates/BorrowPermission.sol";
import {DepositPermission}             from "../../contracts/templates/DepositPermission.sol";
import {SwapPermission}                from "../../contracts/templates/SwapPermission.sol";
import {SwapPermissionNoOracle}        from "../../contracts/templates/SwapPermissionNoOracle.sol";
import {TransferPermission}            from "../../contracts/templates/TransferPermission.sol";
import {WithdrawPermission}            from "../../contracts/templates/WithdrawPermission.sol";

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
///         Each template records an `author` for tooling-layer attribution (the kernel
///         never reads it). The author defaults to the deployer; override via the
///         `TEMPLATE_AUTHOR` env var.
///
///         Writes `deployments/<chainId>/templates.shared.json`.
contract DeploySharedTemplates is Script {
    string internal constant SCHEMA = "sail.deploy.templates.shared";
    string internal constant TARGET = "templates.shared";

    struct Deployment {
        address kernel;
        ApproveAndCallBatchPermission approveAndCallBatch;
        BorrowPermission              borrow;
        DepositPermission             deposit;
        SwapPermission                swap;
        SwapPermissionNoOracle        swapNoOracle;
        TransferPermission            transfer;
        WithdrawPermission            withdraw;
    }

    function run() external returns (Deployment memory d) {
        address deployer = vm.envAddress("DEPLOYER_ADDRESS");
        address author   = _authorOr(deployer);
        bool fresh       = _boolEnv("SAIL_DEPLOY_FRESH");
        ManifestIO.guardOverwrite(block.chainid, TARGET, fresh);

        d.kernel = ManifestIO.readAddress(block.chainid, "core", ".kernel");
        console2.log("=== Sail shared-templates deploy ===");
        console2.log("deployer :", deployer);
        console2.log("author   :", author);
        console2.log("kernel   :", d.kernel);

        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(pk);

        d.approveAndCallBatch = new ApproveAndCallBatchPermission(d.kernel, author);
        d.borrow              = new BorrowPermission(d.kernel, author);
        d.deposit             = new DepositPermission(d.kernel, author);
        d.swap                = new SwapPermission(d.kernel, author);
        d.swapNoOracle        = new SwapPermissionNoOracle(d.kernel, author);
        d.transfer            = new TransferPermission(d.kernel, author);
        d.withdraw            = new WithdrawPermission(d.kernel, author);

        vm.stopBroadcast();

        console2.log("ApproveAndCallBatchPermission :", address(d.approveAndCallBatch));
        console2.log("BorrowPermission              :", address(d.borrow));
        console2.log("DepositPermission             :", address(d.deposit));
        console2.log("SwapPermission                :", address(d.swap));
        console2.log("SwapPermissionNoOracle        :", address(d.swapNoOracle));
        console2.log("TransferPermission            :", address(d.transfer));
        console2.log("WithdrawPermission            :", address(d.withdraw));

        _writeManifest(deployer, d);
    }

    function _writeManifest(address deployer, Deployment memory d) internal {
        string memory k = "sail-shared-templates";
        ManifestIO.serializeHeader(k, SCHEMA, deployer);
        vm.serializeAddress(k, "kernel", d.kernel);
        vm.serializeAddress(k, "approveAndCallBatch", address(d.approveAndCallBatch));
        vm.serializeAddress(k, "borrow",              address(d.borrow));
        vm.serializeAddress(k, "deposit",             address(d.deposit));
        vm.serializeAddress(k, "swap",                address(d.swap));
        vm.serializeAddress(k, "swapNoOracle",        address(d.swapNoOracle));
        vm.serializeAddress(k, "transfer",            address(d.transfer));
        string memory json =
            vm.serializeAddress(k, "withdraw",        address(d.withdraw));

        ManifestIO.write(block.chainid, TARGET, json);
        console2.log("wrote", ManifestIO.manifestPath(block.chainid, TARGET));
    }

    function _authorOr(address fallbackAuthor) internal view returns (address) {
        try vm.envAddress("TEMPLATE_AUTHOR") returns (address a) {
            return a == address(0) ? fallbackAuthor : a;
        } catch { return fallbackAuthor; }
    }

    function _boolEnv(string memory key) internal view returns (bool) {
        try vm.envString(key) returns (string memory v) {
            return bytes(v).length > 0 && keccak256(bytes(v)) != keccak256(bytes("0"));
        } catch { return false; }
    }
}
