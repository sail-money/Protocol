// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script, console2}  from "forge-std/Script.sol";
import {ManifestIO}        from "../lib/ManifestIO.sol";
import {SailGovernance}    from "../../contracts/governance/SailGovernance.sol";
import {SailKernel}        from "../../contracts/core/SailKernel.sol";
import {MandateFactory} from "../../contracts/factory/MandateFactory.sol";
import {StandardFeePolicy} from "../../contracts/policies/StandardFeePolicy.sol";
import {SafeModuleEnabler} from "../../contracts/safe/SafeModuleEnabler.sol";

/// @notice Core protocol deployment.
///
///         Writes `deployments/<chainId>/core.json`.
///
///         Env knobs:
///           DEPLOYER_PRIVATE_KEY      required
///           DEPLOYER_ADDRESS          required
///           TREASURY                  default: deployer
///           EMERGENCY_ADMIN           default: deployer
///           INITIAL_GOVERNANCE        default: deployer
///           FEE_MANAGER               default: deployer
///           DISTRIBUTOR               default: address(0)
///           MAX_PERMISSION_FEE_WEI    default: 0.001 ether (constitutional cap in SailGovernance)
///           INITIAL_PERMISSION_REGISTRATION_FEE  default: 0
///           MGMT_FEE_BPS              default: 200
///           PERF_FEE_BPS              default: 1000
///           DISTRIBUTOR_BPS           default: 0
///           SAIL_DEPLOY_FRESH=1       allow overwriting an existing core manifest
contract DeployCore is Script {
    string internal constant SCHEMA = "sail.deploy.core";
    string internal constant TARGET = "core";

    struct Config {
        address deployer;
        address initialGovernance;
        address treasury;
        address emergencyAdmin;
        address feeManager;
        address distributor;
        uint256 maxPermissionFeeWei;
        uint256 initialPermissionRegistrationFee;
        uint256 managementFeeBps;
        uint256 performanceFeeBps;
        uint256 distributorBps;
    }

    struct Deployment {
        SafeModuleEnabler safeModuleEnabler;
        SailGovernance    governance;
        SailKernel        kernel;
        MandateFactory factory;
        StandardFeePolicy feePolicy;
    }

    function run() external returns (Deployment memory d) {
        Config memory cfg = _loadConfig();
        _printConfig(cfg);

        bool fresh = _boolEnv("SAIL_DEPLOY_FRESH");
        ManifestIO.guardOverwrite(block.chainid, TARGET, fresh);

        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(pk);

        d.safeModuleEnabler = new SafeModuleEnabler();
        console2.log("SafeModuleEnabler  :", address(d.safeModuleEnabler));

        d.governance = new SailGovernance(
            cfg.initialGovernance,
            cfg.maxPermissionFeeWei,
            cfg.emergencyAdmin,
            cfg.initialPermissionRegistrationFee
        );
        console2.log("SailGovernance     :", address(d.governance));
        console2.log("  timelock         :", address(d.governance.timelock()));

        d.kernel = new SailKernel(address(d.governance), cfg.treasury);
        console2.log("SailKernel         :", address(d.kernel));

        d.factory = new MandateFactory(address(d.kernel));
        console2.log("MandateFactory  :", address(d.factory));

        d.feePolicy = new StandardFeePolicy(
            cfg.managementFeeBps,
            cfg.performanceFeeBps,
            cfg.distributor,
            cfg.distributorBps,
            address(d.kernel),
            cfg.feeManager
        );
        console2.log("StandardFeePolicy  :", address(d.feePolicy));

        vm.stopBroadcast();

        _writeManifest(cfg, d);
    }

    // -------------------------------------------------------------------------
    // Config loading
    // -------------------------------------------------------------------------

    function _loadConfig() internal view returns (Config memory c) {
        c.deployer              = vm.envAddress("DEPLOYER_ADDRESS");
        c.initialGovernance     = _envAddrOr("INITIAL_GOVERNANCE",   c.deployer);
        c.treasury              = _envAddrOr("TREASURY",             c.deployer);
        c.emergencyAdmin        = _envAddrOr("EMERGENCY_ADMIN",      c.deployer);
        c.feeManager            = _envAddrOr("FEE_MANAGER",          c.deployer);
        c.distributor           = _envAddrOr("DISTRIBUTOR",          address(0));
        // Constitutional cap in SailGovernance is 0.001 ether — keep the default at-or-below.
        c.maxPermissionFeeWei              = _envUintOr("MAX_PERMISSION_FEE_WEI", 0.001 ether);
        c.initialPermissionRegistrationFee = _envUintOrZero("INITIAL_PERMISSION_REGISTRATION_FEE");
        c.managementFeeBps      = _envUintOr("MGMT_FEE_BPS",            200);
        c.performanceFeeBps     = _envUintOr("PERF_FEE_BPS",          1_000);
        c.distributorBps        = _envUintOr("DISTRIBUTOR_BPS",           0);
    }

    function _envAddrOr(string memory key, address fallback_) internal view returns (address) {
        try vm.envAddress(key) returns (address v) { return v == address(0) ? fallback_ : v; }
        catch { return fallback_; }
    }

    function _envUintOr(string memory key, uint256 fallback_) internal view returns (uint256) {
        try vm.envUint(key) returns (uint256 v) { return v == 0 ? fallback_ : v; }
        catch { return fallback_; }
    }

    function _envUintOrZero(string memory key) internal view returns (uint256) {
        try vm.envUint(key) returns (uint256 v) { return v; } catch { return 0; }
    }

    function _boolEnv(string memory key) internal view returns (bool) {
        try vm.envString(key) returns (string memory v) {
            return bytes(v).length > 0 && keccak256(bytes(v)) != keccak256(bytes("0"));
        } catch { return false; }
    }

    function _printConfig(Config memory c) internal pure {
        console2.log("=== Sail core deploy ===");
        console2.log("deployer             :", c.deployer);
        console2.log("initialGovernance    :", c.initialGovernance);
        console2.log("treasury             :", c.treasury);
        console2.log("emergencyAdmin       :", c.emergencyAdmin);
        console2.log("feeManager           :", c.feeManager);
        console2.log("distributor          :", c.distributor);
        console2.log("maxPermissionFeeWei  :", c.maxPermissionFeeWei);
        console2.log("initialRegFee        :", c.initialPermissionRegistrationFee);
        console2.log("managementFeeBps     :", c.managementFeeBps);
        console2.log("performanceFeeBps    :", c.performanceFeeBps);
        console2.log("distributorBps       :", c.distributorBps);
    }

    // -------------------------------------------------------------------------
    // Manifest
    // -------------------------------------------------------------------------

    function _writeManifest(Config memory c, Deployment memory d) internal {
        string memory k = "sail-core";
        ManifestIO.serializeHeader(k, SCHEMA, c.deployer);

        // addresses
        vm.serializeAddress(k, "safeModuleEnabler",  address(d.safeModuleEnabler));
        vm.serializeAddress(k, "governance",         address(d.governance));
        vm.serializeAddress(k, "timelock",           address(d.governance.timelock()));
        // initialGovernance is the admin wallet passed to SailGovernance's constructor —
        // distinct from the deployed governance contract address. Stored explicitly so
        // verify.sh can reconstruct ABI-encoded constructor args without re-reading config.
        vm.serializeAddress(k, "initialGovernance",  c.initialGovernance);
        vm.serializeAddress(k, "kernel",             address(d.kernel));
        vm.serializeAddress(k, "mandateFactory",  address(d.factory));
        vm.serializeAddress(k, "standardFeePolicy",  address(d.feePolicy));

        // config snapshot
        vm.serializeAddress(k, "treasury",           c.treasury);
        vm.serializeAddress(k, "emergencyAdmin",     c.emergencyAdmin);
        vm.serializeAddress(k, "feeManager",         c.feeManager);
        vm.serializeAddress(k, "distributor",        c.distributor);
        vm.serializeUint(k, "maxPermissionFeeWei",   c.maxPermissionFeeWei);
        vm.serializeUint(k, "initialPermissionRegistrationFee", c.initialPermissionRegistrationFee);
        vm.serializeUint(k, "managementFeeBps",      c.managementFeeBps);
        vm.serializeUint(k, "performanceFeeBps",     c.performanceFeeBps);
        string memory json = vm.serializeUint(k, "distributorBps", c.distributorBps);

        ManifestIO.write(block.chainid, TARGET, json);
        console2.log("wrote", ManifestIO.manifestPath(block.chainid, TARGET));
    }
}
