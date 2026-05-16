// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script, console2}    from "forge-std/Script.sol";
import {SailGovernance}      from "../contracts/governance/SailGovernance.sol";
import {SailKernel}          from "../contracts/core/SailKernel.sol";
import {PermissionFactory}   from "../contracts/factory/PermissionFactory.sol";
import {StandardFeePolicy}   from "../contracts/policies/StandardFeePolicy.sol";
import {SafeModuleEnabler}   from "../contracts/safe/SafeModuleEnabler.sol";

/// @notice One-shot core-protocol deployment for Sail.
///
///         Deploys, in order:
///           1. SafeModuleEnabler     — canonical Safe.setup delegatecall helper
///           2. SailGovernance        — holds the protocol timelock + emergency admin
///           3. SailKernel            — trusted execution surface
///           4. PermissionFactory     — UX bundler for attach/replace flows
///           5. StandardFeePolicy     — canonical fee policy users can opt into
///
///         All addresses configurable via env. Where unset, the deployer is used as a
///         sane default (rotate via governance after deploy on mainnet).
///
///         Env knobs (all optional unless noted):
///           DEPLOYER_PRIVATE_KEY      — required if --private-key not passed
///           TREASURY                  — receives protocol fee cut       (default: deployer)
///           EMERGENCY_ADMIN           — can pause the kernel             (default: deployer)
///           INITIAL_GOVERNANCE        — initial governance address       (default: deployer)
///           FEE_MANAGER               — can tune StandardFeePolicy       (default: deployer)
///           DISTRIBUTOR               — fee split recipient              (default: address(0))
///           MAX_PERMISSION_FEE_WEI    — constitutional cap                (default: 0.01 ether)
///           INITIAL_BASE_FEE          — initial flat reg fee in wei       (default: 0)
///           INITIAL_COMPLEXITY_RATE   — initial per-byte rate in wei      (default: 0)
///           MGMT_FEE_BPS              — StandardFeePolicy mgmt fee bps    (default: 200 = 2%)
///           PERF_FEE_BPS              — StandardFeePolicy perf fee bps    (default: 1000 = 10%)
///           DISTRIBUTOR_BPS           — distributor share of mgr fee bps  (default: 0)
contract Deploy is Script {
    struct Config {
        address deployer;
        address initialGovernance;
        address treasury;
        address emergencyAdmin;
        address feeManager;
        address distributor;
        uint256 maxPermissionFeeWei;
        uint256 initialBaseFee;
        uint256 initialComplexityRate;
        uint256 managementFeeBps;
        uint256 performanceFeeBps;
        uint256 distributorBps;
    }

    struct Deployment {
        SafeModuleEnabler safeModuleEnabler;
        SailGovernance    governance;
        SailKernel        kernel;
        PermissionFactory factory;
        StandardFeePolicy feePolicy;
    }

    function run() external returns (Deployment memory d) {
        Config memory cfg = _loadConfig();
        _printConfig(cfg);

        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(pk);

        d.safeModuleEnabler = new SafeModuleEnabler();
        console2.log("SafeModuleEnabler  :", address(d.safeModuleEnabler));

        d.governance = new SailGovernance(
            cfg.initialGovernance,
            cfg.maxPermissionFeeWei,
            cfg.emergencyAdmin,
            cfg.initialBaseFee,
            cfg.initialComplexityRate
        );
        console2.log("SailGovernance     :", address(d.governance));
        console2.log("  timelock         :", address(d.governance.timelock()));

        d.kernel = new SailKernel(address(d.governance), cfg.treasury);
        console2.log("SailKernel         :", address(d.kernel));

        d.factory = new PermissionFactory(address(d.kernel));
        console2.log("PermissionFactory  :", address(d.factory));

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

        _writeArtifact(cfg, d);
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
        c.maxPermissionFeeWei   = _envUintOr("MAX_PERMISSION_FEE_WEI",  0.01 ether);
        c.initialBaseFee        = _envUintOrZero("INITIAL_BASE_FEE");
        c.initialComplexityRate = _envUintOrZero("INITIAL_COMPLEXITY_RATE");
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

    /// @dev Returns the env value verbatim (allows 0 as a legitimate value).
    function _envUintOrZero(string memory key) internal view returns (uint256) {
        try vm.envUint(key) returns (uint256 v) { return v; } catch { return 0; }
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
        console2.log("initialBaseFee       :", c.initialBaseFee);
        console2.log("initialComplexityRate:", c.initialComplexityRate);
        console2.log("managementFeeBps     :", c.managementFeeBps);
        console2.log("performanceFeeBps    :", c.performanceFeeBps);
        console2.log("distributorBps       :", c.distributorBps);
    }

    // -------------------------------------------------------------------------
    // Artifact: write deployments/<chainId>.json
    // -------------------------------------------------------------------------

    function _writeArtifact(Config memory c, Deployment memory d) internal {
        string memory json = _buildJson(c, d);
        string memory path = string.concat(
            "deployments/", vm.toString(block.chainid), ".json"
        );
        vm.writeFile(path, json);
        console2.log("wrote", path);
    }

    function _buildJson(Config memory c, Deployment memory d)
        internal
        returns (string memory)
    {
        string memory k = "sail-deploy";
        _writeAddresses(k, c, d);
        _writeMeta(k, c);
        vm.serializeUint(k, "performanceFeeBps", c.performanceFeeBps);
        return vm.serializeUint(k, "distributorBps", c.distributorBps);
    }

    function _writeAddresses(string memory k, Config memory c, Deployment memory d) internal {
        vm.serializeAddress(k, "deployer",           c.deployer);
        vm.serializeAddress(k, "safeModuleEnabler",  address(d.safeModuleEnabler));
        vm.serializeAddress(k, "governance",         address(d.governance));
        vm.serializeAddress(k, "timelock",           address(d.governance.timelock()));
        vm.serializeAddress(k, "kernel",             address(d.kernel));
        vm.serializeAddress(k, "permissionFactory",  address(d.factory));
        vm.serializeAddress(k, "standardFeePolicy",  address(d.feePolicy));
        vm.serializeAddress(k, "treasury",           c.treasury);
        vm.serializeAddress(k, "emergencyAdmin",     c.emergencyAdmin);
        vm.serializeAddress(k, "feeManager",         c.feeManager);
        vm.serializeAddress(k, "distributor",        c.distributor);
    }

    function _writeMeta(string memory k, Config memory c) internal {
        vm.serializeUint(k, "chainId",               block.chainid);
        vm.serializeUint(k, "blockNumber",           block.number);
        vm.serializeUint(k, "timestamp",             block.timestamp);
        vm.serializeUint(k, "maxPermissionFeeWei",   c.maxPermissionFeeWei);
        vm.serializeUint(k, "initialBaseFee",        c.initialBaseFee);
        vm.serializeUint(k, "initialComplexityRate", c.initialComplexityRate);
        vm.serializeUint(k, "managementFeeBps",      c.managementFeeBps);
    }
}
