// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script, console2}     from "forge-std/Script.sol";
import {ManifestIO}           from "../lib/ManifestIO.sol";
import {SailGovernance}       from "../../contracts/governance/SailGovernance.sol";
import {SailKernel}           from "../../contracts/core/SailKernel.sol";
import {MandateFactory}       from "../../contracts/factory/MandateFactory.sol";
import {StandardFeePolicy}    from "../../contracts/policies/StandardFeePolicy.sol";
import {SafeModuleEnabler}    from "../../contracts/safe/SafeModuleEnabler.sol";
import {SafeConstants}        from "../SafeConstants.sol";
import {TimelockController}   from "@openzeppelin/contracts/governance/TimelockController.sol";

/// @notice Core protocol deployment via deterministic CREATE2 (global, chain-independent salts).
///
///         ── Same address on every chain ──────────────────────────────────────────────────────
///         Every core contract is deployed through the standard deterministic CREATE2 factory
///         (Arachnid / Nick's factory) at 0x4e59b44847b379578588920cA78FbF26c0B4956C, using a
///         GLOBAL salt per contract (NO chainId mixed into the salt). A CREATE2 address is
///         `keccak256(0xff ++ factory ++ salt ++ keccak256(initCode))[12:]`, so the address is
///         identical across chains iff `initCode` (creation bytecode ++ ABI-encoded constructor
///         args) is identical across chains. Because:
///           • the creation bytecode is the compiled artifact (identical across chains), and
///           • every constructor argument is chain-independent (the deployer config below MUST
///             be identical on every chain, and inter-contract references resolve to the same
///             deterministic addresses),
///         the entire dependency chain — TimelockController → SailGovernance → SailKernel →
///         MandateFactory / StandardFeePolicy, plus the arg-less SafeModuleEnabler — lands at the
///         SAME address on Base, Arbitrum, Unichain, Ethereum, Base Sepolia, and Eth Sepolia.
///         That in turn makes the Safe initializer (which embeds SafeModuleEnabler + SailKernel)
///         identical across chains, giving users the SAME Separately-Managed-Account address
///         everywhere.
///
///         ── CRITICAL: identical config across chains ─────────────────────────────────────────
///         The same-address property holds ONLY if the deployer uses the SAME values for every
///         config knob below on every chain (same INITIAL_GOVERNANCE, TREASURY, EMERGENCY_ADMIN,
///         FEE_MANAGER, DISTRIBUTOR, MAX_PERMISSION_FEE_WEI, INITIAL_PERMISSION_REGISTRATION_FEE,
///         MGMT_FEE_BPS, PERF_FEE_BPS, DISTRIBUTOR_BPS). A single differing value changes that
///         contract's initCode and therefore its address on that chain — and cascades to every
///         contract that references it. The deployer is responsible for keeping config identical.
///
///         ── Why the timelock is deployed first ───────────────────────────────────────────────
///         SailGovernance no longer constructs its TimelockController inline; it accepts one as a
///         constructor argument (see contracts/governance/SailGovernance.sol). The timelock is
///         deployed FIRST, with the team governance wallet (`initialGovernance`) as its sole
///         proposer / executor / canceller and `address(0)` as admin (self-administered). There
///         is NO circular dependency: the timelock references the team WALLET, not the (not-yet-
///         deployed) SailGovernance contract — so no address prediction is needed for wiring.
///         The timelock's deployed address is read back and passed straight into SailGovernance.
///
///         ── Verification ─────────────────────────────────────────────────────────────────────
///         Every deployment computes its predicted CREATE2 address up front and asserts the
///         factory deployed code at exactly that address — failing loudly on any mismatch.
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
///           MAX_PERMISSION_FEE_WEI    default: 0.001 ether (constitutional cap in SailGovernance is 0.01 ether)
///           INITIAL_PERMISSION_REGISTRATION_FEE  default: 0
///           MGMT_FEE_BPS              default: 200
///           PERF_FEE_BPS              default: 1000
///           DISTRIBUTOR_BPS           default: 0
///           SAIL_DEPLOY_FRESH=1       allow overwriting an existing core manifest
///           SAIL_BOOTSTRAP_ALLOWLISTS=1  seed onboarding allowlists at genesis (needs SAFE_PROXY_CODEHASH)
contract DeployCore is Script {
    string internal constant SCHEMA = "sail.deploy.core";
    string internal constant TARGET = "core";

    // The standard deterministic CREATE2 factory (Arachnid / Nick's factory) at
    // 0x4e59b44847b379578588920cA78FbF26c0B4956C is inherited from forge-std as the constant
    // `CREATE2_FACTORY` (CommonBase). It is present at that address on every target chain;
    // the factory call in `_deploy2` reverts if it is somehow absent.

    // ── Global, versioned, chain-independent salts ────────────────────────────────────────────
    // One salt per contract. NO chainId is mixed in — that is the whole point: a global salt with
    // identical initCode yields the SAME address on every chain. Bump the version suffix (`.v1` →
    // `.v2`) only when a deliberate address rotation is wanted (e.g. a new reviewed bytecode that
    // must NOT collide with the previous deployment's address).
    bytes32 internal constant SALT_TIMELOCK        = keccak256("sail.timelock.v1");
    bytes32 internal constant SALT_GOVERNANCE      = keccak256("sail.governance.v1");
    bytes32 internal constant SALT_KERNEL          = keccak256("sail.kernel.v1");
    bytes32 internal constant SALT_MANDATE_FACTORY = keccak256("sail.mandatefactory.v1");
    bytes32 internal constant SALT_FEE_POLICY      = keccak256("sail.feepolicy.v1");
    bytes32 internal constant SALT_MODULE_ENABLER  = keccak256("sail.modulenabler.v1");

    /// @notice Timelock minimum delay — MUST match SailGovernance.REQUIRED_TIMELOCK_DELAY.
    ///         SailGovernance's constructor reverts (`TimelockDelayMismatch`) unless the injected
    ///         timelock reports exactly this delay.
    uint256 internal constant TIMELOCK_DELAY = 48 hours;

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
        TimelockController timelock;
        SafeModuleEnabler  safeModuleEnabler;
        SailGovernance     governance;
        SailKernel         kernel;
        MandateFactory     factory;
        StandardFeePolicy  feePolicy;
    }

    function run() external returns (Deployment memory d) {
        Config memory cfg = _loadConfig();
        _printConfig(cfg);

        bool fresh = _boolEnv("SAIL_DEPLOY_FRESH");
        ManifestIO.guardOverwrite(block.chainid, TARGET, fresh);

        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(pk);

        // (1) TimelockController — deployed FIRST so its (deterministic) address can be injected
        //     into SailGovernance. Sole proposer/executor/canceller is the team governance wallet;
        //     admin is address(0) (self-administered). These args are chain-independent.
        address[] memory proposers = new address[](1);
        proposers[0] = cfg.initialGovernance;
        address[] memory executors = new address[](1);
        executors[0] = cfg.initialGovernance;
        bytes memory timelockInit = abi.encodePacked(
            type(TimelockController).creationCode,
            abi.encode(TIMELOCK_DELAY, proposers, executors, address(0))
        );
        d.timelock = TimelockController(payable(_deploy2(SALT_TIMELOCK, timelockInit, "TimelockController")));

        // Self-administration assertion: confirm no EOA holds admin over the timelock's roles, so
        // roles cannot be granted/revoked and the delay cannot be altered outside the 48-hour
        // process. NOTE: the SailGovernance constructor ALSO enforces this
        // (it reverts with TimelockNotSelfAdministered), so this assertion is now defense-in-depth —
        // kept deliberately because it fails earlier and with a clearer, deploy-time message, and
        // additionally checks that neither the deployer nor the governance wallet holds the admin
        // role. In OpenZeppelin's AccessControl, `getRoleAdmin(role)` returns the *admin role*
        // (a bytes32), not an address: PROPOSER_ROLE is administered by DEFAULT_ADMIN_ROLE, and a
        // self-administered timelock is one where the timelock contract ITSELF holds that admin
        // role while no external party (deployer or governance wallet) does.
        bytes32 adminRole = d.timelock.getRoleAdmin(d.timelock.PROPOSER_ROLE());
        require(adminRole == d.timelock.DEFAULT_ADMIN_ROLE(), "proposer admin role must be DEFAULT_ADMIN_ROLE");
        require(
            d.timelock.hasRole(adminRole, address(d.timelock)),
            "timelock not self-administered (must hold its own admin role)"
        );
        require(!d.timelock.hasRole(adminRole, cfg.deployer),          "deployer must not hold timelock admin role");
        require(!d.timelock.hasRole(adminRole, cfg.initialGovernance), "governance wallet must not hold timelock admin role");
        console2.log("  timelock minDelay  :", d.timelock.getMinDelay());

        // (2) SailGovernance — receives the injected timelock. Its constructor independently
        //     re-verifies the timelock's 48h delay and that initialGovernance holds PROPOSER_ROLE.
        bytes memory governanceInit = abi.encodePacked(
            type(SailGovernance).creationCode,
            abi.encode(
                cfg.initialGovernance,
                cfg.maxPermissionFeeWei,
                cfg.emergencyAdmin,
                cfg.initialPermissionRegistrationFee,
                address(d.timelock)
            )
        );
        d.governance = SailGovernance(_deploy2(SALT_GOVERNANCE, governanceInit, "SailGovernance"));

        // (3a) SafeModuleEnabler — no constructor args, so its initCode (and therefore its address
        //      and runtime codehash) is trivially identical on every chain. Deployed BEFORE the
        //      kernel so the kernel constructor can read its codehash and pin it (the codehash pin).
        bytes memory enablerInit = type(SafeModuleEnabler).creationCode;
        d.safeModuleEnabler = SafeModuleEnabler(_deploy2(SALT_MODULE_ENABLER, enablerInit, "SafeModuleEnabler"));

        // (3b) SailKernel — references the (deterministic) governance address + treasury, and pins
        //      the just-deployed immutable SafeModuleEnabler's runtime codehash (the codehash pin). Because the
        //      kernel and the enabler ship from the SAME build, the pinned codehash matches the
        //      deployed helper by construction.
        bytes memory kernelInit = abi.encodePacked(
            type(SailKernel).creationCode,
            abi.encode(address(d.governance), cfg.treasury, address(d.safeModuleEnabler))
        );
        d.kernel = SailKernel(_deploy2(SALT_KERNEL, kernelInit, "SailKernel"));

        // (4) MandateFactory — references the (deterministic) kernel address.
        bytes memory factoryInit = abi.encodePacked(
            type(MandateFactory).creationCode,
            abi.encode(address(d.kernel))
        );
        d.factory = MandateFactory(payable(_deploy2(SALT_MANDATE_FACTORY, factoryInit, "MandateFactory")));

        // (5) StandardFeePolicy — references the (deterministic) kernel address + fee config.
        bytes memory feePolicyInit = abi.encodePacked(
            type(StandardFeePolicy).creationCode,
            abi.encode(
                cfg.managementFeeBps,
                cfg.performanceFeeBps,
                cfg.distributor,
                cfg.distributorBps,
                address(d.kernel),
                cfg.feeManager
            )
        );
        d.feePolicy = StandardFeePolicy(_deploy2(SALT_FEE_POLICY, feePolicyInit, "StandardFeePolicy"));

        // Genesis allowlist seeding: when SAIL_BOOTSTRAP_ALLOWLISTS is set, seed the onboarding
        // allowlists in this same broadcast (deployer is still `governance`), bypassing the
        // 48-hour timelock exactly once. Without it, fall back to the manual timelock path.
        // The bootstrap call is a direct call from the deployer EOA (NOT routed through the CREATE2
        // factory), so msg.sender is the deployer — which must equal initialGovernance.
        bool bootstrap = _boolEnv("SAIL_BOOTSTRAP_ALLOWLISTS");
        if (bootstrap && !d.governance.allowlistBootstrapped()) {
            _bootstrapAllowlists(cfg, d);
        }

        vm.stopBroadcast();

        if (!bootstrap) {
            _printAllowlistReminder(address(d.safeModuleEnabler));
        }
        _writeManifest(cfg, d);
    }

    // -------------------------------------------------------------------------
    // CREATE2 deployment helper
    // -------------------------------------------------------------------------

    /// @dev Deploy `initCode` through the deterministic CREATE2 factory under `salt`, and verify
    ///      the result lands at the predicted address. Fails loudly on any mismatch.
    ///
    ///      The factory's calldata layout is `salt (32 bytes) ++ initCode`; it performs the CREATE2
    ///      and (in the canonical implementation) returns the 20-byte deployed address. Rather than
    ///      depend on the factory's return-data encoding, we compute the predicted address with
    ///      `vm.computeCreate2Address` and confirm code exists there after the call — robust across
    ///      factory implementations.
    ///
    ///      Idempotent across re-runs: if code already exists at the predicted address (e.g. a
    ///      re-broadcast on the same chain), the existing deployment is reused. CREATE2 guarantees
    ///      it is byte-for-byte what this salt+initCode would have produced.
    function _deploy2(bytes32 salt, bytes memory initCode, string memory label)
        internal
        returns (address deployed)
    {
        address predicted = vm.computeCreate2Address(salt, keccak256(initCode), CREATE2_FACTORY);

        if (predicted.code.length != 0) {
            console2.log(string.concat(label, " (already deployed):"), predicted);
            return predicted;
        }

        (bool ok, ) = CREATE2_FACTORY.call(abi.encodePacked(salt, initCode));
        require(ok, string.concat("CREATE2 deploy failed (factory present?): ", label));
        require(
            predicted.code.length != 0,
            string.concat("CREATE2 produced no code at predicted address: ", label)
        );

        deployed = predicted;
        console2.log(string.concat(label, ":"), deployed);
    }

    /// @dev One-time genesis seeding of SailGovernance's onboarding allowlists, run inside the
    ///      deployment broadcast while the deployer still holds `governance`. Trusts the canonical
    ///      Safe v1.4.1 ProxyFactory, BOTH singleton variants (L2 + non-L2), the freshly deployed
    ///      SafeModuleEnabler and StandardFeePolicy, and the SafeProxy runtime codehash supplied
    ///      via the SAFE_PROXY_CODEHASH env var. Requires `governance == deployer` (the default).
    function _bootstrapAllowlists(Config memory cfg, Deployment memory d) internal {
        require(
            d.governance.governance() == cfg.deployer,
            "bootstrap must be sent by initialGovernance; set INITIAL_GOVERNANCE=deployer"
        );

        bytes32 proxyCodehash = vm.envBytes32("SAFE_PROXY_CODEHASH");
        require(
            proxyCodehash != bytes32(0),
            "SAFE_PROXY_CODEHASH env required: cast keccak $(cast code <a 1.4.1 SafeProxy> --rpc-url $RPC)"
        );

        address[] memory factories = new address[](1);
        factories[0] = SafeConstants.SAFE_PROXY_FACTORY_1_4_1;

        address[] memory singletons = new address[](2);
        singletons[0] = SafeConstants.SAFE_SINGLETON_1_4_1;
        singletons[1] = SafeConstants.SAFE_SINGLETON_L2_1_4_1;

        address[] memory setups = new address[](1);
        setups[0] = address(d.safeModuleEnabler);

        address[] memory policies = new address[](1);
        policies[0] = address(d.feePolicy);

        bytes32[] memory codehashes = new bytes32[](1);
        codehashes[0] = proxyCodehash;

        d.governance.bootstrapAllowlists(factories, singletons, setups, policies, codehashes);

        console2.log("=== BOOTSTRAPPED allowlists at genesis (no timelock) ===");
        console2.log("trustedSafeFactory         :", factories[0]);
        console2.log("trustedSafeSingleton       :", singletons[0]);
        console2.log("trustedSafeSingleton (L2)  :", singletons[1]);
        console2.log("trustedModuleSetup         :", setups[0]);
        console2.log("trustedFeePolicy           :", policies[0]);
        console2.log("trustedSafeProxyCodehash   :");
        console2.logBytes32(codehashes[0]);
    }

    /// @dev The onboarding allowlist setters on SailGovernance are `onlyTimelock`, so they
    ///      cannot be populated inline in this broadcast. Print the values that governance
    ///      must allowlist via the 48-hour timelock before onboarding can be used.
    ///      Note: `trustedModuleSetup` is the Sail-deployed SafeModuleEnabler (the `to` target
    ///      embedded in `safeInitializer`), NOT a canonical Safe address.
    function _printAllowlistReminder(address safeModuleEnabler) internal pure {
        console2.log("=== POST-DEPLOY: allowlist via 48h timelock (onlyTimelock setters) ===");
        console2.log("setTrustedSafeFactory      :", SafeConstants.SAFE_PROXY_FACTORY_1_4_1);
        console2.log("setTrustedSafeSingleton    :", SafeConstants.SAFE_SINGLETON_1_4_1);
        console2.log("setTrustedModuleSetup      :", safeModuleEnabler);
        console2.log("setTrustedSafeProxyCodehash: capture extcodehash of a SafeProxy on-chain");
        console2.log("  (SafeConstants.SAFE_PROXY_CODEHASH_1_4_1 is bytes32(0) until captured)");
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
        // Constitutional cap in SailGovernance is 0.01 ether — keep the default at-or-below.
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
        try vm.envUint(key) returns (uint256 v) { return v; }
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
        console2.log("=== Sail core deploy (CREATE2, global salt - same address every chain) ===");
        console2.log("NOTE: config below MUST be identical on every chain or addresses will differ.");
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

        // Deterministic-deployment metadata: records that addresses are CREATE2-derived with a
        // global salt and are therefore identical across all chains deployed with the same config.
        vm.serializeString(k, "deploymentMode", "create2-global-salt");
        vm.serializeAddress(k, "create2Factory", CREATE2_FACTORY);

        // addresses
        vm.serializeAddress(k, "safeModuleEnabler",  address(d.safeModuleEnabler));
        vm.serializeAddress(k, "governance",         address(d.governance));
        vm.serializeAddress(k, "timelock",           address(d.timelock));
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
