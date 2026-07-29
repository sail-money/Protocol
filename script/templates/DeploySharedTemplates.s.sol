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

/// @notice Shared permission template deployment via deterministic CREATE2 (global, chain-independent salts).
///
///         ── Same address on every chain ──────────────────────────────────────────────────────
///         Every template is deployed through the standard deterministic CREATE2 factory
///         (Arachnid / Nick's factory) at 0x4e59b44847b379578588920cA78FbF26c0B4956C using a
///         GLOBAL salt per template (NO chainId mixed in). A CREATE2 address is
///         `keccak256(0xff ++ factory ++ salt ++ keccak256(initCode))[12:]`, so it is identical
///         across chains iff `initCode` (creation bytecode ++ ABI-encoded constructor args) is
///         identical across chains. Both constructor args are chain-independent:
///           • `kernel` is the canonical CREATE2 core kernel — identical on every chain
///             (read back from `deployments/<chainId>/core.json`), and
///           • `author` is the deployer EOA by default (same on every chain), or an explicit
///             `TEMPLATE_AUTHOR` that the deployer MUST keep identical across chains.
///         The per-chain EIP712 domain separator each template computes is a RUNTIME immutable; it
///         does not enter the init code, so it does not perturb the CREATE2 address (same reasoning
///         that lets the EIP712-using SailKernel land at one address everywhere).
///
///         ── CRITICAL: identical inputs across chains ─────────────────────────────────────────
///         The same-address property holds ONLY if the core was deployed with identical config
///         (so the kernel address matches) and `author` is identical on every chain. A differing
///         kernel or author changes a template's initCode and therefore its address on that chain.
///
///         ── Verification ─────────────────────────────────────────────────────────────────────
///         Each deployment computes its predicted CREATE2 address up front and asserts the factory
///         produced code at exactly that address — failing loudly on any mismatch. Idempotent: a
///         re-run reuses code already present at the predicted address.
///
///         Each template records an `author` for tooling-layer attribution (the kernel never reads
///         it). The author defaults to the deployer; override via the `TEMPLATE_AUTHOR` env var.
///
///         Writes `deployments/<chainId>/templates.shared.json`.
///
///         Env knobs:
///           DEPLOYER_PRIVATE_KEY   required
///           DEPLOYER_ADDRESS       required
///           TEMPLATE_AUTHOR        default: deployer (MUST be identical across chains)
///           SAIL_DEPLOY_FRESH=1    allow overwriting an existing templates manifest
contract DeploySharedTemplates is Script {
    string internal constant SCHEMA = "sail.deploy.templates.shared";
    string internal constant TARGET = "templates.shared";

    // The standard deterministic CREATE2 factory (Arachnid / Nick's factory) at
    // 0x4e59b44847b379578588920cA78FbF26c0B4956C is inherited from forge-std as the constant
    // `CREATE2_FACTORY` (CommonBase). It is present at that address on every target chain;
    // the factory call in `_deploy2` reverts if it is somehow absent.

    // ── Global, versioned, chain-independent salts ────────────────────────────────────────────
    // One salt per template. NO chainId is mixed in — that is the whole point: a global salt with
    // identical initCode yields the SAME address on every chain. Bump the version suffix (`.v1` →
    // `.v2`) only when a deliberate address rotation is wanted (e.g. new reviewed bytecode that
    // must NOT collide with the previous deployment's address).
    bytes32 internal constant SALT_APPROVE_AND_CALL_BATCH = keccak256("sail.template.approveandcallbatch.v1");
    bytes32 internal constant SALT_BORROW                 = keccak256("sail.template.borrow.v1");
    bytes32 internal constant SALT_DEPOSIT                = keccak256("sail.template.deposit.v1");
    bytes32 internal constant SALT_SWAP                   = keccak256("sail.template.swap.v1");
    bytes32 internal constant SALT_SWAP_NO_ORACLE         = keccak256("sail.template.swapnooracle.v1");
    bytes32 internal constant SALT_TRANSFER               = keccak256("sail.template.transfer.v1");
    // .v2: deliberate address rotation — WithdrawPermission was rewritten from an ERC-20
    // single-recipient gate to the vault/pool exit permission. The old bytecode remains live at
    // the .v1 address (0xF5eF5dda450a130e3020d54f565E830e4a7531f8) on every deployed chain; the
    // new contract MUST NOT collide with it.
    bytes32 internal constant SALT_WITHDRAW               = keccak256("sail.template.withdraw.v2");

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
        console2.log("=== Sail shared-templates deploy (CREATE2, global salt - same address every chain) ===");
        console2.log("NOTE: kernel + author MUST be identical on every chain or addresses will differ.");
        console2.log("deployer :", deployer);
        console2.log("author   :", author);
        console2.log("kernel   :", d.kernel);

        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(pk);

        // Every template shares the same constructor shape: (address kernel, address author).
        // The kernel is the canonical CREATE2 core address and author is chain-independent, so
        // each template's initCode — and therefore its CREATE2 address — is identical everywhere.
        bytes memory ctorArgs = abi.encode(d.kernel, author);

        d.approveAndCallBatch = ApproveAndCallBatchPermission(_deploy2(
            SALT_APPROVE_AND_CALL_BATCH,
            abi.encodePacked(type(ApproveAndCallBatchPermission).creationCode, ctorArgs),
            "ApproveAndCallBatchPermission"
        ));
        d.borrow = BorrowPermission(_deploy2(
            SALT_BORROW,
            abi.encodePacked(type(BorrowPermission).creationCode, ctorArgs),
            "BorrowPermission"
        ));
        d.deposit = DepositPermission(_deploy2(
            SALT_DEPOSIT,
            abi.encodePacked(type(DepositPermission).creationCode, ctorArgs),
            "DepositPermission"
        ));
        d.swap = SwapPermission(_deploy2(
            SALT_SWAP,
            abi.encodePacked(type(SwapPermission).creationCode, ctorArgs),
            "SwapPermission"
        ));
        d.swapNoOracle = SwapPermissionNoOracle(_deploy2(
            SALT_SWAP_NO_ORACLE,
            abi.encodePacked(type(SwapPermissionNoOracle).creationCode, ctorArgs),
            "SwapPermissionNoOracle"
        ));
        d.transfer = TransferPermission(_deploy2(
            SALT_TRANSFER,
            abi.encodePacked(type(TransferPermission).creationCode, ctorArgs),
            "TransferPermission"
        ));
        d.withdraw = WithdrawPermission(_deploy2(
            SALT_WITHDRAW,
            abi.encodePacked(type(WithdrawPermission).creationCode, ctorArgs),
            "WithdrawPermission"
        ));

        vm.stopBroadcast();

        _writeManifest(deployer, d);
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

    // -------------------------------------------------------------------------
    // Manifest
    // -------------------------------------------------------------------------

    function _writeManifest(address deployer, Deployment memory d) internal {
        string memory k = "sail-shared-templates";
        ManifestIO.serializeHeader(k, SCHEMA, deployer);

        // Deterministic-deployment metadata: records that addresses are CREATE2-derived with a
        // global salt and are therefore identical across all chains deployed with the same kernel.
        vm.serializeString(k, "deploymentMode", "create2-global-salt");
        vm.serializeAddress(k, "create2Factory", CREATE2_FACTORY);

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
