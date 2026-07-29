// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script, console2} from "forge-std/Script.sol";
import {ManifestIO}       from "../lib/ManifestIO.sol";

import {WithdrawPermission} from "../../contracts/templates/WithdrawPermission.sol";

/// @notice Deploy ONLY the rewritten (vault-exit) WithdrawPermission, under the `.v2` global salt.
///
///         ── Why this exists instead of re-running DeploySharedTemplates ──────────────────────
///         `DeploySharedTemplates` deploys all seven templates. The other six are already live at
///         their canonical addresses on all 12 chains, but THIS WORKING TREE NO LONGER REPRODUCES
///         THEIR BYTECODE: solc's embedded metadata hash has drifted since the original deploy, so
///         a fresh build's initCode — and therefore its CREATE2 address — differs for every one of
///         them. `script/templates/PredictSharedTemplates.s.sol` demonstrates this (all six
///         mismatch). Re-running the shared-template target would therefore NOT be the intended
///         no-op: its `predicted.code.length != 0` reuse check would miss on all six, deploying six
///         duplicate contracts at non-canonical addresses and overwriting
///         `templates.shared.json` with addresses that no downstream consumer knows. This script
///         deploys the one template that actually changed and leaves the other six untouched.
///
///         ── Determinism across all 12 chains ─────────────────────────────────────────────────
///         Address parity across chains holds iff initCode is byte-identical everywhere. Both
///         constructor args are chain-independent (`kernel` is the canonical CREATE2 core kernel,
///         `author` is the deployer EOA), so a SINGLE build produces one initCode good for every
///         chain. To make that guarantee mechanical rather than a hope, this script hard-asserts,
///         before spending any gas:
///           1. `kernel`       == CANONICAL_KERNEL (read back from this chain's core.json),
///           2. `author`       == CANONICAL_AUTHOR,
///           3. initCodeHash   == EXPECTED_INIT_CODE_HASH, and
///           4. predicted addr == EXPECTED_ADDRESS.
///         Any drift in source, compiler settings, or env fails loudly instead of silently landing
///         the template at a different address on one chain. Re-pin the two EXPECTED_* constants
///         (values printed by PredictSharedTemplates) if and only if a deliberate source change is
///         made BEFORE the first chain is broadcast — never mid-campaign.
///
///         ── Idempotent ───────────────────────────────────────────────────────────────────────
///         If code already exists at the predicted address the existing deployment is reused, so a
///         re-run (or a retry after a failed broadcast) is safe.
///
///         Writes `deployments/<chainId>/templates.withdraw.v2.json`. Merge into the canonical
///         registry with `node scripts/apply-withdraw-v2.mjs` once every chain is done.
///
///         Env knobs:
///           DEPLOYER_PRIVATE_KEY   required
///           DEPLOYER_ADDRESS       required
///           TEMPLATE_AUTHOR        default: deployer (MUST equal CANONICAL_AUTHOR)
///           SAIL_DEPLOY_FRESH=1    allow overwriting an existing withdraw.v2 manifest
///           SAIL_DRY_RUN=1         skip the manifest write (set by deploy.sh --dry-run). A
///                                  simulation must not leave behind a manifest: `vm.writeFile`
///                                  runs during simulation too, and a manifest for an address that
///                                  was never broadcast would be indistinguishable from a real
///                                  deploy to scripts/apply-withdraw-v2.mjs and to guardOverwrite.
contract DeployWithdrawPermission is Script {
    string internal constant SCHEMA = "sail.deploy.templates.withdraw.v2";
    string internal constant TARGET = "templates.withdraw.v2";

    /// @dev Deliberate address rotation. WithdrawPermission was rewritten from an ERC-20
    ///      single-recipient transfer gate into the vault / lending-pool exit permission, so the new
    ///      bytecode MUST NOT collide with the old one. The `.v1` deployment stays live and
    ///      untouched at SUPERSEDED_V1 on every chain.
    bytes32 internal constant SALT_WITHDRAW_V2 = keccak256("sail.template.withdraw.v2");

    /// @dev Canonical addresses — deployments/deployments.json → canonicalAddresses / governance.
    address internal constant CANONICAL_KERNEL = 0x38b508756c976e876EFF05a29E731A4d348BA6ED;
    address internal constant CANONICAL_AUTHOR = 0xB01dCE443d052e44b7D13726c0EC9fFB7f5815B6;
    /// @dev The old ERC-20-transfer WithdrawPermission. Recorded for provenance; never redeployed.
    address internal constant SUPERSEDED_V1    = 0xF5eF5dda450a130e3020d54f565E830e4a7531f8;

    /// @dev Frozen build fingerprint. Pinned from the preflight run of
    ///      script/templates/PredictSharedTemplates.s.sol on the branch tip, with
    ///      solc 0.8.26 / via_ir / optimizer_runs 200 / evm_version cancun (foundry.toml).
    ///      A mismatch means the build drifted — STOP and re-run the preflight rather than
    ///      broadcasting a per-chain-divergent address.
    bytes32 internal constant EXPECTED_INIT_CODE_HASH =
        0x633477be1804c86e4aaaeb3765055cddc53e1f1db34407d5d28d281ce02cee9a;
    address internal constant EXPECTED_ADDRESS = 0xB8A6CC40466c0C33a230f87a1EBC368568B96269;

    error KernelMismatch(address got, address want);
    error AuthorMismatch(address got, address want);
    error InitCodeDrift(bytes32 got, bytes32 want);
    error AddressDrift(address got, address want);

    function run() external returns (address withdraw) {
        address deployer = vm.envAddress("DEPLOYER_ADDRESS");
        address author   = _authorOr(deployer);
        bool fresh       = _boolEnv("SAIL_DEPLOY_FRESH");
        ManifestIO.guardOverwrite(block.chainid, TARGET, fresh);

        address kernel = ManifestIO.readAddress(block.chainid, "core", ".kernel");

        console2.log("=== WithdrawPermission v2 deploy (vault exit, CREATE2 global salt) ===");
        console2.log("chainId :", block.chainid);
        console2.log("deployer:", deployer);
        console2.log("author  :", author);
        console2.log("kernel  :", kernel);

        // ── Preflight guards: everything that could break cross-chain parity, checked before gas ──
        if (kernel != CANONICAL_KERNEL) revert KernelMismatch(kernel, CANONICAL_KERNEL);
        if (author != CANONICAL_AUTHOR) revert AuthorMismatch(author, CANONICAL_AUTHOR);

        bytes memory initCode =
            abi.encodePacked(type(WithdrawPermission).creationCode, abi.encode(kernel, author));
        bytes32 initCodeHash = keccak256(initCode);
        if (initCodeHash != EXPECTED_INIT_CODE_HASH) {
            revert InitCodeDrift(initCodeHash, EXPECTED_INIT_CODE_HASH);
        }

        address predicted = vm.computeCreate2Address(SALT_WITHDRAW_V2, initCodeHash, CREATE2_FACTORY);
        if (predicted != EXPECTED_ADDRESS) revert AddressDrift(predicted, EXPECTED_ADDRESS);
        console2.log("predicted:", predicted);

        // ── Deploy (idempotent) ───────────────────────────────────────────────────────────────
        bool alreadyDeployed = predicted.code.length != 0;
        if (alreadyDeployed) {
            console2.log("WithdrawPermission v2 (already deployed):", predicted);
        } else {
            vm.startBroadcast(vm.envUint("DEPLOYER_PRIVATE_KEY"));
            (bool ok, ) = CREATE2_FACTORY.call(abi.encodePacked(SALT_WITHDRAW_V2, initCode));
            require(ok, "CREATE2 deploy failed (factory present?): WithdrawPermission");
            vm.stopBroadcast();
            require(predicted.code.length != 0, "CREATE2 produced no code at predicted address");
            console2.log("WithdrawPermission v2:", predicted);
        }
        withdraw = predicted;

        // ── Post-deploy sanity: the live contract really is bound to the canonical kernel ──────
        require(address(WithdrawPermission(withdraw).kernel()) == CANONICAL_KERNEL, "kernel wiring mismatch");
        require(WithdrawPermission(withdraw).author() == CANONICAL_AUTHOR, "author mismatch on-chain");
        require(
            WithdrawPermission(withdraw).discriminator() == keccak256("WithdrawPermission"),
            "discriminator mismatch"
        );

        _writeManifest(deployer, author, kernel, withdraw, alreadyDeployed);
    }

    function _writeManifest(
        address deployer,
        address author,
        address kernel,
        address withdraw,
        bool alreadyDeployed
    ) internal {
        string memory k = "sail-withdraw-v2";
        ManifestIO.serializeHeader(k, SCHEMA, deployer);

        vm.serializeString(k, "deploymentMode", "create2-global-salt");
        vm.serializeAddress(k, "create2Factory", CREATE2_FACTORY);
        vm.serializeBytes32(k, "salt", SALT_WITHDRAW_V2);
        vm.serializeString(k, "saltPreimage", "sail.template.withdraw.v2");
        vm.serializeBytes32(k, "initCodeHash", EXPECTED_INIT_CODE_HASH);
        vm.serializeAddress(k, "kernel", kernel);
        vm.serializeAddress(k, "author", author);
        vm.serializeBool(k, "reusedExistingCode", alreadyDeployed);
        vm.serializeAddress(k, "supersedesWithdrawV1", SUPERSEDED_V1);
        vm.serializeString(
            k,
            "note",
            "Vault-exit WithdrawPermission (ERC-4626 withdraw/redeem + Aave v2/v3 withdraw). Deployed under the .v2 global salt as a deliberate address rotation; the prior ERC-20-transfer WithdrawPermission remains live at supersedesWithdrawV1 and is not upgraded in place. Deployed standalone via script/templates/DeployWithdrawPermission.s.sol because this tree no longer reproduces the other six templates' live bytecode (solc metadata drift) - see that script's header."
        );
        string memory json = vm.serializeAddress(k, "withdraw", withdraw);

        // A simulation must not leave a manifest behind — see SAIL_DRY_RUN in the header.
        if (_boolEnv("SAIL_DRY_RUN")) {
            console2.log("dry run - manifest NOT written:", ManifestIO.manifestPath(block.chainid, TARGET));
            return;
        }

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
