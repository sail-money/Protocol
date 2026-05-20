// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script, console2}        from "forge-std/Script.sol";
import {ManifestIO}              from "../lib/ManifestIO.sol";
import {SailKernel}              from "../../contracts/core/SailKernel.sol";
import {PermissionFactory}       from "../../contracts/factory/PermissionFactory.sol";
import {TransferTargetPermission} from "../../contracts/templates/TransferTargetPermission.sol";

interface ISafeProxyFactory {
    function createProxyWithNonce(address singleton, bytes memory initializer, uint256 saltNonce)
        external returns (address proxy);
}

interface ISafe {
    function setup(
        address[] calldata _owners,
        uint256 _threshold,
        address to,
        bytes calldata data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    ) external;

    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes calldata signatures
    ) external payable returns (bool);

    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) external view returns (bytes32);

    function nonce() external view returns (uint256);
    function isModuleEnabled(address module) external view returns (bool);
}

interface ISafeModuleEnable {
    function enable(address module) external;
}

/// @notice E2E permission gating test on the live deploy.
///
///         Operating modes:
///           • "Fresh" mode: SAFE_ADDR env unset → deploy a new Safe, register, fund, attach.
///           • "Resume" mode: SAFE_ADDR env set → reuse that Safe. Skip steps already done
///             (checked via on-chain state queries: kernel.registered, safe.balance,
///             kernel.signerNonces for permission attachment).
///
///         Broadcast strategy (works around forge script's inability to estimate gas
///         for transactions that revert on-chain — eth_estimateGas reverts and forge has
///         no fallback gas-limit setting):
///
///           • Setup + Happy (A.1): broadcast via vm.broadcast (cleanly estimable).
///           • Denials (A.2–A.5): SIMULATED only inside this script, no vm.broadcast.
///             The script logs the signed kernel calldata for each so a follow-up
///             `cast send --gas-limit X` from the bash wrapper can broadcast them on
///             chain with an explicit gas cap.
///
///         Required env: DEPLOYER_PRIVATE_KEY, DEPLOYER_ADDRESS,
///                       AGENT_PRIVATE_KEY,    AGENT_ADDRESS,
///                       SAFE_PROXY_FACTORY,   SAFE_SINGLETON.
///         Optional env: SAFE_ADDR (resume), CLONE_ADDR (resume).
contract PermissionDenialE2E is Script {
    // ── tunables ────────────────────────────────────────────────────────────
    uint256 internal constant FUND_AMOUNT     = 80_000_000_000_000;  // 0.00008 ETH
    uint256 internal constant TRANSFER_AMOUNT = 20_000_000_000_000;  // 0.00002 ETH (cap)
    uint256 internal constant SAFE_TX_GAS     = 200_000;
    address internal constant FORBIDDEN_RECIPIENT = 0x000000000000000000000000000000000000dEaD;

    // ── resolved state ──────────────────────────────────────────────────────
    SailKernel        internal kernel;
    PermissionFactory internal factory;
    address           internal transferImpl;
    address           internal moduleEnabler;

    address           internal deployer;
    uint256           internal deployerPk;
    address           internal agent;
    uint256           internal agentPk;

    address payable   internal safe;
    address           internal clone;

    function run() external {
        _loadConfig();
        _logHeader();
        _ensureSafe();
        _ensureRegistered();
        _ensureFunded();
        _ensurePermissionAttached();
        _runHappy_A1();
        _logDenialCalldata_A2_forbiddenRecipient();
        _logDenialCalldata_A3_overCap();
        _logDenialCalldata_A4_staleNonce();
        _logDenialCalldata_A5_expiredDeadline();
        _finalSummary();
    }

    // ────────────────────────────────────────────────────────────────────────
    // Config
    // ────────────────────────────────────────────────────────────────────────

    function _loadConfig() internal {
        uint256 chainId = block.chainid;
        kernel        = SailKernel(ManifestIO.readAddress(chainId, "core", ".kernel"));
        factory       = PermissionFactory(payable(ManifestIO.readAddress(chainId, "core", ".permissionFactory")));
        transferImpl  = ManifestIO.readAddress(chainId, "templates.standalone", ".transferTarget");
        moduleEnabler = ManifestIO.readAddress(chainId, "core", ".safeModuleEnabler");

        deployer    = vm.envAddress("DEPLOYER_ADDRESS");
        deployerPk  = vm.envUint("DEPLOYER_PRIVATE_KEY");
        agent       = vm.envAddress("AGENT_ADDRESS");
        agentPk     = vm.envUint("AGENT_PRIVATE_KEY");

        // Resume mode if SAFE_ADDR is provided.
        safe = payable(vm.envOr("SAFE_ADDR", address(0)));
        clone = vm.envOr("CLONE_ADDR", address(0));
    }

    function _logHeader() internal view {
        console2.log("=========================================================");
        console2.log("Sail Permission Gating E2E (Phase 1: TransferTarget)");
        console2.log("=========================================================");
        console2.log("chainId          :", block.chainid);
        console2.log("kernel           :", address(kernel));
        console2.log("factory          :", address(factory));
        console2.log("transferImpl     :", transferImpl);
        console2.log("moduleEnabler    :", moduleEnabler);
        console2.log("deployer (owner) :", deployer);
        console2.log("agent (manager)  :", agent);
        console2.log("deployer bal     :", deployer.balance);
        console2.log("agent bal        :", agent.balance);
        if (safe != address(0))  console2.log("RESUME safe      :", safe);
        if (clone != address(0)) console2.log("RESUME clone     :", clone);
        console2.log("---------------------------------------------------------");
    }

    // ────────────────────────────────────────────────────────────────────────
    // Setup steps (each idempotent: only acts if the step isn't already done)
    // ────────────────────────────────────────────────────────────────────────

    function _ensureSafe() internal {
        if (safe != address(0)) {
            require(ISafe(safe).isModuleEnabled(address(kernel)), "[setup] resume safe: kernel not enabled");
            console2.log("[setup] reusing safe        :", safe);
            return;
        }
        address safeFactory = vm.envAddress("SAFE_PROXY_FACTORY");
        address singleton   = vm.envAddress("SAFE_SINGLETON");

        address[] memory owners = new address[](1);
        owners[0] = deployer;

        bytes memory enableData = abi.encodeCall(ISafeModuleEnable.enable, (address(kernel)));
        bytes memory setupCall = abi.encodeCall(
            ISafe.setup,
            (owners, 1, moduleEnabler, enableData,
             address(0), address(0), 0, payable(address(0)))
        );
        uint256 saltNonce = uint256(keccak256(
            abi.encode(deployer, block.timestamp, "sail-denial-e2e", block.number)
        ));

        vm.startBroadcast(deployerPk);
        safe = payable(
            ISafeProxyFactory(safeFactory).createProxyWithNonce(singleton, setupCall, saltNonce)
        );
        vm.stopBroadcast();
        require(ISafe(safe).isModuleEnabled(address(kernel)), "kernel module not enabled");
        console2.log("[setup] safe deployed       :", safe);
    }

    function _ensureRegistered() internal {
        if (kernel.registered(safe)) {
            console2.log("[setup] safe already registered with kernel");
            return;
        }
        bytes memory regCall = abi.encodeCall(
            SailKernel.registerAccount,
            (deployer, agent, address(0))
        );
        uint256 safeNonce = ISafe(safe).nonce();
        bytes32 txHash = ISafe(safe).getTransactionHash(
            address(kernel), 0, regCall, 0, SAFE_TX_GAS,
            0, 0, address(0), address(0), safeNonce
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(deployerPk, txHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.startBroadcast(deployerPk);
        bool ok = ISafe(safe).execTransaction(
            address(kernel), 0, regCall, 0, SAFE_TX_GAS,
            0, 0, address(0), payable(address(0)), sig
        );
        vm.stopBroadcast();
        require(ok, "Safe.execTransaction(registerAccount) failed");
        require(kernel.registered(safe), "kernel.registered(safe) = false");
        console2.log("[setup] safe registered with kernel; manager = agent");
    }

    function _ensureFunded() internal {
        if (safe.balance >= TRANSFER_AMOUNT) {
            console2.log("[setup] safe already funded :", safe.balance);
            return;
        }
        vm.startBroadcast(deployerPk);
        (bool funded,) = safe.call{value: FUND_AMOUNT}("");
        vm.stopBroadcast();
        require(funded, "safe funding failed");
        console2.log("[setup] safe funded         :", safe.balance);
    }

    function _ensurePermissionAttached() internal {
        if (clone != address(0)) {
            // Trust the supplied address; basic sanity check.
            require(TransferTargetPermission(clone).initialized(), "[setup] resume clone: not initialized");
            console2.log("[setup] reusing permission  :", clone);
            return;
        }
        bytes32 salt = keccak256(abi.encode(safe, transferImpl, "denial-e2e-1"));
        address predicted;
        vm.prank(deployer);
        predicted = factory.predictCloneAddress(transferImpl, salt);

        address[] memory recipients = new address[](1);
        recipients[0] = deployer;
        address[] memory tokens = new address[](0);
        bytes memory initData = abi.encodeCall(
            TransferTargetPermission.initialize,
            (recipients, tokens, TRANSFER_AMOUNT, deployer)
        );

        uint256 signerNonce = kernel.signerNonces(safe);
        bytes32 structHash  = keccak256(abi.encode(
            kernel.REGISTER_PERMISSION_TYPEHASH(),
            safe,
            predicted,
            signerNonce
        ));
        bytes32 digest      = kernel.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(deployerPk, digest);
        bytes memory kernelSig = abi.encodePacked(r, s, v);

        vm.startBroadcast(deployerPk);
        clone = factory.deployAndAttach(safe, transferImpl, salt, initData, kernelSig);
        vm.stopBroadcast();
        require(clone == predicted, "predicted clone mismatch");
        console2.log("[setup] permission attached :", clone);
    }

    // ────────────────────────────────────────────────────────────────────────
    // A.1 — happy path: broadcast normally (succeeds, gas estimable)
    // ────────────────────────────────────────────────────────────────────────

    function _runHappy_A1() internal {
        uint256 nonceBefore = kernel.managerNonces(safe);
        uint256 safeBalBefore = safe.balance;
        uint256 deployerBalBefore = deployer.balance;

        uint256 deadline = block.timestamp + 600;
        bytes memory data = "";
        bytes memory sig = _signDispatch(agentPk, clone, deployer, TRANSFER_AMOUNT, data, nonceBefore, deadline);

        vm.broadcast(agentPk);
        kernel.dispatch(safe, clone, deployer, TRANSFER_AMOUNT, data, sig, deadline);

        require(kernel.managerNonces(safe) == nonceBefore + 1, "A.1: nonce not advanced");
        require(safe.balance == safeBalBefore - TRANSFER_AMOUNT, "A.1: safe balance wrong");
        require(deployer.balance == deployerBalBefore + TRANSFER_AMOUNT, "A.1: deployer balance delta wrong");
        console2.log("[A.1] OK happy path broadcast: safe -> deployer, amount =", TRANSFER_AMOUNT);
    }

    // ────────────────────────────────────────────────────────────────────────
    // A.2-A.5: log signed kernel-calldata for bash to broadcast via cast send.
    //
    // Each emits a parseable line:
    //   DENIAL_CALLDATA <label> <full kernel calldata as 0x-hex>
    //
    // The bash wrapper extracts these lines and runs:
    //   cast send --gas-limit 250000 --private-key $AGENT_PK $KERNEL <calldata>
    // ────────────────────────────────────────────────────────────────────────

    function _logDenialCalldata_A2_forbiddenRecipient() internal view {
        uint256 nonce = kernel.managerNonces(safe);
        uint256 deadline = block.timestamp + 600;
        bytes memory data = "";
        bytes memory sig = _signDispatch(agentPk, clone, FORBIDDEN_RECIPIENT, TRANSFER_AMOUNT, data, nonce, deadline);
        bytes memory call = abi.encodeCall(
            SailKernel.dispatch,
            (safe, clone, FORBIDDEN_RECIPIENT, TRANSFER_AMOUNT, data, sig, deadline)
        );
        console2.log("DENIAL_CALLDATA A.2 (forbidden recipient, expect PermissionDenied)");
        console2.logBytes(call);
    }

    function _logDenialCalldata_A3_overCap() internal view {
        uint256 nonce = kernel.managerNonces(safe);
        uint256 deadline = block.timestamp + 600;
        bytes memory data = "";
        uint256 overCap = TRANSFER_AMOUNT + 1;
        bytes memory sig = _signDispatch(agentPk, clone, deployer, overCap, data, nonce, deadline);
        bytes memory call = abi.encodeCall(
            SailKernel.dispatch,
            (safe, clone, deployer, overCap, data, sig, deadline)
        );
        console2.log("DENIAL_CALLDATA A.3 (over-cap, expect PermissionDenied)");
        console2.logBytes(call);
    }

    function _logDenialCalldata_A4_staleNonce() internal view {
        uint256 nonceCurrent = kernel.managerNonces(safe);
        require(nonceCurrent >= 1, "A.4 requires at least one prior dispatch");
        uint256 staleNonce = nonceCurrent - 1;
        uint256 deadline = block.timestamp + 600;
        bytes memory data = "";
        bytes memory sig = _signDispatch(agentPk, clone, deployer, TRANSFER_AMOUNT, data, staleNonce, deadline);
        bytes memory call = abi.encodeCall(
            SailKernel.dispatch,
            (safe, clone, deployer, TRANSFER_AMOUNT, data, sig, deadline)
        );
        console2.log("DENIAL_CALLDATA A.4 (stale nonce, expect InvalidManagerSignature)");
        console2.logBytes(call);
    }

    function _logDenialCalldata_A5_expiredDeadline() internal view {
        uint256 nonce = kernel.managerNonces(safe);
        uint256 deadline = block.timestamp - 1; // expired now; valid window when bash broadcasts
        bytes memory data = "";
        bytes memory sig = _signDispatch(agentPk, clone, deployer, TRANSFER_AMOUNT, data, nonce, deadline);
        bytes memory call = abi.encodeCall(
            SailKernel.dispatch,
            (safe, clone, deployer, TRANSFER_AMOUNT, data, sig, deadline)
        );
        console2.log("DENIAL_CALLDATA A.5 (expired deadline, expect DeadlineExpired)");
        console2.logBytes(call);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Helpers
    // ────────────────────────────────────────────────────────────────────────

    function _signDispatch(
        uint256 pk,
        address permission,
        address target,
        uint256 value,
        bytes memory data,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encode(
            kernel.DISPATCH_TYPEHASH(),
            safe,
            permission,
            target,
            value,
            keccak256(data),
            nonce,
            deadline
        ));
        bytes32 digest = kernel.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _finalSummary() internal view {
        console2.log("---------------------------------------------------------");
        console2.log("safe              :", safe);
        console2.log("clone (perm)      :", clone);
        console2.log("safe balance      :", safe.balance);
        console2.log("managerNonces     :", kernel.managerNonces(safe));
        console2.log("");
        console2.log("Setup + A.1 broadcast complete.");
        console2.log("Run scripts/run_denials.sh to broadcast A.2-A.5 via cast send.");
    }
}
