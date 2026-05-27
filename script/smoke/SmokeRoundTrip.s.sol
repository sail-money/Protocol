// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script, console2}        from "forge-std/Script.sol";
import {ManifestIO}              from "../lib/ManifestIO.sol";
import {SailKernel}              from "../../contracts/core/SailKernel.sol";
import {MandateFactory}       from "../../contracts/factory/MandateFactory.sol";
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
    function enableModule(address module) external;
    function isModuleEnabled(address module) external view returns (bool);
    function getOwners() external view returns (address[] memory);
}

interface ISafeModuleEnable {
    function enable(address module) external;
}

/// @notice End-to-end smoke against a live deploy:
///         1. Create a fresh Safe via SafeProxyFactory (kernel pre-installed as module via setup).
///         2. Have the Safe call `kernel.registerAccount(deployer, deployer, addr(0))`.
///         3. Fund the Safe with a tiny amount of ETH (gas for the transfer).
///         4. `factory.deployAndAttach(safe, transferTargetImpl, salt, initData, kernelSig)`
///            with the deployer as the only allowed recipient.
///         5. `kernel.dispatch(safe, clone, deployer, transferAmount, "", managerSig, deadline)`
///            — ETH flows out of the Safe back to the deployer.
///
///         Reads addresses from `deployments/<chainId>/{core,templates.standalone}.json`.
///         Required env: DEPLOYER_PRIVATE_KEY, DEPLOYER_ADDRESS, SAFE_PROXY_FACTORY, SAFE_SINGLETON.
contract SmokeRoundTrip is Script {
    uint256 internal constant FUND_AMOUNT     = 50_000_000_000_000;     // 0.00005 ETH — used as tx value
    uint256 internal constant TRANSFER_AMOUNT = 20_000_000_000_000;     // 0.00002 ETH — sent back via dispatch
    uint256 internal constant SAFE_TX_GAS     = 200_000;

    function run() external {
        // -- load manifest addresses
        uint256 chainId = block.chainid;
        address kernelAddr      = ManifestIO.readAddress(chainId, "core", ".kernel");
        address factoryAddr     = ManifestIO.readAddress(chainId, "core", ".mandateFactory");
        address transferImpl    = ManifestIO.readAddress(chainId, "templates.standalone", ".transferTarget");

        SailKernel kernel        = SailKernel(kernelAddr);
        MandateFactory factory = MandateFactory(payable(factoryAddr));

        address deployer = vm.envAddress("DEPLOYER_ADDRESS");
        uint256 pk       = vm.envUint("DEPLOYER_PRIVATE_KEY");

        address safeFactory = vm.envAddress("SAFE_PROXY_FACTORY");
        address singleton   = vm.envAddress("SAFE_SINGLETON");
        address moduleEnabler = ManifestIO.readAddress(chainId, "core", ".safeModuleEnabler");

        console2.log("=== Sail E2E smoke ===");
        console2.log("chainId          :", chainId);
        console2.log("deployer         :", deployer);
        console2.log("kernel           :", kernelAddr);
        console2.log("factory          :", factoryAddr);
        console2.log("transferImpl     :", transferImpl);
        console2.log("safeFactory      :", safeFactory);
        console2.log("singleton        :", singleton);
        console2.log("moduleEnabler    :", moduleEnabler);

        // ── 1. Deploy Safe with kernel pre-enabled as a module ──────────────────
        address payable safe;
        {
            address[] memory owners = new address[](1);
            owners[0] = deployer;

            bytes memory enableData = abi.encodeCall(ISafeModuleEnable.enable, (kernelAddr));
            bytes memory setupCall = abi.encodeCall(
                ISafe.setup,
                (
                    owners,
                    1,                   // threshold
                    moduleEnabler,       // to: delegatecalled in setup
                    enableData,          // data: enable(kernel)
                    address(0),          // fallback handler
                    address(0),          // payment token
                    0,                   // payment
                    payable(address(0))  // payment receiver
                )
            );
            uint256 saltNonce = uint256(keccak256(abi.encode(deployer, block.timestamp, "sail-smoke")));

            vm.startBroadcast(pk);
            safe = payable(
                ISafeProxyFactory(safeFactory).createProxyWithNonce(singleton, setupCall, saltNonce)
            );
            vm.stopBroadcast();
        }
        console2.log("safe deployed    :", safe);
        require(ISafe(safe).isModuleEnabled(kernelAddr), "kernel module not enabled on Safe");

        // ── 2. Register the Safe with the kernel (ECDSA-signed Safe tx) ─────────
        {
            bytes memory regCall = abi.encodeCall(
                SailKernel.registerAccount,
                (deployer, deployer, address(0), address(0))
            );

            uint256 safeNonce = ISafe(safe).nonce();
            bytes32 txHash = ISafe(safe).getTransactionHash(
                kernelAddr, 0, regCall, 0, SAFE_TX_GAS,
                0, 0, address(0), address(0), safeNonce
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, txHash);
            bytes memory sig = abi.encodePacked(r, s, v);

            vm.startBroadcast(pk);
            bool ok = ISafe(safe).execTransaction(
                kernelAddr,
                0,
                regCall,
                0,            // operation = CALL
                SAFE_TX_GAS,
                0,
                0,
                address(0),
                payable(address(0)),
                sig
            );
            vm.stopBroadcast();
            require(ok, "Safe.execTransaction (registerAccount) failed");
        }
        require(kernel.registered(safe), "kernel did not register Safe");
        console2.log("Safe registered with kernel");

        // ── 3. Fund the Safe with a small amount of ETH ─────────────────────────
        vm.startBroadcast(pk);
        (bool funded,) = safe.call{value: FUND_AMOUNT}("");
        vm.stopBroadcast();
        require(funded, "funding transfer failed");
        require(safe.balance >= TRANSFER_AMOUNT, "safe under-funded");
        console2.log("safe balance     :", safe.balance);

        // ── 4. deployAndAttach a TransferTargetPermission clone ─────────────────
        bytes32 salt = keccak256(abi.encode(safe, transferImpl, "smoke-1"));
        address predicted;
        {
            // predictCloneAddress is namespaced by msg.sender — predict as the EOA
            // that will call deployAndAttach (the deployer).
            vm.prank(deployer);
            predicted = factory.predictCloneAddress(transferImpl, salt);
            console2.log("predicted clone  :", predicted);

            address[] memory recipients = new address[](1);
            recipients[0] = deployer;
            address[] memory tokens = new address[](0); // empty: only ETH transfers
            bytes memory initData = abi.encodeCall(
                TransferTargetPermission.initialize,
                (recipients, tokens, TRANSFER_AMOUNT, deployer)
            );

            uint256 signerNonce = kernel.signerNonces(safe);
            uint256 kDeadline   = block.timestamp + 1 days;
            bytes32 structHash  = keccak256(abi.encode(
                kernel.REGISTER_PERMISSION_TYPEHASH(),
                safe,
                predicted,
                signerNonce,
                kDeadline
            ));
            bytes32 digest      = kernel.hashTypedDataV4(structHash);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
            bytes memory kernelSig = abi.encodePacked(r, s, v);

            vm.startBroadcast(pk);
            address clone = factory.deployAndAttach(safe, transferImpl, salt, initData, kDeadline, kernelSig);
            vm.stopBroadcast();

            require(clone == predicted, "predicted clone mismatch");
            console2.log("clone deployed   :", clone);
        }

        // Sanity: clone is initialized and registered.
        TransferTargetPermission perm = TransferTargetPermission(predicted);
        require(perm.initialized(), "clone not initialized");
        require(perm.permissionSigner() == deployer, "wrong permissionSigner");
        require(perm.maxAmountPerTx() == TRANSFER_AMOUNT, "wrong cap");
        require(perm.isAllowedRecipient(deployer), "deployer not allowlisted");

        // ── 5. Dispatch an ETH transfer from Safe → deployer ────────────────────
        uint256 preDeployerBal = deployer.balance;
        uint256 preSafeBal     = safe.balance;
        {
            uint256 managerNonce = kernel.managerNonces(safe);
            uint256 deadline = block.timestamp + 600;
            bytes memory emptyData = "";
            bytes32 structHash = keccak256(abi.encode(
                kernel.DISPATCH_TYPEHASH(),
                safe,
                predicted,
                deployer,
                TRANSFER_AMOUNT,
                keccak256(emptyData),
                managerNonce,
                deadline
            ));
            bytes32 digest = kernel.hashTypedDataV4(structHash);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
            bytes memory managerSig = abi.encodePacked(r, s, v);

            vm.startBroadcast(pk);
            kernel.dispatch(safe, predicted, deployer, TRANSFER_AMOUNT, emptyData, managerSig, deadline);
            vm.stopBroadcast();
        }

        require(safe.balance == preSafeBal - TRANSFER_AMOUNT, "safe balance mismatch after dispatch");
        console2.log("transfer dispatched. delta safe :", int256(preSafeBal) - int256(safe.balance));
        console2.log("                    delta wallet:", int256(deployer.balance) - int256(preDeployerBal));
        console2.log("OK: end-to-end round-trip verified");
    }
}
