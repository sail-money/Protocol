// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script, console2} from "forge-std/Script.sol";

import {ApproveAndCallBatchPermission} from "../../contracts/templates/ApproveAndCallBatchPermission.sol";
import {BorrowPermission}              from "../../contracts/templates/BorrowPermission.sol";
import {DepositPermission}             from "../../contracts/templates/DepositPermission.sol";
import {SwapPermission}                from "../../contracts/templates/SwapPermission.sol";
import {SwapPermissionNoOracle}        from "../../contracts/templates/SwapPermissionNoOracle.sol";
import {TransferPermission}            from "../../contracts/templates/TransferPermission.sol";
import {WithdrawPermission}            from "../../contracts/templates/WithdrawPermission.sol";

/// @notice Offline CREATE2 address preflight for the shared templates. No RPC, no broadcast.
///
///         Prints, for every shared template, the CREATE2 address the CURRENT working tree would
///         produce under the salt DeploySharedTemplates uses, next to the address that is live on
///         all 12 chains today. A mismatch on an already-deployed template means this working tree
///         no longer reproduces the live bytecode (typically a solc metadata-hash drift), and a
///         `--target templates-shared` run would deploy a duplicate rather than reuse it.
///
///         Run: forge script script/templates/PredictSharedTemplates.s.sol:PredictSharedTemplates
contract PredictSharedTemplates is Script {
    // Canonical live addresses (deployments/deployments.json → canonicalAddresses).
    address internal constant KERNEL   = 0x38b508756c976e876EFF05a29E731A4d348BA6ED;
    address internal constant AUTHOR   = 0xB01dCE443d052e44b7D13726c0EC9fFB7f5815B6; // deployer EOA

    address internal constant LIVE_APPROVE_AND_CALL_BATCH = 0x0535A4D51333484ef583103DAB1a9449756ab732;
    address internal constant LIVE_BORROW                 = 0x3e2666051599223cEAb10De55C89A0842857d8AF;
    address internal constant LIVE_DEPOSIT                = 0xBfB5e13a97b12Ee89d2F2b9B65eCf7e0E371911f;
    address internal constant LIVE_SWAP                   = 0x35cEEa0db96997Cc3CF3beB42FFa36A499342F7C;
    address internal constant LIVE_SWAP_NO_ORACLE         = 0x34Ba96CbEd1f46c88A5265E645DC5fe41662b519;
    address internal constant LIVE_TRANSFER               = 0xda909a1CC584fb7559Ce4A828b008B473Da095e1;
    address internal constant LIVE_WITHDRAW_V1            = 0xF5eF5dda450a130e3020d54f565E830e4a7531f8;

    function run() external view {
        bytes memory ctorArgs = abi.encode(KERNEL, AUTHOR);

        console2.log("=== CREATE2 preflight: current working tree vs live addresses ===");
        console2.log("kernel:", KERNEL);
        console2.log("author:", AUTHOR);
        console2.log("");

        _row("ApproveAndCallBatch", keccak256("sail.template.approveandcallbatch.v1"),
            abi.encodePacked(type(ApproveAndCallBatchPermission).creationCode, ctorArgs), LIVE_APPROVE_AND_CALL_BATCH);
        _row("Borrow", keccak256("sail.template.borrow.v1"),
            abi.encodePacked(type(BorrowPermission).creationCode, ctorArgs), LIVE_BORROW);
        _row("Deposit", keccak256("sail.template.deposit.v1"),
            abi.encodePacked(type(DepositPermission).creationCode, ctorArgs), LIVE_DEPOSIT);
        _row("Swap", keccak256("sail.template.swap.v1"),
            abi.encodePacked(type(SwapPermission).creationCode, ctorArgs), LIVE_SWAP);
        _row("SwapNoOracle", keccak256("sail.template.swapnooracle.v1"),
            abi.encodePacked(type(SwapPermissionNoOracle).creationCode, ctorArgs), LIVE_SWAP_NO_ORACLE);
        _row("Transfer", keccak256("sail.template.transfer.v1"),
            abi.encodePacked(type(TransferPermission).creationCode, ctorArgs), LIVE_TRANSFER);

        console2.log("");
        console2.log("-- WithdrawPermission: old v1 salt (must NOT be reused) --");
        _row("Withdraw(v1 salt, new src)", keccak256("sail.template.withdraw.v1"),
            abi.encodePacked(type(WithdrawPermission).creationCode, ctorArgs), LIVE_WITHDRAW_V1);

        console2.log("");
        console2.log("-- WithdrawPermission: NEW v2 salt (the address to deploy) --");
        address predictedV2 = vm.computeCreate2Address(
            keccak256("sail.template.withdraw.v2"),
            keccak256(abi.encodePacked(type(WithdrawPermission).creationCode, ctorArgs)),
            CREATE2_FACTORY
        );
        console2.log("Withdraw v2 predicted:", predictedV2);
        console2.log("initCodeHash:", vm.toString(
            keccak256(abi.encodePacked(type(WithdrawPermission).creationCode, ctorArgs))
        ));
        console2.log("initCode length:",
            abi.encodePacked(type(WithdrawPermission).creationCode, ctorArgs).length);
    }

    function _row(string memory label, bytes32 salt, bytes memory initCode, address live) internal view {
        address predicted = vm.computeCreate2Address(salt, keccak256(initCode), CREATE2_FACTORY);
        console2.log(label);
        console2.log("   predicted:", predicted);
        console2.log("   live     :", live);
        console2.log(predicted == live ? "   MATCH" : "   *** MISMATCH ***");
    }
}
