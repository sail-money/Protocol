// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script, console2}        from "forge-std/Script.sol";
import {ManifestIO}              from "../lib/ManifestIO.sol";
import {SailKernel}              from "../../contracts/core/SailKernel.sol";
import {MandateFactory}       from "../../contracts/factory/MandateFactory.sol";
import {TransferTargetPermission} from "../../contracts/experimental/TransferTargetPermission.sol";

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @notice Phase 3 E2E: cross-permission isolation + revoke + re-attach.
///
///         Reuses the Safe + permissions from Phase 1 (TransferTarget at OLD_TT_CLONE)
///         and Phase 2 (BoundedSwap at BS_CLONE). Adds a NEW TransferTarget configured
///         for USDC ERC-20 transfers.
///
///         Required env: SAFE_ADDR, OLD_TT_CLONE, BS_CLONE,
///                       DEPLOYER_*, AGENT_*.
contract Phase3_Isolation is Script {
    // ── chain constants (Base mainnet) ───────────────────────────────────────
    address internal constant USDC   = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
    address internal constant ROUTER = 0x2626664c2603336E57B271c5C0b26F421741e481;
    address internal constant WETH   = 0x4200000000000000000000000000000000000006;
    uint24  internal constant POOL_FEE = 500;

    // ── tunables ─────────────────────────────────────────────────────────────
    uint256 internal constant ETH_AMT      = 20_000_000_000_000; // C.1 — drains Safe (matches Phase 1 cap)
    uint256 internal constant USDC_CAP     = 50_000;             // C.6 NEW TT cap (50k base units = $0.05)
    uint256 internal constant USDC_AMT     = 50_000;             // C.7 transfer amount (= cap)

    // ── resolved state ───────────────────────────────────────────────────────
    SailKernel        internal kernel;
    MandateFactory internal factory;
    address           internal transferImpl;

    address           internal deployer;
    uint256           internal deployerPk;
    address           internal agent;
    uint256           internal agentPk;

    address payable   internal safe;
    address           internal oldTT;     // Phase 1 TransferTarget clone (ETH mode)
    address           internal bsClone;   // Phase 2 BoundedSwap clone
    address           internal newTT;     // NEW TransferTarget clone (USDC mode, deployed in C.6)

    // signed denial calldatas + their final manager nonce, captured after broadcasts
    bytes internal calldataC2;
    bytes internal calldataC3;
    bytes internal calldataC5;

    function run() external {
        _loadConfig();
        _logHeader();

        _runHappy_C1();        // ETH transfer via OLD TT → success
        _runRevoke_C4();       // owner revokes OLD TT
        _runAttachNew_C6();    // owner attaches NEW TT (USDC mode)
        _runHappy_C7();        // USDC transfer via NEW TT → success

        // After all broadcasts, sim's managerNonces is the final state.
        // Sign denial calldatas now so their nonce matches on-chain post-script.
        _logDenial_C2_ethViaBoundedSwap();
        _logDenial_C3_swapViaNewTT();
        _logDenial_C5_postRevoke();

        _finalSummary();
    }

    // ────────────────────────────────────────────────────────────────────────
    // Config
    // ────────────────────────────────────────────────────────────────────────

    function _loadConfig() internal {
        uint256 chainId = block.chainid;
        kernel       = SailKernel(ManifestIO.readAddress(chainId, "core", ".kernel"));
        factory      = MandateFactory(payable(ManifestIO.readAddress(chainId, "core", ".mandateFactory")));
        transferImpl = ManifestIO.readAddress(chainId, "templates.standalone", ".transferTarget");

        deployer   = vm.envAddress("DEPLOYER_ADDRESS");
        deployerPk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        agent      = vm.envAddress("AGENT_ADDRESS");
        agentPk    = vm.envUint("AGENT_PRIVATE_KEY");

        safe    = payable(vm.envAddress("SAFE_ADDR"));
        oldTT   = vm.envAddress("OLD_TT_CLONE");
        bsClone = vm.envAddress("BS_CLONE");

        require(safe != address(0), "SAFE_ADDR required");
        require(kernel.registered(safe), "safe not registered");

        // newTT may be set if resuming after a partial run
        newTT = vm.envOr("NEW_TT_CLONE", address(0));
    }

    function _logHeader() internal view {
        console2.log("=========================================================");
        console2.log("Sail Phase 3: cross-permission isolation + revoke");
        console2.log("=========================================================");
        console2.log("chainId          :", block.chainid);
        console2.log("safe             :", safe);
        console2.log("oldTT (P1 ETH)   :", oldTT);
        console2.log("bsClone (P2)     :", bsClone);
        if (newTT != address(0)) console2.log("RESUME newTT     :", newTT);
        console2.log("deployer         :", deployer);
        console2.log("agent            :", agent);
        console2.log("safe ETH         :", safe.balance);
        console2.log("safe USDC        :", IERC20(USDC).balanceOf(safe));
        console2.log("managerNonces    :", kernel.managerNonces(safe));
        console2.log("signerNonces     :", kernel.signerNonces(safe));
        console2.log("---------------------------------------------------------");
    }

    // ────────────────────────────────────────────────────────────────────────
    // C.1 — happy ETH transfer via OLD TransferTarget
    // ────────────────────────────────────────────────────────────────────────

    function _runHappy_C1() internal {
        require(safe.balance >= ETH_AMT, "C.1: insufficient Safe ETH");
        uint256 nonce    = kernel.managerNonces(safe);
        uint256 deadline = block.timestamp + 600;
        bytes memory sig = _signDispatch(agentPk, oldTT, deployer, ETH_AMT, "", nonce, deadline);

        vm.broadcast(agentPk);
        kernel.dispatch(safe, oldTT, deployer, ETH_AMT, "", sig, deadline);

        require(kernel.managerNonces(safe) == nonce + 1, "C.1: nonce not advanced");
        console2.log("[C.1] OK ETH transfer via OLD TT, amount =", ETH_AMT);
    }

    // ────────────────────────────────────────────────────────────────────────
    // C.4 — owner revokes OLD TransferTarget
    // ────────────────────────────────────────────────────────────────────────

    function _runRevoke_C4() internal {
        if (kernel.signerNonces(safe) == 0) {
            // Defensive: should never be zero here, but guard against weird state.
        }
        uint256 sNonce = kernel.signerNonces(safe);
        uint256 revokeDeadline = block.timestamp + 1 days;
        bytes32 structHash = keccak256(abi.encode(
            kernel.REVOKE_PERMISSION_TYPEHASH(),
            safe,
            oldTT,
            sNonce,
            revokeDeadline
        ));
        bytes32 digest = kernel.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(deployerPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.broadcast(deployerPk);
        kernel.revokePermission(safe, oldTT, revokeDeadline, sig);

        require(kernel.signerNonces(safe) == sNonce + 1, "C.4: signerNonce not advanced");
        console2.log("[C.4] OK revoked OLD TransferTarget:", oldTT);
    }

    // ────────────────────────────────────────────────────────────────────────
    // C.6 — owner attaches NEW TransferTarget (USDC mode)
    // ────────────────────────────────────────────────────────────────────────

    function _runAttachNew_C6() internal {
        if (newTT != address(0)) {
            require(TransferTargetPermission(newTT).initialized(), "C.6 resume: not initialized");
            console2.log("[C.6] reusing NEW TT:", newTT);
            return;
        }
        bytes32 salt = keccak256(abi.encode(safe, transferImpl, "phase3-tt-usdc-1"));
        address predicted;
        vm.prank(deployer);
        predicted = factory.predictCloneAddress(transferImpl, salt);

        if (predicted.code.length > 0) {
            newTT = predicted;
            console2.log("[C.6] adopting pre-existing clone:", newTT);
            return;
        }

        address[] memory recipients = new address[](1); recipients[0] = deployer;
        address[] memory tokens     = new address[](1); tokens[0]     = USDC;
        bytes memory initData = abi.encodeCall(
            TransferTargetPermission.initialize,
            (recipients, tokens, USDC_CAP, deployer)
        );

        uint256 sNonce = kernel.signerNonces(safe);
        uint256 regDeadline = block.timestamp + 1 days;
        bytes32 structHash = keccak256(abi.encode(
            kernel.REGISTER_PERMISSION_TYPEHASH(),
            safe,
            predicted,
            sNonce,
            regDeadline
        ));
        bytes32 digest = kernel.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(deployerPk, digest);
        bytes memory kernelSig = abi.encodePacked(r, s, v);

        vm.startBroadcast(deployerPk);
        newTT = factory.deployAndAttach(safe, transferImpl, salt, initData, regDeadline, kernelSig);
        vm.stopBroadcast();
        require(newTT == predicted, "C.6: predicted clone mismatch");
        console2.log("[C.6] OK NEW TransferTarget (USDC mode):", newTT);
    }

    // ────────────────────────────────────────────────────────────────────────
    // C.7 — happy USDC transfer via NEW TransferTarget
    // ────────────────────────────────────────────────────────────────────────

    function _runHappy_C7() internal {
        require(IERC20(USDC).balanceOf(safe) >= USDC_AMT, "C.7: insufficient USDC");
        uint256 usdcBefore = IERC20(USDC).balanceOf(safe);

        bytes memory transferCall = abi.encodeCall(IERC20.transfer, (deployer, USDC_AMT));
        uint256 nonce    = kernel.managerNonces(safe);
        uint256 deadline = block.timestamp + 600;
        bytes memory sig = _signDispatch(agentPk, newTT, USDC, 0, transferCall, nonce, deadline);

        vm.broadcast(agentPk);
        kernel.dispatch(safe, newTT, USDC, 0, transferCall, sig, deadline);

        uint256 usdcAfter = IERC20(USDC).balanceOf(safe);
        require(kernel.managerNonces(safe) == nonce + 1, "C.7: nonce not advanced");
        require(usdcAfter == usdcBefore - USDC_AMT, "C.7: USDC delta wrong");
        console2.log("[C.7] OK USDC transfer via NEW TT, amount =", USDC_AMT);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Denial calldatas — signed AFTER all broadcasts so the manager nonce
    // matches the post-script on-chain state (cast send broadcasts these later).
    // ────────────────────────────────────────────────────────────────────────

    /// C.2 — agent tries an ETH transfer to deployer but names BoundedSwap.
    /// BoundedSwap.evaluate: target=deployer not in isAllowedRouter → false → PermissionDenied(bsClone).
    function _logDenial_C2_ethViaBoundedSwap() internal view {
        uint256 nonce    = kernel.managerNonces(safe);
        uint256 deadline = block.timestamp + 1200; // generous to cover cast-send latency
        bytes memory sig = _signDispatch(agentPk, bsClone, deployer, ETH_AMT, "", nonce, deadline);
        bytes memory call = abi.encodeCall(
            SailKernel.dispatch,
            (safe, bsClone, deployer, ETH_AMT, "", sig, deadline)
        );
        console2.log("DENIAL_CALLDATA C.2 (ETH transfer named BoundedSwap, expect PermissionDenied)");
        console2.logBytes(call);
    }

    /// C.3 — agent tries a swap call to router but names NEW TransferTarget.
    /// NEW TT.evaluate: data.length>=4 with selector 0x04e45aaf (≠ transfer/transferFrom)
    /// AND ctx.target=router not in isAllowedToken → false → PermissionDenied(newTT).
    function _logDenial_C3_swapViaNewTT() internal view {
        uint256 nonce    = kernel.managerNonces(safe);
        uint256 deadline = block.timestamp + 1200;
        // Build a minimal exactInputSingle calldata (selector 0x04e45aaf) — the dispatch
        // won't actually execute the inner call; permission eval rejects first.
        bytes memory swapData = abi.encodeWithSelector(
            bytes4(0x04e45aaf),
            WETH, USDC, POOL_FEE, safe, uint256(1), uint256(0), uint160(0)
        );
        bytes memory sig = _signDispatch(agentPk, newTT, ROUTER, 0, swapData, nonce, deadline);
        bytes memory call = abi.encodeCall(
            SailKernel.dispatch,
            (safe, newTT, ROUTER, 0, swapData, sig, deadline)
        );
        console2.log("DENIAL_CALLDATA C.3 (swap call named NEW TransferTarget, expect PermissionDenied)");
        console2.logBytes(call);
    }

    /// C.5 — agent dispatches naming the REVOKED OLD TransferTarget.
    /// Kernel checks _permissionIndex[safe][oldTT] == 0 at line 860 → PermissionNotRegistered(oldTT).
    /// This revert fires BEFORE the signature check, so the sig content is irrelevant —
    /// but we still produce a syntactically valid one.
    function _logDenial_C5_postRevoke() internal view {
        uint256 nonce    = kernel.managerNonces(safe);
        uint256 deadline = block.timestamp + 1200;
        bytes memory sig = _signDispatch(agentPk, oldTT, deployer, ETH_AMT, "", nonce, deadline);
        bytes memory call = abi.encodeCall(
            SailKernel.dispatch,
            (safe, oldTT, deployer, ETH_AMT, "", sig, deadline)
        );
        console2.log("DENIAL_CALLDATA C.5 (dispatch via revoked OLD TT, expect PermissionNotRegistered)");
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
        console2.log("oldTT (revoked)   :", oldTT);
        console2.log("bsClone           :", bsClone);
        console2.log("newTT (USDC mode) :", newTT);
        console2.log("safe ETH          :", safe.balance);
        console2.log("safe USDC         :", IERC20(USDC).balanceOf(safe));
        console2.log("managerNonces     :", kernel.managerNonces(safe));
        console2.log("signerNonces      :", kernel.signerNonces(safe));
        console2.log("");
        console2.log("4 broadcasts complete (C.1, C.4, C.6, C.7).");
        console2.log("Run cast send for C.2, C.3, C.5 calldatas above.");
    }
}
