// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Script, console2}        from "forge-std/Script.sol";
import {ManifestIO}              from "../lib/ManifestIO.sol";
import {SailKernel}              from "../../contracts/core/SailKernel.sol";
import {MandateFactory}       from "../../contracts/factory/MandateFactory.sol";
import {BoundedSwapPermission}   from "../../contracts/templates/BoundedSwapPermission.sol";

interface ISafe {
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

interface IWETH {
    function deposit() external payable;
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
}

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
}

/// @notice Phase 2 E2E: BoundedSwapPermission live test on Base mainnet.
///
///         Reuses the Safe + agent setup created by Phase 1
///         (PermissionDenialE2E.s.sol). Requires SAFE_ADDR env var pointing at the
///         existing Safe.
///
///         Setup (owner-driven, NOT gated by kernel):
///           S.1  Wrap WRAP_AMOUNT wei of the Safe's ETH → WETH via Safe.execTransaction
///                → WETH.deposit{value: WRAP_AMOUNT}().
///           S.2  Approve SwapRouter02 to spend the Safe's WETH via Safe.execTransaction
///                → WETH.approve(router, type(uint256).max).
///           S.3  Deploy + attach a BoundedSwapPermission clone:
///                allowedRouters    = [SwapRouter02]
///                allowedTokensIn   = [WETH]
///                allowedTokensOut  = [USDC]
///                maxAmountPerTx    = SWAP_CAP
///                maxSlippageBps    = 0  (oracle disabled)
///                priceOracle       = address(0)
///                permissionSigner  = deployer
///
///         Tests (agent-driven, gated):
///           B.1  exactInputSingle(WETH→USDC, fee=500, recipient=safe, amountIn=SWAP_CAP)
///                → success on-chain.
///           B.2  Same but recipient = agent EOA           → PermissionDenied
///           B.3  Same but target = FORBIDDEN_ROUTER       → PermissionDenied
///           B.4  Same but amountIn = SWAP_CAP + 1         → PermissionDenied
///
///         Required env: DEPLOYER_PRIVATE_KEY, DEPLOYER_ADDRESS,
///                       AGENT_PRIVATE_KEY,    AGENT_ADDRESS,
///                       SAFE_ADDR (mandatory; the Phase 1 Safe).
contract Phase2_BoundedSwap is Script {
    // ── chain constants (Base mainnet) ───────────────────────────────────────
    address internal constant WETH    = 0x4200000000000000000000000000000000000006;
    address internal constant USDC    = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
    address internal constant ROUTER  = 0x2626664c2603336E57B271c5C0b26F421741e481; // Uniswap V3 SwapRouter02
    uint24  internal constant POOL_FEE = 500; // 0.05% WETH/USDC pool
    address internal constant FORBIDDEN_ROUTER = address(0xCAFE); // not in allowlist

    // ── tunables ─────────────────────────────────────────────────────────────
    uint256 internal constant WRAP_AMOUNT = 40_000_000_000_000; // 4e13 wei → WETH
    uint256 internal constant SWAP_CAP    = 40_000_000_000_000; // permission cap
    uint256 internal constant SWAP_AMOUNT = 40_000_000_000_000; // B.1 amountIn
    // safeTxGas = 0 ⇒ Safe forwards all remaining gas to the inner call, bypassing
    // Safe v1.4.1's GS010 outer-gas-floor check (gasleft() >= safeTxGas * 64/63 + buffer).
    // Phase 1 used 200_000 and worked because registerAccount used enough gas that
    // foundry's estimate landed above the floor by accident; for cheap inner calls
    // like WETH.deposit (~25k) foundry estimates too low → GS010 revert.
    uint256 internal constant SAFE_TX_GAS = 0;

    // ── resolved state ───────────────────────────────────────────────────────
    SailKernel        internal kernel;
    MandateFactory internal factory;
    address           internal boundedSwapImpl;

    address           internal deployer;
    uint256           internal deployerPk;
    address           internal agent;
    uint256           internal agentPk;

    address payable   internal safe;
    address           internal clone;

    function run() external {
        _loadConfig();
        _logHeader();
        _ensureWrapped();
        _ensureApproved();
        _ensureBoundedSwapAttached();
        _runHappy_B1();
        _logDenialCalldata_B2_forbiddenRecipient();
        _logDenialCalldata_B3_forbiddenRouter();
        _logDenialCalldata_B4_overCap();
        _finalSummary();
    }

    // ────────────────────────────────────────────────────────────────────────
    // Config
    // ────────────────────────────────────────────────────────────────────────

    function _loadConfig() internal {
        uint256 chainId = block.chainid;
        kernel          = SailKernel(ManifestIO.readAddress(chainId, "core", ".kernel"));
        factory         = MandateFactory(payable(ManifestIO.readAddress(chainId, "core", ".mandateFactory")));
        boundedSwapImpl = ManifestIO.readAddress(chainId, "templates.standalone", ".boundedSwap");

        deployer   = vm.envAddress("DEPLOYER_ADDRESS");
        deployerPk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        agent      = vm.envAddress("AGENT_ADDRESS");
        agentPk    = vm.envUint("AGENT_PRIVATE_KEY");

        safe = payable(vm.envAddress("SAFE_ADDR"));
        require(safe != address(0), "SAFE_ADDR required");
        require(ISafe(safe).isModuleEnabled(address(kernel)), "kernel not enabled on Safe");
        require(kernel.registered(safe), "Safe not registered with kernel");

        // optional: resume an already-attached BoundedSwap clone
        clone = vm.envOr("BS_CLONE_ADDR", address(0));
    }

    function _logHeader() internal view {
        console2.log("=========================================================");
        console2.log("Sail Phase 2: BoundedSwapPermission live test");
        console2.log("=========================================================");
        console2.log("chainId          :", block.chainid);
        console2.log("kernel           :", address(kernel));
        console2.log("factory          :", address(factory));
        console2.log("boundedSwapImpl  :", boundedSwapImpl);
        console2.log("safe             :", safe);
        console2.log("deployer (owner) :", deployer);
        console2.log("agent (manager)  :", agent);
        console2.log("safe ETH balance :", safe.balance);
        console2.log("safe WETH balance:", IWETH(WETH).balanceOf(safe));
        console2.log("safe USDC balance:", IERC20(USDC).balanceOf(safe));
        console2.log("---------------------------------------------------------");
    }

    // ────────────────────────────────────────────────────────────────────────
    // Setup (owner-driven Safe.execTransaction calls; NOT through the kernel)
    // ────────────────────────────────────────────────────────────────────────

    /// @dev Wraps WRAP_AMOUNT wei of the Safe's ETH into WETH.
    function _ensureWrapped() internal {
        if (IWETH(WETH).balanceOf(safe) >= WRAP_AMOUNT) {
            console2.log("[S.1] safe already holds sufficient WETH:", IWETH(WETH).balanceOf(safe));
            return;
        }
        require(safe.balance >= WRAP_AMOUNT, "[S.1] safe lacks ETH for wrapping");

        bytes memory data = abi.encodeWithSelector(IWETH.deposit.selector);
        _execSafeTx(WETH, WRAP_AMOUNT, data, "S.1 WETH.deposit");
    }

    /// @dev Approves the router to spend the Safe's WETH.
    function _ensureApproved() internal {
        if (IWETH(WETH).allowance(safe, ROUTER) >= SWAP_AMOUNT) {
            console2.log("[S.2] router already approved; allowance:", IWETH(WETH).allowance(safe, ROUTER));
            return;
        }
        bytes memory data = abi.encodeCall(IWETH.approve, (ROUTER, type(uint256).max));
        _execSafeTx(WETH, 0, data, "S.2 WETH.approve(router, max)");
    }

    /// @dev Deploy + attach BoundedSwapPermission clone (idempotent via deterministic salt).
    function _ensureBoundedSwapAttached() internal {
        if (clone != address(0)) {
            require(BoundedSwapPermission(clone).initialized(), "[S.3] resume clone: not initialized");
            console2.log("[S.3] reusing BoundedSwap clone:", clone);
            return;
        }
        bytes32 salt = keccak256(abi.encode(safe, boundedSwapImpl, "phase2-bs-1"));
        address predicted;
        vm.prank(deployer);
        predicted = factory.predictCloneAddress(boundedSwapImpl, salt);

        if (predicted.code.length > 0) {
            // Already deployed in a prior partial run; just adopt it.
            clone = predicted;
            console2.log("[S.3] adopting pre-existing clone:", clone);
            return;
        }

        address[] memory routers       = new address[](1); routers[0]       = ROUTER;
        address[] memory tokensIn      = new address[](1); tokensIn[0]      = WETH;
        address[] memory tokensOut     = new address[](1); tokensOut[0]     = USDC;
        bytes memory initData = abi.encodeCall(
            BoundedSwapPermission.initialize,
            (routers, tokensIn, tokensOut, SWAP_CAP, 0, address(0), 0, deployer)
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
        bytes32 digest = kernel.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(deployerPk, digest);
        bytes memory kernelSig = abi.encodePacked(r, s, v);

        vm.startBroadcast(deployerPk);
        clone = factory.deployAndAttach(safe, boundedSwapImpl, salt, initData, kDeadline, kernelSig);
        vm.stopBroadcast();
        require(clone == predicted, "predicted clone mismatch");
        console2.log("[S.3] BoundedSwap clone attached:", clone);
    }

    function _execSafeTx(address to, uint256 value, bytes memory data, string memory label) internal {
        uint256 safeNonce = ISafe(safe).nonce();
        bytes32 txHash = ISafe(safe).getTransactionHash(
            to, value, data, 0, SAFE_TX_GAS,
            0, 0, address(0), address(0), safeNonce
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(deployerPk, txHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.startBroadcast(deployerPk);
        bool ok = ISafe(safe).execTransaction(
            to, value, data, 0, SAFE_TX_GAS,
            0, 0, address(0), payable(address(0)), sig
        );
        vm.stopBroadcast();
        require(ok, string.concat(label, ": Safe.execTransaction failed"));
        console2.log(string.concat("[", label, "] ok"));
    }

    // ────────────────────────────────────────────────────────────────────────
    // Tests
    // ────────────────────────────────────────────────────────────────────────

    function _runHappy_B1() internal {
        uint256 nonceBefore = kernel.managerNonces(safe);
        uint256 wethBefore  = IWETH(WETH).balanceOf(safe);
        uint256 usdcBefore  = IERC20(USDC).balanceOf(safe);

        bytes memory swapData = _exactInputSingleData(WETH, USDC, POOL_FEE, safe, SWAP_AMOUNT, 1);
        uint256 deadline = block.timestamp + 600;
        bytes memory sig = _signDispatch(agentPk, clone, ROUTER, 0, swapData, nonceBefore, deadline);

        vm.broadcast(agentPk);
        kernel.dispatch(safe, clone, ROUTER, 0, swapData, sig, deadline);

        uint256 wethAfter = IWETH(WETH).balanceOf(safe);
        uint256 usdcAfter = IERC20(USDC).balanceOf(safe);
        require(kernel.managerNonces(safe) == nonceBefore + 1, "B.1: nonce not advanced");
        require(wethAfter == wethBefore - SWAP_AMOUNT, "B.1: WETH delta wrong");
        require(usdcAfter > usdcBefore, "B.1: no USDC received");
        console2.log("[B.1] OK swap WETH->USDC: in =", SWAP_AMOUNT);
        console2.log("              out USDC delta =", usdcAfter - usdcBefore);
    }

    function _logDenialCalldata_B2_forbiddenRecipient() internal view {
        uint256 nonce    = kernel.managerNonces(safe);
        uint256 deadline = block.timestamp + 600;
        // recipient = agent EOA (not the Safe)
        bytes memory swapData = _exactInputSingleData(WETH, USDC, POOL_FEE, agent, SWAP_AMOUNT, 1);
        bytes memory sig = _signDispatch(agentPk, clone, ROUTER, 0, swapData, nonce, deadline);
        bytes memory call = abi.encodeCall(
            SailKernel.dispatch,
            (safe, clone, ROUTER, 0, swapData, sig, deadline)
        );
        console2.log("DENIAL_CALLDATA B.2 (forbidden recipient=agent, expect PermissionDenied)");
        console2.logBytes(call);
    }

    function _logDenialCalldata_B3_forbiddenRouter() internal view {
        uint256 nonce    = kernel.managerNonces(safe);
        uint256 deadline = block.timestamp + 600;
        bytes memory swapData = _exactInputSingleData(WETH, USDC, POOL_FEE, safe, SWAP_AMOUNT, 1);
        // target != allowlisted router → permission rejects on first check
        bytes memory sig = _signDispatch(agentPk, clone, FORBIDDEN_ROUTER, 0, swapData, nonce, deadline);
        bytes memory call = abi.encodeCall(
            SailKernel.dispatch,
            (safe, clone, FORBIDDEN_ROUTER, 0, swapData, sig, deadline)
        );
        console2.log("DENIAL_CALLDATA B.3 (forbidden router, expect PermissionDenied)");
        console2.logBytes(call);
    }

    function _logDenialCalldata_B4_overCap() internal view {
        uint256 nonce    = kernel.managerNonces(safe);
        uint256 deadline = block.timestamp + 600;
        uint256 overCap  = SWAP_CAP + 1;
        bytes memory swapData = _exactInputSingleData(WETH, USDC, POOL_FEE, safe, overCap, 1);
        bytes memory sig = _signDispatch(agentPk, clone, ROUTER, 0, swapData, nonce, deadline);
        bytes memory call = abi.encodeCall(
            SailKernel.dispatch,
            (safe, clone, ROUTER, 0, swapData, sig, deadline)
        );
        console2.log("DENIAL_CALLDATA B.4 (over-cap amountIn, expect PermissionDenied)");
        console2.logBytes(call);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Helpers
    // ────────────────────────────────────────────────────────────────────────

    /// @dev Encodes Uniswap V3 SwapRouter02 exactInputSingle (selector 0x04e45aaf).
    function _exactInputSingleData(
        address tokenIn,
        address tokenOut,
        uint24  fee,
        address recipient,
        uint256 amountIn,
        uint256 amountOutMinimum
    ) internal pure returns (bytes memory) {
        // Manually encode because the struct layout differs from V1 (no deadline field).
        return abi.encodeWithSelector(
            0x04e45aaf,
            tokenIn, tokenOut, fee, recipient,
            amountIn, amountOutMinimum, uint160(0)
        );
    }

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
        console2.log("BoundedSwap clone :", clone);
        console2.log("safe ETH          :", safe.balance);
        console2.log("safe WETH         :", IWETH(WETH).balanceOf(safe));
        console2.log("safe USDC         :", IERC20(USDC).balanceOf(safe));
        console2.log("managerNonces     :", kernel.managerNonces(safe));
        console2.log("");
        console2.log("Setup + B.1 broadcast complete.");
        console2.log("Use cast send --gas-limit 250000 for B.2-B.4 calldata logged above.");
    }
}
