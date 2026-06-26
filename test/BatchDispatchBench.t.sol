// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import {SailKernel}     from "../contracts/core/SailKernel.sol";
import {SailGovernance} from "../contracts/governance/SailGovernance.sol";
import {TimelockDeployer} from "./support/TimelockDeployer.sol";
import {Context}        from "../contracts/interfaces/IPermission.sol";
import {IBatchPermission, Call, BatchContext} from "../contracts/interfaces/IBatchPermission.sol";
import {ApproveAndCallBatchPermission}   from "../contracts/templates/ApproveAndCallBatchPermission.sol";

// Re-uses the forwarding Safe / mock router / mock ERC20 from BatchDispatch.t.sol
// by re-declaring minimal versions here. Keep this file standalone so snapshot
// numbers are deterministic regardless of the order forge picks tests in.

contract BenchSafe {
    // Octane group 1a test support: a finalized Safe reports nonce>=1 (setup never bumps it)
    // and exposes its trusted singleton via masterCopy() (intercepted by a real SafeProxy fallback).
    function nonce() external pure returns (uint256) { return 1; }
    function checkSignatures(bytes32, bytes calldata, bytes calldata) external view {}
    function masterCopy() external pure returns (address) { return address(0x5AFE); }

    receive() external payable {}
    function execTransactionFromModule(address to, uint256 value, bytes calldata data, uint8 op)
        external returns (bool)
    {
        require(op == 0, "DELEGATECALL forbidden");
        bool ok;
        if (data.length == 0) {
            (ok,) = payable(to).call{value: value}("");
        } else {
            (ok,) = to.call{value: value}(data);
        }
        return ok;
    }
    function isModuleEnabled(address) external pure returns (bool) { return true; }
}

contract BenchERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    function mint(address to, uint256 amt) external { balanceOf[to] += amt; }
    function approve(address sp, uint256 a) external returns (bool) {
        allowance[msg.sender][sp] = a;
        return true;
    }
    function transferFrom(address f, address t, uint256 a) external returns (bool) {
        require(allowance[f][msg.sender] >= a, "allow");
        require(balanceOf[f] >= a, "bal");
        allowance[f][msg.sender] -= a;
        balanceOf[f] -= a;
        balanceOf[t] += a;
        return true;
    }
}

contract BenchRouter {
    // Uniswap V2-style: a member of the template's decodable selector set (asset = path[0]).
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 /* amountOutMin */,
        address[] calldata path,
        address /* to */,
        uint256 /* deadline */
    ) external {
        // Mock router; revert propagates from the token if transferFrom fails.
        // forge-lint: disable-next-line(erc20-unchecked-transfer)
        BenchERC20(path[0]).transferFrom(msg.sender, address(this), amountIn);
    }
}

/// @notice Always-allow batch permission to isolate kernel + subcall overhead
///         from any template-side evaluation cost in the larger batch benchmark.
contract BenchAllowBatch is IBatchPermission {
    function evaluateBatch(Call[] calldata, BatchContext calldata) external pure returns (bool) {
        return true;
    }
    function isBatchPermission() external pure returns (bool) { return true; }
}

contract BatchDispatchBenchmark is Test {
    uint256 internal constant PERM_SIGNER_KEY = 0xA11CE;
    uint256 internal constant MANAGER_KEY     = 0xB0B;
    address internal constant TREASURY        = address(0xAAAA);
    uint256 internal constant BASE_FEE        = 0.001 ether;
    uint256 internal constant MAX_PERM_FEE    = 0.001 ether;

    SailGovernance internal gov;
    SailKernel     internal kernel;
    BenchSafe      internal safe;
    BenchERC20     internal token;
    BenchRouter    internal router;
    ApproveAndCallBatchPermission internal batchPerm;
    BenchAllowBatch internal allowPerm;

    address internal permSigner;
    address internal manager;

    bytes4  internal constant APPROVE_SEL = 0x095ea7b3;
    bytes4  internal constant SWAP_SEL    = BenchRouter.swapExactTokensForTokens.selector;

    /// @dev V2 consuming calldata: amountIn at word 0 (requireAmountMatch), path[0] == approved token.
    function _swapData(uint256 amountIn) internal view returns (bytes memory) {
        address[] memory path = new address[](2);
        path[0] = address(token);
        path[1] = address(0xBEEF);
        return abi.encodeWithSelector(SWAP_SEL, amountIn, uint256(1), path, address(safe), uint256(0));
    }

    function setUp() public {
        permSigner = vm.addr(PERM_SIGNER_KEY);
        manager    = vm.addr(MANAGER_KEY);
        vm.deal(address(this), 100 ether);

        gov = new SailGovernance(address(this), MAX_PERM_FEE, address(this), BASE_FEE, TimelockDeployer.deploy(address(this)));
        kernel = new SailKernel(address(gov), TREASURY, address(0));

        safe = new BenchSafe();
        vm.deal(address(safe), 10 ether);
        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeProxyCodehash(address(safe).codehash, true);
        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeSingleton(address(0x5AFE), true); // Octane #9: trust the mock singleton
        vm.prank(address(safe));
        kernel.registerAccount(permSigner, manager, address(0), address(0), block.timestamp + 1 days, "");

        token  = new BenchERC20();
        token.mint(address(safe), 10_000 ether);
        router = new BenchRouter();

        batchPerm = new ApproveAndCallBatchPermission(address(kernel), address(0xA11CE));
        allowPerm = new BenchAllowBatch();

        _register(address(batchPerm));
        _register(address(allowPerm));
        _configure();
    }

    function _register(address perm) internal {
        uint256 n = kernel.signerNonces(address(safe));
        uint256 deadline = block.timestamp + 1 days;
        bytes32 sh = keccak256(abi.encode(kernel.REGISTER_PERMISSION_TYPEHASH(), address(safe), perm, n, deadline));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PERM_SIGNER_KEY, kernel.hashTypedDataV4(sh));
        kernel.registerPermission{value: gov.permissionRegistrationFee()}(address(safe), perm, deadline, abi.encodePacked(r, s, v));
    }

    function _configure() internal {
        ApproveAndCallBatchPermission.Config memory cfg;
        cfg.tokens = new address[](1);             cfg.tokens[0] = address(token);
        cfg.spenders = new address[](1);           cfg.spenders[0] = address(router);
        cfg.consumingPairs = new ApproveAndCallBatchPermission.ConsumingPair[](1);
        cfg.consumingPairs[0] = ApproveAndCallBatchPermission.ConsumingPair({target: address(router), selector: SWAP_SEL});
        cfg.maxApprovalAmounts = new uint256[](1); cfg.maxApprovalAmounts[0] = 1_000 ether;
        cfg.requireAmountMatch = true;

        bytes memory params = abi.encode(cfg);
        uint256 deadline = block.timestamp + 1 hours;
        uint256 n = batchPerm.configNonces(address(safe));
        uint256 epoch = batchPerm.kernel().registrationEpoch(address(safe), address(batchPerm));
        bytes32 sh = keccak256(abi.encode(batchPerm.CONFIGURE_TYPEHASH(), address(safe), keccak256(params), n, deadline, epoch));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PERM_SIGNER_KEY, batchPerm.hashTypedDataV4(sh));
        batchPerm.configure(address(safe), params, deadline, abi.encodePacked(r, s, v));
    }

    function _signBatch(address perm, Call[] memory calls, uint256 nonce, uint256 deadline)
        internal view returns (bytes memory)
    {
        bytes32 ch = keccak256(abi.encode(calls));
        bytes32 sh = keccak256(abi.encode(
            kernel.DISPATCH_BATCH_TYPEHASH(), address(safe), perm, ch, nonce, deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(MANAGER_KEY, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }

    function _build3Call(uint256 amount) internal view returns (Call[] memory calls) {
        calls = new Call[](3);
        calls[0] = Call(address(token),  0, abi.encodeWithSelector(APPROVE_SEL, address(router), amount));
        calls[1] = Call(address(router), 0, _swapData(amount));
        calls[2] = Call(address(token),  0, abi.encodeWithSelector(APPROVE_SEL, address(router), uint256(0)));
    }

    /// @notice 3-call batch via dispatchBatch — the canonical use case.
    function test_Bench_BatchDispatch_3Calls() public {
        Call[] memory calls = _build3Call(10 ether);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _signBatch(address(batchPerm), calls, 0, deadline);

        uint256 gasBefore = gasleft();
        kernel.dispatchBatch(address(safe), address(batchPerm), calls, sig, deadline);
        uint256 used = gasBefore - gasleft();
        emit log_named_uint("BENCH 3-call dispatchBatch (gas)", used);
    }

    /// @notice 8-call batch via dispatchBatch — multi-step strategy.
    function test_Bench_BatchDispatch_8Calls() public {
        // 8-call shape: approve(big) / swap1 / swap2 / swap3 / approve(reset) / approve(big) / swap4 / approve(reset)
        // This uses the allow-all permission so we can construct any 8-call sequence
        // without being restricted by the strict 3-call template shape.
        Call[] memory calls = new Call[](8);
        for (uint256 i = 0; i < 4; i++) {
            calls[i*2]   = Call(address(token), 0, abi.encodeWithSelector(APPROVE_SEL, address(router), uint256(1 ether)));
            calls[i*2+1] = Call(address(router), 0, _swapData(uint256(1 ether)));
        }
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _signBatch(address(allowPerm), calls, 0, deadline);

        uint256 gasBefore = gasleft();
        kernel.dispatchBatch(address(safe), address(allowPerm), calls, sig, deadline);
        uint256 used = gasBefore - gasleft();
        emit log_named_uint("BENCH 8-call dispatchBatch (gas)", used);
    }

    /// @notice Equivalent 3 separate single dispatch() calls for comparison.
    ///         Note: the ApproveAndCallBatchPermission template's `evaluate`
    ///         returns false (batch-only), so single dispatch with it would deny.
    ///         For a fair "what if you did the same calls one at a time" comparison
    ///         we need a permission that allows each of the three calls individually.
    ///         We simulate this with an inline always-allow IPermission and measure
    ///         just the kernel + single-permission + Safe overhead per call.
    function test_Bench_ThreeSeparateDispatches() public {
        AlwaysAllow allow = new AlwaysAllow();
        _register(address(allow));

        uint256 deadline = block.timestamp + 1 hours;
        Call[] memory calls = _build3Call(10 ether);

        // First we have to revoke batchPerm so that single dispatch can succeed —
        // currently batchPerm.evaluate() returns false and would deny single dispatch.
        // We do an in-test revoke of the two registered permissions, leaving only `allow`.
        _revoke(address(batchPerm));
        _revoke(address(allowPerm));

        uint256 totalUsed;
        for (uint256 i; i < 3; i++) {
            uint256 nonce = kernel.managerNonces(address(safe));
            bytes32 sh = keccak256(abi.encode(
                kernel.DISPATCH_TYPEHASH(),
                address(safe),
                address(allow),
                calls[i].target,
                calls[i].value,
                keccak256(calls[i].data),
                nonce,
                deadline
            ));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(MANAGER_KEY, kernel.hashTypedDataV4(sh));
            bytes memory sig = abi.encodePacked(r, s, v);

            uint256 gasBefore = gasleft();
            kernel.dispatch(address(safe), address(allow), calls[i].target, calls[i].value, calls[i].data, sig, deadline);
            totalUsed += gasBefore - gasleft();
        }
        emit log_named_uint("BENCH 3x single dispatch() (gas total)", totalUsed);
    }

    function _revoke(address perm) internal {
        uint256 n = kernel.signerNonces(address(safe));
        uint256 deadline = block.timestamp + 1 days;
        bytes32 sh = keccak256(abi.encode(kernel.REVOKE_PERMISSION_TYPEHASH(), address(safe), perm, n, deadline));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PERM_SIGNER_KEY, kernel.hashTypedDataV4(sh));
        kernel.revokePermission(address(safe), perm, deadline, abi.encodePacked(r, s, v));
    }
}

contract AlwaysAllow {
    function evaluate(bytes calldata, Context calldata) external pure returns (bool) { return true; }
    function discriminator() external pure returns (bytes32) { return bytes32(0); }
}
