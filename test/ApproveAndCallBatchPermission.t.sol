// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import {Context}                        from "../contracts/interfaces/IPermission.sol";
import {Call, BatchContext}             from "../contracts/interfaces/IBatchPermission.sol";
import {SailCapabilities}               from "../contracts/interfaces/SailCapabilities.sol";
import {ApproveAndCallBatchPermission}  from "../contracts/templates/ApproveAndCallBatchPermission.sol";

/// @dev Minimal kernel view: every account registered; this test contract is the permissionSigner.
contract BatchMockKernel {
    address public immutable signer;
    constructor(address _signer) { signer = _signer; }
    function registered(address) external pure returns (bool) { return true; }
    function configs(address) external view returns (address) { return signer; }
}

/// @notice Covers the (target, selector) pair binding and the optional output-recipient mode of
///         ApproveAndCallBatchPermission. The batch is evaluated directly via evaluateBatch with a
///         constructed BatchContext (no kernel dispatch needed for a view check).
contract ApproveAndCallBatchPermissionTest is Test {
    // consuming selectors
    bytes4 internal constant SWAP_V2   = 0x38ed1739; // swapExactTokensForTokens(...)        — to @ word 3
    bytes4 internal constant V3        = 0x414bf389; // exactInputSingle (SwapRouter)        — recipient @ word 3
    bytes4 internal constant V3_02     = 0x04e45aaf; // exactInputSingle (SwapRouter02)      — recipient @ word 3
    bytes4 internal constant AAVE_SUP  = 0x617ba037; // supply(address,uint256,address,uint16)  — onBehalfOf @ word 2
    bytes4 internal constant AAVE_DEP  = 0xe8eda9df; // deposit(address,uint256,address,uint16) — onBehalfOf @ word 2
    bytes4 internal constant V4626_DEP = 0x6e553f65; // deposit(uint256,address)             — receiver @ word 1
    bytes4 internal constant V4626_MNT = 0x94bf804d; // mint(uint256,address)                — receiver @ word 1
    bytes4 internal constant EXACT_INPUT = 0xc04b8d59; // exactInput(...) dynamic path       — NOT decodable
    bytes4 internal constant APPROVE     = 0x095ea7b3;

    address internal constant AUTHOR  = address(0xA11CE);
    address internal constant ACCOUNT = address(0xACC0);
    address internal constant TOKEN   = address(0x7000);
    address internal constant SPENDER = address(0x5111);
    address internal constant ROUTERA = address(0xAA01);
    address internal constant ROUTERB = address(0xBB02);
    address internal constant OTHER   = address(0xBEEF);

    uint256 internal constant CAP    = 1_000;
    uint256 internal constant AMOUNT = 100;

    BatchMockKernel                  internal kernel;
    ApproveAndCallBatchPermission    internal batchPerm;

    function setUp() public {
        kernel    = new BatchMockKernel(address(this));
        batchPerm = new ApproveAndCallBatchPermission(address(kernel), AUTHOR);
    }

    // ── config helpers ────────────────────────────────────────────────────────

    function _pair(address t, bytes4 s) internal pure returns (ApproveAndCallBatchPermission.ConsumingPair memory p) {
        p.target = t; p.selector = s;
    }

    function _configure(
        ApproveAndCallBatchPermission.ConsumingPair[] memory pairs,
        bool reqAmount,
        bool reqRecipient
    ) internal {
        ApproveAndCallBatchPermission.Config memory cfg;
        cfg.tokens = new address[](1);             cfg.tokens[0] = TOKEN;
        cfg.spenders = new address[](1);           cfg.spenders[0] = SPENDER;
        cfg.consumingPairs = pairs;
        cfg.maxApprovalAmounts = new uint256[](1); cfg.maxApprovalAmounts[0] = CAP;
        cfg.requireAmountMatch = reqAmount;
        cfg.requireRecipientIsAccount = reqRecipient;
        batchPerm.configureDirect(ACCOUNT, abi.encode(cfg));
    }

    function _pairs1(address t, bytes4 s) internal pure returns (ApproveAndCallBatchPermission.ConsumingPair[] memory a) {
        a = new ApproveAndCallBatchPermission.ConsumingPair[](1);
        a[0] = _pair(t, s);
    }

    // ── batch builders ──────────────────────────────────────────────────────────

    function _batch(address consumingTarget, bytes memory consumingData) internal pure returns (Call[] memory calls) {
        calls = new Call[](3);
        calls[0] = Call({target: TOKEN, value: 0, data: abi.encodeWithSelector(APPROVE, SPENDER, AMOUNT)});
        calls[1] = Call({target: consumingTarget, value: 0, data: consumingData});
        calls[2] = Call({target: TOKEN, value: 0, data: abi.encodeWithSelector(APPROVE, SPENDER, uint256(0))});
    }

    function _ctx() internal pure returns (BatchContext memory c) {
        c.account = ACCOUNT;
    }

    function _eval(address consumingTarget, bytes memory consumingData) internal view returns (bool) {
        return batchPerm.evaluateBatch(_batch(consumingTarget, consumingData), _ctx());
    }

    // consuming-call calldata builders, each placing the recipient at its real offset
    function _swapV2(address to) internal pure returns (bytes memory) {
        address[] memory path = new address[](2); path[0] = TOKEN; path[1] = OTHER;
        return abi.encodeWithSelector(SWAP_V2, uint256(AMOUNT), uint256(1), path, to, uint256(0));
    }
    function _v3(address recipient) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(V3, TOKEN, OTHER, uint24(3000), recipient, uint256(0), uint256(AMOUNT), uint256(1), uint160(0));
    }
    function _v3_02(address recipient) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(V3_02, TOKEN, OTHER, uint24(3000), recipient, uint256(AMOUNT), uint256(1), uint160(0));
    }
    function _aave(bytes4 sel, address onBehalfOf) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(sel, TOKEN, uint256(AMOUNT), onBehalfOf, uint16(0));
    }
    function _erc4626(bytes4 sel, address receiver) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(sel, uint256(AMOUNT), receiver);
    }

    // ── introspection ───────────────────────────────────────────────────────────

    function test_Introspection_Ids() public view {
        assertEq(batchPerm.discriminator(), keccak256("ApproveAndCallBatchPermission"));
        assertEq(batchPerm.permissionId(),  keccak256("sail.permission.ApproveAndCallBatchPermission.v1"));
        assertEq(batchPerm.capabilityIds()[0], SailCapabilities.BATCH_DISPATCH);
    }

    // ── T-2: pair binding closes the cartesian leak ──────────────────────────────

    function test_PairBinding_IntendedPairsPass_CrossPairsDeny() public {
        ApproveAndCallBatchPermission.ConsumingPair[] memory pairs = new ApproveAndCallBatchPermission.ConsumingPair[](2);
        pairs[0] = _pair(ROUTERA, SWAP_V2);
        pairs[1] = _pair(ROUTERB, V4626_DEP);
        _configure(pairs, false, false);

        // intended pairs pass
        assertTrue(_eval(ROUTERA, _swapV2(OTHER)),            "(routerA, swap) should pass");
        assertTrue(_eval(ROUTERB, _erc4626(V4626_DEP, OTHER)), "(routerB, deposit) should pass");

        // cross pairs (the cartesian leak) must now DENY
        assertFalse(_eval(ROUTERA, _erc4626(V4626_DEP, OTHER)), "(routerA, deposit) must deny");
        assertFalse(_eval(ROUTERB, _swapV2(OTHER)),             "(routerB, swap) must deny");
    }

    function test_UnboundPair_Denies() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        assertFalse(_eval(ROUTERB, _swapV2(OTHER)), "wrong target denies");
        assertFalse(_eval(ROUTERA, _erc4626(V4626_DEP, OTHER)), "wrong selector denies");
    }

    // ── T-1 mode ON: recipient must equal the account, per safe-set selector ─────

    function test_RecipientMode_SwapV2() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, true);
        assertTrue(_eval(ROUTERA, _swapV2(ACCOUNT)), "recipient==account passes");
        assertFalse(_eval(ROUTERA, _swapV2(OTHER)),  "recipient!=account denies");
    }

    function test_RecipientMode_V3() public {
        _configure(_pairs1(ROUTERA, V3), false, true);
        assertTrue(_eval(ROUTERA, _v3(ACCOUNT)));
        assertFalse(_eval(ROUTERA, _v3(OTHER)));
    }

    function test_RecipientMode_V3_02() public {
        _configure(_pairs1(ROUTERA, V3_02), false, true);
        assertTrue(_eval(ROUTERA, _v3_02(ACCOUNT)));
        assertFalse(_eval(ROUTERA, _v3_02(OTHER)));
    }

    function test_RecipientMode_AaveSupply() public {
        _configure(_pairs1(ROUTERA, AAVE_SUP), false, true);
        assertTrue(_eval(ROUTERA, _aave(AAVE_SUP, ACCOUNT)));
        assertFalse(_eval(ROUTERA, _aave(AAVE_SUP, OTHER)));
    }

    function test_RecipientMode_AaveDeposit() public {
        _configure(_pairs1(ROUTERA, AAVE_DEP), false, true);
        assertTrue(_eval(ROUTERA, _aave(AAVE_DEP, ACCOUNT)));
        assertFalse(_eval(ROUTERA, _aave(AAVE_DEP, OTHER)));
    }

    function test_RecipientMode_Erc4626Deposit() public {
        _configure(_pairs1(ROUTERA, V4626_DEP), false, true);
        assertTrue(_eval(ROUTERA, _erc4626(V4626_DEP, ACCOUNT)));
        assertFalse(_eval(ROUTERA, _erc4626(V4626_DEP, OTHER)));
    }

    function test_RecipientMode_Erc4626Mint() public {
        _configure(_pairs1(ROUTERA, V4626_MNT), false, true);
        assertTrue(_eval(ROUTERA, _erc4626(V4626_MNT, ACCOUNT)));
        assertFalse(_eval(ROUTERA, _erc4626(V4626_MNT, OTHER)));
    }

    // ── T-1 mode ON: non-decodable selector fails closed ─────────────────────────

    function test_RecipientMode_NonDecodableSelector_FailsClosed() public {
        // exactInput carries its recipient behind a dynamic offset — not in the decodable set.
        _configure(_pairs1(ROUTERA, EXACT_INPUT), false, true);
        // Even with a recipient-looking word equal to the account, the selector is denied.
        bytes memory data = abi.encodeWithSelector(EXACT_INPUT, ACCOUNT, ACCOUNT, ACCOUNT, ACCOUNT, ACCOUNT);
        assertFalse(_eval(ROUTERA, data), "non-decodable selector must fail closed under recipient mode");
    }

    // ── T-1 mode OFF: recipient unconstrained (documents the boundary) ───────────

    function test_RecipientMode_Off_RecipientUnconstrained() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        // Output goes to OTHER, not the account — still passes with the mode OFF.
        assertTrue(_eval(ROUTERA, _swapV2(OTHER)), "mode OFF: output recipient is unconstrained");
    }

    // ── bounds safety: a too-short payload fails closed under recipient mode ──────

    function test_RecipientMode_ShortPayload_FailsClosed() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, true);
        // SWAP_V2 needs >= 132 bytes to read the recipient word; this payload is 36 bytes.
        bytes memory tooShort = abi.encodeWithSelector(SWAP_V2, uint256(AMOUNT));
        assertFalse(_eval(ROUTERA, tooShort), "short consuming payload must fail closed, not read OOB");
    }

    // ── unchanged structural checks still hold ───────────────────────────────────

    function test_WrongShape_NotThreeCalls_Denies() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        Call[] memory calls = new Call[](2);
        calls[0] = Call({target: TOKEN, value: 0, data: abi.encodeWithSelector(APPROVE, SPENDER, AMOUNT)});
        calls[1] = Call({target: ROUTERA, value: 0, data: _swapV2(OTHER)});
        assertFalse(batchPerm.evaluateBatch(calls, _ctx()));
    }

    function test_NonZeroReset_Denies() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        Call[] memory calls = _batch(ROUTERA, _swapV2(OTHER));
        calls[2].data = abi.encodeWithSelector(APPROVE, SPENDER, uint256(1)); // reset must be 0
        assertFalse(batchPerm.evaluateBatch(calls, _ctx()));
    }

    function test_AmountAboveCap_Denies() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        Call[] memory calls = _batch(ROUTERA, _swapV2(OTHER));
        calls[0].data = abi.encodeWithSelector(APPROVE, SPENDER, CAP + 1);
        assertFalse(batchPerm.evaluateBatch(calls, _ctx()));
    }

    function test_RequireAmountMatch_Enforced() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), true, false);
        // _swapV2 sets the leading uint256 (amountIn) to AMOUNT == approveAmount → passes.
        assertTrue(_eval(ROUTERA, _swapV2(OTHER)));
        // Mismatched leading amount → denies.
        address[] memory path = new address[](2); path[0] = TOKEN; path[1] = OTHER;
        bytes memory mismatched = abi.encodeWithSelector(SWAP_V2, uint256(AMOUNT + 1), uint256(1), path, OTHER, uint256(0));
        assertFalse(_eval(ROUTERA, mismatched));
    }

    // ── configure() validation ───────────────────────────────────────────────────

    function test_Configure_RejectsZeroSelectorPair() public {
        vm.expectRevert(ApproveAndCallBatchPermission.EmptyAllowlist.selector);
        _configure(_pairs1(ROUTERA, bytes4(0)), false, false);
    }

    function test_Configure_RejectsZeroTargetPair() public {
        vm.expectRevert(ApproveAndCallBatchPermission.EmptyAllowlist.selector);
        _configure(_pairs1(address(0), SWAP_V2), false, false);
    }

    function test_Configure_RejectsEmptyPairs() public {
        ApproveAndCallBatchPermission.ConsumingPair[] memory none = new ApproveAndCallBatchPermission.ConsumingPair[](0);
        vm.expectRevert(ApproveAndCallBatchPermission.EmptyAllowlist.selector);
        _configure(none, false, false);
    }

    function test_IsConsumingPairAllowed_View() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        assertTrue(batchPerm.isConsumingPairAllowed(ACCOUNT, ROUTERA, SWAP_V2));
        assertFalse(batchPerm.isConsumingPairAllowed(ACCOUNT, ROUTERA, V4626_DEP));
        assertFalse(batchPerm.isConsumingPairAllowed(ACCOUNT, ROUTERB, SWAP_V2));
    }

    // ── recipient-mode length guards for the word-2 and word-1 offset classes ─────

    function test_RecipientMode_ShortPayload_Aave_FailsClosed() public {
        _configure(_pairs1(ROUTERA, AAVE_SUP), false, true);
        // supply needs >= 100 bytes to read onBehalfOf (word 2); this payload is 36 bytes.
        bytes memory tooShort = abi.encodeWithSelector(AAVE_SUP, TOKEN);
        assertFalse(_eval(ROUTERA, tooShort));
    }

    function test_RecipientMode_ShortPayload_Erc4626_FailsClosed() public {
        _configure(_pairs1(ROUTERA, V4626_DEP), false, true);
        // deposit needs >= 68 bytes to read receiver (word 1); this payload is 36 bytes.
        bytes memory tooShort = abi.encodeWithSelector(V4626_DEP, uint256(AMOUNT));
        assertFalse(_eval(ROUTERA, tooShort));
    }

    // ── structural denials on each of the three calls ────────────────────────────

    function test_Approve_NonZeroValue_Denies() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        Call[] memory calls = _batch(ROUTERA, _swapV2(OTHER));
        calls[0].value = 1;
        assertFalse(batchPerm.evaluateBatch(calls, _ctx()));
    }

    function test_Approve_WrongSelector_Denies() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        Call[] memory calls = _batch(ROUTERA, _swapV2(OTHER));
        calls[0].data = abi.encodeWithSelector(bytes4(0xdeadbeef), SPENDER, AMOUNT);
        assertFalse(batchPerm.evaluateBatch(calls, _ctx()));
    }

    function test_Approve_WrongLength_Denies() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        Call[] memory calls = _batch(ROUTERA, _swapV2(OTHER));
        calls[0].data = abi.encodeWithSelector(APPROVE, SPENDER); // 36 bytes, not 68
        assertFalse(batchPerm.evaluateBatch(calls, _ctx()));
    }

    function test_Approve_TokenNotAllowlisted_Denies() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        Call[] memory calls = _batch(ROUTERA, _swapV2(OTHER));
        calls[0].target = OTHER; // token with cap 0
        assertFalse(batchPerm.evaluateBatch(calls, _ctx()));
    }

    function test_Approve_NonSpender_Denies() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        Call[] memory calls = _batch(ROUTERA, _swapV2(OTHER));
        calls[0].data = abi.encodeWithSelector(APPROVE, OTHER, AMOUNT); // not the allowlisted spender
        assertFalse(batchPerm.evaluateBatch(calls, _ctx()));
    }

    function test_Approve_ZeroAmount_Denies() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        Call[] memory calls = _batch(ROUTERA, _swapV2(OTHER));
        calls[0].data = abi.encodeWithSelector(APPROVE, SPENDER, uint256(0));
        assertFalse(batchPerm.evaluateBatch(calls, _ctx()));
    }

    function test_Consuming_NonZeroValue_Denies() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        Call[] memory calls = _batch(ROUTERA, _swapV2(OTHER));
        calls[1].value = 1;
        assertFalse(batchPerm.evaluateBatch(calls, _ctx()));
    }

    function test_Consuming_ShortData_Denies() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        // data shorter than CONSUMING_MIN_LEN (36) — denied before any decode.
        assertFalse(_eval(ROUTERA, abi.encodePacked(SWAP_V2)));
    }

    function test_Reset_NonZeroValue_Denies() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        Call[] memory calls = _batch(ROUTERA, _swapV2(OTHER));
        calls[2].value = 1;
        assertFalse(batchPerm.evaluateBatch(calls, _ctx()));
    }

    function test_Reset_WrongToken_Denies() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        Call[] memory calls = _batch(ROUTERA, _swapV2(OTHER));
        calls[2].target = OTHER;
        assertFalse(batchPerm.evaluateBatch(calls, _ctx()));
    }

    function test_Reset_WrongLength_Denies() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        Call[] memory calls = _batch(ROUTERA, _swapV2(OTHER));
        calls[2].data = abi.encodeWithSelector(APPROVE, SPENDER); // 36 bytes
        assertFalse(batchPerm.evaluateBatch(calls, _ctx()));
    }

    function test_Reset_WrongSelector_Denies() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        Call[] memory calls = _batch(ROUTERA, _swapV2(OTHER));
        calls[2].data = abi.encodeWithSelector(bytes4(0xdeadbeef), SPENDER, uint256(0));
        assertFalse(batchPerm.evaluateBatch(calls, _ctx()));
    }

    function test_Reset_WrongSpender_Denies() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        Call[] memory calls = _batch(ROUTERA, _swapV2(OTHER));
        calls[2].data = abi.encodeWithSelector(APPROVE, OTHER, uint256(0)); // different spender
        assertFalse(batchPerm.evaluateBatch(calls, _ctx()));
    }

    function test_HappyPath_Passes() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        assertTrue(_eval(ROUTERA, _swapV2(OTHER)));
    }

    function test_Evaluate_AlwaysFalse() public view {
        // Single-dispatch evaluate is never authorised for this batch-only template.
        Context memory c;
        assertFalse(batchPerm.evaluate("", c));
    }
}
