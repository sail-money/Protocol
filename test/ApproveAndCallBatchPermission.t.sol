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
    uint256 public regEpoch;
    function registrationEpoch(address, address) external view returns (uint256) { return regEpoch; }
    function setRegEpoch(uint256 e) external { regEpoch = e; }
    function configs(address) external view returns (address) { return signer; }
}

/// @dev Minimal ERC-20 used as the approved token: exposes allowance() (default 0) so the
///      template's pre-batch allowance==0 staticcall resolves, plus a setter to stage stale state.
contract MockERC20 {
    mapping(address => mapping(address => uint256)) public allowance;
    function setAllowance(address owner, address spender, uint256 amount) external {
        allowance[owner][spender] = amount;
    }
}

/// @dev Minimal ERC-4626 vault used as the consuming target for deposit/mint: exposes asset()
///      so the template can bind the consumed underlying to the approved token.
contract MockVault {
    address public asset;
    constructor(address _asset) { asset = _asset; }
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
    address internal constant ROUTERA = address(0xAA01);
    address internal constant ROUTERB = address(0xBB02);
    address internal constant OTHER   = address(0xBEEF);

    uint256 internal constant CAP    = 1_000;
    uint256 internal constant AMOUNT = 100;

    BatchMockKernel                  internal kernel;
    ApproveAndCallBatchPermission    internal batchPerm;
    MockVault                        internal vault; // ERC-4626 consuming target; asset() == TOKEN

    function setUp() public {
        kernel    = new BatchMockKernel(address(this));
        batchPerm = new ApproveAndCallBatchPermission(address(kernel), AUTHOR);
        // Put real ERC-20 code at TOKEN so the template's pre-batch allowance() staticcall resolves
        // (a code-less token would fail closed). Fresh storage ⇒ allowance defaults to zero.
        vm.etch(TOKEN, address(new MockERC20()).code);
        // ERC-4626 target whose underlying is the approved token.
        vault = new MockVault(TOKEN);
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
        // The approved spender must equal the consuming target (#7). Allowlist every target a test
        // may consume on (the two router-like addresses and the ERC-4626 vault) as a spender.
        ApproveAndCallBatchPermission.Config memory cfg;
        cfg.tokens = new address[](1);             cfg.tokens[0] = TOKEN;
        cfg.spenders = new address[](3);
        cfg.spenders[0] = ROUTERA; cfg.spenders[1] = ROUTERB; cfg.spenders[2] = address(vault);
        cfg.consumingPairs = pairs;
        cfg.maxApprovalAmounts = new uint256[](1); cfg.maxApprovalAmounts[0] = CAP;
        cfg.requireAmountMatch = reqAmount;
        // The helper's `reqRecipient` keeps its intent (true = pin recipient to account). The config
        // field is now the opt-OUT `allowUnconstrainedRecipient`, so translate: pin ⇔ not-opted-out.
        cfg.allowUnconstrainedRecipient = !reqRecipient;
        batchPerm.configureDirect(ACCOUNT, abi.encode(cfg));
    }

    function _pairs1(address t, bytes4 s) internal pure returns (ApproveAndCallBatchPermission.ConsumingPair[] memory a) {
        a = new ApproveAndCallBatchPermission.ConsumingPair[](1);
        a[0] = _pair(t, s);
    }

    // ── batch builders ──────────────────────────────────────────────────────────

    function _batch(address consumingTarget, bytes memory consumingData) internal pure returns (Call[] memory calls) {
        // Approve and reset the consuming target itself: the approved spender must be the call's target.
        calls = new Call[](3);
        calls[0] = Call({target: TOKEN, value: 0, data: abi.encodeWithSelector(APPROVE, consumingTarget, AMOUNT)});
        calls[1] = Call({target: consumingTarget, value: 0, data: consumingData});
        calls[2] = Call({target: TOKEN, value: 0, data: abi.encodeWithSelector(APPROVE, consumingTarget, uint256(0))});
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
    // Variants that consume an arbitrary asset (≠ the approved token) — for the #7 stale-allowance shapes.
    function _swapV2Asset(address tokenIn, address to) internal pure returns (bytes memory) {
        address[] memory path = new address[](2); path[0] = tokenIn; path[1] = OTHER;
        return abi.encodeWithSelector(SWAP_V2, uint256(AMOUNT), uint256(1), path, to, uint256(0));
    }
    function _aaveAsset(bytes4 sel, address asset, address onBehalfOf) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(sel, asset, uint256(AMOUNT), onBehalfOf, uint16(0));
    }

    // ── introspection ───────────────────────────────────────────────────────────

    function test_Introspection_Ids() public view {
        assertEq(batchPerm.discriminator(), keccak256("ApproveAndCallBatchPermission"));
        assertEq(batchPerm.permissionId(),  keccak256("sail.permission.ApproveAndCallBatchPermission.v1"));
        assertEq(batchPerm.capabilityIds()[0], SailCapabilities.BATCH_DISPATCH);
    }

    // ── T-2: pair binding closes the cartesian leak ──────────────────────────────

    function test_PairBinding_IntendedPairsPass_CrossPairsDeny() public {
        address vaultAddr = address(vault);
        ApproveAndCallBatchPermission.ConsumingPair[] memory pairs = new ApproveAndCallBatchPermission.ConsumingPair[](2);
        pairs[0] = _pair(ROUTERA, SWAP_V2);
        pairs[1] = _pair(vaultAddr, V4626_DEP);
        _configure(pairs, false, false);

        // intended pairs pass
        assertTrue(_eval(ROUTERA, _swapV2(OTHER)),               "(routerA, swap) should pass");
        assertTrue(_eval(vaultAddr, _erc4626(V4626_DEP, OTHER)), "(vault, deposit) should pass");

        // cross pairs (the cartesian leak) must now DENY
        assertFalse(_eval(ROUTERA, _erc4626(V4626_DEP, OTHER)), "(routerA, deposit) must deny");
        assertFalse(_eval(vaultAddr, _swapV2(OTHER)),           "(vault, swap) must deny");
    }

    function test_UnboundPair_Denies() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        assertFalse(_eval(ROUTERB, _swapV2(OTHER)), "wrong target denies");
        assertFalse(_eval(ROUTERA, _erc4626(V4626_DEP, OTHER)), "wrong selector denies");
    }

    // ── Epoch-binding guard in evaluateBatch ──────────────────────────────────────
    /// @dev A well-formed batch passes while the config's stamped epoch matches the kernel's
    ///      current epoch, is denied once a revoke→re-register cycle bumps the epoch (stale config),
    ///      and passes again only after a fresh configure for the new epoch.
    function test_ConfigEpoch_StaleBatchConfig_Denied() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false); // configureDirect stamps configuredEpoch = 0

        // Epoch-current: stored stamp (0) == ctx.configEpoch (0) → the valid batch passes.
        assertTrue(_eval(ROUTERA, _swapV2(OTHER)), "epoch-current batch should pass");

        // Simulate a revoke → re-register cycle that bumped the kernel epoch to 1, with NO reconfigure.
        kernel.setRegEpoch(1);
        BatchContext memory staleCtx;
        staleCtx.account = ACCOUNT;
        staleCtx.configEpoch = 1; // kernel now pushes epoch 1; stored stamp is still 0
        assertFalse(
            batchPerm.evaluateBatch(_batch(ROUTERA, _swapV2(OTHER)), staleCtx),
            "stale batch config must be denied on epoch mismatch"
        );

        // A fresh configure for the new epoch re-stamps configuredEpoch = 1 and re-enables the batch.
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        assertTrue(
            batchPerm.evaluateBatch(_batch(ROUTERA, _swapV2(OTHER)), staleCtx),
            "re-configured batch should pass at the new epoch"
        );
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
        // ERC-4626 consuming target must be the vault (spender == target; asset() == approved token).
        _configure(_pairs1(address(vault), V4626_DEP), false, true);
        assertTrue(_eval(address(vault), _erc4626(V4626_DEP, ACCOUNT)));
        assertFalse(_eval(address(vault), _erc4626(V4626_DEP, OTHER)));
    }

    function test_RecipientMode_Erc4626Mint() public {
        _configure(_pairs1(address(vault), V4626_MNT), false, true);
        assertTrue(_eval(address(vault), _erc4626(V4626_MNT, ACCOUNT)));
        assertFalse(_eval(address(vault), _erc4626(V4626_MNT, OTHER)));
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
        // Explicit opt-out: reqRecipient=false makes the helper set allowUnconstrainedRecipient=true.
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        // Output goes to OTHER, not the account — still passes once the operator explicitly opts out.
        assertTrue(_eval(ROUTERA, _swapV2(OTHER)), "explicit opt-out: output recipient is unconstrained");
    }

    /// @dev DEFAULT posture: a config that does NOT set `allowUnconstrainedRecipient` (left at its
    ///      zero/false default) pins the recipient to the account — fail-closed by default. Leaving
    ///      the recipient unconstrained now requires the explicit opt-out exercised in the test above.
    function test_RecipientPinnedByDefault() public {
        ApproveAndCallBatchPermission.Config memory cfg;
        cfg.tokens = new address[](1);             cfg.tokens[0] = TOKEN;
        cfg.spenders = new address[](1);           cfg.spenders[0] = ROUTERA;
        cfg.consumingPairs = _pairs1(ROUTERA, SWAP_V2);
        cfg.maxApprovalAmounts = new uint256[](1); cfg.maxApprovalAmounts[0] = CAP;
        // requireAmountMatch and allowUnconstrainedRecipient deliberately left at zero (false).
        batchPerm.configureDirect(ACCOUNT, abi.encode(cfg));
        assertTrue(_eval(ROUTERA, _swapV2(ACCOUNT)), "default: recipient==account passes");
        assertFalse(_eval(ROUTERA, _swapV2(OTHER)),  "default: recipient!=account denied (pinned by default)");
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
        calls[0] = Call({target: TOKEN, value: 0, data: abi.encodeWithSelector(APPROVE, ROUTERA, AMOUNT)});
        calls[1] = Call({target: ROUTERA, value: 0, data: _swapV2(OTHER)});
        assertFalse(batchPerm.evaluateBatch(calls, _ctx()));
    }

    function test_NonZeroReset_Denies() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        Call[] memory calls = _batch(ROUTERA, _swapV2(OTHER));
        calls[2].data = abi.encodeWithSelector(APPROVE, ROUTERA, uint256(1)); // reset must be 0
        assertFalse(batchPerm.evaluateBatch(calls, _ctx()));
    }

    function test_AmountAboveCap_Denies() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        Call[] memory calls = _batch(ROUTERA, _swapV2(OTHER));
        calls[0].data = abi.encodeWithSelector(APPROVE, ROUTERA, CAP + 1);
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

    /// @dev requireAmountMatch is selector-aware: for ERC-4626 deposit(assets,receiver) the consumed
    ///      amount is word 0 (assets), so a deposit of exactly the approved amount passes.
    function test_RequireAmountMatch_ERC4626Deposit_BindsAssetsWord() public {
        _configure(_pairs1(address(vault), V4626_DEP), true, false);
        assertTrue(_eval(address(vault), _erc4626(V4626_DEP, ACCOUNT)));
    }

    /// @dev For ERC-4626 mint(shares,receiver) the pulled assets are previewMint(shares) — NOT in
    ///      calldata — so the approved amount cannot be bound to it. requireAmountMatch must fail
    ///      closed (deny) rather than mis-bind the shares word, which the old word-0 read did.
    function test_RequireAmountMatch_ERC4626Mint_FailsClosed() public {
        bytes4 mintSel = 0x94bf804d; // mint(uint256,address)
        _configure(_pairs1(address(vault), mintSel), true, false);
        assertFalse(_eval(address(vault), _erc4626(mintSel, ACCOUNT)));
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
        // Use the vault as target so the asset binds (asset() == token) and the short payload is
        // caught by the recipient word-1 guard, not the asset decode.
        _configure(_pairs1(address(vault), V4626_DEP), false, true);
        // deposit needs >= 68 bytes to read receiver (word 1); this payload is 36 bytes.
        bytes memory tooShort = abi.encodeWithSelector(V4626_DEP, uint256(AMOUNT));
        assertFalse(_eval(address(vault), tooShort));
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
        calls[0].data = abi.encodeWithSelector(bytes4(0xdeadbeef), ROUTERA, AMOUNT);
        assertFalse(batchPerm.evaluateBatch(calls, _ctx()));
    }

    function test_Approve_WrongLength_Denies() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        Call[] memory calls = _batch(ROUTERA, _swapV2(OTHER));
        calls[0].data = abi.encodeWithSelector(APPROVE, ROUTERA); // 36 bytes, not 68
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
        calls[0].data = abi.encodeWithSelector(APPROVE, ROUTERA, uint256(0));
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
        calls[2].data = abi.encodeWithSelector(APPROVE, ROUTERA); // 36 bytes
        assertFalse(batchPerm.evaluateBatch(calls, _ctx()));
    }

    function test_Reset_WrongSelector_Denies() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        Call[] memory calls = _batch(ROUTERA, _swapV2(OTHER));
        calls[2].data = abi.encodeWithSelector(bytes4(0xdeadbeef), ROUTERA, uint256(0));
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

    // ── #7: bind consumed asset + spender to the approved (token, spender) ─────────

    // Shape 1 — Uniswap V2 stale-allowance theft: approve A=TOKEN to the router, but the swap pulls a
    // DIFFERENT token (path[0] = OTHER) to an attacker via a stale OTHER->router allowance.
    function test_Sec7_V2_ConsumedAssetMismatch_Denies() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        // Sanity: same-asset swap to an arbitrary recipient still passes with the mode OFF.
        assertTrue(_eval(ROUTERA, _swapV2Asset(TOKEN, OTHER)), "consumed asset == approved token passes");
        // Wrong consumed asset → denied even though the (target, selector) pair is allowlisted.
        assertFalse(_eval(ROUTERA, _swapV2Asset(OTHER, OTHER)), "consumed asset != approved token must deny");
    }

    // Shape 2 — Aave supply stale-allowance theft: approve A=TOKEN to the pool, but supply asset=OTHER
    // with onBehalfOf=attacker, pulling OTHER via a stale OTHER->pool allowance.
    function test_Sec7_Aave_ConsumedAssetMismatch_Denies() public {
        _configure(_pairs1(ROUTERA, AAVE_SUP), false, false);
        assertTrue(_eval(ROUTERA, _aaveAsset(AAVE_SUP, TOKEN, OTHER)), "asset == approved token passes");
        assertFalse(_eval(ROUTERA, _aaveAsset(AAVE_SUP, OTHER, OTHER)), "asset != approved token must deny");
    }

    // Shape 3 — aggregator / opaque consuming selector: the consumed asset cannot be located, so the
    // call is denied (fail closed) even when the recipient pin is opted out — not just under the pin.
    function test_Sec7_NonDecodableSelector_FailsClosed_ModeOff() public {
        _configure(_pairs1(ROUTERA, EXACT_INPUT), false, false);
        bytes memory opaque = abi.encodeWithSelector(EXACT_INPUT, ACCOUNT, ACCOUNT, ACCOUNT, ACCOUNT, ACCOUNT);
        assertFalse(_eval(ROUTERA, opaque), "non-decodable consuming selector must fail closed");
    }

    // Spender binding — the consuming call must hit the very spender approved in calls[0].
    function test_Sec7_ConsumingTargetNotApprovedSpender_Denies() public {
        // Allowlist the swap pair on BOTH routers so the pair check passes and we isolate the spender bind.
        ApproveAndCallBatchPermission.ConsumingPair[] memory pairs = new ApproveAndCallBatchPermission.ConsumingPair[](2);
        pairs[0] = _pair(ROUTERA, SWAP_V2);
        pairs[1] = _pair(ROUTERB, SWAP_V2);
        _configure(pairs, false, false);

        // approve TOKEN -> ROUTERA, but consume on ROUTERB (consumed asset == TOKEN, pair allowlisted).
        Call[] memory calls = new Call[](3);
        calls[0] = Call({target: TOKEN, value: 0, data: abi.encodeWithSelector(APPROVE, ROUTERA, AMOUNT)});
        calls[1] = Call({target: ROUTERB, value: 0, data: _swapV2Asset(TOKEN, OTHER)});
        calls[2] = Call({target: TOKEN, value: 0, data: abi.encodeWithSelector(APPROVE, ROUTERA, uint256(0))});
        assertFalse(batchPerm.evaluateBatch(calls, _ctx()), "consuming target != approved spender must deny");
    }

    // Bundled Medium — a pre-existing stale allowance on the SAME (token, spender) pair must deny:
    // otherwise a non-reverting false approve could leave it consumable beyond the bracket.
    function test_Sec7Medium_StalePreBatchAllowance_Denies() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, false);
        // With zero pre-batch allowance the bracket passes.
        assertTrue(_eval(ROUTERA, _swapV2Asset(TOKEN, OTHER)), "zero pre-batch allowance passes");
        // Stage a residual allowance on the exact (token, spender) pair the batch uses → must deny.
        MockERC20(TOKEN).setAllowance(ACCOUNT, ROUTERA, 1);
        assertFalse(_eval(ROUTERA, _swapV2Asset(TOKEN, OTHER)), "non-zero pre-batch allowance must deny");
    }

    // Happy path under full binding — correct bracket with asset == token, recipient == account, and
    // zero pre-batch allowance still PASSES (guards against over-blocking).
    function test_Sec7_FullBinding_HappyPath_Passes() public {
        _configure(_pairs1(ROUTERA, SWAP_V2), false, true);
        assertTrue(_eval(ROUTERA, _swapV2Asset(TOKEN, ACCOUNT)), "fully-bound correct bracket passes");
    }
}
