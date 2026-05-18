// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {AzuroPredictionPermission} from "../contracts/templates/AzuroPredictionPermission.sol";
import {Context} from "../contracts/interfaces/IPermission.sol";

contract AzuroPredictionPermissionTest is Test {
    AzuroPredictionPermission perm;

    address constant SAFE   = address(0x5AFE);
    address constant CORE   = address(0xA200);
    address constant LP     = address(0x1234);
    address constant SIGNER = address(0x5161);
    address constant ORACLE = address(0x0FAC);
    address constant OTHER  = address(0x9999);

    uint256 constant COND_FOOTBALL = 1001;
    uint256 constant COND_TENNIS   = 2002;
    uint256 constant COND_CRYPTO   = 3003;
    uint256 constant COND_BLOCKED  = 9999;

    uint128 constant MAX_PAYOUT = 1000e6; // 1000 USDC

    bytes4 private constant BET_FOR = bytes4(
        keccak256(
            "betFor((address,(uint256,uint256,uint8,uint64[],uint128[],uint128,uint8)[],uint8,address,bytes,bytes,bytes)[])"
        )
    );

    // ── decode-only structs (mirrors contract internals) ──────────────────────

    struct ConditionData {
        uint256  gameId;
        uint256  conditionId;
        uint8    conditionKind;
        uint64[] odds;
        uint128[] outcomes;
        uint128  payoutLimit;
        uint8    winningOutcomesCount;
    }

    struct OrderData {
        address         betOwner;
        ConditionData[] conditionDatas;
        uint8           betType;
        address         oracle;
        bytes           clientBetData;
        bytes           bettorSignature;
        bytes           oracleSignature;
    }

    // ── setup ─────────────────────────────────────────────────────────────────

    function setUp() public {
        uint256[] memory conditions = new uint256[](3);
        conditions[0] = COND_FOOTBALL;
        conditions[1] = COND_TENNIS;
        conditions[2] = COND_CRYPTO;

        perm = new AzuroPredictionPermission(
            CORE,
            LP,
            conditions,
            MAX_PAYOUT,
            true,  // allowComboBets
            SIGNER
        );
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    function _singleCondition(uint256 conditionId, uint128 payoutLimit)
        internal
        pure
        returns (ConditionData memory)
    {
        uint64[] memory odds     = new uint64[](2);
        odds[0] = 1500; odds[1] = 2500;
        uint128[] memory outcomes = new uint128[](2);
        outcomes[0] = 0; outcomes[1] = 1;

        return ConditionData({
            gameId:               42,
            conditionId:          conditionId,
            conditionKind:        0,
            odds:                 odds,
            outcomes:             outcomes,
            payoutLimit:          payoutLimit,
            winningOutcomesCount: 1
        });
    }

    function _buildOrders(address betOwner, uint256 conditionId, uint128 payoutLimit)
        internal
        pure
        returns (bytes memory)
    {
        OrderData[] memory orders = new OrderData[](1);
        orders[0].betOwner        = betOwner;
        orders[0].conditionDatas  = new ConditionData[](1);
        orders[0].conditionDatas[0] = _singleCondition(conditionId, payoutLimit);
        orders[0].betType         = 0;
        orders[0].oracle          = ORACLE;
        orders[0].clientBetData   = "";
        orders[0].bettorSignature = "";
        orders[0].oracleSignature = "";

        return abi.encodeWithSelector(BET_FOR, LP, orders);
    }

    function _buildComboOrders(address betOwner, uint256 cond1, uint256 cond2, uint128 payoutLimit)
        internal
        pure
        returns (bytes memory)
    {
        OrderData[] memory orders = new OrderData[](1);
        orders[0].betOwner        = betOwner;
        orders[0].conditionDatas  = new ConditionData[](2);
        orders[0].conditionDatas[0] = _singleCondition(cond1, payoutLimit);
        orders[0].conditionDatas[1] = _singleCondition(cond2, payoutLimit);
        orders[0].betType         = 1; // combo
        orders[0].oracle          = ORACLE;
        orders[0].clientBetData   = "";
        orders[0].bettorSignature = "";
        orders[0].oracleSignature = "";

        return abi.encodeWithSelector(BET_FOR, LP, orders);
    }

    function _ctx(bytes memory /*data*/) internal view returns (Context memory) {
        return Context({
            account:        SAFE,
            manager:        address(0),
            submitter:      address(0),
            target:         CORE,
            selector:       BET_FOR,
            value:          0,
            blockTimestamp: block.timestamp,
            blockNumber:    block.number
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────────────

    function test_Constructor_SetsFields() public view {
        assertEq(perm.azuroCore(),        CORE);
        assertEq(perm.azuroLP(),          LP);
        assertEq(perm.permissionSigner(), SIGNER);
        assertEq(perm.maxPayoutLimit(),   MAX_PAYOUT);
        assertTrue(perm.allowComboBets());
    }

    function test_Constructor_SetsConditionAllowlist() public view {
        assertTrue(perm.isAllowedCondition(COND_FOOTBALL));
        assertTrue(perm.isAllowedCondition(COND_TENNIS));
        assertTrue(perm.isAllowedCondition(COND_CRYPTO));
        assertFalse(perm.isAllowedCondition(COND_BLOCKED));
    }

    function test_Constructor_RevertsOnZeroCore() public {
        uint256[] memory conds = new uint256[](0);
        vm.expectRevert(AzuroPredictionPermission.ZeroAddress.selector);
        new AzuroPredictionPermission(address(0), LP, conds, MAX_PAYOUT, true, SIGNER);
    }

    function test_Constructor_RevertsOnZeroLP() public {
        uint256[] memory conds = new uint256[](0);
        vm.expectRevert(AzuroPredictionPermission.ZeroAddress.selector);
        new AzuroPredictionPermission(CORE, address(0), conds, MAX_PAYOUT, true, SIGNER);
    }

    function test_Constructor_RevertsOnZeroSigner() public {
        uint256[] memory conds = new uint256[](0);
        vm.expectRevert(AzuroPredictionPermission.ZeroAddress.selector);
        new AzuroPredictionPermission(CORE, LP, conds, MAX_PAYOUT, true, address(0));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden paths
    // ─────────────────────────────────────────────────────────────────────────

    function test_GoldenPath_SingleBet() public view {
        bytes memory data = _buildOrders(SAFE, COND_FOOTBALL, MAX_PAYOUT);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    function test_GoldenPath_BetAtPayoutCap() public view {
        bytes memory data = _buildOrders(SAFE, COND_TENNIS, MAX_PAYOUT);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    function test_GoldenPath_BetBelowPayoutCap() public view {
        bytes memory data = _buildOrders(SAFE, COND_CRYPTO, MAX_PAYOUT / 2);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    function test_GoldenPath_ComboBet() public view {
        bytes memory data = _buildComboOrders(SAFE, COND_FOOTBALL, COND_TENNIS, MAX_PAYOUT / 2);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Gate 1: wrong target
    // ─────────────────────────────────────────────────────────────────────────

    function test_WrongTarget_ReturnsFalse() public view {
        bytes memory data = _buildOrders(SAFE, COND_FOOTBALL, MAX_PAYOUT);
        Context memory ctx = Context({account: SAFE, manager: address(0), submitter: address(0), target: address(0xDEAD), selector: BET_FOR, value: 0, blockTimestamp: block.timestamp, blockNumber: block.number});
        assertFalse(perm.evaluate(data, ctx));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Gate 2: wrong selector
    // ─────────────────────────────────────────────────────────────────────────

    function test_WrongSelector_ReturnsFalse() public view {
        bytes memory data = _buildOrders(SAFE, COND_FOOTBALL, MAX_PAYOUT);
        Context memory ctx = Context({account: SAFE, manager: address(0), submitter: address(0), target: CORE, selector: bytes4(0xdeadbeef), value: 0, blockTimestamp: block.timestamp, blockNumber: block.number});
        assertFalse(perm.evaluate(data, ctx));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Gate 3: betOwner check
    // ─────────────────────────────────────────────────────────────────────────

    function test_WrongBetOwner_ReturnsFalse() public view {
        bytes memory data = _buildOrders(OTHER, COND_FOOTBALL, MAX_PAYOUT);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    function test_ZeroBetOwner_ReturnsFalse() public view {
        bytes memory data = _buildOrders(address(0), COND_FOOTBALL, MAX_PAYOUT);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Gate 3: conditionId allowlist
    // ─────────────────────────────────────────────────────────────────────────

    function test_BlockedCondition_ReturnsFalse() public view {
        bytes memory data = _buildOrders(SAFE, COND_BLOCKED, MAX_PAYOUT);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    function test_ComboWithOneBlockedCondition_ReturnsFalse() public view {
        bytes memory data = _buildComboOrders(SAFE, COND_FOOTBALL, COND_BLOCKED, MAX_PAYOUT / 2);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Gate 3: payout cap
    // ─────────────────────────────────────────────────────────────────────────

    function test_OversizedPayout_ReturnsFalse() public view {
        bytes memory data = _buildOrders(SAFE, COND_FOOTBALL, MAX_PAYOUT + 1);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    function test_ZeroPayout_ReturnsTrue() public view {
        bytes memory data = _buildOrders(SAFE, COND_FOOTBALL, 0);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Gate 3: combo bet allowance
    // ─────────────────────────────────────────────────────────────────────────

    function test_ComboBet_BlockedWhenDisallowed() public {
        vm.prank(SIGNER);
        perm.setAllowComboBets(false);

        bytes memory data = _buildComboOrders(SAFE, COND_FOOTBALL, COND_TENNIS, MAX_PAYOUT / 2);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    function test_SingleBet_AllowedWhenCombosDisabled() public {
        vm.prank(SIGNER);
        perm.setAllowComboBets(false);

        bytes memory data = _buildOrders(SAFE, COND_FOOTBALL, MAX_PAYOUT);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Empty orders array
    // ─────────────────────────────────────────────────────────────────────────

    function test_EmptyOrdersArray_ReturnsFalse() public view {
        OrderData[] memory orders = new OrderData[](0);
        bytes memory data = abi.encodeWithSelector(BET_FOR, LP, orders);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Calldata length guard
    // ─────────────────────────────────────────────────────────────────────────

    function test_TooShortCalldata_ReturnsFalse() public view {
        bytes memory short_ = new bytes(99);
        Context memory ctx = Context({account: SAFE, manager: address(0), submitter: address(0), target: CORE, selector: BET_FOR, value: 0, blockTimestamp: block.timestamp, blockNumber: block.number});
        assertFalse(perm.evaluate(short_, ctx));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // setMaxPayoutLimit
    // ─────────────────────────────────────────────────────────────────────────

    function test_SetMaxPayoutLimit_Updates() public {
        vm.prank(SIGNER);
        perm.setMaxPayoutLimit(500e6);
        assertEq(perm.maxPayoutLimit(), 500e6);
    }

    function test_SetMaxPayoutLimit_EmitsEvent() public {
        vm.expectEmit(false, false, false, true);
        emit AzuroPredictionPermission.MaxPayoutLimitUpdated(MAX_PAYOUT, 500e6);
        vm.prank(SIGNER);
        perm.setMaxPayoutLimit(500e6);
    }

    function test_SetMaxPayoutLimit_BlocksBetsOverNewCap() public {
        vm.prank(SIGNER);
        perm.setMaxPayoutLimit(100e6);

        bytes memory data = _buildOrders(SAFE, COND_FOOTBALL, 101e6);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    function test_SetMaxPayoutLimit_RevertsIfNotSigner() public {
        vm.prank(OTHER);
        vm.expectRevert(AzuroPredictionPermission.NotPermissionSigner.selector);
        perm.setMaxPayoutLimit(500e6);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // setAllowComboBets
    // ─────────────────────────────────────────────────────────────────────────

    function test_SetAllowComboBets_Updates() public {
        vm.prank(SIGNER);
        perm.setAllowComboBets(false);
        assertFalse(perm.allowComboBets());
    }

    function test_SetAllowComboBets_EmitsEvent() public {
        vm.expectEmit(false, false, false, true);
        emit AzuroPredictionPermission.AllowComboBetsUpdated(false);
        vm.prank(SIGNER);
        perm.setAllowComboBets(false);
    }

    function test_SetAllowComboBets_RevertsIfNotSigner() public {
        vm.prank(OTHER);
        vm.expectRevert(AzuroPredictionPermission.NotPermissionSigner.selector);
        perm.setAllowComboBets(false);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // discriminator
    // ─────────────────────────────────────────────────────────────────────────

    function test_Discriminator() public view {
        assertEq(perm.discriminator(), keccak256("AzuroPredictionPermission"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // fuzz
    // ─────────────────────────────────────────────────────────────────────────

    function testFuzz_PayoutAtOrBelowCap_Passes(uint128 payout) public view {
        payout = uint128(bound(payout, 0, MAX_PAYOUT));
        bytes memory data = _buildOrders(SAFE, COND_FOOTBALL, payout);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    function testFuzz_PayoutAboveCap_Fails(uint128 payout) public view {
        payout = uint128(bound(payout, uint256(MAX_PAYOUT) + 1, type(uint128).max));
        bytes memory data = _buildOrders(SAFE, COND_FOOTBALL, payout);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    function testFuzz_WrongBetOwner_Fails(address owner) public view {
        vm.assume(owner != SAFE);
        bytes memory data = _buildOrders(owner, COND_FOOTBALL, MAX_PAYOUT);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }
}
