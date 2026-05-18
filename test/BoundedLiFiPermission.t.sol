// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import {BoundedLiFiPermission} from "../contracts/templates/BoundedLiFiPermission.sol";
import {Context} from "../contracts/interfaces/IPermission.sol";

contract BoundedLiFiPermissionTest is Test {
    BoundedLiFiPermission internal perm;

    address constant SAFE         = address(0xA11);
    address constant MANAGER      = address(0xB22);
    address constant PERM_SIGNER  = address(0xC33);
    address constant ATTACKER     = address(0xDEAD);

    address constant LIFI         = 0x1231DEB6f5749EF6cE6943a275A1D3E7486F4EaE; // LiFi diamond
    address constant FAKE_DIAMOND = address(0xABBA);

    // Real LiFi selectors (computed via cast sig).
    bytes4  constant SWAP_SINGLE_V3 = 0x4666fc80; // swapTokensSingleV3ERC20ToERC20
    bytes4  constant SWAP_GENERIC   = 0x4630a0d8; // swapTokensGeneric
    bytes4  constant SWAP_MULTI_V3  = 0x5fd9ae2e; // swapTokensMultipleV3ERC20ToERC20

    uint256 constant MAX_MIN = 1_000_000e6; // 1M USDC minOut cap

    function setUp() public {
        address[] memory diamonds = new address[](1);
        diamonds[0] = LIFI;

        // Operator opts in to single-V3 + multi-V3 only (not the more permissive Generic).
        bytes4[] memory sels = new bytes4[](2);
        sels[0] = SWAP_SINGLE_V3;
        sels[1] = SWAP_MULTI_V3;

        perm = new BoundedLiFiPermission(diamonds, sels, MAX_MIN, PERM_SIGNER);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// @dev Build calldata matching the head of LiFi's V3 single-swap entry:
    ///      (bytes32 txId, string integrator, string referrer, address receiver,
    ///       uint256 minAmount, SwapData swapData)
    ///      We don't need a real SwapData for offset extraction — placeholder bytes
    ///      after the head is fine. The permission only reads bytes [100, 164].
    function _lifiCalldata(bytes4 sel, address receiver, uint256 minAmount)
        internal pure
        returns (bytes memory)
    {
        // Use abi.encodeWithSelector. We build a *valid* call shape so that
        // abi.decode at the receiver/minAmount offsets returns the right values.
        bytes32 txId = bytes32(uint256(1));
        string memory integ = "sail";
        string memory ref   = "";
        // Use a fixed-shape SwapData placeholder
        bytes memory inner = abi.encode(
            address(0), address(0), address(0), address(0), uint256(0), bytes(""), false
        );
        // For V3 single-swap variants, SwapData is a single struct (not array).
        // For multi-V3, it's an array — different ABI tail. Since our permission
        // only reads bytes [100:164] (receiver + minAmount), the tail layout
        // doesn't matter for the property under test; just ensure length >= 164.
        return abi.encodeWithSelector(sel, txId, integ, ref, receiver, minAmount, inner);
    }

    function _ctx(address target, bytes memory data) internal pure returns (Context memory) {
        return Context({
            account:        SAFE,
            manager:        MANAGER,
            submitter:      MANAGER,
            target:         target,
            selector:       data.length >= 4 ? bytes4(data) : bytes4(0),
            value:          0,
            blockTimestamp: 1,
            blockNumber:    1
        });
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    function test_Constructor_RegistersAllowlists() public view {
        assertTrue(perm.isAllowedDiamond(LIFI));
        assertFalse(perm.isAllowedDiamond(FAKE_DIAMOND));
        assertTrue(perm.isAllowedSelector(SWAP_SINGLE_V3));
        assertTrue(perm.isAllowedSelector(SWAP_MULTI_V3));
        assertFalse(perm.isAllowedSelector(SWAP_GENERIC));
        assertEq(perm.maxMinAmountPerTx(), MAX_MIN);
        assertEq(perm.permissionSigner(), PERM_SIGNER);
    }

    function test_Constructor_RevertsOnZeroSigner() public {
        address[] memory empty;
        bytes4[]  memory emptySels;
        vm.expectRevert(BoundedLiFiPermission.ZeroAddress.selector);
        new BoundedLiFiPermission(empty, emptySels, 0, address(0));
    }

    function test_Discriminator() public view {
        assertEq(perm.discriminator(), keccak256("BoundedLiFiPermission"));
    }

    // -------------------------------------------------------------------------
    // Happy paths
    // -------------------------------------------------------------------------

    function test_Allowed_SingleV3_ReceiverIsSafe() public view {
        bytes memory data = _lifiCalldata(SWAP_SINGLE_V3, SAFE, 1_000e6);
        assertTrue(perm.evaluate(data, _ctx(LIFI, data)));
    }

    function test_Allowed_MultiV3_ReceiverIsSafe() public view {
        bytes memory data = _lifiCalldata(SWAP_MULTI_V3, SAFE, 1_000e6);
        assertTrue(perm.evaluate(data, _ctx(LIFI, data)));
    }

    function test_Allowed_MinAmountAtCap() public view {
        bytes memory data = _lifiCalldata(SWAP_SINGLE_V3, SAFE, MAX_MIN);
        assertTrue(perm.evaluate(data, _ctx(LIFI, data)));
    }

    // -------------------------------------------------------------------------
    // Custody-relevant denials (the real safety properties)
    // -------------------------------------------------------------------------

    /// @notice CRITICAL: manager tries to send swap output to attacker → denied.
    function test_Denied_ReceiverIsAttacker() public view {
        bytes memory data = _lifiCalldata(SWAP_SINGLE_V3, ATTACKER, 1_000e6);
        assertFalse(perm.evaluate(data, _ctx(LIFI, data)));
    }

    function test_Denied_ReceiverIsManager() public view {
        bytes memory data = _lifiCalldata(SWAP_SINGLE_V3, MANAGER, 1_000e6);
        assertFalse(perm.evaluate(data, _ctx(LIFI, data)));
    }

    function test_Denied_ReceiverIsZero() public view {
        bytes memory data = _lifiCalldata(SWAP_SINGLE_V3, address(0), 1_000e6);
        assertFalse(perm.evaluate(data, _ctx(LIFI, data)));
    }

    function test_Denied_UnknownDiamond() public view {
        bytes memory data = _lifiCalldata(SWAP_SINGLE_V3, SAFE, 1_000e6);
        assertFalse(perm.evaluate(data, _ctx(FAKE_DIAMOND, data)));
    }

    function test_Denied_DisallowedSelector_Generic() public view {
        // setUp() did NOT enable SWAP_GENERIC — denied even with correct receiver.
        bytes memory data = _lifiCalldata(SWAP_GENERIC, SAFE, 1_000e6);
        assertFalse(perm.evaluate(data, _ctx(LIFI, data)));
    }

    function test_Denied_MinAmountAboveCap() public view {
        bytes memory data = _lifiCalldata(SWAP_SINGLE_V3, SAFE, MAX_MIN + 1);
        assertFalse(perm.evaluate(data, _ctx(LIFI, data)));
    }

    function test_Denied_TruncatedCalldata() public view {
        bytes memory full = _lifiCalldata(SWAP_SINGLE_V3, SAFE, 1_000e6);
        bytes memory shortBuf = new bytes(163); // one byte short of LEN_MIN_HEAD
        for (uint256 i; i < 163; i++) shortBuf[i] = full[i];
        assertFalse(perm.evaluate(shortBuf, _ctx(LIFI, full)));
    }

    function test_Denied_ApproveSelector_OnLifi() public view {
        // A manager who tried to "approve" on the LiFi target (nonsensical but possible)
        // must be denied — only swap selectors are allowed.
        bytes memory data = abi.encodeWithSignature("approve(address,uint256)", ATTACKER, 1e18);
        assertFalse(perm.evaluate(data, _ctx(LIFI, data)));
    }

    // -------------------------------------------------------------------------
    // Setters
    // -------------------------------------------------------------------------

    function test_SetMaxMinAmount_OnlySigner() public {
        vm.expectRevert(BoundedLiFiPermission.NotPermissionSigner.selector);
        perm.setMaxMinAmountPerTx(1);

        vm.prank(PERM_SIGNER);
        perm.setMaxMinAmountPerTx(42);
        assertEq(perm.maxMinAmountPerTx(), 42);
    }

    function test_SetMaxMinAmount_EmitsEvent() public {
        vm.expectEmit(true, true, true, true);
        emit BoundedLiFiPermission.MaxMinAmountUpdated(MAX_MIN, 7);
        vm.prank(PERM_SIGNER);
        perm.setMaxMinAmountPerTx(7);
    }

    // -------------------------------------------------------------------------
    // Fuzz: the receiver invariant
    // -------------------------------------------------------------------------

    /// @notice The single most important property: for ANY receiver != Safe, deny.
    function testFuzz_ReceiverMustBeSafe(address randomReceiver) public view {
        vm.assume(randomReceiver != SAFE);
        bytes memory data = _lifiCalldata(SWAP_SINGLE_V3, randomReceiver, 1_000e6);
        assertFalse(perm.evaluate(data, _ctx(LIFI, data)));
    }

    function testFuzz_DenyUnknownSelectors(bytes4 sel) public view {
        vm.assume(sel != SWAP_SINGLE_V3 && sel != SWAP_MULTI_V3);
        bytes memory data = _lifiCalldata(sel, SAFE, 1_000e6);
        assertFalse(perm.evaluate(data, _ctx(LIFI, data)));
    }

    function testFuzz_DenyUnknownDiamonds(address randomDiamond) public view {
        vm.assume(randomDiamond != LIFI);
        bytes memory data = _lifiCalldata(SWAP_SINGLE_V3, SAFE, 1_000e6);
        assertFalse(perm.evaluate(data, _ctx(randomDiamond, data)));
    }
}
