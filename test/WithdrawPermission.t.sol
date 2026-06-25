// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import {Context}                from "../contracts/interfaces/IPermission.sol";
import {SailCapabilities}       from "../contracts/interfaces/SailCapabilities.sol";
import {ConfigurablePermission} from "../contracts/templates/ConfigurablePermission.sol";
import {WithdrawPermission}     from "../contracts/templates/WithdrawPermission.sol";

/// @dev Minimal kernel view: every account registered; this test contract is the permissionSigner.
contract WithdrawMockKernel {
    address public immutable signer;
    constructor(address _signer) { signer = _signer; }
    function registered(address) external pure returns (bool) { return true; }
    uint256 public regEpoch;
    function registrationEpoch(address, address) external view returns (uint256) { return regEpoch; }
    function setRegEpoch(uint256 e) external { regEpoch = e; }
    function configs(address) external view returns (address, address, address, bool) {
        return (signer, address(0), address(0), true);
    }
}

contract WithdrawPermissionTest is Test {
    bytes4 internal constant TRANSFER     = 0xa9059cbb;
    bytes4 internal constant TRANSFERFROM = 0x23b872dd;
    bytes4 internal constant APPROVE      = 0x095ea7b3;

    address internal constant AUTHOR    = address(0xA11CE);
    address internal constant ACCOUNT   = address(0xACC0);
    address internal constant TOKEN     = address(0x1010);
    address internal constant RECIPIENT = address(0x5AFE);
    address internal constant OTHER     = address(0xBEEF);

    WithdrawMockKernel    internal kernel;
    WithdrawPermission internal wp;

    function setUp() public {
        kernel = new WithdrawMockKernel(address(this));
        wp     = new WithdrawPermission(address(kernel), AUTHOR);
        _configure(_one(TOKEN), RECIPIENT, 100 ether);
    }

    // ── helpers ─────────────────────────────────────────────────────────────
    function _one(address a) internal pure returns (address[] memory arr) { arr = new address[](1); arr[0] = a; }
    function _configure(address[] memory tokens, address recipient, uint256 cap) internal {
        wp.configureDirect(ACCOUNT, abi.encode(tokens, recipient, cap));
    }
    function _ctx(bytes4 sel, uint256 value) internal pure returns (Context memory c) {
        c = Context(ACCOUNT, address(0), address(0), TOKEN, sel, value, 0, 0, 0);
    }
    function _transfer(address to, uint256 amt) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(TRANSFER, to, amt);
    }
    function _transferFrom(address from, address to, uint256 amt) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(TRANSFERFROM, from, to, amt);
    }

    // ── author + introspection ───────────────────────────────────────────────
    function test_Author_IsRecorded() public view { assertEq(wp.author(), AUTHOR); }
    function test_Introspection_Ids() public view {
        assertEq(wp.discriminator(), keccak256("WithdrawPermission"));
        assertEq(wp.permissionId(),  keccak256("sail.permission.WithdrawPermission.v1"));
        bytes32[] memory ids = wp.capabilityIds();
        assertEq(ids.length, 1);
        assertEq(ids[0], SailCapabilities.WITHDRAW);
    }

    // ── config validation ─────────────────────────────────────────────────────
    function test_Config_Valid() public view {
        (address[] memory toks, address rec, uint256 cap) = wp.getConfig(ACCOUNT);
        assertEq(toks.length, 1); assertEq(toks[0], TOKEN); assertEq(rec, RECIPIENT); assertEq(cap, 100 ether);
        assertTrue(wp.isAllowedToken(ACCOUNT, TOKEN));
    }
    function test_Config_RevertsEmptyTokens() public {
        vm.expectRevert(WithdrawPermission.EmptyAllowlist.selector);
        wp.configureDirect(ACCOUNT, abi.encode(new address[](0), RECIPIENT, uint256(1)));
    }
    function test_Config_RevertsTooLong() public {
        address[] memory toks = new address[](51);
        for (uint256 i; i < 51; i++) toks[i] = address(uint160(i + 1));
        vm.expectRevert(WithdrawPermission.AllowlistTooLong.selector);
        wp.configureDirect(ACCOUNT, abi.encode(toks, RECIPIENT, uint256(1)));
    }
    function test_Config_RevertsZeroToken() public {
        vm.expectRevert(ConfigurablePermission.ZeroAddress.selector);
        wp.configureDirect(ACCOUNT, abi.encode(_one(address(0)), RECIPIENT, uint256(1)));
    }
    function test_Config_RevertsZeroRecipient() public {
        vm.expectRevert(ConfigurablePermission.ZeroAddress.selector);
        wp.configureDirect(ACCOUNT, abi.encode(_one(TOKEN), address(0), uint256(1)));
    }

    // ── transfer ───────────────────────────────────────────────────────────────
    function test_Transfer_ToRecipient_WithinCap_Allowed() public view {
        assertTrue(wp.evaluate(_transfer(RECIPIENT, 100 ether), _ctx(TRANSFER, 0)));
    }
    function test_Transfer_ToNonRecipient_Denied() public view {
        assertFalse(wp.evaluate(_transfer(OTHER, 1 ether), _ctx(TRANSFER, 0)));
    }
    function test_Transfer_OverCap_Denied() public view {
        assertFalse(wp.evaluate(_transfer(RECIPIENT, 100 ether + 1), _ctx(TRANSFER, 0)));
    }
    function test_Transfer_TokenNotAllowed_Denied() public {
        // reconfigure with a different token; TOKEN is no longer allowlisted
        _configure(_one(OTHER), RECIPIENT, 100 ether);
        assertFalse(wp.evaluate(_transfer(RECIPIENT, 1 ether), _ctx(TRANSFER, 0)));
    }

    // ── transferFrom ─────────────────────────────────────────────────────────
    function test_TransferFrom_FromAccount_ToRecipient_Allowed() public view {
        assertTrue(wp.evaluate(_transferFrom(ACCOUNT, RECIPIENT, 50 ether), _ctx(TRANSFERFROM, 0)));
    }
    function test_TransferFrom_FromNotAccount_Denied() public view {
        assertFalse(wp.evaluate(_transferFrom(OTHER, RECIPIENT, 50 ether), _ctx(TRANSFERFROM, 0)));
    }
    function test_TransferFrom_ToNonRecipient_Denied() public view {
        assertFalse(wp.evaluate(_transferFrom(ACCOUNT, OTHER, 50 ether), _ctx(TRANSFERFROM, 0)));
    }

    // ── value + unrouted ───────────────────────────────────────────────────────
    function test_NativeValue_Denied() public view {
        assertFalse(wp.evaluate(_transfer(RECIPIENT, 1 ether), _ctx(TRANSFER, 1)));
    }
    function test_UnroutedSelector_Approve_Denied() public view {
        bytes memory data = abi.encodeWithSelector(APPROVE, RECIPIENT, uint256(1));
        assertFalse(wp.evaluate(data, _ctx(APPROVE, 0)));
    }

    // ── coverage close-out ───────────────────────────────────────────────────────
    function test_TransferFrom_OverCap_Denied() public view {
        assertFalse(wp.evaluate(_transferFrom(ACCOUNT, RECIPIENT, 100 ether + 1), _ctx(TRANSFERFROM, 0)));
    }
    function test_Transfer_ShortCalldata_Denied() public view {
        bytes memory short = abi.encodeWithSelector(TRANSFER, RECIPIENT); // < 68 bytes
        assertFalse(wp.evaluate(short, _ctx(TRANSFER, 0)));
    }
    function test_TransferFrom_ShortCalldata_Denied() public view {
        bytes memory short = abi.encodeWithSelector(TRANSFERFROM, ACCOUNT, RECIPIENT); // < 100 bytes
        assertFalse(wp.evaluate(short, _ctx(TRANSFERFROM, 0)));
    }

    // ── documented edge (pinned, not a fix): maxAmountPerTx == 0 is fail-closed ───
    function test_Pin_ZeroCap_BlocksAnyNonZeroWithdrawal() public {
        _configure(_one(TOKEN), RECIPIENT, 0);
        assertFalse(wp.evaluate(_transfer(RECIPIENT, 1), _ctx(TRANSFER, 0)));        // non-zero denied
        assertTrue(wp.evaluate(_transfer(RECIPIENT, 0), _ctx(TRANSFER, 0)));         // zero to pinned recipient ok
    }
}
