// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import {Context}                from "../contracts/interfaces/IPermission.sol";
import {SailCapabilities}       from "../contracts/interfaces/SailCapabilities.sol";
import {ConfigurablePermission} from "../contracts/templates/ConfigurablePermission.sol";
import {TransferPermission}     from "../contracts/templates/TransferPermission.sol";

/// @dev Minimal kernel view: every account registered; this test contract is the permissionSigner.
contract TransferMockKernel {
    address public immutable signer;
    constructor(address _signer) { signer = _signer; }
    function registered(address) external pure returns (bool) { return true; }
    function configs(address) external view returns (address, address, address, bool) {
        return (signer, address(0), address(0), true);
    }
}

/// @notice Dedicated coverage + regression locks for TransferPermission (no logic changes). Pins
///         every branch of evaluate() and every configure() validation revert, plus the
///         documented fail-closed edge where maxAmountPerTx == 0 blocks all non-zero transfers.
contract TransferPermissionTest is Test {
    bytes4 internal constant TRANSFER     = 0xa9059cbb;
    bytes4 internal constant TRANSFERFROM = 0x23b872dd;
    bytes4 internal constant APPROVE      = 0x095ea7b3;

    address internal constant AUTHOR    = address(0xA11CE);
    address internal constant ACCOUNT   = address(0xACC0);
    address internal constant TOKEN     = address(0x1010);
    address internal constant RECIPIENT = address(0x5AFE);
    address internal constant OTHER     = address(0xBEEF);

    TransferMockKernel internal kernel;
    TransferPermission internal tp;

    function setUp() public {
        kernel = new TransferMockKernel(address(this));
        tp     = new TransferPermission(address(kernel), AUTHOR);
        _configure(_one(RECIPIENT), _one(TOKEN), 100 ether);
    }

    // ── helpers ─────────────────────────────────────────────────────────────
    function _one(address a) internal pure returns (address[] memory arr) { arr = new address[](1); arr[0] = a; }
    function _configure(address[] memory recipients, address[] memory tokens, uint256 cap) internal {
        tp.configureDirect(ACCOUNT, abi.encode(recipients, tokens, cap));
    }
    function _ctx(bytes4 sel, uint256 value) internal pure returns (Context memory c) {
        c = Context(ACCOUNT, address(0), address(0), TOKEN, sel, value, 0, 0);
    }
    function _transfer(address to, uint256 amt) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(TRANSFER, to, amt);
    }
    function _transferFrom(address from, address to, uint256 amt) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(TRANSFERFROM, from, to, amt);
    }

    // ── author + introspection ───────────────────────────────────────────────
    function test_Author_IsRecorded() public view { assertEq(tp.author(), AUTHOR); }
    function test_Introspection_Ids() public view {
        assertEq(tp.discriminator(), keccak256("TransferPermission"));
        assertEq(tp.permissionId(),  keccak256("sail.permission.TransferPermission.v1"));
        bytes32[] memory ids = tp.capabilityIds();
        assertEq(ids.length, 1);
        assertEq(ids[0], SailCapabilities.TRANSFER_TARGET);
    }

    // ── config validation ─────────────────────────────────────────────────────
    function test_Config_Valid() public view {
        (address[] memory rec, address[] memory tok, uint256 cap) = tp.getConfig(ACCOUNT);
        assertEq(rec.length, 1); assertEq(rec[0], RECIPIENT);
        assertEq(tok.length, 1); assertEq(tok[0], TOKEN);
        assertEq(cap, 100 ether);
        assertTrue(tp.isAllowedRecipient(ACCOUNT, RECIPIENT));
        assertTrue(tp.isAllowedToken(ACCOUNT, TOKEN));
    }
    function test_Config_RevertsEmptyRecipients() public {
        vm.expectRevert(TransferPermission.EmptyAllowlist.selector);
        tp.configureDirect(ACCOUNT, abi.encode(new address[](0), _one(TOKEN), uint256(1)));
    }
    function test_Config_RevertsEmptyTokens() public {
        vm.expectRevert(TransferPermission.EmptyAllowlist.selector);
        tp.configureDirect(ACCOUNT, abi.encode(_one(RECIPIENT), new address[](0), uint256(1)));
    }
    function test_Config_RevertsTooLongRecipients() public {
        address[] memory rec = new address[](51);
        for (uint256 i; i < 51; i++) rec[i] = address(uint160(i + 1));
        vm.expectRevert(TransferPermission.AllowlistTooLong.selector);
        tp.configureDirect(ACCOUNT, abi.encode(rec, _one(TOKEN), uint256(1)));
    }
    function test_Config_RevertsTooLongTokens() public {
        address[] memory tok = new address[](51);
        for (uint256 i; i < 51; i++) tok[i] = address(uint160(i + 1));
        vm.expectRevert(TransferPermission.AllowlistTooLong.selector);
        tp.configureDirect(ACCOUNT, abi.encode(_one(RECIPIENT), tok, uint256(1)));
    }
    function test_Config_RevertsZeroRecipient() public {
        vm.expectRevert(ConfigurablePermission.ZeroAddress.selector);
        tp.configureDirect(ACCOUNT, abi.encode(_one(address(0)), _one(TOKEN), uint256(1)));
    }
    function test_Config_RevertsZeroToken() public {
        vm.expectRevert(ConfigurablePermission.ZeroAddress.selector);
        tp.configureDirect(ACCOUNT, abi.encode(_one(RECIPIENT), _one(address(0)), uint256(1)));
    }

    // ── transfer(to, amount) ────────────────────────────────────────────────────
    function test_Transfer_ToRecipient_WithinCap_Allowed() public view {
        assertTrue(tp.evaluate(_transfer(RECIPIENT, 100 ether), _ctx(TRANSFER, 0)));
    }
    function test_Transfer_ToNonRecipient_Denied() public view {
        assertFalse(tp.evaluate(_transfer(OTHER, 1 ether), _ctx(TRANSFER, 0)));
    }
    function test_Transfer_OverCap_Denied() public view {
        assertFalse(tp.evaluate(_transfer(RECIPIENT, 100 ether + 1), _ctx(TRANSFER, 0)));
    }
    function test_Transfer_TokenNotAllowed_Denied() public {
        _configure(_one(RECIPIENT), _one(OTHER), 100 ether); // TOKEN no longer allowlisted
        assertFalse(tp.evaluate(_transfer(RECIPIENT, 1 ether), _ctx(TRANSFER, 0)));
    }
    function test_Transfer_ShortCalldata_Denied() public view {
        bytes memory short = abi.encodeWithSelector(TRANSFER, RECIPIENT); // < 68 bytes
        assertFalse(tp.evaluate(short, _ctx(TRANSFER, 0)));
    }

    // ── transferFrom(from, to, amount) ───────────────────────────────────────────
    function test_TransferFrom_FromAccount_ToRecipient_Allowed() public view {
        assertTrue(tp.evaluate(_transferFrom(ACCOUNT, RECIPIENT, 50 ether), _ctx(TRANSFERFROM, 0)));
    }
    function test_TransferFrom_FromNotAccount_Denied() public view {
        // `from` must be the account itself — prevents pulling tokens from arbitrary approvers.
        assertFalse(tp.evaluate(_transferFrom(OTHER, RECIPIENT, 1 ether), _ctx(TRANSFERFROM, 0)));
    }
    function test_TransferFrom_ToNonRecipient_Denied() public view {
        assertFalse(tp.evaluate(_transferFrom(ACCOUNT, OTHER, 1 ether), _ctx(TRANSFERFROM, 0)));
    }
    function test_TransferFrom_OverCap_Denied() public view {
        assertFalse(tp.evaluate(_transferFrom(ACCOUNT, RECIPIENT, 100 ether + 1), _ctx(TRANSFERFROM, 0)));
    }
    function test_TransferFrom_ShortCalldata_Denied() public view {
        bytes memory short = abi.encodeWithSelector(TRANSFERFROM, ACCOUNT, RECIPIENT); // < 100 bytes
        assertFalse(tp.evaluate(short, _ctx(TRANSFERFROM, 0)));
    }

    // ── value + unrouted selector ────────────────────────────────────────────────
    function test_NativeValue_Denied() public view {
        assertFalse(tp.evaluate(_transfer(RECIPIENT, 1 ether), _ctx(TRANSFER, 1)));
    }
    function test_UnroutedSelector_Approve_Denied() public view {
        bytes memory data = abi.encodeWithSelector(APPROVE, RECIPIENT, uint256(1));
        assertFalse(tp.evaluate(data, _ctx(APPROVE, 0)));
    }

    // ── documented edge (pinned, not a fix): maxAmountPerTx == 0 is fail-closed ───
    function test_Pin_ZeroCap_BlocksAnyNonZeroTransfer() public {
        _configure(_one(RECIPIENT), _one(TOKEN), 0);
        // Any non-zero amount is denied (0 > 0 is false, but 1 > 0 is true → deny).
        assertFalse(tp.evaluate(_transfer(RECIPIENT, 1), _ctx(TRANSFER, 0)));
        // A zero-amount transfer to an allowed recipient is still permitted — documents the edge.
        assertTrue(tp.evaluate(_transfer(RECIPIENT, 0), _ctx(TRANSFER, 0)));
    }
}
