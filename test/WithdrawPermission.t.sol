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
    // ── recognized exit selectors ─────────────────────────────────────────────
    bytes4 internal constant WITHDRAW_4626 = bytes4(keccak256("withdraw(uint256,address,address)")); // 0xb460af94
    bytes4 internal constant REDEEM_4626   = bytes4(keccak256("redeem(uint256,address,address)"));   // 0xba087652
    bytes4 internal constant WITHDRAW_AAVE = bytes4(keccak256("withdraw(address,uint256,address)")); // 0x69328dec

    // ── excluded / deferred selectors (must all deny) ─────────────────────────
    bytes4 internal constant TRANSFER            = 0xa9059cbb; // ERC-20 transfer (old contract's selector)
    bytes4 internal constant APPROVE             = 0x095ea7b3; // ERC-20 approve
    bytes4 internal constant COMPOUND_V2_REDEEM  = 0xdb006a75; // redeem(uint256)
    bytes4 internal constant COMPOUND_V3_WITHDRAW = 0xf3fef3a3; // withdraw(address,uint256)
    bytes4 internal constant AAVE_V4_WITHDRAW    = 0x0ad58d2f; // withdraw(uint256,uint256,address)

    address internal constant AUTHOR    = address(0xA11CE);
    address internal constant ACCOUNT   = address(0xACC0);
    address internal constant VAULT     = address(0x7A17); // ERC-4626 vault (target)
    address internal constant AAVE_POOL = address(0xAAEE); // Aave v2/v3 pool (target)
    address internal constant ASSET     = address(0xA55E); // Aave underlying (token)
    address internal constant OTHER     = address(0xBEEF); // attacker / third party

    uint256 internal constant CAP = 100 ether;

    WithdrawMockKernel internal kernel;
    WithdrawPermission internal wp;

    function setUp() public {
        kernel = new WithdrawMockKernel(address(this));
        wp     = new WithdrawPermission(address(kernel), AUTHOR);
        // targets: VAULT + AAVE_POOL ; tokens: ASSET (consulted on the Aave path only)
        _configure(_two(VAULT, AAVE_POOL), _one(ASSET), CAP);
    }

    // ── helpers ─────────────────────────────────────────────────────────────
    function _one(address a) internal pure returns (address[] memory r) { r = new address[](1); r[0] = a; }
    function _two(address a, address b) internal pure returns (address[] memory r) { r = new address[](2); r[0] = a; r[1] = b; }
    function _configure(address[] memory targets, address[] memory tokens, uint256 cap) internal {
        wp.configureDirect(ACCOUNT, abi.encode(targets, tokens, cap));
    }
    function _ctx(address target, bytes4 sel, uint256 value) internal pure returns (Context memory c) {
        c = Context(ACCOUNT, address(0), address(0), target, sel, value, 0, 0, 0);
    }
    /// @dev ERC-4626 exit calldata: withdraw(assets, receiver, owner) / redeem(shares, receiver, owner).
    function _vaultExit(bytes4 sel, uint256 amt, address receiver, address owner) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(sel, amt, receiver, owner);
    }
    /// @dev Aave v2/v3 exit calldata: withdraw(asset, amount, to).
    function _aaveExit(address asset, uint256 amt, address to) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(WITHDRAW_AAVE, asset, amt, to);
    }
    /// @dev Truncate `data` to `len` bytes (for exact-length under-read tests).
    function _truncate(bytes memory data, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i; i < len; i++) out[i] = data[i];
    }

    // ── author + introspection (identity strings unchanged from the old contract) ──
    function test_Author_IsRecorded() public view { assertEq(wp.author(), AUTHOR); }
    function test_Introspection_Ids() public view {
        assertEq(wp.discriminator(), keccak256("WithdrawPermission"));
        assertEq(wp.permissionId(),  keccak256("sail.permission.WithdrawPermission.v1"));
        bytes32[] memory ids = wp.capabilityIds();
        assertEq(ids.length, 1);
        assertEq(ids[0], SailCapabilities.WITHDRAW);
    }
    function test_Selectors_MatchVerifiedIds() public pure {
        // Pin the constants to the cast-sig-verified ids so a signature typo cannot slip in.
        assertEq(WITHDRAW_4626, bytes4(0xb460af94));
        assertEq(REDEEM_4626,   bytes4(0xba087652));
        assertEq(WITHDRAW_AAVE, bytes4(0x69328dec));
        assertEq(AAVE_V4_WITHDRAW, bytes4(keccak256("withdraw(uint256,uint256,address)")));
    }

    // ── config validation ─────────────────────────────────────────────────────
    function test_Config_Valid() public view {
        (address[] memory tg, address[] memory tk, uint256 cap) = wp.getConfig(ACCOUNT);
        assertEq(tg.length, 2); assertEq(tk.length, 1); assertEq(cap, CAP);
        assertTrue(wp.isAllowedTarget(ACCOUNT, VAULT));
        assertTrue(wp.isAllowedTarget(ACCOUNT, AAVE_POOL));
        assertTrue(wp.isAllowedToken(ACCOUNT, ASSET));
    }
    function test_Config_RevertsEmptyTargets() public {
        vm.expectRevert(WithdrawPermission.EmptyAllowlist.selector);
        wp.configureDirect(ACCOUNT, abi.encode(new address[](0), _one(ASSET), uint256(1)));
    }
    function test_Config_RevertsEmptyTokens() public {
        vm.expectRevert(WithdrawPermission.EmptyAllowlist.selector);
        wp.configureDirect(ACCOUNT, abi.encode(_one(VAULT), new address[](0), uint256(1)));
    }
    function test_Config_RevertsTooLong() public {
        address[] memory tg = new address[](51);
        for (uint256 i; i < 51; i++) tg[i] = address(uint160(i + 1));
        vm.expectRevert(WithdrawPermission.AllowlistTooLong.selector);
        wp.configureDirect(ACCOUNT, abi.encode(tg, _one(ASSET), uint256(1)));
    }
    function test_Config_RevertsZeroTarget() public {
        vm.expectRevert(ConfigurablePermission.ZeroAddress.selector);
        wp.configureDirect(ACCOUNT, abi.encode(_one(address(0)), _one(ASSET), uint256(1)));
    }
    function test_Config_RevertsZeroToken() public {
        vm.expectRevert(ConfigurablePermission.ZeroAddress.selector);
        wp.configureDirect(ACCOUNT, abi.encode(_one(VAULT), _one(address(0)), uint256(1)));
    }

    // ── happy paths (both pins satisfied, at-cap) ─────────────────────────────
    function test_Withdraw4626_BothPinned_AtCap_Allowed() public view {
        assertTrue(wp.evaluate(_vaultExit(WITHDRAW_4626, CAP, ACCOUNT, ACCOUNT), _ctx(VAULT, WITHDRAW_4626, 0)));
    }
    function test_Redeem4626_BothPinned_AtCap_Allowed() public view {
        assertTrue(wp.evaluate(_vaultExit(REDEEM_4626, CAP, ACCOUNT, ACCOUNT), _ctx(VAULT, REDEEM_4626, 0)));
    }
    function test_AaveWithdraw_ToPinned_AtCap_Allowed() public view {
        assertTrue(wp.evaluate(_aaveExit(ASSET, CAP, ACCOUNT), _ctx(AAVE_POOL, WITHDRAW_AAVE, 0)));
    }

    // ── matrix 1a: receiver drain (both 4626 arms) ────────────────────────────
    function test_Withdraw4626_ReceiverNotAccount_Denied() public view {
        assertFalse(wp.evaluate(_vaultExit(WITHDRAW_4626, 1 ether, OTHER, ACCOUNT), _ctx(VAULT, WITHDRAW_4626, 0)));
    }
    function test_Redeem4626_ReceiverNotAccount_Denied() public view {
        assertFalse(wp.evaluate(_vaultExit(REDEEM_4626, 1 ether, OTHER, ACCOUNT), _ctx(VAULT, REDEEM_4626, 0)));
    }

    // ── matrix 1b: owner drain (the subtle one — allowance over a third party's shares) ──
    function test_Withdraw4626_OwnerNotAccount_Denied() public view {
        // receiver IS the account, but owner is a third party whose shares would be burned
        // via an allowance — the third-party-position drain. Must fail closed.
        assertFalse(wp.evaluate(_vaultExit(WITHDRAW_4626, 1 ether, ACCOUNT, OTHER), _ctx(VAULT, WITHDRAW_4626, 0)));
    }
    function test_Redeem4626_OwnerNotAccount_Denied() public view {
        assertFalse(wp.evaluate(_vaultExit(REDEEM_4626, 1 ether, ACCOUNT, OTHER), _ctx(VAULT, REDEEM_4626, 0)));
    }

    // ── matrix 2: per-arm offset pinning (word-exact; catches copy-paste offset errors) ──
    function test_Offsets_Withdraw4626_WrongWord1_Only_Denied() public view {
        // wrong address at word 1 (receiver), word 2 correct
        assertFalse(wp.evaluate(_vaultExit(WITHDRAW_4626, 1 ether, OTHER, ACCOUNT), _ctx(VAULT, WITHDRAW_4626, 0)));
    }
    function test_Offsets_Withdraw4626_WrongWord2_Only_Denied() public view {
        // word 1 correct, wrong address at word 2 (owner) — cross-check that a correct word-1
        // value cannot mask a wrong word-2 value
        assertFalse(wp.evaluate(_vaultExit(WITHDRAW_4626, 1 ether, ACCOUNT, OTHER), _ctx(VAULT, WITHDRAW_4626, 0)));
    }
    function test_Offsets_Withdraw4626_BothWrong_Denied() public view {
        assertFalse(wp.evaluate(_vaultExit(WITHDRAW_4626, 1 ether, OTHER, OTHER), _ctx(VAULT, WITHDRAW_4626, 0)));
    }
    function test_Offsets_Redeem4626_WrongWord1_Only_Denied() public view {
        assertFalse(wp.evaluate(_vaultExit(REDEEM_4626, 1 ether, OTHER, ACCOUNT), _ctx(VAULT, REDEEM_4626, 0)));
    }
    function test_Offsets_Redeem4626_WrongWord2_Only_Denied() public view {
        assertFalse(wp.evaluate(_vaultExit(REDEEM_4626, 1 ether, ACCOUNT, OTHER), _ctx(VAULT, REDEEM_4626, 0)));
    }
    function test_Offsets_Redeem4626_BothWrong_Denied() public view {
        assertFalse(wp.evaluate(_vaultExit(REDEEM_4626, 1 ether, OTHER, OTHER), _ctx(VAULT, REDEEM_4626, 0)));
    }
    function test_Offsets_Aave_WrongWord2_To_Denied() public view {
        // Aave's pinned address lives at word 2 (`to`), not words 1/2 like 4626 — wrong `to` denies.
        assertFalse(wp.evaluate(_aaveExit(ASSET, 1 ether, OTHER), _ctx(AAVE_POOL, WITHDRAW_AAVE, 0)));
    }
    function test_Offsets_Aave_AccountAtWrongWord_Denied() public view {
        // The account placed at word 0 (asset slot) instead of word 2 must not satisfy the pin.
        assertFalse(wp.evaluate(_aaveExit(ACCOUNT, 1 ether, OTHER), _ctx(AAVE_POOL, WITHDRAW_AAVE, 0)));
    }

    // ── matrix 3: calldata under-read (length guard before decode; no panic) ─────
    function test_Withdraw4626_ShortCalldata_99Bytes_Denied() public view {
        bytes memory short = _truncate(_vaultExit(WITHDRAW_4626, 1 ether, ACCOUNT, ACCOUNT), 99);
        assertFalse(wp.evaluate(short, _ctx(VAULT, WITHDRAW_4626, 0)));
    }
    function test_Redeem4626_ShortCalldata_99Bytes_Denied() public view {
        bytes memory short = _truncate(_vaultExit(REDEEM_4626, 1 ether, ACCOUNT, ACCOUNT), 99);
        assertFalse(wp.evaluate(short, _ctx(VAULT, REDEEM_4626, 0)));
    }
    function test_AaveWithdraw_ShortCalldata_99Bytes_Denied() public view {
        bytes memory short = _truncate(_aaveExit(ASSET, 1 ether, ACCOUNT), 99);
        assertFalse(wp.evaluate(short, _ctx(AAVE_POOL, WITHDRAW_AAVE, 0)));
    }
    function test_Withdraw4626_TwoWordCalldata_Denied() public view {
        bytes memory short = abi.encodeWithSelector(WITHDRAW_4626, uint256(1), ACCOUNT); // 68 bytes
        assertFalse(wp.evaluate(short, _ctx(VAULT, WITHDRAW_4626, 0)));
    }
    function test_SelectorOnlyCalldata_Denied() public view {
        assertFalse(wp.evaluate(abi.encodePacked(WITHDRAW_4626), _ctx(VAULT, WITHDRAW_4626, 0)));
        assertFalse(wp.evaluate(abi.encodePacked(REDEEM_4626),   _ctx(VAULT, REDEEM_4626, 0)));
        assertFalse(wp.evaluate(abi.encodePacked(WITHDRAW_AAVE), _ctx(AAVE_POOL, WITHDRAW_AAVE, 0)));
    }

    // ── matrix 4: unknown / excluded / deferred selectors all deny ───────────────
    function test_UnknownSelector_ERC20Transfer_Denied() public view {
        // The OLD contract's core selector — must now deny.
        bytes memory data = abi.encodeWithSelector(TRANSFER, ACCOUNT, uint256(1));
        assertFalse(wp.evaluate(data, _ctx(VAULT, TRANSFER, 0)));
    }
    function test_UnknownSelector_ERC20Approve_Denied() public view {
        bytes memory data = abi.encodeWithSelector(APPROVE, ACCOUNT, uint256(1));
        assertFalse(wp.evaluate(data, _ctx(VAULT, APPROVE, 0)));
    }
    function test_ExcludedSelector_CompoundV2Redeem_Denied() public view {
        bytes memory data = abi.encodeWithSelector(COMPOUND_V2_REDEEM, uint256(1));
        assertFalse(wp.evaluate(data, _ctx(VAULT, COMPOUND_V2_REDEEM, 0)));
    }
    function test_ExcludedSelector_CompoundV3Withdraw_Denied() public view {
        bytes memory data = abi.encodeWithSelector(COMPOUND_V3_WITHDRAW, ASSET, uint256(1));
        assertFalse(wp.evaluate(data, _ctx(VAULT, COMPOUND_V3_WITHDRAW, 0)));
    }
    function test_DeferredSelector_AaveV4Withdraw_Denied() public view {
        // Aave v4 Spoke withdraw(reserveId, amount, onBehalfOf): well-formed 100-byte calldata
        // against an allowlisted target, with the account even present at word 2 — still denied,
        // because v4's destination is msg.sender, not calldata, and the selector is unrecognized.
        bytes memory data = abi.encodeWithSelector(AAVE_V4_WITHDRAW, uint256(1), uint256(1 ether), ACCOUNT);
        assertFalse(wp.evaluate(data, _ctx(AAVE_POOL, AAVE_V4_WITHDRAW, 0)));
    }

    // ── matrix 5a: native value rejected ─────────────────────────────────────────
    function test_NativeValue_Denied() public view {
        assertFalse(wp.evaluate(_vaultExit(WITHDRAW_4626, 1 ether, ACCOUNT, ACCOUNT), _ctx(VAULT, WITHDRAW_4626, 1)));
    }

    // ── matrix 5b: config freshness fail-closed (inherited) ──────────────────────
    function test_StaleEpoch_Denied() public view {
        // Config was stamped at epoch 0; a ctx carrying a bumped epoch (revoke → re-register)
        // must deny until a fresh configure.
        Context memory c = Context(ACCOUNT, address(0), address(0), VAULT, WITHDRAW_4626, 0, 0, 0, 1);
        assertFalse(wp.evaluate(_vaultExit(WITHDRAW_4626, 1 ether, ACCOUNT, ACCOUNT), c));
    }
    function test_UnconfiguredAccount_Denied() public view {
        Context memory c = Context(OTHER, address(0), address(0), VAULT, WITHDRAW_4626, 0, 0, 0, 0);
        assertFalse(wp.evaluate(_vaultExit(WITHDRAW_4626, 1 ether, OTHER, OTHER), c));
    }

    // ── matrix 6: allowlists ─────────────────────────────────────────────────────
    function test_TargetNotAllowlisted_Denied() public view {
        assertFalse(wp.evaluate(_vaultExit(WITHDRAW_4626, 1 ether, ACCOUNT, ACCOUNT), _ctx(OTHER, WITHDRAW_4626, 0)));
    }
    function test_Aave_AssetNotAllowlisted_Denied() public view {
        assertFalse(wp.evaluate(_aaveExit(OTHER, 1 ether, ACCOUNT), _ctx(AAVE_POOL, WITHDRAW_AAVE, 0)));
    }

    // ── matrix 7: caps, denominated per selector ─────────────────────────────────
    function test_Withdraw4626_OverCap_Denied() public view {
        assertFalse(wp.evaluate(_vaultExit(WITHDRAW_4626, CAP + 1, ACCOUNT, ACCOUNT), _ctx(VAULT, WITHDRAW_4626, 0)));
    }
    function test_Redeem4626_OverCap_Denied() public view {
        assertFalse(wp.evaluate(_vaultExit(REDEEM_4626, CAP + 1, ACCOUNT, ACCOUNT), _ctx(VAULT, REDEEM_4626, 0)));
    }
    function test_AaveWithdraw_OverCap_Denied() public view {
        assertFalse(wp.evaluate(_aaveExit(ASSET, CAP + 1, ACCOUNT), _ctx(AAVE_POOL, WITHDRAW_AAVE, 0)));
    }

    // ── documented edges (pinned, not fixes) ─────────────────────────────────────
    function test_Pin_RedeemCapIsInShares_NotAssets() public {
        // The redeem cap bounds the `shares` argument directly; its asset/USD value floats with
        // the share price. Shares within the cap pass regardless of underlying value.
        _configure(_two(VAULT, AAVE_POOL), _one(ASSET), 1_000);
        assertTrue(wp.evaluate(_vaultExit(REDEEM_4626, 1_000, ACCOUNT, ACCOUNT), _ctx(VAULT, REDEEM_4626, 0)));  // shares == cap
        assertFalse(wp.evaluate(_vaultExit(REDEEM_4626, 1_001, ACCOUNT, ACCOUNT), _ctx(VAULT, REDEEM_4626, 0))); // shares > cap
    }
    function test_Pin_ZeroCap_BlocksAnyNonZeroExit() public {
        _configure(_two(VAULT, AAVE_POOL), _one(ASSET), 0);
        assertFalse(wp.evaluate(_vaultExit(WITHDRAW_4626, 1, ACCOUNT, ACCOUNT), _ctx(VAULT, WITHDRAW_4626, 0))); // non-zero denied
        assertTrue(wp.evaluate(_vaultExit(WITHDRAW_4626, 0, ACCOUNT, ACCOUNT), _ctx(VAULT, WITHDRAW_4626, 0)));  // zero, fully pinned, ok
    }
}
