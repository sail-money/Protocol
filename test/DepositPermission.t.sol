// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import {Context}                from "../contracts/interfaces/IPermission.sol";
import {SailCapabilities}       from "../contracts/interfaces/SailCapabilities.sol";
import {ConfigurablePermission} from "../contracts/templates/ConfigurablePermission.sol";
import {DepositPermission}      from "../contracts/templates/DepositPermission.sol";

/// @dev Minimal kernel view: every account registered; this test contract is the permissionSigner.
contract DepositMockKernel {
    address public immutable signer;
    constructor(address _signer) { signer = _signer; }
    function registered(address) external pure returns (bool) { return true; }
    function configs(address) external view returns (address, address, address, bool) {
        return (signer, address(0), address(0), true);
    }
}

contract DepositPermissionTest is Test {
    bytes4 internal constant DEPOSIT_SIMPLE = bytes4(keccak256("deposit(uint256,address)"));
    bytes4 internal constant MINT           = bytes4(keccak256("mint(uint256,address)"));
    bytes4 internal constant DEPOSIT_AAVE   = bytes4(keccak256("deposit(address,uint256,address,uint16)"));
    bytes4 internal constant SUPPLY_AAVE    = bytes4(keccak256("supply(address,uint256,address,uint16)"));
    bytes4 internal constant WITHDRAW_SEL   = bytes4(keccak256("withdraw(uint256,address,address)"));

    address internal constant AUTHOR    = address(0xA11CE);
    address internal constant ACCOUNT   = address(0xACC0);
    address internal constant VAULT     = address(0x7A17); // ERC-4626 vault (target AND token)
    address internal constant AAVE_POOL = address(0xAAEE); // Aave pool (target)
    address internal constant ASSET     = address(0xA55E); // Aave underlying (token)
    address internal constant OTHER     = address(0xBEEF);

    DepositMockKernel internal kernel;
    DepositPermission internal dp;

    function setUp() public {
        kernel = new DepositMockKernel(address(this));
        dp     = new DepositPermission(address(kernel), AUTHOR);
        // targets: VAULT + AAVE_POOL ; tokens: VAULT (for ERC-4626) + ASSET (for Aave)
        _configure(_two(VAULT, AAVE_POOL), _two(VAULT, ASSET), 100 ether);
    }

    // ── helpers ─────────────────────────────────────────────────────────────
    function _one(address a) internal pure returns (address[] memory r) { r = new address[](1); r[0] = a; }
    function _two(address a, address b) internal pure returns (address[] memory r) { r = new address[](2); r[0] = a; r[1] = b; }
    function _configure(address[] memory targets, address[] memory tokens, uint256 cap) internal {
        dp.configureDirect(ACCOUNT, abi.encode(targets, tokens, cap));
    }
    function _ctx(address target, bytes4 sel, uint256 value) internal pure returns (Context memory c) {
        c = Context(ACCOUNT, address(0), address(0), target, sel, value, 0, 0);
    }
    function _erc4626(bytes4 sel, uint256 amt, address receiver) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(sel, amt, receiver);
    }
    function _aave(bytes4 sel, address asset, uint256 amt, address onBehalfOf) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(sel, asset, amt, onBehalfOf, uint16(0));
    }

    // ── author + introspection ───────────────────────────────────────────────
    function test_Author_IsRecorded() public view { assertEq(dp.author(), AUTHOR); }
    function test_Introspection_Ids() public view {
        assertEq(dp.discriminator(), keccak256("DepositPermission"));
        assertEq(dp.permissionId(),  keccak256("sail.permission.DepositPermission.v1"));
        bytes32[] memory ids = dp.capabilityIds();
        assertEq(ids.length, 1);
        assertEq(ids[0], SailCapabilities.DEPOSIT);
    }

    // ── config validation ─────────────────────────────────────────────────────
    function test_Config_Valid() public view {
        (address[] memory tg, address[] memory tk, uint256 cap) = dp.getConfig(ACCOUNT);
        assertEq(tg.length, 2); assertEq(tk.length, 2); assertEq(cap, 100 ether);
        assertTrue(dp.isAllowedTarget(ACCOUNT, VAULT));
        assertTrue(dp.isAllowedToken(ACCOUNT, VAULT));
        assertTrue(dp.isAllowedToken(ACCOUNT, ASSET));
    }
    function test_Config_RevertsEmptyTargets() public {
        vm.expectRevert(DepositPermission.EmptyAllowlist.selector);
        dp.configureDirect(ACCOUNT, abi.encode(new address[](0), _one(ASSET), uint256(1)));
    }
    function test_Config_RevertsEmptyTokens() public {
        vm.expectRevert(DepositPermission.EmptyAllowlist.selector);
        dp.configureDirect(ACCOUNT, abi.encode(_one(VAULT), new address[](0), uint256(1)));
    }
    function test_Config_RevertsTooLong() public {
        address[] memory tg = new address[](51);
        for (uint256 i; i < 51; i++) tg[i] = address(uint160(i + 1));
        vm.expectRevert(DepositPermission.AllowlistTooLong.selector);
        dp.configureDirect(ACCOUNT, abi.encode(tg, _one(ASSET), uint256(1)));
    }
    function test_Config_RevertsZeroTarget() public {
        vm.expectRevert(ConfigurablePermission.ZeroAddress.selector);
        dp.configureDirect(ACCOUNT, abi.encode(_one(address(0)), _one(ASSET), uint256(1)));
    }
    function test_Config_RevertsZeroToken() public {
        vm.expectRevert(ConfigurablePermission.ZeroAddress.selector);
        dp.configureDirect(ACCOUNT, abi.encode(_one(VAULT), _one(address(0)), uint256(1)));
    }

    // ── ERC-4626 deposit(assets,receiver) ──────────────────────────────────────
    function test_DepositSimple_ReceiverIsAccount_Allowed() public view {
        assertTrue(dp.evaluate(_erc4626(DEPOSIT_SIMPLE, 100 ether, ACCOUNT), _ctx(VAULT, DEPOSIT_SIMPLE, 0)));
    }
    function test_DepositSimple_ReceiverNotAccount_Denied() public view {
        assertFalse(dp.evaluate(_erc4626(DEPOSIT_SIMPLE, 1 ether, OTHER), _ctx(VAULT, DEPOSIT_SIMPLE, 0)));
    }
    function test_DepositSimple_OverCap_Denied() public view {
        assertFalse(dp.evaluate(_erc4626(DEPOSIT_SIMPLE, 100 ether + 1, ACCOUNT), _ctx(VAULT, DEPOSIT_SIMPLE, 0)));
    }
    function test_DepositSimple_TargetNotAllowed_Denied() public view {
        assertFalse(dp.evaluate(_erc4626(DEPOSIT_SIMPLE, 1 ether, ACCOUNT), _ctx(OTHER, DEPOSIT_SIMPLE, 0)));
    }
    function test_DepositSimple_VaultNotTokenAllowlisted_Denied() public {
        // FIX coverage: vault is an allowed TARGET but NOT in the token allowlist → deny.
        _configure(_one(VAULT), _one(ASSET), 100 ether); // VAULT not in tokens
        assertFalse(dp.evaluate(_erc4626(DEPOSIT_SIMPLE, 1 ether, ACCOUNT), _ctx(VAULT, DEPOSIT_SIMPLE, 0)));
    }

    // ── ERC-4626 mint(shares,receiver) ─────────────────────────────────────────
    function test_Mint_ReceiverIsAccount_Allowed() public view {
        assertTrue(dp.evaluate(_erc4626(MINT, 100 ether, ACCOUNT), _ctx(VAULT, MINT, 0)));
    }
    function test_Mint_ReceiverNotAccount_Denied() public view {
        assertFalse(dp.evaluate(_erc4626(MINT, 1 ether, OTHER), _ctx(VAULT, MINT, 0)));
    }

    // ── Aave deposit / supply ───────────────────────────────────────────────────
    function test_AaveDeposit_OnBehalfOfAccount_Allowed() public view {
        assertTrue(dp.evaluate(_aave(DEPOSIT_AAVE, ASSET, 100 ether, ACCOUNT), _ctx(AAVE_POOL, DEPOSIT_AAVE, 0)));
    }
    function test_AaveDeposit_OnBehalfOfNotAccount_Denied() public view {
        assertFalse(dp.evaluate(_aave(DEPOSIT_AAVE, ASSET, 1 ether, OTHER), _ctx(AAVE_POOL, DEPOSIT_AAVE, 0)));
    }
    function test_AaveDeposit_AssetNotAllowed_Denied() public view {
        assertFalse(dp.evaluate(_aave(DEPOSIT_AAVE, OTHER, 1 ether, ACCOUNT), _ctx(AAVE_POOL, DEPOSIT_AAVE, 0)));
    }
    function test_AaveSupply_OnBehalfOfAccount_Allowed() public view {
        assertTrue(dp.evaluate(_aave(SUPPLY_AAVE, ASSET, 50 ether, ACCOUNT), _ctx(AAVE_POOL, SUPPLY_AAVE, 0)));
    }
    function test_AaveSupply_OverCap_Denied() public view {
        assertFalse(dp.evaluate(_aave(SUPPLY_AAVE, ASSET, 100 ether + 1, ACCOUNT), _ctx(AAVE_POOL, SUPPLY_AAVE, 0)));
    }

    // ── value + unrouted ───────────────────────────────────────────────────────
    function test_NativeValue_Denied() public view {
        assertFalse(dp.evaluate(_erc4626(DEPOSIT_SIMPLE, 1 ether, ACCOUNT), _ctx(VAULT, DEPOSIT_SIMPLE, 1)));
    }
    function test_UnroutedSelector_Denied() public view {
        bytes memory data = abi.encodeWithSelector(WITHDRAW_SEL, uint256(1), ACCOUNT, ACCOUNT);
        assertFalse(dp.evaluate(data, _ctx(VAULT, WITHDRAW_SEL, 0)));
    }

    // ── coverage close-out: remaining denial branches per path ───────────────────
    function test_Mint_OverCap_Denied() public view {
        assertFalse(dp.evaluate(_erc4626(MINT, 100 ether + 1, ACCOUNT), _ctx(VAULT, MINT, 0)));
    }
    function test_Mint_VaultNotTokenAllowlisted_Denied() public {
        _configure(_one(VAULT), _one(ASSET), 100 ether); // VAULT is a target but not a token
        assertFalse(dp.evaluate(_erc4626(MINT, 1 ether, ACCOUNT), _ctx(VAULT, MINT, 0)));
    }
    function test_AaveDeposit_OverCap_Denied() public view {
        assertFalse(dp.evaluate(_aave(DEPOSIT_AAVE, ASSET, 100 ether + 1, ACCOUNT), _ctx(AAVE_POOL, DEPOSIT_AAVE, 0)));
    }
    function test_AaveSupply_AssetNotAllowed_Denied() public view {
        assertFalse(dp.evaluate(_aave(SUPPLY_AAVE, OTHER, 1 ether, ACCOUNT), _ctx(AAVE_POOL, SUPPLY_AAVE, 0)));
    }
    function test_AaveSupply_OnBehalfOfNotAccount_Denied() public view {
        assertFalse(dp.evaluate(_aave(SUPPLY_AAVE, ASSET, 1 ether, OTHER), _ctx(AAVE_POOL, SUPPLY_AAVE, 0)));
    }

    // ── short-calldata guards (fail closed, no out-of-bounds read) ───────────────
    function test_DepositSimple_ShortCalldata_Denied() public view {
        bytes memory short = abi.encodeWithSelector(DEPOSIT_SIMPLE, uint256(1)); // < 68 bytes
        assertFalse(dp.evaluate(short, _ctx(VAULT, DEPOSIT_SIMPLE, 0)));
    }
    function test_Mint_ShortCalldata_Denied() public view {
        bytes memory short = abi.encodeWithSelector(MINT, uint256(1)); // < 68 bytes
        assertFalse(dp.evaluate(short, _ctx(VAULT, MINT, 0)));
    }
    function test_AaveDeposit_ShortCalldata_Denied() public view {
        bytes memory short = abi.encodeWithSelector(DEPOSIT_AAVE, ASSET, uint256(1)); // < 132 bytes
        assertFalse(dp.evaluate(short, _ctx(AAVE_POOL, DEPOSIT_AAVE, 0)));
    }
    function test_AaveSupply_ShortCalldata_Denied() public view {
        bytes memory short = abi.encodeWithSelector(SUPPLY_AAVE, ASSET, uint256(1)); // < 132 bytes
        assertFalse(dp.evaluate(short, _ctx(AAVE_POOL, SUPPLY_AAVE, 0)));
    }

    // ── documented edge (pinned, not a fix): mint() cap is denominated in SHARES ──
    function test_Pin_MintCapIsInShares_NotAssets() public {
        // The cap bounds the `shares` argument directly; its asset/USD value floats with the share
        // price. A shares amount within the cap is allowed regardless of underlying value.
        _configure(_two(VAULT, AAVE_POOL), _two(VAULT, ASSET), 1_000);
        assertTrue(dp.evaluate(_erc4626(MINT, 1_000, ACCOUNT), _ctx(VAULT, MINT, 0)));   // shares == cap
        assertFalse(dp.evaluate(_erc4626(MINT, 1_001, ACCOUNT), _ctx(VAULT, MINT, 0)));  // shares > cap
    }
}
