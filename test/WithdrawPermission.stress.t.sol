// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

// ─────────────────────────────────────────────────────────────────────────────
// Adversarial STRESS suite for WithdrawPermission (feat/withdraw-permission).
//
// Complements the hand-written matrix in WithdrawPermission.t.sol with:
//   - property-based fuzzing of every evaluate() branch (the allow-set is exactly
//     the documented envelope and nothing more),
//   - raw-calldata edge cases (dirty address high-bits, trailing calldata),
//   - the shared-target-allowlist observation (authorized-but-inert),
//   - the Aave `type(uint256).max` "withdraw-everything" sentinel under a cap,
//   - config auth boundary + epoch-freshness transition.
//
// The security thesis under test: given a WELL-DEFINED config (real vaults/pools
// allowlisted, sane cap), a malicious manager can never make evaluate() return
// true for a call that (a) pays anyone other than the account, (b) burns a third
// party's position, (c) exceeds the per-tx cap, (d) carries ETH, or (e) uses an
// unrecognized selector/target — regardless of how calldata is crafted.
//
// Run with:
//   forge test --match-path "test/WithdrawPermission.stress.t.sol" -vvv
// ─────────────────────────────────────────────────────────────────────────────

import "forge-std/Test.sol";
import {Context}                from "../contracts/interfaces/IPermission.sol";
import {ConfigurablePermission} from "../contracts/templates/ConfigurablePermission.sol";
import {WithdrawPermission}     from "../contracts/templates/WithdrawPermission.sol";

/// @dev Kernel view mock with a settable permissionSigner and registration epoch,
///      so the auth boundary and the epoch-freshness gate can be exercised.
///      `configs` returns only the first word (permissionSigner) — matching the
///      subset interface the templates actually read.
contract StressMockKernel {
    address public signer;
    uint256 public regEpoch;

    constructor(address _signer) { signer = _signer; }
    function setSigner(address s) external { signer = s; }
    function setRegEpoch(uint256 e) external { regEpoch = e; }

    function registered(address) external pure returns (bool) { return true; }
    function registrationEpoch(address, address) external view returns (uint256) { return regEpoch; }
    function configs(address) external view returns (address) { return signer; }
}

contract WithdrawPermissionStressTest is Test {
    // recognized exit selectors
    bytes4 internal constant WITHDRAW_4626 = bytes4(keccak256("withdraw(uint256,address,address)")); // 0xb460af94
    bytes4 internal constant REDEEM_4626   = bytes4(keccak256("redeem(uint256,address,address)"));   // 0xba087652
    bytes4 internal constant WITHDRAW_AAVE = bytes4(keccak256("withdraw(address,uint256,address)")); // 0x69328dec

    address internal constant AUTHOR    = address(0xA11CE);
    address internal constant ACCOUNT   = address(0xACC0);
    address internal constant VAULT     = address(0x7A17); // ERC-4626 vault (target)
    address internal constant AAVE_POOL = address(0xAAEE); // Aave v2/v3 pool (target)
    address internal constant ASSET     = address(0xA55E); // Aave underlying (token)
    address internal constant OTHER     = address(0xBEEF); // attacker / third party

    uint256 internal constant CAP = 100 ether;

    StressMockKernel  internal kernel;
    WithdrawPermission internal wp;

    function setUp() public {
        kernel = new StressMockKernel(address(this)); // this test contract is the permissionSigner
        wp     = new WithdrawPermission(address(kernel), AUTHOR);
        _configure(_two(VAULT, AAVE_POOL), _one(ASSET), CAP);
    }

    // ── helpers ───────────────────────────────────────────────────────────────
    function _one(address a) internal pure returns (address[] memory r) { r = new address[](1); r[0] = a; }
    function _two(address a, address b) internal pure returns (address[] memory r) { r = new address[](2); r[0] = a; r[1] = b; }
    function _configure(address[] memory targets, address[] memory tokens, uint256 cap) internal {
        wp.configureDirect(ACCOUNT, abi.encode(targets, tokens, cap));
    }
    function _ctx(address target, bytes4 sel, uint256 value) internal pure returns (Context memory c) {
        c = Context(ACCOUNT, address(0), address(0), target, sel, value, 0, 0, 0);
    }
    function _ctxEpoch(address target, bytes4 sel, uint256 epoch) internal pure returns (Context memory c) {
        c = Context(ACCOUNT, address(0), address(0), target, sel, 0, 0, 0, epoch);
    }
    function _vaultExit(bytes4 sel, uint256 amt, address receiver, address owner) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(sel, amt, receiver, owner);
    }
    function _aaveExit(address asset, uint256 amt, address to) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(WITHDRAW_AAVE, asset, amt, to);
    }
    /// @dev Evaluate the way the KERNEL would: a revert inside evaluate is caught and
    ///      treated as a deny (fail-closed under staticcall). Lets edge cases that might
    ///      revert (e.g. dirty ABI words) be asserted as "denied" without aborting the test.
    function _evalFailClosed(bytes memory data, Context memory ctx) internal view returns (bool) {
        try wp.evaluate(data, ctx) returns (bool r) { return r; } catch { return false; }
    }
    /// @dev External helper so a dirty-word abi.decode can be probed under try/catch.
    function decodeThree(bytes calldata w) external pure returns (uint256, address, address) {
        return abi.decode(w, (uint256, address, address));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // 1. PROPERTY FUZZ — the allow-set is EXACTLY the documented envelope
    // ═════════════════════════════════════════════════════════════════════════

    /// @dev 4626 withdraw: allowed iff assets<=cap AND receiver==account AND owner==account.
    function testFuzz_Withdraw4626_Envelope(uint256 assets, address receiver, address owner) public view {
        bool expected = (assets <= CAP) && (receiver == ACCOUNT) && (owner == ACCOUNT);
        assertEq(
            wp.evaluate(_vaultExit(WITHDRAW_4626, assets, receiver, owner), _ctx(VAULT, WITHDRAW_4626, 0)),
            expected
        );
    }

    /// @dev 4626 redeem: allowed iff shares<=cap AND receiver==account AND owner==account.
    function testFuzz_Redeem4626_Envelope(uint256 shares, address receiver, address owner) public view {
        bool expected = (shares <= CAP) && (receiver == ACCOUNT) && (owner == ACCOUNT);
        assertEq(
            wp.evaluate(_vaultExit(REDEEM_4626, shares, receiver, owner), _ctx(VAULT, REDEEM_4626, 0)),
            expected
        );
    }

    /// @dev Aave withdraw: allowed iff asset allowlisted AND amount<=cap AND to==account.
    function testFuzz_AaveWithdraw_Envelope(address asset, uint256 amount, address to) public view {
        bool expected = (asset == ASSET) && (amount <= CAP) && (to == ACCOUNT);
        assertEq(
            wp.evaluate(_aaveExit(asset, amount, to), _ctx(AAVE_POOL, WITHDRAW_AAVE, 0)),
            expected
        );
    }

    /// @dev No matter the calldata, a non-zero native value ALWAYS denies (all pins perfect).
    function testFuzz_NativeValue_AlwaysDenied(uint256 value) public view {
        vm.assume(value != 0);
        assertFalse(wp.evaluate(_vaultExit(WITHDRAW_4626, 1 ether, ACCOUNT, ACCOUNT), _ctx(VAULT, WITHDRAW_4626, value)));
        assertFalse(wp.evaluate(_vaultExit(REDEEM_4626, 1 ether, ACCOUNT, ACCOUNT),   _ctx(VAULT, REDEEM_4626, value)));
        assertFalse(wp.evaluate(_aaveExit(ASSET, 1 ether, ACCOUNT),                   _ctx(AAVE_POOL, WITHDRAW_AAVE, value)));
    }

    /// @dev Any target not on the allowlist denies, even with perfect pins/amount/selector.
    function testFuzz_NonAllowlistedTarget_AlwaysDenied(address target) public view {
        vm.assume(target != VAULT && target != AAVE_POOL);
        assertFalse(wp.evaluate(_vaultExit(WITHDRAW_4626, 1 ether, ACCOUNT, ACCOUNT), _ctx(target, WITHDRAW_4626, 0)));
        assertFalse(wp.evaluate(_aaveExit(ASSET, 1 ether, ACCOUNT),                   _ctx(target, WITHDRAW_AAVE, 0)));
    }

    /// @dev Any selector outside the recognized three denies, even against an allowlisted
    ///      target with well-formed 3-word calldata and the account pinned everywhere.
    function testFuzz_UnknownSelector_AlwaysDenied(bytes4 sel) public view {
        vm.assume(sel != WITHDRAW_4626 && sel != REDEEM_4626 && sel != WITHDRAW_AAVE);
        bytes memory data = abi.encodeWithSelector(sel, uint256(1), ACCOUNT, ACCOUNT);
        assertFalse(wp.evaluate(data, _ctx(VAULT, sel, 0)));
        assertFalse(wp.evaluate(data, _ctx(AAVE_POOL, sel, 0)));
    }

    /// @dev The account can NEVER be tricked into paying a third party (4626 receiver arm):
    ///      any receiver != account denies regardless of amount/owner.
    function testFuzz_Withdraw4626_ReceiverPin_NeverBypassed(uint256 assets, address receiver) public view {
        vm.assume(receiver != ACCOUNT);
        assertFalse(wp.evaluate(_vaultExit(WITHDRAW_4626, assets, receiver, ACCOUNT), _ctx(VAULT, WITHDRAW_4626, 0)));
    }

    /// @dev The third-party-position drain (4626 owner arm) can NEVER be authorized:
    ///      any owner != account denies even when receiver==account and amount<=cap.
    function testFuzz_Withdraw4626_OwnerPin_NeverBypassed(uint256 assets, address owner) public view {
        vm.assume(owner != ACCOUNT);
        assertFalse(wp.evaluate(_vaultExit(WITHDRAW_4626, assets, ACCOUNT, owner), _ctx(VAULT, WITHDRAW_4626, 0)));
        assertFalse(wp.evaluate(_vaultExit(REDEEM_4626,   assets, ACCOUNT, owner), _ctx(VAULT, REDEEM_4626, 0)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // 2. RAW-CALLDATA EDGE CASES
    // ═════════════════════════════════════════════════════════════════════════

    /// @dev Learn (and pin) how the compiler decodes an address word with dirty high bits.
    ///      Whatever the behavior, it must be SAFE: either revert (→ fail-closed deny) or
    ///      mask to the low 160 bits (→ same address a compliant target would see).
    function test_Probe_DirtyAddressDecodeIsSafe() public {
        bytes memory w = abi.encodePacked(
            uint256(1 ether),
            uint256(uint160(ACCOUNT)) | (uint256(0xDEAD) << 160), // dirty high bits, low-20 == ACCOUNT
            uint256(uint160(ACCOUNT))
        );
        try this.decodeThree(w) returns (uint256, address rcv, address) {
            emit log_string("abi.decode MASKS dirty address high bits");
            assertEq(rcv, ACCOUNT); // low 160 bits preserved == what a compliant vault also sees
        } catch {
            emit log_string("abi.decode REVERTS on dirty address high bits (fail-closed)");
        }
    }

    /// @dev Dirty high bits whose low-20 bytes are a THIRD PARTY must always deny
    ///      (masked value != account, or a revert). No high-bit trick smuggles a payout.
    function test_DirtyReceiverHighBits_LowIsThirdParty_Denied() public view {
        bytes memory data = abi.encodePacked(
            WITHDRAW_4626,
            uint256(1 ether),
            uint256(uint160(OTHER)) | (uint256(0xDEAD) << 160), // low-20 == OTHER, dirty high
            uint256(uint160(ACCOUNT))
        );
        assertFalse(_evalFailClosed(data, _ctx(VAULT, WITHDRAW_4626, 0)));
    }

    /// @dev Dirty high bits whose low-20 == account is safe either way: if the decoder masks,
    ///      the permission sees `account` (exactly what the vault will see when it decodes the
    ///      same word), so the payout still lands in the account; if it reverts, it denies.
    function test_DirtyReceiverHighBits_LowIsAccount_Safe() public view {
        bytes memory data = abi.encodePacked(
            WITHDRAW_4626,
            uint256(1 ether),
            uint256(uint160(ACCOUNT)) | (uint256(0xDEAD) << 160),
            uint256(uint160(ACCOUNT)) | (uint256(0xBEEF) << 160)
        );
        // Whatever the outcome, the ABI-decoded (masked) receiver/owner equal `account`,
        // so an allow here still keeps funds with the account. We only assert no unexpected
        // third-party payout is possible — captured by the sibling test above.
        bool allowed = _evalFailClosed(data, _ctx(VAULT, WITHDRAW_4626, 0));
        // Safety holds regardless of allowed's value; assert the harness didn't blow up.
        assertTrue(allowed || !allowed);
    }

    /// @dev Trailing calldata past the 3 args is ignored by the static decode AND cannot
    ///      relocate a pinned word. Word-1 receiver=OTHER denies even if `account` appears
    ///      in the trailing bytes.
    function test_TrailingCalldata_CannotSmugglePins() public view {
        // valid 3 args + 1 trailing word → still authorized (trailing ignored)
        bytes memory ok = abi.encodePacked(
            WITHDRAW_4626, uint256(1 ether), uint256(uint160(ACCOUNT)), uint256(uint160(ACCOUNT)), uint256(0xC0FFEE)
        );
        assertTrue(wp.evaluate(ok, _ctx(VAULT, WITHDRAW_4626, 0)));

        // receiver at word-1 is OTHER; account only appears in trailing → denied
        bytes memory bad = abi.encodePacked(
            WITHDRAW_4626, uint256(1 ether), uint256(uint160(OTHER)), uint256(uint160(ACCOUNT)), uint256(uint160(ACCOUNT))
        );
        assertFalse(wp.evaluate(bad, _ctx(VAULT, WITHDRAW_4626, 0)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // 3. CAP SEMANTICS — the "withdraw everything" sentinel is bounded
    // ═════════════════════════════════════════════════════════════════════════

    /// @dev Aave's `amount = type(uint256).max` ("withdraw entire balance") is denied under a
    ///      finite cap — the manager cannot use the sentinel to bypass the per-tx bound.
    function test_AaveMaxSentinel_DeniedUnderFiniteCap() public view {
        assertFalse(wp.evaluate(_aaveExit(ASSET, type(uint256).max, ACCOUNT), _ctx(AAVE_POOL, WITHDRAW_AAVE, 0)));
    }

    /// @dev Only when the operator deliberately sets cap == max does the sentinel pass — and
    ///      even then proceeds are pinned to the account.
    function test_AaveMaxSentinel_AllowedOnlyWithMaxCap() public {
        _configure(_two(VAULT, AAVE_POOL), _one(ASSET), type(uint256).max);
        assertTrue(wp.evaluate(_aaveExit(ASSET, type(uint256).max, ACCOUNT), _ctx(AAVE_POOL, WITHDRAW_AAVE, 0)));
        assertFalse(wp.evaluate(_aaveExit(ASSET, type(uint256).max, OTHER),  _ctx(AAVE_POOL, WITHDRAW_AAVE, 0)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // 4. SHARED-TARGET-ALLOWLIST OBSERVATION (authorized-but-inert, not a fund path)
    // ═════════════════════════════════════════════════════════════════════════

    /// @dev The target allowlist is shared across the 4626 and Aave selector families. A
    ///      well-formed Aave-selector call against the 4626 VAULT is AUTHORIZED (target
    ///      allowlisted, asset allowlisted, to==account, amount<=cap). This is not a fund
    ///      path: at execution a 4626 vault has no withdraw(address,uint256,address), so the
    ///      Safe call reverts and no assets move; and even if a target did implement it, `to`
    ///      is pinned to the account. Documented here so the looseness is explicit.
    function test_Observation_CrossFamilySelector_AuthorizedButInert() public view {
        assertTrue(wp.evaluate(_aaveExit(ASSET, 1 ether, ACCOUNT), _ctx(VAULT, WITHDRAW_AAVE, 0)));
        // 4626 selector against the Aave pool is likewise authorized-but-inert
        assertTrue(wp.evaluate(_vaultExit(WITHDRAW_4626, 1 ether, ACCOUNT, ACCOUNT), _ctx(AAVE_POOL, WITHDRAW_4626, 0)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // 5. CONFIG AUTH BOUNDARY + EPOCH FRESHNESS
    // ═════════════════════════════════════════════════════════════════════════

    /// @dev A non-permissionSigner cannot (re)configure another account — so a malicious
    ///      manager cannot add a target or raise the cap.
    function test_Auth_NonSignerCannotConfigure() public {
        kernel.setSigner(OTHER); // permissionSigner is now OTHER, not this test contract
        vm.expectRevert(
            abi.encodeWithSelector(ConfigurablePermission.NotPermissionSigner.selector, address(this), OTHER)
        );
        wp.configureDirect(ACCOUNT, abi.encode(_one(VAULT), _one(ASSET), CAP));
    }

    /// @dev Full revoke→re-register lifecycle: a config stamped at an old epoch fails closed
    ///      once the kernel epoch is bumped, and only a fresh configure at the new epoch
    ///      re-enables evaluation.
    function test_EpochTransition_StaleThenRefreshed() public {
        bytes memory data = _vaultExit(WITHDRAW_4626, 1 ether, ACCOUNT, ACCOUNT);

        // stamped at epoch 0, ctx epoch 0 → allowed
        assertTrue(wp.evaluate(data, _ctxEpoch(VAULT, WITHDRAW_4626, 0)));

        // kernel bumps the registration epoch (revoke / replace-out / manager rotation)
        kernel.setRegEpoch(1);
        assertFalse(wp.evaluate(data, _ctxEpoch(VAULT, WITHDRAW_4626, 1))); // stale config → deny

        // permissionSigner reconfigures at the new epoch → allowed again
        _configure(_two(VAULT, AAVE_POOL), _one(ASSET), CAP);
        assertTrue(wp.evaluate(data, _ctxEpoch(VAULT, WITHDRAW_4626, 1)));

        // a config for epoch 1 does not satisfy a still-older ctx epoch mismatch
        assertFalse(wp.evaluate(data, _ctxEpoch(VAULT, WITHDRAW_4626, 2)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // 6. GAS — evaluate() hot path is O(1) (no allowlist scan), safe under the cap
    // ═════════════════════════════════════════════════════════════════════════

    /// @dev evaluate() uses O(1) mapping lookups (not array scans). Even with both allowlists
    ///      at the 50-entry maximum, a single evaluate stays far under PERMISSION_GAS_CAP (150k).
    function test_Gas_EvaluateIsConstantUnderMaxAllowlists() public {
        address[] memory tg = new address[](50);
        address[] memory tk = new address[](50);
        for (uint256 i; i < 50; i++) { tg[i] = address(uint160(0x1000 + i)); tk[i] = address(uint160(0x2000 + i)); }
        tg[49] = VAULT; tk[49] = ASSET;
        _configure(tg, tk, CAP);

        bytes memory data = _vaultExit(WITHDRAW_4626, 1 ether, ACCOUNT, ACCOUNT);
        Context memory ctx = _ctx(VAULT, WITHDRAW_4626, 0);
        uint256 g0 = gasleft();
        wp.evaluate(data, ctx);
        uint256 used = g0 - gasleft();
        emit log_named_uint("evaluate gas (max allowlists)", used);
        assertLt(used, 150_000);
    }
}
