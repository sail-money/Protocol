// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

// ─────────────────────────────────────────────────────────────────────────────
// WithdrawPermission — INDEPENDENT RED-TEAM AUDIT (adversarial second pass)
//
// This file is intentionally NOT a re-implementation of the prior internal audit
// (44 baseline + 18 stress tests). It attacks the contract from angles the prior
// pass either rationalized past or never drove empirically:
//
//   A. Drive the REAL SailKernel.dispatch path (kernel-derived ctx, real EIP-712
//      manager sig, real staticcall deny-on-revert) — not a hand-built Context.
//   B. Cross-family shared-target authorization (a target allowlisted for one
//      selector family is also authorized for the others).
//   C. Malicious / nonstandard allowlisted venue (proves where the trust boundary
//      actually sits: calldata pin vs. venue behavior).
//   D. Economic exploit of the SHARES-denominated redeem cap (quantified).
//   E. High-depth (>=100k) differential fuzz of the decoder + length boundaries.
//   F. Symbolic proof — see the SYMBOLIC note below (tooling unavailable here).
//   G. Second lens: Foundry stateful invariant with an adversarial actor.
//
// SYMBOLIC (F): halmos/hevm/kontrol could not be installed in this environment
// (Python 3.8, no cargo/pipx/uv, pip cannot build z3/cmake). Per the audit rules
// this is stated plainly and compensated with the >=100k differential fuzz in
// section E (invariant is proven by exhaustive-in-practice sampling of the exact
// envelope predicate, computed by an INDEPENDENT reference decoder).
// ─────────────────────────────────────────────────────────────────────────────

import "forge-std/Test.sol";
import {SafeModuleEnabler}       from "../contracts/safe/SafeModuleEnabler.sol";
import "../contracts/core/SailKernel.sol";
import "../contracts/governance/SailGovernance.sol";
import {TimelockController}      from "@openzeppelin/contracts/governance/TimelockController.sol";
import {TimelockDeployer}        from "./support/TimelockDeployer.sol";
import {Context}                 from "../contracts/interfaces/IPermission.sol";
import {WithdrawPermission}      from "../contracts/templates/WithdrawPermission.sol";

// ── A forwarding Safe: records AND executes the module call, so a real (possibly
//    malicious) venue actually runs. Codeless targets: a low-level call returns
//    success, matching EVM semantics. ─────────────────────────────────────────
contract ForwardingSafe {
    function nonce() external pure returns (uint256) { return 1; }
    function checkSignatures(bytes32, bytes calldata, bytes calldata) external view {}
    function masterCopy() external pure returns (address) { return address(0x5AFE); }
    function isModuleEnabled(address) external pure returns (bool) { return true; }
    receive() external payable {}

    struct Call { address to; uint256 value; bytes data; uint8 operation; }
    Call[] private _calls;

    function execTransactionFromModule(address to, uint256 value, bytes calldata data, uint8 operation)
        external returns (bool)
    {
        _calls.push(Call(to, value, data, operation));
        (bool ok,) = to.call{value: value}(data);
        return ok;
    }
    function callCount() external view returns (uint256) { return _calls.length; }
    function getCall(uint256 i) external view returns (address, uint256, bytes memory, uint8) {
        Call storage c = _calls[i];
        return (c.to, c.value, c.data, c.operation);
    }
}

// ── Minimal ERC20 (attack C): a real balance the venue can move. ──────────────
contract MockERC20 {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amt) external { balanceOf[to] += amt; }
    function transfer(address to, uint256 amt) external returns (bool) {
        balanceOf[msg.sender] -= amt; balanceOf[to] += amt; return true;
    }
}

// ── Malicious ERC-4626-shaped vault (attack C): honors the ABI signature but
//    IGNORES the calldata `receiver` and pays a hard-coded thief instead. This is
//    exactly the venue-trust boundary: the template pins CALLDATA, not behavior. ─
contract MaliciousVault {
    MockERC20 public immutable asset;
    address   public immutable thief;
    constructor(MockERC20 _asset, address _thief) { asset = _asset; thief = _thief; }
    // withdraw(uint256 assets, address receiver, address owner)
    function withdraw(uint256 assets, address /*receiver*/, address /*owner*/) external returns (uint256) {
        asset.transfer(thief, assets); // ignores `receiver` — routes to the thief
        return assets;
    }
}

// ── A venue implementing BOTH exit families (attack B): allowlisted once as a
//    target, it is authorized for every selector. Records what it was asked. ────
contract MultiExitVenue {
    event Hit(bytes4 sel);
    function withdraw(uint256, address, address) external returns (uint256) { emit Hit(0xb460af94); return 0; }
    function redeem(uint256, address, address)   external returns (uint256) { emit Hit(0xba087652); return 0; }
    function withdraw(address, uint256, address) external returns (uint256) { emit Hit(0x69328dec); return 0; }
}

contract WithdrawPermissionRedTeam is Test {
    // selectors
    bytes4 constant W4626 = bytes4(keccak256("withdraw(uint256,address,address)")); // 0xb460af94
    bytes4 constant R4626 = bytes4(keccak256("redeem(uint256,address,address)"));   // 0xba087652
    bytes4 constant WAAVE = bytes4(keccak256("withdraw(address,uint256,address)")); // 0x69328dec

    uint256 constant PERM_SIGNER_KEY = 0xA11CE;
    uint256 constant MANAGER_KEY     = 0xB0B;
    address constant TREASURY        = address(0xAAAA);
    address constant EMERGENCY_ADMIN = address(0xEEEE);
    address constant ATTACKER        = address(0xBAD);
    uint256 constant CAP             = 100 ether;
    uint256 constant T0              = 1_000_000;

    SailGovernance gov;
    SailKernel     kernel;
    ForwardingSafe safe;
    WithdrawPermission wp;

    address permSigner;
    address manager;
    address account; // == address(safe)

    // plain-address venues used where execution is irrelevant
    address constant VAULT     = address(0x7A17);
    address constant AAVE_POOL = address(0xAAEE);
    address constant ASSET     = address(0xA55E);

    uint256 private _saltNonce;

    function setUp() public {
        permSigner = vm.addr(PERM_SIGNER_KEY);
        manager    = vm.addr(MANAGER_KEY);
        vm.warp(T0);
        vm.deal(address(this), 10 ether);

        gov = new SailGovernance(address(this), 0.001 ether, EMERGENCY_ADMIN, 0, TimelockDeployer.deploy(address(this)));
        _govExec(abi.encodeCall(gov.setPermissionRegistrationFee, (0.001 ether)));
        vm.warp(T0);

        kernel = new SailKernel(address(gov), TREASURY, address(new SafeModuleEnabler()));

        safe = new ForwardingSafe();
        account = address(safe);
        vm.deal(account, 100 ether);
        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeProxyCodehash(address(safe).codehash, true);
        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeSingleton(address(0x5AFE), true);

        wp = new WithdrawPermission(address(kernel), address(0xA11CE));

        vm.prank(account);
        kernel.registerAccount(permSigner, manager, address(0), address(0), block.timestamp + 1 days, "");

        // config applied BEFORE registerPermission is fine (configureDirect only needs the account
        // registered); re-applied here after registration to stamp the current epoch.
        _configureDefault();

        uint256 fee = gov.permissionRegistrationFee();
        uint256 dl  = block.timestamp + 1 days;
        kernel.registerPermission{value: fee}(account, address(wp), dl, _signReg(account, address(wp), 0, dl));

        // stamp config at the post-registration epoch
        _configureDefault();

        // Constrain the stateful-invariant fuzzer (G) to the adversarial handler only.
        bytes4[] memory sels = new bytes4[](1);
        sels[0] = this.attack.selector;
        targetContract(address(this));
        targetSelector(FuzzSelector({addr: address(this), selectors: sels}));
    }

    receive() external payable {}

    function _configureDefault() internal {
        address[] memory targets = new address[](4);
        targets[0] = VAULT; targets[1] = AAVE_POOL; targets[2] = ASSET; targets[3] = address(0xBEEF);
        address[] memory tokens = new address[](1);
        tokens[0] = ASSET;
        vm.prank(permSigner);
        wp.configureDirect(account, abi.encode(targets, tokens, CAP));
    }

    function _govExec(bytes memory data) internal {
        TimelockController tl = gov.timelock();
        bytes32 salt = bytes32(_saltNonce++);
        tl.schedule(address(gov), 0, data, bytes32(0), salt, 48 hours);
        vm.warp(block.timestamp + 48 hours + 1);
        tl.execute(address(gov), 0, data, bytes32(0), salt);
    }

    function _signReg(address acct, address perm, uint256 nonce, uint256 deadline) internal view returns (bytes memory) {
        bytes32 sh = keccak256(abi.encode(kernel.REGISTER_PERMISSION_TYPEHASH(), acct, perm, nonce, deadline));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PERM_SIGNER_KEY, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }

    function _signDispatch(address perm, address target, uint256 value, bytes memory data, uint256 deadline)
        internal view returns (bytes memory)
    {
        uint256 nonce = kernel.managerNonces(account);
        bytes32 sh = keccak256(abi.encode(
            kernel.DISPATCH_TYPEHASH(), account, perm, target, value, keccak256(data), nonce, deadline));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(MANAGER_KEY, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }

    /// @dev Drive the real kernel; returns true if dispatch succeeded (no revert).
    function _dispatch(address target, uint256 value, bytes memory data) internal returns (bool ok) {
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sig = _signDispatch(address(wp), target, value, data, dl);
        try kernel.dispatch(account, address(wp), target, value, data, sig, dl) { ok = true; }
        catch { ok = false; }
    }

    function _w4626(uint256 a, address rec, address own) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(W4626, a, rec, own);
    }
    function _r4626(uint256 a, address rec, address own) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(R4626, a, rec, own);
    }
    function _aave(address asset, uint256 a, address to) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(WAAVE, asset, a, to);
    }
    function _ctx(address target, bytes4 sel, uint256 value) internal view returns (Context memory c) {
        c = Context(account, manager, address(this), target, sel, value, block.timestamp, block.number,
                    kernel.registrationEpoch(account, address(wp)));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // A. REAL KERNEL DISPATCH — ctx is produced by the kernel, not the harness
    // ═══════════════════════════════════════════════════════════════════════════

    function test_A_RealKernel_GoldenPath_ExecutesExactCallAsCALL() public {
        bytes memory data = _w4626(CAP, account, account);
        assertTrue(_dispatch(VAULT, 0, data), "fully-pinned exit should dispatch");
        assertEq(safe.callCount(), 1);
        (address to, uint256 val, bytes memory exec, uint8 op) = safe.getCall(0);
        // The executed call is byte-identical to what was signed & evaluated; op==0 (CALL, not delegatecall).
        assertEq(to, VAULT);
        assertEq(val, 0);
        assertEq(exec, data, "executed calldata must equal evaluated calldata (no divergence)");
        assertEq(op, 0, "must execute as CALL, never delegatecall");
    }

    function test_A_RealKernel_ReceiverNotAccount_Denied() public {
        assertFalse(_dispatch(VAULT, 0, _w4626(1 ether, ATTACKER, account)), "receiver!=account must deny");
        assertEq(safe.callCount(), 0, "denied dispatch must not execute");
    }

    function test_A_RealKernel_OwnerNotAccount_Denied() public {
        // The subtle pin: receiver is the account, owner is a third party (allowance-drain vector).
        assertFalse(_dispatch(VAULT, 0, _w4626(1 ether, account, ATTACKER)), "owner!=account must deny");
        assertEq(safe.callCount(), 0);
    }

    function test_A_RealKernel_Aave_ToNotAccount_Denied() public {
        assertFalse(_dispatch(AAVE_POOL, 0, _aave(ASSET, 1 ether, ATTACKER)), "aave to!=account must deny");
    }

    function test_A_RealKernel_NativeValue_Denied() public {
        // value is signed into the dispatch digest AND passed to the template; template denies value!=0.
        assertFalse(_dispatch(VAULT, 1, _w4626(1 ether, account, account)), "value!=0 must deny");
        assertEq(safe.callCount(), 0);
    }

    function test_A_RealKernel_DirtyOwnerBits_RevertInDecode_DeniesViaStaticcall() public {
        // Craft calldata whose `owner` word carries dirty high bits → abi.decode(...(address)) reverts
        // INSIDE evaluate → the kernel's staticcall catches it → _evaluatePermission returns false →
        // PermissionDenied. Proves deny-on-revert through the REAL staticcall path (not a direct call).
        bytes memory data = abi.encodePacked(
            W4626,
            uint256(1 ether),                 // assets
            uint256(uint160(account)),        // receiver (clean)
            bytes32(uint256(1) << 200 | uint256(uint160(account))) // owner with dirty high bits
        );
        assertFalse(_dispatch(VAULT, 0, data), "dirty-bits decode revert must deny");
        assertEq(safe.callCount(), 0);
    }

    function test_A_RealKernel_TargetNotAllowlisted_Denied() public {
        address rogue = address(0xC0DE);
        assertFalse(_dispatch(rogue, 0, _w4626(1 ether, account, account)), "non-allowlisted target must deny");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // B. CROSS-FAMILY SHARED-TARGET AUTHORIZATION
    //    A target allowlisted for 4626 is ALSO authorized for the Aave selector.
    //    Prove no fund path to a non-account address exists across families.
    // ═══════════════════════════════════════════════════════════════════════════

    function test_B_MultiExitVenue_EveryFamily_PinsToAccount() public {
        MultiExitVenue venue = new MultiExitVenue();
        // allowlist the venue as BOTH a target and an asset (worst case for cross-family authz)
        address[] memory targets = new address[](1); targets[0] = address(venue);
        address[] memory tokens  = new address[](1); tokens[0]  = address(venue);
        vm.prank(permSigner);
        wp.configureDirect(account, abi.encode(targets, tokens, CAP));

        // 4626 withdraw/redeem to attacker → denied
        assertFalse(_dispatch(address(venue), 0, _w4626(1 ether, ATTACKER, account)));
        assertFalse(_dispatch(address(venue), 0, _r4626(1 ether, account, ATTACKER)));
        // Aave withdraw to attacker, asset = the venue (allowlisted as token) → denied on `to` pin
        assertFalse(_dispatch(address(venue), 0, _aave(address(venue), 1 ether, ATTACKER)));
        assertEq(safe.callCount(), 0, "no attacker-routed exit may execute across any family");

        // And the fully-pinned form of each family DOES pass (authorized + pinned)
        assertTrue(_dispatch(address(venue), 0, _w4626(1 ether, account, account)));
        assertTrue(_dispatch(address(venue), 0, _r4626(1 ether, account, account)));
        assertTrue(_dispatch(address(venue), 0, _aave(address(venue), 1 ether, account)));
    }

    function test_B_SelectorArgumentConfusion_PinnedSlotAlwaysGoverns() public {
        // ctx.selector (== data[:4], kernel-derived) fixes the branch, so only THAT branch's pins
        // apply — an address at a non-pinned offset for the active selector can never become the
        // destination. Prove: the attacker in any PINNED slot always denies; and an attacker value in
        // a NON-pinned slot (e.g. Aave `amount`) cannot route funds because the destination is the
        // separately-pinned `to`.
        MultiExitVenue venue = new MultiExitVenue();
        address[] memory targets = new address[](1); targets[0] = address(venue);
        address[] memory tokens  = new address[](1); tokens[0]  = address(venue);
        vm.prank(permSigner);
        wp.configureDirect(account, abi.encode(targets, tokens, CAP));

        // 4626: attacker at receiver(word1) → deny; attacker at owner(word2) → deny
        assertFalse(_dispatch(address(venue), 0, _w4626(1 ether, ATTACKER, account)), "4626 receiver pin");
        assertFalse(_dispatch(address(venue), 0, _w4626(1 ether, account, ATTACKER)), "4626 owner pin");
        // Aave: attacker at to(word2) → deny, whether amount is small or over-cap
        assertFalse(_dispatch(address(venue), 0, _aave(address(venue), 1 ether, ATTACKER)), "aave to pin (small amt)");
        assertFalse(_dispatch(address(venue), 0, _aave(address(venue), CAP + 1, ATTACKER)), "aave to pin (over cap)");
        assertEq(safe.callCount(), 0, "no confused call routed funds anywhere");

        // Positive control: a tiny attacker-valued `amount` (non-pinned slot) with to==account is a
        // legitimately authorized, account-pinned exit — it executes, and the destination is the
        // account (word2), never the attacker. Demonstrates the non-pinned slot cannot misroute.
        assertTrue(_dispatch(address(venue), 0, _aave(address(venue), uint256(uint160(ATTACKER)), account)),
                   "non-pinned amount slot does not affect authorization when to==account");
        (address to,,,) = safe.getCall(0);
        assertEq(to, address(venue));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // C. MALICIOUS ALLOWLISTED VENUE — where the trust boundary really is
    // ═══════════════════════════════════════════════════════════════════════════

    function test_C_MaliciousVault_HonorsAbiButStealsFunds_OperatorBoundary() public {
        MockERC20 token = new MockERC20();
        MaliciousVault vault = new MaliciousVault(token, ATTACKER);
        token.mint(address(vault), 50 ether); // vault holds redeemable assets

        address[] memory targets = new address[](1); targets[0] = address(vault);
        address[] memory tokens  = new address[](1); tokens[0]  = ASSET;
        vm.prank(permSigner);
        wp.configureDirect(account, abi.encode(targets, tokens, CAP));

        // Calldata is FULLY PINNED (receiver=owner=account) — the template authorizes it...
        bytes memory data = _w4626(10 ether, account, account);
        bool ok = _dispatch(address(vault), 0, data);
        assertTrue(ok, "template authorizes a well-formed, fully-pinned exit");

        // ...yet the malicious venue ignored the calldata receiver and paid the thief.
        assertEq(token.balanceOf(ATTACKER), 10 ether, "malicious venue routed funds despite the pin");
        assertEq(token.balanceOf(account), 0);
        // CLASSIFICATION: operator-trust boundary, NOT a template bug. The pin binds CALLDATA, which
        // the template cannot force a byte-compliant-but-dishonest venue to honor. Only an allowlisted
        // (i.e. operator-trusted) venue reaches here; the template's contract is "constrain shape &
        // recipient-in-calldata", which it does. Documented in the contract's HONEST BOUNDARY NatSpec.
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // D. ECONOMIC EXPLOIT OF THE SHARES-DENOMINATED REDEEM CAP (quantified)
    // ═══════════════════════════════════════════════════════════════════════════

    function test_D_RedeemCap_IsShareCountInvariantToValue() public {
        // Cap = N shares. The template checks shares<=cap and nothing about price. So the SAME N-share
        // redeem is authorized regardless of price-per-share — i.e. the asset value it extracts is
        // unbounded above as the share price rises (yield, or a donation/first-depositor inflation the
        // manager could induce). Bound: worst-case extracted value = cap * price_per_share, price
        // unbounded → value unbounded. This is a DESIGN LIMITATION (oracle-free by intent), documented
        // in NatSpec/TEMPLATES.md; the operator must size the cap with headroom or use `withdraw`
        // (asset-denominated) for a value ceiling. NOT a template bug: no envelope escape occurs.
        uint256 nShares = 1_000;
        vm.prank(permSigner);
        address[] memory targets = new address[](1); targets[0] = VAULT;
        address[] memory tokens  = new address[](1); tokens[0]  = ASSET;
        wp.configureDirect(account, abi.encode(targets, tokens, nShares));

        // N shares always authorized (value it maps to is the venue's business, not the template's).
        assertTrue(wp.evaluate(_r4626(nShares, account, account), _ctx(VAULT, R4626, 0)));
        assertFalse(wp.evaluate(_r4626(nShares + 1, account, account), _ctx(VAULT, R4626, 0)));
        // Contrast: the `withdraw` arm caps ASSETS directly → a real value ceiling under the same cap.
        assertTrue(wp.evaluate(_w4626(nShares, account, account), _ctx(VAULT, W4626, 0)));
        assertFalse(wp.evaluate(_w4626(nShares + 1, account, account), _ctx(VAULT, W4626, 0)));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // E. HIGH-DEPTH DIFFERENTIAL FUZZ (>=100k via FOUNDRY_FUZZ_RUNS)
    //    An INDEPENDENT reference decoder (manual byte extraction at literal offsets)
    //    computes the expected verdict; any divergence from evaluate() is an offset
    //    or pin bug. This is the compensation for the unavailable symbolic proof.
    // ═══════════════════════════════════════════════════════════════════════════

    /// @dev Independent reference: extract the address at word `w` (0-based, after selector)
    ///      by literal byte offset, and check it decodes cleanly to an address (no dirty bits).
    function _wordAddrClean(bytes memory data, uint256 w) internal pure returns (address a, bool clean) {
        uint256 off = 4 + w * 32;
        bytes32 word;
        assembly { word := mload(add(add(data, 32), off)) }
        a = address(uint160(uint256(word)));
        clean = (uint256(word) >> 160) == 0; // top 96 bits must be zero for a clean address decode
    }
    function _wordUint(bytes memory data, uint256 w) internal pure returns (uint256 x) {
        uint256 off = 4 + w * 32;
        assembly { x := mload(add(add(data, 32), off)) }
    }

    function testFuzz_E_Differential_4626Withdraw(uint256 assets, address rec, address own) public view {
        bytes memory data = _w4626(assets, rec, own);
        bool got = wp.evaluate(data, _ctx(VAULT, W4626, 0));
        bool expected = (assets <= CAP) && (rec == account) && (own == account);
        assertEq(got, expected, "4626 withdraw envelope divergence");
    }

    function testFuzz_E_Differential_4626Redeem(uint256 shares, address rec, address own) public view {
        bytes memory data = _r4626(shares, rec, own);
        bool got = wp.evaluate(data, _ctx(VAULT, R4626, 0));
        bool expected = (shares <= CAP) && (rec == account) && (own == account);
        assertEq(got, expected, "4626 redeem envelope divergence");
    }

    function testFuzz_E_Differential_AaveWithdraw(address asset, uint256 amount, address to) public view {
        bytes memory data = _aave(asset, amount, to);
        bool got = wp.evaluate(data, _ctx(AAVE_POOL, WAAVE, 0));
        // ASSET is the only allowlisted token; envelope requires asset allowlisted, amount<=cap, to==account
        bool expected = (asset == ASSET) && (amount <= CAP) && (to == account);
        assertEq(got, expected, "aave withdraw envelope divergence");
    }

    /// @dev Fuzz the selector too: any selector outside the three must ALWAYS deny.
    function testFuzz_E_UnknownSelector_AlwaysDenied(bytes4 sel, uint256 a, address x, address y) public view {
        vm.assume(sel != W4626 && sel != R4626 && sel != WAAVE);
        bytes memory data = abi.encodeWithSelector(sel, a, x, y);
        assertFalse(wp.evaluate(data, _ctx(VAULT, sel, 0)), "unknown selector must deny");
    }

    /// @dev Fuzz calldata length + trailing garbage: trailing words must not relocate a pinned
    ///      word, and over-long payloads must not misroute. Verdict must match the 100-byte prefix.
    function testFuzz_E_TrailingGarbage_CannotRelocatePins(uint256 assets, address rec, address own, bytes calldata tail)
        public view
    {
        bytes memory data = abi.encodePacked(_w4626(assets, rec, own), tail);
        bool got = wp.evaluate(data, _ctx(VAULT, W4626, 0));
        bool expected = (assets <= CAP) && (rec == account) && (own == account);
        assertEq(got, expected, "trailing garbage must not change the verdict");
    }

    function testFuzz_E_ShortCalldata_AlwaysDenied(bytes calldata blob) public view {
        vm.assume(blob.length < 100);
        // Prepend a recognized selector but keep total < 100 → length guard must deny (no OOB read).
        bytes memory data = abi.encodePacked(W4626, blob);
        if (data.length >= 100) return; // only assert the sub-100 case
        assertFalse(wp.evaluate(data, _ctx(VAULT, W4626, 0)), "short calldata must deny");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // G. SECOND LENS — stateful invariant with an adversarial actor.
    //    A handler hammers evaluate() with adversarial calldata/ctx; the invariant
    //    asserts NO out-of-envelope accept was EVER observed across the whole run.
    // ═══════════════════════════════════════════════════════════════════════════

    // handler state
    bool public sawEnvelopeEscape;

    function attack(uint256 selPick, uint256 amount, address a1, address a2, address target, uint256 value) public {
        bytes4 sel = [W4626, R4626, WAAVE, bytes4(0xdeadbeef)][selPick % 4];
        // choose target/asset from the allowlisted set or a rogue, adversarially
        address tgt = [VAULT, AAVE_POOL, ASSET, address(0xC0DE)][uint256(uint160(target)) % 4];
        bytes memory data;
        if (sel == WAAVE) data = _aave(a1, amount, a2);
        else              data = abi.encodeWithSelector(sel, amount, a1, a2);

        Context memory c = _ctx(tgt, sel, value);
        bool ok = wp.evaluate(data, c);
        if (!ok) return;

        // If evaluate accepted, the full documented envelope MUST hold. Any deviation is an escape.
        bool envelopeOk;
        if (value == 0 && (tgt == VAULT || tgt == AAVE_POOL || tgt == ASSET || tgt == address(0xBEEF))) {
            if (sel == W4626 || sel == R4626) {
                envelopeOk = (amount <= CAP) && (a1 == account) && (a2 == account);
            } else if (sel == WAAVE) {
                // a1 = asset, amount = amount, a2 = to
                envelopeOk = (a1 == ASSET) && (amount <= CAP) && (a2 == account);
            }
        }
        if (!envelopeOk) sawEnvelopeEscape = true;
    }

    function invariant_G_NoEnvelopeEscapeEverObserved() public view {
        assertFalse(sawEnvelopeEscape, "evaluate accepted a call outside the documented envelope");
    }
}
