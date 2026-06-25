// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {FactoryTestBase} from "./support/FactoryTestBase.sol";
import {SailKernel} from "../contracts/core/SailKernel.sol";
import {ConfigurablePermission} from "../contracts/templates/ConfigurablePermission.sol";
import {TransferPermission} from "../contracts/templates/TransferPermission.sol";

/// @notice Octane #2 (non-atomic configure+register front-run) and #8 (configure-sig replay across
///         epochs) regression suite. Both findings are closed by ONE mechanism: a per-(account,
///         permission) registration epoch (kernel), stamped into the template's config and rechecked
///         (fail-closed) in evaluate(). These tests exercise the REAL kernel + a real template.
contract Octane05_ConfigEpochTest is FactoryTestBase {
    bytes4 internal constant TRANSFER_SEL = 0xa9059cbb;
    address internal constant TOKEN     = address(0x7000);
    address internal constant RECIPIENT = address(0xC0FFEE);

    // Pre-fix Configure typehash (4 fields, no epoch) — used to prove the typehash bump invalidates
    // any signature built against the old shape.
    bytes32 internal constant OLD_CONFIGURE_TYPEHASH =
        keccak256("Configure(address account,bytes32 paramsHash,uint256 nonce,uint256 deadline)");

    TransferPermission internal P;
    TransferPermission internal Q;

    function setUp() public override {
        super.setUp();
        P = new TransferPermission(address(kernel), address(this));
        Q = new TransferPermission(address(kernel), address(this));
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    function _deadline() internal view returns (uint256) {
        return block.timestamp + 1 days;
    }

    function _params(uint256 cap) internal pure returns (bytes memory) {
        address[] memory recips = new address[](1); recips[0] = RECIPIENT;
        address[] memory toks   = new address[](1); toks[0]   = TOKEN;
        return abi.encode(recips, toks, cap);
    }

    function _register(address perm) internal {
        uint256 n = kernel.signerNonces(address(safe));
        bytes memory sig = _signRegisterPermission(address(safe), perm, n);
        kernel.registerPermission{value: gov.permissionRegistrationFee()}(
            address(safe), perm, _deadline(), sig
        );
    }

    function _revoke(address perm) internal {
        uint256 n = kernel.signerNonces(address(safe));
        bytes memory sig = _signRevokePermission(address(safe), perm, n);
        kernel.revokePermission(address(safe), perm, _deadline(), sig);
    }

    function _configure(TransferPermission t, uint256 cap) internal {
        bytes memory params = _params(cap);
        bytes memory sig = _signConfigure(t, address(safe), params, _deadline(), PERM_SIGNER_KEY);
        t.configure(address(safe), params, _deadline(), sig);
    }

    function _dispatch(address perm, uint256 amount) internal {
        bytes memory data = abi.encodeWithSelector(TRANSFER_SEL, RECIPIENT, amount);
        uint256 n = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), perm, TOKEN, 0, data, n, _deadline());
        kernel.dispatch(address(safe), perm, TOKEN, 0, data, sig, _deadline());
    }

    // ── 1. happy path ───────────────────────────────────────────────────────────

    function test_Lifecycle_RegisterConfigureDispatch() public {
        _register(address(P));
        _configure(P, 1_000);
        assertEq(kernel.registrationEpoch(address(safe), address(P)), 0, "fresh register keeps epoch 0");
        assertEq(P.configuredEpoch(address(safe)), 0, "config stamped at epoch 0");

        uint256 before = safe.callCount();
        _dispatch(address(P), 100);
        assertEq(safe.callCount(), before + 1, "transfer executed");
    }

    // ── 2. Octane #2: front-run of the register leg under stale config ────────────

    function test_Octane2_FrontRunReregister_StaleConfigDenied() public {
        _register(address(P));
        _configure(P, 1_000);             // broad config applied at epoch 0
        _dispatch(address(P), 100);       // sanity: works at epoch 0

        // Revoke bumps the per-(account,permission) epoch to 1; the template's stored config
        // (configuredEpoch = 0) is left untouched — the kernel cannot reach template storage.
        _revoke(address(P));
        assertEq(kernel.registrationEpoch(address(safe), address(P)), 1, "revoke bumped epoch");

        // Attacker front-runs ONLY the register leg (no fresh configure). Re-register does NOT bump,
        // so the kernel now pushes epoch 1 while the stale stamp is still 0.
        _register(address(P));
        assertEq(kernel.registrationEpoch(address(safe), address(P)), 1, "register does not bump");
        assertTrue(P.isConfigured(address(safe)), "stale config still present in template storage");
        assertEq(P.configuredEpoch(address(safe)), 0, "stale stamp is the old epoch");

        // Dispatch under the stale config is denied (configuredEpoch 0 != ctx.configEpoch 1).
        // Build the signed dispatch first so expectRevert binds to the kernel.dispatch call itself
        // (not the managerNonces view inside the helper).
        {
            bytes memory data = abi.encodeWithSelector(TRANSFER_SEL, RECIPIENT, uint256(100));
            uint256 n = kernel.managerNonces(address(safe));
            bytes memory sig = _signDispatch(address(safe), address(P), TOKEN, 0, data, n, _deadline());
            vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(P)));
            kernel.dispatch(address(safe), address(P), TOKEN, 0, data, sig, _deadline());
        }

        // A fresh configure for the current epoch re-enables dispatch under the new bounds.
        _configure(P, 1_000);
        assertEq(P.configuredEpoch(address(safe)), 1, "re-stamped at the new epoch");
        uint256 before = safe.callCount();
        _dispatch(address(P), 100);
        assertEq(safe.callCount(), before + 1, "dispatch re-enabled after fresh configure");
    }

    // ── 3. Octane #8: stale configure signatures cannot replay across an epoch change ─

    function test_Octane8_StaleEpochConfigureSig_Rejected() public {
        _register(address(P));
        _configure(P, 1_000);
        _revoke(address(P));
        _register(address(P)); // current epoch is now 1

        bytes memory params = _params(2_000);
        uint256 nonce = P.configNonces(address(safe));
        uint256 dl = _deadline();

        // (a) A signature that signs the STALE epoch (0) fails: the contract rebuilds the digest with
        //     the current epoch (1), so it no longer recovers the permissionSigner.
        bytes32 staleStruct = keccak256(abi.encode(
            P.CONFIGURE_TYPEHASH(), address(safe), keccak256(params), nonce, dl, uint256(0)
        ));
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(PERM_SIGNER_KEY, P.hashTypedDataV4(staleStruct));
        vm.expectRevert(ConfigurablePermission.InvalidSignature.selector);
        P.configure(address(safe), params, dl, abi.encodePacked(r1, s1, v1));

        // (b) A signature built against the PRE-FIX typehash (no epoch field) is rejected — the
        //     typehash bump invalidates any old-shape configure signature.
        bytes32 oldShape = keccak256(abi.encode(
            OLD_CONFIGURE_TYPEHASH, address(safe), keccak256(params), nonce, dl
        ));
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(PERM_SIGNER_KEY, P.hashTypedDataV4(oldShape));
        vm.expectRevert(ConfigurablePermission.InvalidSignature.selector);
        P.configure(address(safe), params, dl, abi.encodePacked(r2, s2, v2));

        // (c) A signature for the CURRENT epoch (1) succeeds.
        _configure(P, 2_000);
        assertEq(P.configuredEpoch(address(safe)), 1, "fresh configure stamps the current epoch");
    }

    // ── 4. Option B surgical property: revoking P does not invalidate Q ───────────

    function test_OptionB_RevokingP_DoesNotInvalidateQ() public {
        _register(address(P));
        _register(address(Q));
        _configure(P, 1_000);
        _configure(Q, 1_000);
        _dispatch(address(P), 100);
        _dispatch(address(Q), 100);

        // Revoke P. With a per-(account,permission) epoch this bumps ONLY P's counter; an account-wide
        // epoch would have invalidated Q's config too.
        _revoke(address(P));
        assertEq(kernel.registrationEpoch(address(safe), address(P)), 1, "P epoch bumped");
        assertEq(kernel.registrationEpoch(address(safe), address(Q)), 0, "Q epoch untouched");

        // Q still dispatches under its still-current config — proves the surgical property.
        uint256 before = safe.callCount();
        _dispatch(address(Q), 100);
        assertEq(safe.callCount(), before + 1, "Q unaffected by P's revoke");
    }

    // ── 5. configureDirect stamps the current epoch (no signed epoch needed) ──────

    function test_ConfigureDirect_StampsCurrentEpoch() public {
        _register(address(P));
        vm.prank(permSigner);
        P.configureDirect(address(safe), _params(1_000));
        assertEq(P.configuredEpoch(address(safe)), 0, "direct config stamped at epoch 0");
        _dispatch(address(P), 100);

        // After a revoke → re-register, a fresh direct config stamps the new epoch and re-enables.
        _revoke(address(P));
        _register(address(P));
        vm.prank(permSigner);
        P.configureDirect(address(safe), _params(1_000));
        assertEq(P.configuredEpoch(address(safe)), 1, "direct config re-stamped at the new epoch");
        uint256 before = safe.callCount();
        _dispatch(address(P), 100);
        assertEq(safe.callCount(), before + 1, "direct re-config re-enables dispatch");
    }
}
