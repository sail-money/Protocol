// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {SailKernel}       from "../contracts/core/SailKernel.sol";
import {SailGovernance}   from "../contracts/governance/SailGovernance.sol";
import {TimelockDeployer} from "./support/TimelockDeployer.sol";

/// @dev Configurable Safe-proxy stand-in for the group-1a registration-auth regression tests.
///      Stores its singleton in regular storage (not immutable / not in code), so every instance
///      shares one runtime codehash — exactly like a real SafeProxy — letting a single codehash
///      seed cover the trusted- and untrusted-singleton instances alike. `nonce` and module-enabled
///      are settable so a test can reproduce the setup-time (nonce == 0) attack shape.
contract ConfigurableSafe {
    address private _singleton;
    uint256 private _nonce = 1;          // a finalized Safe has nonce >= 1
    bool    private _moduleEnabled = true;

    constructor(address singleton_) { _singleton = singleton_; }

    function masterCopy() external view returns (address) { return _singleton; }
    function nonce() external view returns (uint256) { return _nonce; }
    function isModuleEnabled(address) external view returns (bool) { return _moduleEnabled; }

    function setNonce(uint256 n) external { _nonce = n; }
    function setModuleEnabled(bool v) external { _moduleEnabled = v; }

    /// @dev Forward `data` to `kernel`, then mimic Safe's FallbackManager by appending the
    ///      original caller's 20 bytes — reproducing a fallbackHandler==kernel relay (W1).
    function relayWithTrailingBytes(address kernel, bytes calldata data, address originalCaller)
        external
        returns (bool ok, bytes memory ret)
    {
        (ok, ret) = kernel.call(abi.encodePacked(data, bytes20(originalCaller)));
    }

    /// @dev Forward `data` to `kernel` verbatim (exact length) — a legitimate direct Safe call.
    function relayExact(address kernel, bytes calldata data) external returns (bool ok, bytes memory ret) {
        (ok, ret) = kernel.call(data);
    }
}

contract OctaneGroup1aRegistrationAuthTest is Test {
    SailKernel     kernel;
    SailGovernance gov;

    address constant TEAM      = address(0x1111);
    address constant TREASURY  = address(0x2222);
    address constant EMERGENCY = address(0xEEEE);

    address constant TRUSTED_SINGLETON   = address(0x600D);
    address constant UNTRUSTED_SINGLETON = address(0x0BAD);

    address permSigner = address(0x5161);
    address manager    = address(0x6A11);

    function setUp() public {
        gov    = new SailGovernance(TEAM, 0.001 ether, EMERGENCY, 0, TimelockDeployer.deploy(TEAM));
        kernel = new SailKernel(address(gov), TREASURY);

        // One codehash seed covers every ConfigurableSafe instance.
        ConfigurableSafe seed = new ConfigurableSafe(TRUSTED_SINGLETON);
        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeProxyCodehash(address(seed).codehash, true);
        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeSingleton(TRUSTED_SINGLETON, true);
    }

    function _newSafe(address singleton) internal returns (ConfigurableSafe s) {
        s = new ConfigurableSafe(singleton);
    }

    // ── #4: setup-not-finalized (nonce == 0) ────────────────────────────────────

    /// A registration attempted while the Safe nonce is still 0 (the Safe.setup-delegatecall
    /// attack shape) is rejected; a finalized Safe (nonce >= 1) registers normally.
    function test_Reg4_NonceZero_Rejected() public {
        ConfigurableSafe safe = _newSafe(TRUSTED_SINGLETON);
        safe.setNonce(0);
        vm.prank(address(safe));
        vm.expectRevert(SailKernel.SetupNotFinalized.selector);
        kernel.registerAccount(permSigner, manager, address(0), address(0));
    }

    function test_Reg4_NonceFinalized_Registers() public {
        ConfigurableSafe safe = _newSafe(TRUSTED_SINGLETON); // nonce defaults to 1
        vm.prank(address(safe));
        kernel.registerAccount(permSigner, manager, address(0), address(0));
        assertTrue(kernel.registered(address(safe)));
        (address ps, address mgr,,,) = kernel.configs(address(safe));
        assertEq(ps, permSigner);
        assertEq(mgr, manager);
    }

    // ── #9: trusted-singleton check ─────────────────────────────────────────────

    /// A genuine proxy (trusted codehash) that delegates to an UNtrusted singleton is rejected.
    function test_Reg9_UntrustedSingleton_Rejected() public {
        ConfigurableSafe safe = _newSafe(UNTRUSTED_SINGLETON);
        vm.prank(address(safe));
        vm.expectRevert(abi.encodeWithSelector(SailKernel.UntrustedSingleton.selector, UNTRUSTED_SINGLETON));
        kernel.registerAccount(permSigner, manager, address(0), address(0));
    }

    function test_Reg9_TrustedSingleton_Registers() public {
        ConfigurableSafe safe = _newSafe(TRUSTED_SINGLETON);
        vm.prank(address(safe));
        kernel.registerAccount(permSigner, manager, address(0), address(0));
        assertTrue(kernel.registered(address(safe)));
    }

    // ── W1: exact-calldata-length guards ────────────────────────────────────────

    /// A fallback-relayed registerAccount (calldata + 20 trailing bytes) is rejected; the
    /// exact-length direct call registers.
    function test_RegW1_RegisterAccount_FallbackShape_Rejected() public {
        ConfigurableSafe safe = _newSafe(TRUSTED_SINGLETON);
        bytes memory data = abi.encodeWithSelector(
            kernel.registerAccount.selector, permSigner, manager, address(0), address(0)
        );
        (bool ok, bytes memory ret) = safe.relayWithTrailingBytes(address(kernel), data, address(0xA77ACC));
        assertFalse(ok, "fallback-shaped call must revert");
        assertEq(bytes4(ret), SailKernel.UnexpectedCalldataLength.selector);
        assertFalse(kernel.registered(address(safe)), "must not register via fallback relay");

        // Exact-length direct call still works.
        (bool ok2,) = safe.relayExact(address(kernel), data);
        assertTrue(ok2, "exact-length direct call must succeed");
        assertTrue(kernel.registered(address(safe)));
    }

    /// setManager via fallback shape is rejected; exact-length call works (after registration).
    function test_RegW1_SetManager_FallbackShape_Rejected() public {
        ConfigurableSafe safe = _newSafe(TRUSTED_SINGLETON);
        vm.prank(address(safe));
        kernel.registerAccount(permSigner, manager, address(0), address(0));

        bytes memory data = abi.encodeWithSelector(kernel.setManager.selector, address(0xBEEF));
        (bool ok, bytes memory ret) = safe.relayWithTrailingBytes(address(kernel), data, address(0xA77ACC));
        assertFalse(ok);
        assertEq(bytes4(ret), SailKernel.UnexpectedCalldataLength.selector);
        assertEq(kernel.getManager(address(safe)), manager, "manager must be unchanged");

        (bool ok2,) = safe.relayExact(address(kernel), data);
        assertTrue(ok2);
        assertEq(kernel.getManager(address(safe)), address(0xBEEF));
    }

    /// collectFees via fallback shape is rejected by the length guard (the first check), before
    /// any auth/policy logic; an exact-length call passes the guard (and fails later for a
    /// different, non-length reason — proving the guard itself did not fire).
    function test_RegW1_CollectFees_FallbackShape_Rejected() public {
        ConfigurableSafe safe = _newSafe(TRUSTED_SINGLETON);
        vm.prank(address(safe));
        kernel.registerAccount(permSigner, manager, address(0), address(0));

        bytes memory data = abi.encodeWithSelector(
            kernel.collectFees.selector, address(safe), uint256(1), uint256(1), address(0)
        );
        (bool ok, bytes memory ret) = safe.relayWithTrailingBytes(address(kernel), data, address(0xA77ACC));
        assertFalse(ok);
        assertEq(bytes4(ret), SailKernel.UnexpectedCalldataLength.selector);

        // Exact-length call clears the length guard; it reverts later (no fee policy set), which
        // is a DIFFERENT selector — proving the calldata-length guard did not reject it.
        (bool ok2, bytes memory ret2) = safe.relayExact(address(kernel), data);
        assertFalse(ok2);
        assertTrue(bytes4(ret2) != SailKernel.UnexpectedCalldataLength.selector, "must pass length guard");
        assertEq(bytes4(ret2), SailKernel.FeePolicyNotSet.selector);
    }
}
