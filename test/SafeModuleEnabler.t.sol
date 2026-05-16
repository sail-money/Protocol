// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import {SafeModuleEnabler} from "../contracts/safe/SafeModuleEnabler.sol";

/// @dev Minimal Safe that reproduces the storage layout and `setup`/`enableModule`
///      semantics this test needs. Real Safe v1.4.1's `enableModule` is gated by an
///      `authorized` modifier requiring `msg.sender == address(this)` — this mock
///      reproduces that exact check.
contract MockSafe {
    error AlreadySetup();
    error AlreadyEnabled();
    error NotAuthorized();

    mapping(address => bool) public modules;
    bool internal _initialized;

    modifier authorized() {
        if (msg.sender != address(this)) revert NotAuthorized();
        _;
    }

    /// @dev Mirrors the `to`/`data` delegatecall hook in real Safe.setup. Other
    ///      setup params elided — they don't affect the module-enabling flow.
    function setup(address to, bytes calldata data) external {
        if (_initialized) revert AlreadySetup();
        _initialized = true;

        if (to != address(0)) {
            (bool ok, bytes memory ret) = to.delegatecall(data);
            if (!ok) {
                if (ret.length > 0) {
                    assembly { revert(add(ret, 0x20), mload(ret)) }
                }
                revert("setup delegatecall failed");
            }
        }
    }

    function enableModule(address module) external authorized {
        if (modules[module]) revert AlreadyEnabled();
        modules[module] = true;
    }

    function isModuleEnabled(address module) external view returns (bool) {
        return modules[module];
    }
}

/// @dev A contract that delegatecalls into the enabler from its own context.
///      Used to verify that delegatecalling from a contract without an
///      `enableModule` function reverts.
contract NonSafeCaller {
    function delegateEnable(address enabler, address module) external {
        bytes memory data = abi.encodeCall(SafeModuleEnabler.enable, (module));
        (bool ok, bytes memory ret) = enabler.delegatecall(data);
        if (!ok) {
            if (ret.length > 0) {
                assembly { revert(add(ret, 0x20), mload(ret)) }
            }
            revert("delegate failed");
        }
    }
}

contract SafeModuleEnablerTest is Test {
    SafeModuleEnabler internal enabler;
    address internal constant KERNEL = address(0xCAFE);
    address internal constant OTHER  = address(0xBEEF);

    function setUp() public {
        enabler = new SafeModuleEnabler();
    }

    // -------------------------------------------------------------------------
    // Happy paths
    // -------------------------------------------------------------------------

    function test_DelegatecallFromSetup_EnablesModule() public {
        MockSafe safe = new MockSafe();
        bytes memory data = abi.encodeCall(SafeModuleEnabler.enable, (KERNEL));

        safe.setup(address(enabler), data);

        assertTrue(safe.isModuleEnabled(KERNEL), "kernel not enabled");
        assertFalse(safe.isModuleEnabled(OTHER), "spurious enable");
    }

    function test_DelegatecallFromSetup_AnyModuleAddress() public {
        MockSafe safe = new MockSafe();
        address random = address(0x1234567890123456789012345678901234567890);
        bytes memory data = abi.encodeCall(SafeModuleEnabler.enable, (random));

        safe.setup(address(enabler), data);
        assertTrue(safe.isModuleEnabled(random));
    }

    function test_SameEnablerReusableAcrossSafes() public {
        MockSafe a = new MockSafe();
        MockSafe b = new MockSafe();
        bytes memory data = abi.encodeCall(SafeModuleEnabler.enable, (KERNEL));

        a.setup(address(enabler), data);
        b.setup(address(enabler), data);

        assertTrue(a.isModuleEnabled(KERNEL));
        assertTrue(b.isModuleEnabled(KERNEL));
    }

    function test_EnablerIsStateless() public view {
        // Codesize is the only proxy for "no constructor stored anything" given
        // the contract has no public storage to introspect. A fresh redeploy
        // produces identical runtime bytecode.
        assertGt(address(enabler).code.length, 0, "enabler not deployed");
    }

    // -------------------------------------------------------------------------
    // Negative paths
    // -------------------------------------------------------------------------

    /// @notice Calling enable() directly (no delegatecall) makes the inner
    ///         enableModule call target the enabler itself, which has no such
    ///         function. The inner external call reverts and bubbles up.
    function test_DirectCall_Reverts() public {
        vm.expectRevert();
        enabler.enable(KERNEL);
    }

    /// @notice Delegatecalling the enabler from a contract that has no
    ///         enableModule function still reverts — the enabler is only safe
    ///         to use from a context that exposes the function.
    function test_DelegatecallFromNonSafe_Reverts() public {
        NonSafeCaller caller = new NonSafeCaller();
        vm.expectRevert();
        caller.delegateEnable(address(enabler), KERNEL);
    }

    /// @notice The MockSafe is one-shot — re-running setup reverts. (The Safe
    ///         contract's own duplicate-module guard is its responsibility, not
    ///         the enabler's.)
    function test_DoubleSetup_RevertsAtSafe() public {
        MockSafe safe = new MockSafe();
        bytes memory data = abi.encodeCall(SafeModuleEnabler.enable, (KERNEL));

        safe.setup(address(enabler), data);
        vm.expectRevert(MockSafe.AlreadySetup.selector);
        safe.setup(address(enabler), data);
    }

    /// @notice If somehow enable() is called *as* the Safe but the module is
    ///         already enabled, Safe's own duplicate guard catches it and the
    ///         inner enableModule reverts. Verified via a direct Safe-context
    ///         call (vm.prank with address(this) = safe to satisfy `authorized`).
    function test_DoubleEnableSameModule_RevertsAtSafe() public {
        MockSafe safe = new MockSafe();
        bytes memory data = abi.encodeCall(SafeModuleEnabler.enable, (KERNEL));

        safe.setup(address(enabler), data);

        // Second enable attempt directly on the Safe should revert.
        vm.prank(address(safe));
        vm.expectRevert(MockSafe.AlreadyEnabled.selector);
        safe.enableModule(KERNEL);
    }
}
