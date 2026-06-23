// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import {Context} from "../contracts/interfaces/IPermission.sol";
import {ConfigurablePermission} from "../contracts/templates/ConfigurablePermission.sol";

/// @dev Minimal concrete subclass for exercising the base. ConfigurablePermission is abstract:
///      it leaves `_applyConfig` unimplemented and inherits IPermission (`evaluate`,
///      `discriminator`), which a concrete contract must satisfy. The IPermission methods are
///      irrelevant to C-10 — they are stubbed. Records the last applied params so tests can
///      assert configuration ran.
contract TestConfigurable is ConfigurablePermission {
    bytes public lastParams;

    constructor(address k) ConfigurablePermission(k, "TestConfigurable", "1") {}

    function _applyConfig(address, bytes calldata params) internal override {
        lastParams = params;
    }

    function evaluate(bytes calldata, Context calldata) external pure returns (bool) {
        return false;
    }

    function discriminator() external pure returns (bytes32) {
        return keccak256("TestConfigurable");
    }
}

/// @dev Kernel mock that returns the kernel's REAL 5-field AccountConfig shape, with a
///      NON-ZERO `feeAsset` sitting in ABI position 3 — immediately before `sessionActive`
///      (position 4) which is set to `false`. This is the exact layout that the previous
///      4-field `ISailKernelView` mis-decoded: it read word 3 (feeAsset, an address) into the
///      slot it labelled `sessionActive` (a bool), so a non-zero feeAsset surfaced as
///      `sessionActive == true`.
contract MockKernel5Field {
    address public immutable signer;
    address public constant MANAGER   = address(0x1111);
    address public constant FEE_POLICY = address(0x2222);
    address public constant FEE_ASSET = address(0xFEE); // non-zero, ABI position 3

    constructor(address _signer) {
        signer = _signer;
    }

    function registered(address) external pure returns (bool) {
        return true;
    }

    // Full 5-field getter, matching SailKernel's public `configs` mapping getter.
    function configs(address)
        external
        view
        returns (address permissionSigner, address manager, address feePolicy, address feeAsset, bool sessionActive)
    {
        return (signer, MANAGER, FEE_POLICY, FEE_ASSET, false); // sessionActive = false
    }
}

/// @dev The pre-fix (buggy) interface shape: 4 fields, dropping `feeAsset`.
interface IOldKernelView {
    function configs(address account)
        external
        view
        returns (address permissionSigner, address manager, address feePolicy, bool sessionActive);
}

/// @dev The post-fix (option c) minimized interface: declares only the field templates read.
interface INewKernelView {
    function configs(address account) external view returns (address permissionSigner);
}

contract ConfigurablePermissionTest is Test {
    address internal constant ACCOUNT = address(0xACC0);
    address internal signer;

    MockKernel5Field internal kernel;
    TestConfigurable internal tc;

    function setUp() public {
        signer = makeAddr("permissionSigner");
        kernel = new MockKernel5Field(signer);
        tc     = new TestConfigurable(address(kernel));
    }

    // ── C-10: characterization of the bug the fix removes ──────────────────────

    /// @notice Proves the OLD 4-field interface was genuinely broken against a real config: it
    ///         decodes word 3 (the kernel's `feeAsset`, an address) into a `bool` slot, and the
    ///         ABI decoder validates bools as 0/1 — so a non-zero `feeAsset` makes the decode
    ///         REVERT. This is the latent footgun C-10 removes: any account with a fee asset set
    ///         would have broken every `configs()` read through the old shape.
    function test_C10_OldFourFieldInterface_RevertsDecodingNonZeroFeeAsset() public {
        vm.expectRevert();
        this.readSessionActiveViaOldInterface();
    }

    /// @dev External wrapper so the decode happens across a call boundary and `vm.expectRevert`
    ///      can catch the ABI-decode revert.
    function readSessionActiveViaOldInterface() external view returns (bool sessionActive) {
        (, , , sessionActive) = IOldKernelView(address(kernel)).configs(ACCOUNT);
    }

    /// @notice The fixed minimized interface reads `permissionSigner` (word 0) correctly from
    ///         the 5-field getter, ignoring all trailing returndata.
    function test_C10_MinimizedInterface_ReadsPermissionSigner() public view {
        address ps = INewKernelView(address(kernel)).configs(ACCOUNT);
        assertEq(ps, signer, "minimized interface reads permissionSigner correctly");
    }

    // ── C-10: end-to-end through ConfigurablePermission's own code ──────────────

    /// @notice configureDirect authenticates against field-0 `permissionSigner` read through the
    ///         (now minimized) interface, against a kernel returning the full 5-field struct with
    ///         a non-zero feeAsset. The correct signer succeeds.
    function test_ConfigureDirect_AuthenticatesAgainstPermissionSigner() public {
        vm.prank(signer);
        tc.configureDirect(ACCOUNT, abi.encode("ok"));

        assertEq(tc.lastParams(), abi.encode("ok"), "config applied");
        assertEq(tc.configNonces(ACCOUNT), 1, "nonce advanced");
        assertTrue(tc.isConfigured(ACCOUNT), "marked configured");
    }

    /// @notice A non-signer is rejected — proving the template read the RIGHT permissionSigner
    ///         (field 0), not a value corrupted by the struct's trailing fields.
    function test_ConfigureDirect_RejectsNonSigner() public {
        address bad = makeAddr("notTheSigner");
        vm.prank(bad);
        vm.expectRevert(
            abi.encodeWithSelector(ConfigurablePermission.NotPermissionSigner.selector, bad, signer)
        );
        tc.configureDirect(ACCOUNT, abi.encode("nope"));
    }
}
