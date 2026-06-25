// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "./support/FactoryTestBase.sol";
import "./mocks/MockClonePermission.sol";
import "../contracts/utils/CloneInitializable.sol";

contract MandateFactoryDeployAndAttachTest is FactoryTestBase {
    // Test-only clone template — the production shared/ templates are configure-based,
    // not clones, so a clone permission is used here to cover the factory's clone path.
    MockClonePermission internal impl;

    address internal constant USDC = address(0xCC03);

    function setUp() public override {
        super.setUp();
        impl = new MockClonePermission();
    }

    function test_DeployAndAttach_GoldenPath() public {
        bytes32 salt = _salt(address(impl), "golden-path");
        address predicted = factory.predictCloneAddress(address(impl), salt);

        bytes memory initData = _initData(address(safe), permSigner);
        uint256 kDeadline = block.timestamp + 1 days;
        bytes memory kernelSig = _signRegisterPermission(
            address(safe), predicted, kernel.signerNonces(address(safe))
        );

        address clone = factory.deployAndAttach{value: _calcFee(predicted)}(
            address(safe), address(impl), salt, initData, kDeadline, kernelSig
        );

        assertEq(clone, predicted, "clone address should match prediction");
        assertTrue(kernel.isPermissionRegistered(address(safe), clone), "clone should be registered");
        assertTrue(CloneInitializable(clone).initialized(), "clone should be initialized");
        assertEq(MockClonePermission(clone).allowedRecipient(), address(safe));
        assertEq(MockClonePermission(clone).maxAmountPerTx(), 5 ether);
        assertEq(MockClonePermission(clone).permissionSigner(), permSigner);
        assertTrue(MockClonePermission(clone).isAllowedToken(USDC));
    }

    function test_DeployAndAttach_BubblesInitializeRevert() public {
        bytes32 salt = _salt(address(impl), "bubble-init-revert");
        address predicted = factory.predictCloneAddress(address(impl), salt);

        // maxAmountPerTx == 0 makes the clone's initialize() revert with InvalidConfig.
        bytes memory initData = abi.encodeCall(
            MockClonePermission.initialize,
            (address(safe), _one(USDC), 0, permSigner)
        );
        uint256 kDeadline = block.timestamp + 1 days;
        bytes memory kernelSig = _signRegisterPermission(
            address(safe), predicted, kernel.signerNonces(address(safe))
        );
        uint256 fee = _calcFee(predicted);

        vm.expectRevert(MockClonePermission.InvalidConfig.selector);
        factory.deployAndAttach{value: fee}(address(safe), address(impl), salt, initData, kDeadline, kernelSig);
    }

    function test_DeployAndAttach_ShortInitDataReverts() public {
        bytes32 salt = _salt(address(impl), "short-init-data");
        address predicted = factory.predictCloneAddress(address(impl), salt);
        uint256 kDeadline = block.timestamp + 1 days;
        bytes memory kernelSig = _signRegisterPermission(
            address(safe), predicted, kernel.signerNonces(address(safe))
        );
        uint256 fee = _calcFee(predicted);

        vm.expectRevert(MandateFactory.InitDataTooShort.selector);
        factory.deployAndAttach{value: fee}(
            address(safe), address(impl), salt, hex"123456", kDeadline, kernelSig
        );
    }

    function test_DeployAndAttach_SuccessfulNonInitializerCallReverts() public {
        bytes32 salt = _salt(address(impl), "non-initializer-call");
        address predicted = factory.predictCloneAddress(address(impl), salt);

        // A successful non-initializer call (discriminator) leaves initialized() == false,
        // so the factory's liveness guard reverts with CloneInitFailed.
        bytes memory initData = abi.encodeCall(MockClonePermission.discriminator, ());
        uint256 kDeadline = block.timestamp + 1 days;
        bytes memory kernelSig = _signRegisterPermission(
            address(safe), predicted, kernel.signerNonces(address(safe))
        );
        uint256 fee = _calcFee(predicted);

        vm.expectRevert(MandateFactory.CloneInitFailed.selector);
        factory.deployAndAttach{value: fee}(
            address(safe), address(impl), salt, initData, kDeadline, kernelSig
        );
    }

    function test_DeployAndAttach_SameImplSaltCannotBeReused() public {
        bytes32 salt = _salt(address(impl), "shared-salt");
        address predicted = factory.predictCloneAddress(address(impl), salt);

        MockSafe otherSafe = new MockSafe();
        vm.prank(address(otherSafe));
        kernel.registerAccount(permSigner, manager, address(0), address(0), block.timestamp + 1 days, "");

        bytes memory firstInitData = _initData(address(otherSafe), permSigner);
        uint256 kDeadline = block.timestamp + 1 days;
        bytes memory firstKernelSig = _signRegisterPermission(
            address(otherSafe), predicted, kernel.signerNonces(address(otherSafe))
        );

        factory.deployAndAttach{value: _calcFee(predicted)}(
            address(otherSafe), address(impl), salt, firstInitData, kDeadline, firstKernelSig
        );
        assertTrue(kernel.isPermissionRegistered(address(otherSafe), predicted));

        bytes memory secondInitData = _initData(address(safe), permSigner);
        bytes memory secondKernelSig = _signRegisterPermission(
            address(safe), predicted, kernel.signerNonces(address(safe))
        );
        uint256 secondFee = _calcFee(predicted);

        vm.expectRevert();
        factory.deployAndAttach{value: secondFee}(
            address(safe), address(impl), salt, secondInitData, kDeadline, secondKernelSig
        );
    }

    function _initData(address recipient, address signer) internal pure returns (bytes memory) {
        return abi.encodeCall(MockClonePermission.initialize, (recipient, _one(USDC), 5 ether, signer));
    }

    function _one(address value) internal pure returns (address[] memory arr) {
        arr = new address[](1);
        arr[0] = value;
    }

    function _salt(address _impl, string memory label) internal view returns (bytes32) {
        return keccak256(abi.encode(address(safe), _impl, label));
    }
}
