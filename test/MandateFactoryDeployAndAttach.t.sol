// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "./support/FactoryTestBase.sol";
import "../contracts/experimental/BoundedSwapPermission.sol";
import "../contracts/experimental/BoundedWithdrawPermission.sol";
import "../contracts/templates/base/CloneInitializable.sol";

contract MandateFactoryDeployAndAttachTest is FactoryTestBase {
    BoundedWithdrawPermission internal withdrawImpl;
    BoundedSwapPermission internal swapImpl;

    address internal constant ROUTER = address(0xCC01);
    address internal constant WETH = address(0xCC02);
    address internal constant USDC = address(0xCC03);

    function setUp() public override {
        super.setUp();
        withdrawImpl = new BoundedWithdrawPermission();
        swapImpl = new BoundedSwapPermission();
    }

    function test_DeployAndAttach_GoldenPath() public {
        bytes32 salt = _salt(address(withdrawImpl), "golden-path");
        address predicted = factory.predictCloneAddress(address(withdrawImpl), salt);

        bytes memory initData = _withdrawInitData(address(safe), permSigner);
        uint256 kDeadline = block.timestamp + 1 days;
        bytes memory kernelSig = _signRegisterPermission(
            address(safe), predicted, kernel.signerNonces(address(safe))
        );

        address clone = factory.deployAndAttach{value: _calcFee(predicted)}(
            address(safe), address(withdrawImpl), salt, initData, kDeadline, kernelSig
        );

        assertEq(clone, predicted, "clone address should match prediction");
        assertTrue(kernel.isPermissionRegistered(address(safe), clone), "clone should be registered");
        assertTrue(CloneInitializable(clone).initialized(), "clone should be initialized");
        assertEq(BoundedWithdrawPermission(clone).allowedRecipient(), address(safe));
        assertEq(BoundedWithdrawPermission(clone).maxAmountPerTx(), 5 ether);
        assertEq(BoundedWithdrawPermission(clone).permissionSigner(), permSigner);
        assertTrue(BoundedWithdrawPermission(clone).isAllowedToken(USDC));
    }

    function test_DeployAndAttach_BubblesInitializeRevert() public {
        bytes32 salt = _salt(address(swapImpl), "bubble-init-revert");
        address predicted = factory.predictCloneAddress(address(swapImpl), salt);

        bytes memory initData = abi.encodeCall(
            BoundedSwapPermission.initialize,
            (_one(ROUTER), _one(WETH), _one(USDC), 5 ether, 10_000, address(0), 0, permSigner)
        );
        uint256 kDeadline = block.timestamp + 1 days;
        bytes memory kernelSig = _signRegisterPermission(
            address(safe), predicted, kernel.signerNonces(address(safe))
        );
        uint256 fee = _calcFee(predicted);

        vm.expectRevert(abi.encodeWithSelector(BoundedSwapPermission.SlippageBpsTooLarge.selector, 10_000));
        factory.deployAndAttach{value: fee}(address(safe), address(swapImpl), salt, initData, kDeadline, kernelSig);
    }

    function test_DeployAndAttach_ShortInitDataReverts() public {
        bytes32 salt = _salt(address(withdrawImpl), "short-init-data");
        address predicted = factory.predictCloneAddress(address(withdrawImpl), salt);
        uint256 kDeadline = block.timestamp + 1 days;
        bytes memory kernelSig = _signRegisterPermission(
            address(safe), predicted, kernel.signerNonces(address(safe))
        );
        uint256 fee = _calcFee(predicted);

        vm.expectRevert(MandateFactory.InitDataTooShort.selector);
        factory.deployAndAttach{value: fee}(
            address(safe), address(withdrawImpl), salt, hex"123456", kDeadline, kernelSig
        );
    }

    function test_DeployAndAttach_SuccessfulNonInitializerCallReverts() public {
        bytes32 salt = _salt(address(withdrawImpl), "non-initializer-call");
        address predicted = factory.predictCloneAddress(address(withdrawImpl), salt);

        bytes memory initData = abi.encodeCall(BoundedWithdrawPermission.discriminator, ());
        uint256 kDeadline = block.timestamp + 1 days;
        bytes memory kernelSig = _signRegisterPermission(
            address(safe), predicted, kernel.signerNonces(address(safe))
        );
        uint256 fee = _calcFee(predicted);

        vm.expectRevert(MandateFactory.CloneInitFailed.selector);
        factory.deployAndAttach{value: fee}(
            address(safe), address(withdrawImpl), salt, initData, kDeadline, kernelSig
        );
    }

    function test_DeployAndAttach_SameImplSaltCannotBeReused() public {
        bytes32 salt = _salt(address(withdrawImpl), "shared-salt");
        address predicted = factory.predictCloneAddress(address(withdrawImpl), salt);

        MockSafe otherSafe = new MockSafe();
        vm.prank(address(otherSafe));
        kernel.registerAccount(permSigner, manager, address(0), address(0));

        bytes memory firstInitData = _withdrawInitData(address(otherSafe), permSigner);
        uint256 kDeadline = block.timestamp + 1 days;
        bytes memory firstKernelSig = _signRegisterPermission(
            address(otherSafe), predicted, kernel.signerNonces(address(otherSafe))
        );

        factory.deployAndAttach{value: _calcFee(predicted)}(
            address(otherSafe), address(withdrawImpl), salt, firstInitData, kDeadline, firstKernelSig
        );
        assertTrue(kernel.isPermissionRegistered(address(otherSafe), predicted));

        bytes memory secondInitData = _withdrawInitData(address(safe), permSigner);
        bytes memory secondKernelSig = _signRegisterPermission(
            address(safe), predicted, kernel.signerNonces(address(safe))
        );
        uint256 secondFee = _calcFee(predicted);

        vm.expectRevert();
        factory.deployAndAttach{value: secondFee}(
            address(safe), address(withdrawImpl), salt, secondInitData, kDeadline, secondKernelSig
        );
    }

    function _withdrawInitData(address recipient, address signer) internal pure returns (bytes memory) {
        return abi.encodeCall(BoundedWithdrawPermission.initialize, (recipient, _one(USDC), 5 ether, signer));
    }

    function _one(address value) internal pure returns (address[] memory arr) {
        arr = new address[](1);
        arr[0] = value;
    }

    function _salt(address impl, string memory label) internal view returns (bytes32) {
        return keccak256(abi.encode(address(safe), impl, label));
    }
}
