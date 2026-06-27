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
        bytes memory initData = _initData(address(safe), permSigner);
        address predicted = factory.predictCloneAddress(address(impl), address(safe), salt, initData);

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

        // maxAmountPerTx == 0 makes the clone's initialize() revert with InvalidConfig.
        bytes memory initData = abi.encodeCall(
            MockClonePermission.initialize,
            (address(safe), _one(USDC), 0, permSigner)
        );
        address predicted = factory.predictCloneAddress(address(impl), address(safe), salt, initData);

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
        address predicted = factory.predictCloneAddress(address(impl), address(safe), salt, hex"123456");
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

        // A successful non-initializer call (discriminator) leaves initialized() == false,
        // so the factory's liveness guard reverts with CloneInitFailed.
        bytes memory initData = abi.encodeCall(MockClonePermission.discriminator, ());
        address predicted = factory.predictCloneAddress(address(impl), address(safe), salt, initData);

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

    /// @notice Same (caller, account, salt) tuple maps to one CREATE2 address; a second
    ///         deploy for the same account collides and reverts. This is the true
    ///         single-address-per-namespace guarantee after caller+account binding.
    function test_DeployAndAttach_SameCallerAccountSaltCannotBeReused() public {
        bytes32 salt = _salt(address(impl), "reuse-same-account");
        bytes memory initData = _initData(address(safe), permSigner);
        address predicted = factory.predictCloneAddress(address(impl), address(safe), salt, initData);

        uint256 kDeadline = block.timestamp + 1 days;
        bytes memory firstKernelSig = _signRegisterPermission(
            address(safe), predicted, kernel.signerNonces(address(safe))
        );

        factory.deployAndAttach{value: _calcFee(predicted)}(
            address(safe), address(impl), salt, initData, kDeadline, firstKernelSig
        );
        assertTrue(kernel.isPermissionRegistered(address(safe), predicted));

        bytes memory secondKernelSig = _signRegisterPermission(
            address(safe), predicted, kernel.signerNonces(address(safe))
        );
        uint256 secondFee = _calcFee(predicted);

        // Same caller + same account + same salt => same address => CREATE2 collision.
        vm.expectRevert();
        factory.deployAndAttach{value: secondFee}(
            address(safe), address(impl), salt, initData, kDeadline, secondKernelSig
        );
    }

    /// @notice Account-bound salt. Two DIFFERENT accounts using the same
    ///         caller + impl + raw salt resolve to DIFFERENT, non-colliding clone
    ///         addresses — a shared relayer caller cannot make distinct accounts collide.
    function test_DeployAndAttach_DifferentAccountsGetDifferentCloneAddresses() public {
        bytes32 salt = _salt(address(impl), "shared-relayer-salt");

        MockSafe otherSafe = new MockSafe();
        vm.prank(address(otherSafe));
        kernel.registerAccount(permSigner, manager, address(0), address(0), block.timestamp + 1 days, "");

        // Same caller (this test contract) + same impl + same raw salt, two accounts.
        bytes memory safeInit  = _initData(address(safe), permSigner);
        bytes memory otherInit = _initData(address(otherSafe), permSigner);
        address predictedSafe  = factory.predictCloneAddress(address(impl), address(safe), salt, safeInit);
        address predictedOther = factory.predictCloneAddress(address(impl), address(otherSafe), salt, otherInit);
        assertTrue(predictedSafe != predictedOther, "account binding must separate address spaces");

        uint256 kDeadline = block.timestamp + 1 days;

        bytes memory otherSig = _signRegisterPermission(
            address(otherSafe), predictedOther, kernel.signerNonces(address(otherSafe))
        );
        factory.deployAndAttach{value: _calcFee(predictedOther)}(
            address(otherSafe), address(impl), salt, otherInit, kDeadline, otherSig
        );
        assertTrue(kernel.isPermissionRegistered(address(otherSafe), predictedOther));

        // The first deploy occupied only otherSafe's address; safe's deploy still lands
        // at its own caller+account-bound address, unaffected by the other account.
        bytes memory safeSig = _signRegisterPermission(
            address(safe), predictedSafe, kernel.signerNonces(address(safe))
        );
        address clone = factory.deployAndAttach{value: _calcFee(predictedSafe)}(
            address(safe), address(impl), salt, safeInit, kDeadline, safeSig
        );
        assertEq(clone, predictedSafe, "safe's clone lands at its own account-bound address");
        assertTrue(kernel.isPermissionRegistered(address(safe), predictedSafe));
    }

    /// @notice A third-party caller cannot squat a victim's predicted address: a different
    ///         msg.sender yields a different namespace, so the victim's own deploy still
    ///         lands at its caller+account-bound address.
    function test_DeployAndAttach_ThirdPartyCallerCannotSquatPredictedAddress() public {
        bytes32 salt = _salt(address(impl), "squat-attempt");
        bytes memory initData = _initData(address(safe), permSigner);

        // Victim predicts from its own caller (this test contract) + account.
        address victimPredicted = factory.predictCloneAddress(address(impl), address(safe), salt, initData);

        // Attacker (a distinct EOA) deploys with the SAME impl + raw salt + victim account,
        // but a different msg.sender => a different namespace => a different address.
        address attacker = address(0xBADBAD);
        vm.deal(attacker, 10 ether);
        vm.prank(attacker);
        address attackerPredicted = factory.predictCloneAddress(address(impl), address(safe), salt, initData);
        assertTrue(attackerPredicted != victimPredicted, "different caller => different address");

        uint256 kDeadline = block.timestamp + 1 days;

        // Attacker deploys at their own (caller-bound) address for the victim account.
        // Compute the fee before vm.prank: _calcFee makes an external staticcall that would
        // otherwise consume the prank and let the deploy run as the wrong msg.sender.
        bytes memory attackerSig = _signRegisterPermission(
            address(safe), attackerPredicted, kernel.signerNonces(address(safe))
        );
        uint256 attackerFee = _calcFee(attackerPredicted);
        vm.prank(attacker);
        factory.deployAndAttach{value: attackerFee}(
            address(safe), address(impl), salt, initData, kDeadline, attackerSig
        );

        // Victim's own deploy is unaffected: it lands at the victim's predicted address.
        bytes memory victimSig = _signRegisterPermission(
            address(safe), victimPredicted, kernel.signerNonces(address(safe))
        );
        address clone = factory.deployAndAttach{value: _calcFee(victimPredicted)}(
            address(safe), address(impl), salt, initData, kDeadline, victimSig
        );
        assertEq(clone, victimPredicted, "victim's clone unaffected by third-party pre-deploy");
        assertTrue(kernel.isPermissionRegistered(address(safe), victimPredicted));
    }

    /// @notice The predicted clone address binds the initialization payload: the same caller,
    ///         account, and salt but different initData resolve to different addresses. This is
    ///         what prevents reusing a registration signature (which authorizes one specific
    ///         address) with a substituted init payload.
    function test_DeployAndAttach_DifferentInitDataDifferentCloneAddress() public {
        bytes32 salt = _salt(address(impl), "init-data-binding");

        // initData_V: the benign payload the victim intends and signs over.
        bytes memory initDataV = _initData(address(safe), permSigner);
        // initData_M: a substituted payload (different bounds) an attacker might prefer.
        bytes memory initDataM = abi.encodeCall(
            MockClonePermission.initialize,
            (address(safe), _one(USDC), 1_000_000 ether, permSigner)
        );
        assertTrue(keccak256(initDataV) != keccak256(initDataM), "payloads must differ");

        address predictedV = factory.predictCloneAddress(address(impl), address(safe), salt, initDataV);
        address predictedM = factory.predictCloneAddress(address(impl), address(safe), salt, initDataM);
        assertTrue(predictedV != predictedM, "different initData must map to different addresses");

        uint256 kDeadline = block.timestamp + 1 days;

        // The victim's signature authorizes predictedV (the address bound to initDataV).
        bytes memory victimSig = _signRegisterPermission(
            address(safe), predictedV, kernel.signerNonces(address(safe))
        );

        // Deploying with the substituted payload lands at predictedM, not predictedV, so the
        // victim's signature (bound to predictedV) does not authorize it. The kernel verifies
        // the signature against the freshly deployed clone (predictedM) and rejects it.
        uint256 feeM = _calcFee(predictedM);
        vm.expectRevert();
        factory.deployAndAttach{value: feeM}(
            address(safe), address(impl), salt, initDataM, kDeadline, victimSig
        );

        // The legitimate flow still matches: the victim's signed-over payload deploys at the
        // predicted address and registers successfully.
        address clone = factory.deployAndAttach{value: _calcFee(predictedV)}(
            address(safe), address(impl), salt, initDataV, kDeadline, victimSig
        );
        assertEq(clone, predictedV, "legitimate initData lands at the predicted, signed-for address");
        assertTrue(kernel.isPermissionRegistered(address(safe), predictedV));
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
