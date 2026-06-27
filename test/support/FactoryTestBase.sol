// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "../../contracts/core/SailKernel.sol";
import "../../contracts/governance/SailGovernance.sol";
import "../../contracts/factory/MandateFactory.sol";
import "../../contracts/templates/ConfigurablePermission.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {TimelockDeployer} from "./TimelockDeployer.sol";

/// @notice Records every execTransactionFromModule call and forwards plain-ETH transfers
///         so fee splits land in real balances.
contract MockSafe {
    // Test support: a finalized Safe reports nonce>=1 (setup never bumps it)
    // and exposes its trusted singleton via masterCopy() (intercepted by a real SafeProxy fallback).
    function nonce() external pure returns (uint256) { return 1; }
    function checkSignatures(bytes32, bytes calldata, bytes calldata) external view {}
    function masterCopy() external pure returns (address) { return address(0x5AFE); }

    struct Call {
        address to;
        uint256 value;
        bytes   data;
        uint8   operation;
    }

    Call[] private _calls;

    receive() external payable {}

    function execTransactionFromModule(address to, uint256 value, bytes calldata data, uint8 op)
        external
        returns (bool)
    {
        _calls.push(Call({to: to, value: value, data: data, operation: op}));
        if (value > 0 && data.length == 0) {
            (bool ok,) = payable(to).call{value: value}("");
            return ok;
        }
        return true;
    }

    function callCount() external view returns (uint256) { return _calls.length; }

    function getCall(uint256 i)
        external
        view
        returns (address to, uint256 value, bytes memory data, uint8 op)
    {
        Call storage c = _calls[i];
        return (c.to, c.value, c.data, c.operation);
    }

    function isModuleEnabled(address) external pure returns (bool) { return true; }
}

/// @dev Test fixture deploying the full stack: governance, kernel, factory, mock Safe.
///      Subclasses deploy templates and write per-use-case scenarios on top.
abstract contract FactoryTestBase is Test {
    uint256 internal constant PERM_SIGNER_KEY = 0xA11CE;
    uint256 internal constant MANAGER_KEY     = 0xB0B;

    address internal constant TREASURY = address(0xAAAA);

    uint256 internal constant BASE_FEE         = 0.001 ether;
    uint256 internal constant MAX_PERM_FEE     = 0.001 ether;
    uint256 internal constant PROTOCOL_CUT_BPS = 1_000;

    SailGovernance    internal gov;
    SailKernel        internal kernel;
    MandateFactory internal factory;
    MockSafe          internal safe;

    address internal permSigner;
    address internal manager;

    function setUp() public virtual {
        permSigner = vm.addr(PERM_SIGNER_KEY);
        manager    = vm.addr(MANAGER_KEY);

        vm.deal(address(this), 100 ether);

        // Deploy governance with this test contract as governance + emergencyAdmin,
        // seeding the initial permission-registration fee directly via the constructor.
        gov = new SailGovernance(address(this), MAX_PERM_FEE, address(this), BASE_FEE, TimelockDeployer.deploy(address(this)));
        vm.prank(address(gov.timelock()));
        gov.setProtocolCutBps(PROTOCOL_CUT_BPS);

        kernel  = new SailKernel(address(gov), TREASURY, address(0));
        factory = new MandateFactory(address(kernel));

        safe = new MockSafe();
        vm.deal(address(safe), 100 ether);

        // registerAccount now requires the caller's codehash to be allowlisted as a trusted
        // Safe proxy. Seed the mock's codehash via the governance timelock.
        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeProxyCodehash(address(safe).codehash, true);
        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeSingleton(address(0x5AFE), true); // trust the mock singleton

        // registerAccount is called by the Safe itself (msg.sender == account)
        vm.prank(address(safe));
        kernel.registerAccount(permSigner, manager, address(0), address(0), block.timestamp + 1 days, "");
    }

    receive() external payable {}

    // ── helpers shared by all tests ──────────────────────────────────────────

    function _calcFee(address) internal view returns (uint256) {
        return gov.permissionRegistrationFee();
    }

    function _signConfigure(
        ConfigurablePermission template,
        address account,
        bytes memory params,
        uint256 deadline,
        uint256 signerKey
    ) internal view returns (bytes memory) {
        uint256 nonce = template.configNonces(account);
        uint256 epoch = kernel.registrationEpoch(account, address(template));
        bytes32 structHash = keccak256(abi.encode(
            template.CONFIGURE_TYPEHASH(),
            account,
            keccak256(params),
            nonce,
            deadline,
            epoch
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, template.hashTypedDataV4(structHash));
        return abi.encodePacked(r, s, v);
    }

    function _signRegisterPermission(address account, address permission, uint256 nonce)
        internal
        view
        returns (bytes memory)
    {
        uint256 deadline = block.timestamp + 1 days;
        bytes32 sh = keccak256(abi.encode(
            kernel.REGISTER_PERMISSION_TYPEHASH(), account, permission, nonce, deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PERM_SIGNER_KEY, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }

    function _signRegisterPermissions(
        address account,
        address[] memory permissions,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes32[] memory buf = new bytes32[](permissions.length);
        for (uint256 i; i < permissions.length; i++) {
            buf[i] = bytes32(uint256(uint160(permissions[i])));
        }
        bytes32 sh = keccak256(abi.encode(
            kernel.REGISTER_PERMISSIONS_TYPEHASH(),
            account,
            keccak256(abi.encodePacked(buf)),
            nonce,
            deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PERM_SIGNER_KEY, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }

    function _signReplacePermission(
        address account,
        address oldP,
        address newP,
        uint256 nonce
    ) internal view returns (bytes memory) {
        uint256 deadline = block.timestamp + 1 days;
        bytes32 sh = keccak256(abi.encode(
            kernel.REPLACE_PERMISSION_TYPEHASH(), account, oldP, newP, nonce, deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PERM_SIGNER_KEY, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }

    function _signRevokePermission(address account, address permission, uint256 nonce)
        internal
        view
        returns (bytes memory)
    {
        uint256 deadline = block.timestamp + 1 days;
        bytes32 sh = keccak256(abi.encode(
            kernel.REVOKE_PERMISSION_TYPEHASH(), account, permission, nonce, deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PERM_SIGNER_KEY, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }

    function _signDispatch(
        address account,
        address permission,
        address target,
        uint256 value,
        bytes memory data,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes32 sh = keccak256(abi.encode(
            kernel.DISPATCH_TYPEHASH(), account, permission, target, value, keccak256(data), nonce, deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(MANAGER_KEY, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }
}
