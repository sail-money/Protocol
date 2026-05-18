// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "../../contracts/core/SailKernel.sol";
import "../../contracts/governance/SailGovernance.sol";
import "../../contracts/factory/PermissionFactory.sol";
import "../../contracts/templates/shared/BaseSharedPermission.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

/// @notice Records every execTransactionFromModule call and forwards plain-ETH transfers
///         so fee splits land in real balances.
contract MockSafe {
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
    PermissionFactory internal factory;
    MockSafe          internal safe;

    address internal permSigner;
    address internal manager;

    function setUp() public virtual {
        permSigner = vm.addr(PERM_SIGNER_KEY);
        manager    = vm.addr(MANAGER_KEY);

        vm.deal(address(this), 100 ether);

        // Deploy governance with this test contract as governance + emergencyAdmin,
        // seeding the initial permission-registration fee directly via the constructor.
        gov = new SailGovernance(address(this), MAX_PERM_FEE, address(this), BASE_FEE);
        vm.prank(address(gov.timelock()));
        gov.setProtocolCutBps(PROTOCOL_CUT_BPS);

        kernel  = new SailKernel(address(gov), TREASURY);
        factory = new PermissionFactory(address(kernel));

        safe = new MockSafe();
        vm.deal(address(safe), 100 ether);

        // registerAccount is called by the Safe itself (msg.sender == account)
        vm.prank(address(safe));
        kernel.registerAccount(permSigner, manager, address(0));
    }

    receive() external payable {}

    // ── helpers shared by all tests ──────────────────────────────────────────

    function _calcFee(address) internal view returns (uint256) {
        return gov.permissionRegistrationFee();
    }

    function _signConfigure(
        BaseSharedPermission template,
        address account,
        bytes memory params,
        uint256 deadline,
        uint256 signerKey
    ) internal view returns (bytes memory) {
        uint256 nonce = template.configNonces(account);
        bytes32 structHash = keccak256(abi.encode(
            template.CONFIGURE_TYPEHASH(),
            account,
            keccak256(params),
            nonce,
            deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, template.hashTypedDataV4(structHash));
        return abi.encodePacked(r, s, v);
    }

    function _signRegisterPermission(address account, address permission, uint256 nonce)
        internal
        view
        returns (bytes memory)
    {
        bytes32 sh = keccak256(abi.encode(
            kernel.REGISTER_PERMISSION_TYPEHASH(), account, permission, nonce
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
        bytes32 sh = keccak256(abi.encode(
            kernel.REPLACE_PERMISSION_TYPEHASH(), account, oldP, newP, nonce
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PERM_SIGNER_KEY, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }

    function _signRevokePermission(address account, address permission, uint256 nonce)
        internal
        view
        returns (bytes memory)
    {
        bytes32 sh = keccak256(abi.encode(
            kernel.REVOKE_PERMISSION_TYPEHASH(), account, permission, nonce
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PERM_SIGNER_KEY, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }

    function _signDispatch(
        address account,
        address target,
        uint256 value,
        bytes memory data,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes32 sh = keccak256(abi.encode(
            kernel.DISPATCH_TYPEHASH(), account, target, value, keccak256(data), nonce, deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(MANAGER_KEY, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }
}
