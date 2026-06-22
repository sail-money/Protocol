// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IPermission, Context} from "../../contracts/interfaces/IPermission.sol";
import {CloneInitializable}   from "../../contracts/templates/base/CloneInitializable.sol";

/// @notice TEST-ONLY clone permission.
///
///         Exercises the `MandateFactory.deployAndAttach` / `CloneInitializable`
///         (EIP-1167 clone + `initialize()`) path. The production reference templates
///         under `contracts/templates/shared/` use the multi-account `configure()`
///         pattern and are NOT clones, so a clone template is needed purely to keep the
///         factory's clone path covered. This contract is never deployed in production.
///
///         Config hook for tests:
///           • `_maxAmountPerTx == 0` reverts with `InvalidConfig` — used to assert that
///             `deployAndAttach` bubbles an `initialize()` revert.
contract MockClonePermission is IPermission, CloneInitializable {
    bool public constant IS_SINGLE_ACCOUNT = true;

    address public allowedRecipient;
    uint256 public maxAmountPerTx;
    address public permissionSigner;
    mapping(address token => bool) public isAllowedToken;

    error InvalidConfig();

    constructor() {
        _disableInitializers();
    }

    /// @notice One-shot initializer called by the factory on the freshly deployed clone.
    function initialize(
        address _allowedRecipient,
        address[] memory tokens,
        uint256 _maxAmountPerTx,
        address _permissionSigner
    ) external initializer {
        if (_permissionSigner == address(0)) revert InvalidConfig();
        if (_maxAmountPerTx == 0) revert InvalidConfig(); // revert-bubbling test hook
        allowedRecipient = _allowedRecipient;
        maxAmountPerTx = _maxAmountPerTx;
        permissionSigner = _permissionSigner;
        for (uint256 i; i < tokens.length; i++) isAllowedToken[tokens[i]] = true;
    }

    /// @inheritdoc IPermission
    function evaluate(bytes calldata, Context calldata) external pure returns (bool) {
        return true;
    }

    /// @inheritdoc IPermission
    function discriminator() external pure returns (bytes32) {
        return keccak256("MockClonePermission");
    }
}
