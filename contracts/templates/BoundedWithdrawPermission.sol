// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IPermission, Context} from "../interfaces/IPermission.sol";

/// @notice Gates ERC-20 withdrawals so the recipient is always the designated Safe,
///         the token is on the allowlist, and the amount is within the per-tx cap.
contract BoundedWithdrawPermission is IPermission {
    // transfer(address,uint256)
    bytes4 private constant TRANSFER_SELECTOR = 0xa9059cbb;
    // transferFrom(address,address,uint256)
    bytes4 private constant TRANSFERFROM_SELECTOR = 0x23b872dd;

    /// @notice The only address that may receive tokens (the owner's Safe).
    address public immutable allowedRecipient;

    /// @notice Tokens the manager is permitted to move.
    mapping(address token => bool) public isAllowedToken;

    /// @notice Per-transaction amount cap (inclusive).
    uint256 public maxAmountPerTx;

    /// @notice Address authorised to update mutable settings.
    address public permissionSigner;

    event MaxAmountUpdated(uint256 oldMax, uint256 newMax);

    error NotPermissionSigner();
    error ZeroAddress();

    modifier onlyPermissionSigner() {
        if (msg.sender != permissionSigner) revert NotPermissionSigner();
        _;
    }

    constructor(
        address safe,
        address[] memory allowedTokens,
        uint256 _maxAmountPerTx,
        address _permissionSigner
    ) {
        if (safe == address(0) || _permissionSigner == address(0)) revert ZeroAddress();
        allowedRecipient = safe;
        maxAmountPerTx   = _maxAmountPerTx;
        permissionSigner = _permissionSigner;
        for (uint256 i = 0; i < allowedTokens.length; i++) {
            isAllowedToken[allowedTokens[i]] = true;
        }
    }

    /// @notice Update the per-transaction cap. Only permissionSigner may call.
    function setMaxAmountPerTx(uint256 newMax) external onlyPermissionSigner {
        uint256 old = maxAmountPerTx;
        maxAmountPerTx = newMax;
        emit MaxAmountUpdated(old, newMax);
    }

    /// @inheritdoc IPermission
    /// @dev Decodes transfer() and transferFrom() calldata and enforces three invariants:
    ///      recipient == allowedRecipient, token in allowlist, amount <= cap.
    ///      Any other selector, malformed calldata, or non-zero ETH value returns false.
    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool) {
        // ERC-20 calls carry no ETH
        if (ctx.value != 0) return false;

        // Token must be on the allowlist
        if (!isAllowedToken[ctx.target]) return false;

        if (ctx.selector == TRANSFER_SELECTOR) {
            // Encoded: selector(4) + to(32) + amount(32) = 68 bytes minimum
            if (txData.length < 68) return false;
            (address to, uint256 amount) = abi.decode(txData[4:], (address, uint256));
            return to == allowedRecipient && amount <= maxAmountPerTx;
        }

        if (ctx.selector == TRANSFERFROM_SELECTOR) {
            // Encoded: selector(4) + from(32) + to(32) + amount(32) = 100 bytes minimum
            if (txData.length < 100) return false;
            (, address to, uint256 amount) = abi.decode(txData[4:], (address, address, uint256));
            // WARNING: the `from` field is not validated. A manager can pull tokens from any
            // address that has previously approved the Safe (e.g., an integrated DeFi protocol).
            // Use the `transfer` path if only pulling from the Safe's own balance is intended.
            return to == allowedRecipient && amount <= maxAmountPerTx;
        }

        return false;
    }

    /// @inheritdoc IPermission
    function discriminator() external pure returns (bytes32) {
        return keccak256("BoundedWithdrawPermission");
    }
}
