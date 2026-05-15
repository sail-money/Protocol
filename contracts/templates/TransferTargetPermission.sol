// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IPermission, Context} from "../interfaces/IPermission.sol";

/// @notice Gates raw ERC-20 transfers by enforcing that the recipient is in an
///         allowlist and the token is in an allowlist. This is the simplest
///         canonical template — no amount cap, no oracle.
///
///         Supported selectors:
///           0xa9059cbb  transfer(address,uint256)
///           0x23b872dd  transferFrom(address,address,uint256)
contract TransferTargetPermission is IPermission {
    // transfer(address to, uint256 amount)
    bytes4 private constant TRANSFER_SELECTOR     = 0xa9059cbb;
    // transferFrom(address from, address to, uint256 amount)
    bytes4 private constant TRANSFERFROM_SELECTOR = 0x23b872dd;

    // selector(4) + to(32) + amount(32)
    uint256 private constant LEN_TRANSFER     = 68;
    // selector(4) + from(32) + to(32) + amount(32)
    uint256 private constant LEN_TRANSFERFROM = 100;

    // ── allowlists ────────────────────────────────────────────────────────────
    mapping(address recipient => bool) public isAllowedRecipient;
    mapping(address token     => bool) public isAllowedToken;

    address public permissionSigner;

    // ── events ────────────────────────────────────────────────────────────────
    event RecipientAdded(address indexed recipient);
    event RecipientRemoved(address indexed recipient);

    // ── errors ────────────────────────────────────────────────────────────────
    error NotPermissionSigner();
    error ZeroAddress();
    error RecipientNotInAllowlist(address recipient);

    modifier onlyPermissionSigner() {
        if (msg.sender != permissionSigner) revert NotPermissionSigner();
        _;
    }

    constructor(
        address[] memory allowedRecipients,
        address[] memory allowedTokens,
        address _permissionSigner
    ) {
        if (_permissionSigner == address(0)) revert ZeroAddress();
        permissionSigner = _permissionSigner;
        for (uint256 i; i < allowedRecipients.length; i++) {
            isAllowedRecipient[allowedRecipients[i]] = true;
            emit RecipientAdded(allowedRecipients[i]);
        }
        for (uint256 i; i < allowedTokens.length; i++) {
            isAllowedToken[allowedTokens[i]] = true;
        }
    }

    // ── setters ───────────────────────────────────────────────────────────────

    function addRecipient(address recipient) external onlyPermissionSigner {
        isAllowedRecipient[recipient] = true;
        emit RecipientAdded(recipient);
    }

    function removeRecipient(address recipient) external onlyPermissionSigner {
        if (!isAllowedRecipient[recipient]) revert RecipientNotInAllowlist(recipient);
        isAllowedRecipient[recipient] = false;
        emit RecipientRemoved(recipient);
    }

    // ── IPermission ───────────────────────────────────────────────────────────

    /// @inheritdoc IPermission
    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool) {
        // ERC-20 transfers carry no ETH
        if (ctx.value != 0) return false;

        // Token must be on the allowlist
        if (!isAllowedToken[ctx.target]) return false;

        if (ctx.selector == TRANSFER_SELECTOR) {
            if (txData.length < LEN_TRANSFER) return false;
            (address to,) = abi.decode(txData[4:], (address, uint256));
            return isAllowedRecipient[to];
        }

        if (ctx.selector == TRANSFERFROM_SELECTOR) {
            if (txData.length < LEN_TRANSFERFROM) return false;
            (, address to,) = abi.decode(txData[4:], (address, address, uint256));
            return isAllowedRecipient[to];
        }

        return false;
    }

    /// @inheritdoc IPermission
    function discriminator() external pure returns (bytes32) {
        return keccak256("TransferTargetPermission");
    }
}
