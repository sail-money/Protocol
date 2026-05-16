// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {Context} from "../../interfaces/IPermission.sol";
import {BaseSharedPermission} from "./BaseSharedPermission.sol";

/// @notice Multi-account variant of TransferTargetPermission. One deployment serves any
///         number of accounts; each account stores its own recipient and token allowlists.
///
///         Config blob:
///             abi.encode(
///                 address[] allowedRecipients,
///                 address[] allowedTokens,
///                 uint256   maxAmountPerTx
///             )
contract SharedTransferTargetPermission is BaseSharedPermission {
    bytes4 private constant TRANSFER_SELECTOR     = 0xa9059cbb;
    bytes4 private constant TRANSFERFROM_SELECTOR = 0x23b872dd;

    uint256 private constant LEN_TRANSFER     = 68;
    uint256 private constant LEN_TRANSFERFROM = 100;

    uint256 private constant MAX_ALLOWLIST_LENGTH = 50;

    error AllowlistTooLong();

    struct Slot {
        address[] recipients;
        address[] tokens;
        uint256   maxAmountPerTx;
    }

    mapping(address account => Slot) private _slots;
    mapping(address account => mapping(address => bool)) public isAllowedRecipient;
    mapping(address account => mapping(address => bool)) public isAllowedToken;

    constructor(address _kernel)
        BaseSharedPermission(_kernel, "SharedTransferTargetPermission", "1")
    {}

    function getConfig(address account)
        external
        view
        returns (address[] memory recipients, address[] memory tokens, uint256 maxAmountPerTx)
    {
        Slot storage s = _slots[account];
        return (s.recipients, s.tokens, s.maxAmountPerTx);
    }

    function _applyConfig(address account, bytes calldata params) internal override {
        (address[] memory recipients, address[] memory tokens, uint256 maxAmountPerTx) =
            abi.decode(params, (address[], address[], uint256));

        if (recipients.length > MAX_ALLOWLIST_LENGTH) revert AllowlistTooLong();
        if (tokens.length     > MAX_ALLOWLIST_LENGTH) revert AllowlistTooLong();

        Slot storage s = _slots[account];
        for (uint256 i; i < s.recipients.length; i++) isAllowedRecipient[account][s.recipients[i]] = false;
        for (uint256 i; i < s.tokens.length; i++)     isAllowedToken[account][s.tokens[i]]         = false;

        for (uint256 i; i < recipients.length; i++) isAllowedRecipient[account][recipients[i]] = true;
        for (uint256 i; i < tokens.length; i++)     isAllowedToken[account][tokens[i]]         = true;

        s.recipients     = recipients;
        s.tokens         = tokens;
        s.maxAmountPerTx = maxAmountPerTx;
    }

    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool) {
        if (ctx.value != 0) return false;
        if (!isAllowedToken[ctx.account][ctx.target]) return false;
        Slot storage s = _slots[ctx.account];

        if (ctx.selector == TRANSFER_SELECTOR) {
            if (txData.length < LEN_TRANSFER) return false;
            (address to, uint256 amount) = abi.decode(txData[4:], (address, uint256));
            if (amount > s.maxAmountPerTx) return false;
            return isAllowedRecipient[ctx.account][to];
        }

        if (ctx.selector == TRANSFERFROM_SELECTOR) {
            if (txData.length < LEN_TRANSFERFROM) return false;
            (, address to, uint256 amount) = abi.decode(txData[4:], (address, address, uint256));
            if (amount > s.maxAmountPerTx) return false;
            return isAllowedRecipient[ctx.account][to];
        }

        return false;
    }

    function discriminator() external pure returns (bytes32) {
        return keccak256("SharedTransferTargetPermission");
    }
}
