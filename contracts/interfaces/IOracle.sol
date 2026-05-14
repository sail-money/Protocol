// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @notice Minimal price oracle interface consumed by BoundedSwapPermission.
/// @dev    price is expressed as: 1 unit of base = price / 10^decimals units of quote.
///         Both amounts use the token's own native units (no normalisation required here).
interface IOracle {
    function getPrice(address base, address quote)
        external
        view
        returns (uint256 price, uint8 decimals);
}
