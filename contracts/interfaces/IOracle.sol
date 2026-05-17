// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title  IOracle
/// @notice Minimal price oracle interface consumed by BoundedSwapPermission.
/// @dev    Price is expressed as: 1 unit of `base` = `price / 10^decimals` units of `quote`.
///         Both amounts use the token's own native units (no normalisation required here).
///
///         STALENESS WARNING: This interface does not expose an `updatedAt` timestamp.
///         Integrators that need staleness protection must either extend this interface or
///         use an oracle adapter that performs the staleness check internally before
///         returning a price. A stale oracle price can allow or deny swaps based on an
///         outdated rate.
interface IOracle {
    /// @notice Fetch the current price of `base` in terms of `quote`.
    /// @param  base      Address of the base token (the token being sold in a swap).
    /// @param  quote     Address of the quote token (the token being bought).
    /// @return price     Raw price mantissa: 1 base unit = `price / 10^decimals` quote units.
    /// @return decimals  Decimal precision of `price`. Values above 77 are not supported by
    ///                   BoundedSwapPermission and will cause the oracle check to be skipped.
    /// @return updatedAt Unix timestamp of the last oracle update. Consumers SHOULD validate
    ///                   freshness. A stale price can allow or deny operations based on an
    ///                   outdated rate.
    function getPrice(address base, address quote)
        external
        view
        returns (uint256 price, uint8 decimals, uint256 updatedAt);
}
