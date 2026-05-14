// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

interface IFeePolicy {
    function computeFee(address account, uint256 currentNav)
        external
        view
        returns (uint256 grossFee, address distributor, uint256 distributorBps);

    function recordCollection(address account, uint256 grossFee, uint256 currentNav) external;
}
