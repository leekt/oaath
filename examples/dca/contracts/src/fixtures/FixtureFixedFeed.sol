// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

/// @notice TESTNET FIXTURE ONLY: a constant 8-decimal price that is always fresh, so a
/// hosted example market never goes stale. Never use as a real price source.
contract FixtureFixedFeed {
    uint8 public constant decimals = 8;
    int256 public immutable answer;

    constructor(int256 p) {
        answer = p;
    }

    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80) {
        return (1, answer, block.timestamp, block.timestamp, 1);
    }
}
