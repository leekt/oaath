// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

/// @notice LOCAL TEST FIXTURE ONLY: a settable 8-decimal price feed for Anvil and forge tests.
contract FixtureFeed {
    uint8 public constant decimals = 8;
    int256 public answer;
    uint256 public updatedAt;

    constructor(int256 p) {
        answer = p;
        updatedAt = block.timestamp;
    }

    function set(int256 p, uint256 at) external {
        answer = p;
        updatedAt = at;
    }

    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80) {
        return (1, answer, updatedAt, updatedAt, 1);
    }
}
