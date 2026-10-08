// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import {DcaExecutor} from "../src/DcaExecutor.sol";
import {FixtureFixedFeed} from "../src/fixtures/FixtureFixedFeed.sol";
import {FixtureToken} from "../src/fixtures/FixtureToken.sol";

interface FixedFeedVm {
    function warp(uint256) external;
}

contract FixedRateRouter {
    struct Params {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }

    function exactInputSingle(Params calldata p) external returns (uint256 amountOut) {
        FixtureToken(p.tokenIn).transferFrom(msg.sender, address(this), p.amountIn);
        amountOut = p.amountIn * 1e12 / 2000;
        require(amountOut >= p.amountOutMinimum);
        FixtureToken(p.tokenOut).mint(p.recipient, amountOut);
    }
}

/// The hosted Arbitrum Sepolia market prices with fixed feeds that never go stale.
contract FixtureFixedFeedTest {
    FixedFeedVm constant vm = FixedFeedVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 constant PLAN = bytes32(uint256(7));
    uint64 constant START = 1_800_000_000;

    function testLaterSlotPricesWithoutAnyFeedUpdate() public {
        vm.warp(START);
        FixtureToken sell = new FixtureToken(6);
        FixtureToken buy = new FixtureToken(18);
        DcaExecutor dca = new DcaExecutor(
            address(sell),
            address(buy),
            address(new FixedRateRouter()),
            3000,
            address(new FixtureFixedFeed(1e8)),
            address(new FixtureFixedFeed(2000e8)),
            3600
        );
        sell.mint(address(this), 10e6);
        sell.approve(address(dca), 10e6);
        dca.open(PLAN, 10e6, 5, START, 86400, 900, 300);
        dca.execute(PLAN, 0);
        // Four days on, far past maxPriceAgeSeconds, with no feed transaction.
        vm.warp(START + 4 * 86400);
        dca.execute(PLAN, 4);
        require(buy.balanceOf(address(this)) == 2 * 2e6 * 1e12 / 2000);
    }
}
