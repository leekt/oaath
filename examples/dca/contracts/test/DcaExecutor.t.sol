// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import {DcaExecutor} from "../src/DcaExecutor.sol";
import {FixtureFeed} from "../src/fixtures/FixtureFeed.sol";
import {FixtureToken} from "../src/fixtures/FixtureToken.sol";

interface Vm {
    function warp(uint256) external;
    function prank(address) external;
    function expectRevert() external;
}

contract Router {
    struct Params {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }

    bool public fail;

    function setFail(bool v) external {
        fail = v;
    }

    function exactInputSingle(Params calldata p) external returns (uint256 amountOut) {
        require(!fail);
        FixtureToken(p.tokenIn).transferFrom(msg.sender, address(this), p.amountIn);
        amountOut = p.amountIn * 1e12 / 2000;
        require(amountOut >= p.amountOutMinimum);
        FixtureToken(p.tokenOut).mint(p.recipient, amountOut);
    }
}

contract DcaExecutorTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 constant PLAN = bytes32(uint256(1));
    uint64 constant START = 1_800_000_000;
    FixtureToken sell;
    FixtureToken buy;
    FixtureFeed sf;
    FixtureFeed bf;
    Router router;
    DcaExecutor dca;

    function setUp() public {
        vm.warp(START);
        sell = new FixtureToken(6);
        buy = new FixtureToken(18);
        sf = new FixtureFeed(1e8);
        bf = new FixtureFeed(2000e8);
        router = new Router();
        dca = new DcaExecutor(address(sell), address(buy), address(router), 3000, address(sf), address(bf), 3600);
        dca.open(PLAN, 750e6, 30, START, 86400, 900, 50);
        sell.mint(address(this), 750e6);
        sell.approve(address(dca), 750e6);
    }

    function testAcceptedPurchase() public {
        dca.execute(PLAN, 0);
        require(dca.consumed(address(this), PLAN, 0));
        require(buy.balanceOf(address(this)) == 125e14);
        DcaExecutor.Plan memory p = dca.plan(address(this), PLAN);
        require(p.spent == 25e6 && p.amountIn == 25e6);
    }

    function testSecondSlotInItsWindow() public {
        dca.execute(PLAN, 0);
        vm.warp(START + 86400);
        sf.set(1e8, block.timestamp);
        bf.set(2000e8, block.timestamp);
        dca.execute(PLAN, 1);
        require(dca.plan(address(this), PLAN).spent == 50e6);
    }

    function testOpenOnce() public {
        vm.expectRevert();
        dca.open(PLAN, 750e6, 30, START, 86400, 900, 50);
    }

    function testOpenValidation() public {
        bytes32 id = bytes32(uint256(2));
        vm.expectRevert();
        dca.open(bytes32(0), 750e6, 30, START, 86400, 900, 50);
        vm.expectRevert();
        dca.open(id, 750e6 + 1, 30, START, 86400, 900, 50); // not divisible
        vm.expectRevert();
        dca.open(id, 0, 30, START, 86400, 900, 50);
        vm.expectRevert();
        dca.open(id, 1001, 1001, START, 86400, 900, 50); // too many runs
        vm.expectRevert();
        dca.open(id, 750e6, 30, START, 59, 30, 50); // interval below a minute
        vm.expectRevert();
        dca.open(id, 750e6, 30, START, 86400, 86401, 50); // grace above interval
        vm.expectRevert();
        dca.open(id, 750e6, 30, START, 86400, 0, 50);
        vm.expectRevert();
        dca.open(id, 750e6, 30, START, 86400, 900, 1001);
        vm.expectRevert();
        dca.open(id, 750e6, 30, 0, 86400, 900, 50);
    }

    function testPlansAreKeyedByAccount() public {
        vm.prank(address(9));
        vm.expectRevert();
        dca.execute(PLAN, 0);
        vm.prank(address(9));
        vm.expectRevert();
        dca.cancel(PLAN);
    }

    function testWrongSlot() public {
        vm.expectRevert();
        dca.execute(PLAN, 1);
        vm.expectRevert();
        dca.execute(PLAN, 30);
    }

    function testDuplicateSlot() public {
        dca.execute(PLAN, 0);
        vm.expectRevert();
        dca.execute(PLAN, 0);
    }

    function testTooEarly() public {
        vm.warp(START - 1);
        vm.expectRevert();
        dca.execute(PLAN, 0);
    }

    function testGraceExclusive() public {
        vm.warp(START + 900);
        vm.expectRevert();
        dca.execute(PLAN, 0);
    }

    function testCancellation() public {
        dca.cancel(PLAN);
        require(dca.plan(address(this), PLAN).cancelled);
        vm.expectRevert();
        dca.execute(PLAN, 0);
    }

    function testBudgetBoundsSpending() public {
        bytes32 id = bytes32(uint256(3));
        dca.open(id, 2e6, 1, START, 60, 60, 50);
        sell.mint(address(this), 2e6);
        sell.approve(address(dca), 752e6);
        dca.execute(id, 0);
        vm.expectRevert();
        dca.execute(id, 0);
        require(dca.plan(address(this), id).spent == 2e6);
    }

    function testStalePrice() public {
        sf.set(1e8, block.timestamp - 3601);
        vm.expectRevert();
        dca.execute(PLAN, 0);
    }

    function testFuturePrice() public {
        sf.set(1e8, block.timestamp + 1);
        vm.expectRevert();
        dca.execute(PLAN, 0);
    }

    function testInvalidPrice() public {
        bf.set(0, block.timestamp);
        vm.expectRevert();
        dca.execute(PLAN, 0);
    }

    function testPriceLimit() public {
        bf.set(1000e8, block.timestamp);
        vm.expectRevert();
        dca.execute(PLAN, 0);
        require(!dca.consumed(address(this), PLAN, 0));
    }

    function testRevertLeavesNoConsumption() public {
        router.setFail(true);
        vm.expectRevert();
        dca.execute(PLAN, 0);
        require(!dca.consumed(address(this), PLAN, 0));
        require(dca.plan(address(this), PLAN).spent == 0);
        require(sell.balanceOf(address(this)) == 750e6);
    }

    function testWrongTokenDecimals() public {
        vm.expectRevert();
        new DcaExecutor(address(buy), address(sell), address(router), 3000, address(sf), address(bf), 3600);
    }

    function testNoArbitrarySelector() public {
        (bool ok,) =
            address(dca).call(abi.encodeWithSignature("approve(address,uint256)", address(9), type(uint256).max));
        require(!ok);
    }
}
