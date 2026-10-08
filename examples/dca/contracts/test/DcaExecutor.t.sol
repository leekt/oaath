// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;
import {DcaExecutor, DcaFactory} from "../src/DcaExecutor.sol";

interface Vm {
    function warp(uint256) external;
    function prank(address) external;
    function expectRevert() external;
}

contract Token {
    uint8 public immutable decimals;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(uint8 d) {
        decimals = d;
    }

    function mint(address to, uint256 value) external {
        balanceOf[to] += value;
        emit Transfer(address(0), to, value);
    }

    function approve(address to, uint256 value) external returns (bool) {
        allowance[msg.sender][to] = value;
        return true;
    }

    function transfer(address to, uint256 value) external returns (bool) {
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        allowance[from][msg.sender] -= value;
        balanceOf[from] -= value;
        balanceOf[to] += value;
        emit Transfer(from, to, value);
        return true;
    }
}

contract Feed {
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
        Token(p.tokenIn).transferFrom(msg.sender, address(this), p.amountIn);
        amountOut = p.amountIn * 1e12 / 2000;
        require(amountOut >= p.amountOutMinimum);
        Token(p.tokenOut).mint(p.recipient, amountOut);
    }
}

contract DcaExecutorTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    Token sell;
    Token buy;
    Feed sf;
    Feed bf;
    Router router;
    DcaExecutor executor;
    DcaFactory factory;
    DcaExecutor.Terms t;

    function setUp() public {
        vm.warp(1_800_000_000);
        sell = new Token(6);
        buy = new Token(18);
        sf = new Feed(1e8);
        bf = new Feed(2000e8);
        router = new Router();
        factory = new DcaFactory();
        t = DcaExecutor.Terms(
            bytes32(uint256(1)),
            address(this),
            block.chainid,
            address(sell),
            address(buy),
            25e6,
            750e6,
            uint64(block.timestamp),
            86400,
            900,
            30,
            uint64(block.timestamp + 29 * 86400 + 900),
            address(this),
            address(router),
            3000,
            address(sf),
            address(bf),
            3600,
            50
        );
        executor = DcaExecutor(factory.create(t));
        sell.mint(address(this), 750e6);
        sell.approve(address(executor), 750e6);
    }

    function testAcceptedPurchase() public {
        executor.execute(0);
        require(executor.consumed(0));
        require(buy.balanceOf(address(this)) == 125e14);
        require(executor.totalSpent() == 25e6);
    }

    function testWrongAccount() public {
        vm.prank(address(9));
        vm.expectRevert();
        executor.execute(0);
    }

    function testWrongSlot() public {
        vm.expectRevert();
        executor.execute(1);
    }

    function testDuplicateSlot() public {
        executor.execute(0);
        vm.expectRevert();
        executor.execute(0);
    }

    function testTooEarly() public {
        vm.warp(t.startAt - 1);
        vm.expectRevert();
        executor.execute(0);
    }

    function testGraceExclusive() public {
        vm.warp(t.startAt + 900);
        vm.expectRevert();
        executor.execute(0);
    }

    function testExpiryExclusive() public {
        vm.warp(t.endAt);
        vm.expectRevert();
        executor.execute(29);
    }

    function testCancellation() public {
        executor.cancel();
        vm.expectRevert();
        executor.execute(0);
    }

    function testUnauthorizedCancel() public {
        vm.prank(address(9));
        vm.expectRevert();
        executor.cancel();
    }

    function testStalePrice() public {
        sf.set(1e8, block.timestamp - 3601);
        vm.expectRevert();
        executor.execute(0);
    }

    function testFuturePrice() public {
        sf.set(1e8, block.timestamp + 1);
        vm.expectRevert();
        executor.execute(0);
    }

    function testInvalidPrice() public {
        bf.set(0, block.timestamp);
        vm.expectRevert();
        executor.execute(0);
    }

    function testPriceLimit() public {
        bf.set(1000e8, block.timestamp);
        vm.expectRevert();
        executor.execute(0);
        require(!executor.consumed(0));
    }

    function testRevertLeavesNoConsumption() public {
        router.setFail(true);
        vm.expectRevert();
        executor.execute(0);
        require(!executor.consumed(0));
        require(executor.totalSpent() == 0);
        require(sell.balanceOf(address(this)) == 750e6);
    }

    function testWrongRecipient() public {
        t.planId = bytes32(uint256(2));
        t.recipient = address(9);
        vm.expectRevert();
        factory.create(t);
    }

    function testWrongTokenDecimals() public {
        t.planId = bytes32(uint256(2));
        t.sellToken = address(buy);
        vm.expectRevert();
        factory.create(t);
    }

    function testWrongCap() public {
        t.planId = bytes32(uint256(2));
        t.totalInputCap = 25e6;
        vm.expectRevert();
        factory.create(t);
    }

    function testFactoryPredictionAndRecreation() public view {
        require(factory.predict(t) == address(executor));
    }

    function testCannotReinitialize() public {
        vm.expectRevert();
        factory.create(t);
    }

    function testNoArbitrarySelector() public {
        (bool ok,) =
            address(executor).call(abi.encodeWithSignature("approve(address,uint256)", address(9), type(uint256).max));
        require(!ok);
    }
}
