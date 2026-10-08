// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

interface DcaFeed {
    function decimals() external view returns (uint8);
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}

interface DcaRouter {
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }

    function exactInputSingle(ExactInputSingleParams calldata) external payable returns (uint256);
}

/// @title Shared DCA executor for one market (sell/buy pair, route and feeds).
/// @notice Each account opens plans keyed by `planId` and executes their slots itself
/// (`msg.sender` is always the account). OAAth 0.3.x Grant policies allow-list only a
/// target and selector, so the per-plan budget, slot timing, single use per slot and
/// the oracle price bound are enforced here, not by the account's session policy.
contract DcaExecutor {
    using SafeERC20 for IERC20;

    struct Plan {
        uint256 budget;
        uint256 amountIn;
        uint256 spent;
        uint64 startAt;
        uint32 runs;
        uint32 interval;
        uint32 grace;
        uint16 maxSlippageBps;
        bool cancelled;
    }

    address public immutable sellToken;
    address public immutable buyToken;
    address public immutable router;
    uint24 public immutable poolFee;
    address public immutable sellFeed;
    address public immutable buyFeed;
    uint32 public immutable maxPriceAgeSeconds;

    mapping(address => mapping(bytes32 => Plan)) private plans;
    mapping(address => mapping(bytes32 => mapping(uint256 => uint256))) private used;
    uint256 private entered = 1;

    event Opened(bytes32 indexed planId, address indexed account, uint256 budget, uint32 runs);
    event Purchased(
        bytes32 indexed planId, uint32 indexed slot, address indexed account, uint256 amountIn, uint256 amountOut
    );
    event Cancelled(bytes32 indexed planId, address indexed account);

    error InvalidMarket();
    error InvalidPlan();
    error PlanExists();
    error UnknownPlan();
    error Ineligible();
    error InvalidPrice();
    error InvalidSwap();

    constructor(
        address sellToken_,
        address buyToken_,
        address router_,
        uint24 poolFee_,
        address sellFeed_,
        address buyFeed_,
        uint32 maxPriceAgeSeconds_
    ) {
        if (
            sellToken_ == buyToken_ || router_.code.length == 0 || poolFee_ == 0 || poolFee_ >= 1_000_000
                || maxPriceAgeSeconds_ == 0 || maxPriceAgeSeconds_ > 86400
        ) revert InvalidMarket();
        if (
            IERC20Metadata(sellToken_).decimals() != 6 || IERC20Metadata(buyToken_).decimals() != 18
                || DcaFeed(sellFeed_).decimals() != 8 || DcaFeed(buyFeed_).decimals() != 8
        ) revert InvalidMarket();
        sellToken = sellToken_;
        buyToken = buyToken_;
        router = router_;
        poolFee = poolFee_;
        sellFeed = sellFeed_;
        buyFeed = buyFeed_;
        maxPriceAgeSeconds = maxPriceAgeSeconds_;
    }

    /// @notice Opens the caller's plan once. `budget` is split evenly across `runs` slots.
    function open(
        bytes32 planId,
        uint256 budget,
        uint32 runs,
        uint64 startAt,
        uint32 interval,
        uint32 grace,
        uint16 maxSlippageBps
    ) external {
        Plan storage p = plans[msg.sender][planId];
        if (p.budget != 0) revert PlanExists();
        if (
            planId == bytes32(0) || runs == 0 || runs > 1000 || budget == 0 || budget % runs != 0 || interval < 60
                || grace == 0 || grace > interval || maxSlippageBps > 1000 || startAt == 0
        ) revert InvalidPlan();
        p.budget = budget;
        p.amountIn = budget / runs;
        p.startAt = startAt;
        p.runs = runs;
        p.interval = interval;
        p.grace = grace;
        p.maxSlippageBps = maxSlippageBps;
        emit Opened(planId, msg.sender, budget, runs);
    }

    /// @notice Buys once for slot `slot` of the caller's plan, inside that slot's window.
    function execute(bytes32 planId, uint32 slot) external returns (uint256 amountOut) {
        address account = msg.sender;
        Plan storage p = plans[account][planId];
        if (p.budget == 0) revert UnknownPlan();
        uint256 scheduled = uint256(p.startAt) + uint256(slot) * p.interval;
        if (
            entered != 1 || p.cancelled || slot >= p.runs || block.timestamp < scheduled
                || block.timestamp >= scheduled + p.grace || consumed(account, planId, slot)
                || p.spent + p.amountIn > p.budget
        ) revert Ineligible();
        entered = 2;
        uint256 amountIn = p.amountIn;
        uint256 minimum = _minimumOutput(amountIn, p.maxSlippageBps);
        uint256 sellBefore = IERC20(sellToken).balanceOf(account);
        uint256 buyBefore = IERC20(buyToken).balanceOf(account);
        used[account][planId][slot >> 8] |= uint256(1) << (slot & 255);
        p.spent += amountIn;
        IERC20(sellToken).safeTransferFrom(account, address(this), amountIn);
        IERC20(sellToken).forceApprove(router, amountIn);
        amountOut = DcaRouter(router).exactInputSingle(
            DcaRouter.ExactInputSingleParams(sellToken, buyToken, poolFee, account, amountIn, minimum, 0)
        );
        IERC20(sellToken).forceApprove(router, 0);
        if (
            IERC20(sellToken).balanceOf(account) + amountIn != sellBefore
                || IERC20(buyToken).balanceOf(account) - buyBefore != amountOut || amountOut < minimum
        ) revert InvalidSwap();
        entered = 1;
        emit Purchased(planId, slot, account, amountIn, amountOut);
    }

    /// @notice Stops the caller's plan; no later slot can execute.
    function cancel(bytes32 planId) external {
        Plan storage p = plans[msg.sender][planId];
        if (p.budget == 0) revert UnknownPlan();
        p.cancelled = true;
        emit Cancelled(planId, msg.sender);
    }

    function plan(address account, bytes32 planId) external view returns (Plan memory) {
        return plans[account][planId];
    }

    function consumed(address account, bytes32 planId, uint32 slot) public view returns (bool) {
        return used[account][planId][slot >> 8] & (uint256(1) << (slot & 255)) != 0;
    }

    function minimumOutput(address account, bytes32 planId) external view returns (uint256) {
        Plan storage p = plans[account][planId];
        if (p.budget == 0) revert UnknownPlan();
        return _minimumOutput(p.amountIn, p.maxSlippageBps);
    }

    function _price(address feed) private view returns (uint256) {
        (uint80 round, int256 answer,, uint256 updated, uint80 answered) = DcaFeed(feed).latestRoundData();
        if (
            answer <= 0 || uint256(answer) > 1e30 || updated == 0 || updated > block.timestamp
                || block.timestamp - updated > maxPriceAgeSeconds || answered < round
        ) revert InvalidPrice();
        return uint256(answer);
    }

    function _minimumOutput(uint256 amountIn, uint16 maxSlippageBps) private view returns (uint256) {
        uint256 quoted = Math.mulDiv(amountIn, _price(sellFeed) * 1e12, _price(buyFeed));
        uint256 minimum = Math.mulDiv(quoted, 10000 - maxSlippageBps, 10000);
        if (minimum == 0) revert InvalidPrice();
        return minimum;
    }
}
