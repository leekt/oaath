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
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }
    function exactInputSingle(ExactInputSingleParams calldata) external payable returns (uint256);
}

/// @notice One immutable plan per address. Session authority is only execute(uint32).
contract DcaExecutor {
    using SafeERC20 for IERC20;

    struct Terms {
        bytes32 planId;
        address account;
        uint256 chainId;
        address sellToken;
        address buyToken;
        uint256 amountIn;
        uint256 totalInputCap;
        uint64 startAt;
        uint32 intervalSeconds;
        uint32 graceSeconds;
        uint32 maxRuns;
        uint64 endAt;
        address recipient;
        address router;
        uint24 poolFee;
        address sellFeed;
        address buyFeed;
        uint32 maxPriceAgeSeconds;
        uint16 maxSlippageBps;
    }
    bytes32 public constant DOMAIN = keccak256("oaath.dca-terms/v1");
    bytes32 public immutable termsHash;
    bytes32 public immutable planId;
    address public immutable account;
    uint256 public immutable chainId;
    address public immutable sellToken;
    address public immutable buyToken;
    uint256 public immutable amountIn;
    uint256 public immutable totalInputCap;
    uint64 public immutable startAt;
    uint32 public immutable intervalSeconds;
    uint32 public immutable graceSeconds;
    uint32 public immutable maxRuns;
    uint64 public immutable endAt;
    address public immutable recipient;
    address public immutable router;
    uint24 public immutable poolFee;
    address public immutable sellFeed;
    address public immutable buyFeed;
    uint32 public immutable maxPriceAgeSeconds;
    uint16 public immutable maxSlippageBps;
    bool public cancelled;
    uint256 public totalSpent;
    mapping(uint256 => uint256) private used;
    uint256 private entered = 1;
    event Purchased(
        bytes32 indexed planId,
        uint32 indexed slot,
        address indexed account,
        address sellToken,
        address buyToken,
        uint256 amountIn,
        uint256 amountOut
    );
    event Cancelled(bytes32 indexed planId);
    error InvalidTerms();
    error NotAccount();
    error Ineligible();
    error InvalidPrice();
    error InvalidSwap();

    constructor(Terms memory t) {
        if (
            t.planId == bytes32(0) || t.account == address(0) || t.chainId != block.chainid || t.recipient != t.account
                || t.sellToken == t.buyToken || t.amountIn == 0 || t.maxRuns == 0 || t.maxRuns > 365
                || t.totalInputCap / t.maxRuns != t.amountIn || t.totalInputCap % t.maxRuns != 0
                || t.intervalSeconds != 86400 || t.graceSeconds == 0 || t.graceSeconds > t.intervalSeconds
                || t.endAt != uint256(t.startAt) + (uint256(t.maxRuns) - 1) * t.intervalSeconds + t.graceSeconds
                || t.maxSlippageBps > 1000 || t.maxPriceAgeSeconds == 0 || t.maxPriceAgeSeconds > 86400
                || t.poolFee == 0 || t.poolFee >= 1_000_000 || t.router.code.length == 0
        ) revert InvalidTerms();
        if (
            IERC20Metadata(t.sellToken).decimals() != 6 || IERC20Metadata(t.buyToken).decimals() != 18
                || DcaFeed(t.sellFeed).decimals() != 8 || DcaFeed(t.buyFeed).decimals() != 8
        ) revert InvalidTerms();
        termsHash = keccak256(abi.encode(DOMAIN, t));
        planId = t.planId;
        account = t.account;
        chainId = t.chainId;
        sellToken = t.sellToken;
        buyToken = t.buyToken;
        amountIn = t.amountIn;
        totalInputCap = t.totalInputCap;
        startAt = t.startAt;
        intervalSeconds = t.intervalSeconds;
        graceSeconds = t.graceSeconds;
        maxRuns = t.maxRuns;
        endAt = t.endAt;
        recipient = t.recipient;
        router = t.router;
        poolFee = t.poolFee;
        sellFeed = t.sellFeed;
        buyFeed = t.buyFeed;
        maxPriceAgeSeconds = t.maxPriceAgeSeconds;
        maxSlippageBps = t.maxSlippageBps;
    }

    function consumed(uint32 slot) public view returns (bool) {
        return used[slot >> 8] & (uint256(1) << (slot & 255)) != 0;
    }

    function price(address feed) private view returns (uint256) {
        (uint80 round, int256 answer,, uint256 updated, uint80 answered) = DcaFeed(feed).latestRoundData();
        if (
            answer <= 0 || uint256(answer) > 1e30 || updated == 0 || updated > block.timestamp
                || block.timestamp - updated > maxPriceAgeSeconds || answered < round
        ) revert InvalidPrice();
        return uint256(answer);
    }

    function minimumOutput() public view returns (uint256) {
        uint256 quoted = Math.mulDiv(amountIn, price(sellFeed) * 1e12, price(buyFeed));
        uint256 minimum = Math.mulDiv(quoted, 10000 - maxSlippageBps, 10000);
        if (minimum == 0) revert InvalidPrice();
        return minimum;
    }

    function execute(uint32 slot) external returns (uint256 amountOut) {
        if (msg.sender != account) revert NotAccount();
        uint256 scheduled = uint256(startAt) + uint256(slot) * intervalSeconds;
        if (
            entered != 1 || cancelled || block.chainid != chainId || slot >= maxRuns || block.timestamp < scheduled
                || block.timestamp >= scheduled + graceSeconds || block.timestamp >= endAt || consumed(slot)
                || totalSpent + amountIn > totalInputCap
        ) revert Ineligible();
        entered = 2;
        uint256 minimum = minimumOutput();
        uint256 sellBefore = IERC20(sellToken).balanceOf(account);
        uint256 buyBefore = IERC20(buyToken).balanceOf(account);
        used[slot >> 8] |= uint256(1) << (slot & 255);
        totalSpent += amountIn;
        IERC20(sellToken).safeTransferFrom(account, address(this), amountIn);
        IERC20(sellToken).forceApprove(router, amountIn);
        amountOut = DcaRouter(router)
            .exactInputSingle(
                DcaRouter.ExactInputSingleParams(
                    sellToken, buyToken, poolFee, recipient, scheduled + graceSeconds - 1, amountIn, minimum, 0
                )
            );
        IERC20(sellToken).forceApprove(router, 0);
        if (
            IERC20(sellToken).balanceOf(account) + amountIn != sellBefore
                || IERC20(buyToken).balanceOf(account) - buyBefore != amountOut || amountOut < minimum
        ) revert InvalidSwap();
        entered = 1;
        emit Purchased(planId, slot, account, sellToken, buyToken, amountIn, amountOut);
    }

    function cancel() external {
        if (msg.sender != account) revert NotAccount();
        cancelled = true;
        emit Cancelled(planId);
    }
}

contract DcaFactory {
    event Created(bytes32 indexed planId, address indexed account, address executor, bytes32 termsHash);

    function create(DcaExecutor.Terms calldata terms) external returns (address executor) {
        if (msg.sender != terms.account) revert DcaExecutor.NotAccount();
        executor = address(new DcaExecutor{salt: terms.planId}(terms));
        emit Created(terms.planId, terms.account, executor, DcaExecutor(executor).termsHash());
    }

    function predict(DcaExecutor.Terms calldata terms) external view returns (address) {
        return address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            bytes1(0xff),
                            address(this),
                            terms.planId,
                            keccak256(abi.encodePacked(type(DcaExecutor).creationCode, abi.encode(terms)))
                        )
                    )
                )
            )
        );
    }
}
