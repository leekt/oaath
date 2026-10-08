// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {DcaExecutor} from "../src/DcaExecutor.sol";
import {FixtureFixedFeed} from "../src/fixtures/FixtureFixedFeed.sol";
import {FixtureToken} from "../src/fixtures/FixtureToken.sol";

interface ScriptVm {
    function startBroadcast() external;
    function stopBroadcast() external;
    function readCallers() external returns (uint256 mode, address sender, address origin);
}

interface PeripheryState {
    function factory() external view returns (address);
}

interface PositionManager {
    struct MintParams {
        address token0;
        address token1;
        uint24 fee;
        int24 tickLower;
        int24 tickUpper;
        uint256 amount0Desired;
        uint256 amount1Desired;
        uint256 amount0Min;
        uint256 amount1Min;
        address recipient;
        uint256 deadline;
    }

    function createAndInitializePoolIfNecessary(address, address, uint24, uint160) external payable returns (address);
    function mint(MintParams calldata) external payable returns (uint256, uint128, uint256, uint256);
}

/// @title The hosted DCA example market on Arbitrum Sepolia (421614).
/// @notice Deploys a mintable 6-decimal sell token (tUSD) and 18-decimal buy token (tETH),
/// two fixed always-fresh feeds (1 tUSD = $1, 1 tETH = $2000), a full-range 0.3% pool on
/// Uniswap's own v3 deployment seeded at that price, and the shared `DcaExecutor` routing
/// through Uniswap's SwapRouter02. Every token here is a test fixture with no value.
/// Uniswap addresses: https://developers.uniswap.org/docs/protocols/v3/deployments/v3-arbitrum-deployments
contract DeployArbSep {
    ScriptVm constant vm = ScriptVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address constant CONSOLE = 0x000000000000000000636F6e736F6c652e6c6f67;

    address constant FACTORY = 0x248AB79Bbb9bC29bB72f7Cd42F17e054Fc40188e;
    address constant POSITION_MANAGER = 0x6b2937Bde17889EDCf8fbD8dE31C3C2a70Bc4d65;
    address constant SWAP_ROUTER_02 = 0x101F443B4d1b059569D643917553c771E1b9663E;
    uint24 constant FEE = 3000;
    int24 constant FULL_RANGE = 887220;
    // 100M tUSD against 50k tETH: deep enough that plan purchases barely move the price.
    uint256 constant SELL_LIQUIDITY = 100_000_000e6;
    uint256 constant BUY_LIQUIDITY = 50_000e18;

    FixtureToken public sell;
    FixtureToken public buy;
    DcaExecutor public dca;

    function run() external {
        require(block.chainid == 421614, "not Arbitrum Sepolia");
        require(PeripheryState(POSITION_MANAGER).factory() == FACTORY, "position manager");
        require(PeripheryState(SWAP_ROUTER_02).factory() == FACTORY, "swap router");

        vm.startBroadcast();
        (, address deployer,) = vm.readCallers();
        sell = new FixtureToken(6);
        buy = new FixtureToken(18);
        FixtureFixedFeed sellFeed = new FixtureFixedFeed(1e8);
        FixtureFixedFeed buyFeed = new FixtureFixedFeed(2000e8);

        sell.mint(deployer, SELL_LIQUIDITY);
        buy.mint(deployer, BUY_LIQUIDITY);
        sell.approve(POSITION_MANAGER, SELL_LIQUIDITY);
        buy.approve(POSITION_MANAGER, BUY_LIQUIDITY);

        bool sellFirst = address(sell) < address(buy);
        // token1 per token0 in base units: 1e6 tUSD units buy 5e14 tETH units.
        uint256 priceX192 = sellFirst ? uint256(5e8) << 192 : (uint256(1) << 192) / 5e8;
        (address token0, address token1) = sellFirst ? (address(sell), address(buy)) : (address(buy), address(sell));
        address pool = PositionManager(POSITION_MANAGER).createAndInitializePoolIfNecessary(
            token0, token1, FEE, uint160(Math.sqrt(priceX192))
        );
        PositionManager(POSITION_MANAGER).mint(
            PositionManager.MintParams({
                token0: token0,
                token1: token1,
                fee: FEE,
                tickLower: -FULL_RANGE,
                tickUpper: FULL_RANGE,
                amount0Desired: sellFirst ? SELL_LIQUIDITY : BUY_LIQUIDITY,
                amount1Desired: sellFirst ? BUY_LIQUIDITY : SELL_LIQUIDITY,
                amount0Min: 0,
                amount1Min: 0,
                recipient: deployer,
                deadline: block.timestamp + 3600
            })
        );

        dca = new DcaExecutor(
            address(sell), address(buy), SWAP_ROUTER_02, FEE, address(sellFeed), address(buyFeed), 3600
        );
        vm.stopBroadcast();

        _log("SELL_TOKEN=", address(sell));
        _log("BUY_TOKEN=", address(buy));
        _log("SELL_FEED=", address(sellFeed));
        _log("BUY_FEED=", address(buyFeed));
        _log("POOL=", pool);
        _log("DCA_EXECUTOR=", address(dca));
    }

    function _log(string memory key, address value) private view {
        (bool ok,) = CONSOLE.staticcall(abi.encodeWithSignature("log(string,address)", key, value));
        ok;
    }
}
