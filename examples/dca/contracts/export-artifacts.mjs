/**
 * Rebuilds artifacts/*.json ({ abi, bytecode, deployedBytecode }) from `forge build` output.
 * Run `forge build` in this directory first.
 *
 * @author taek <leekt216@gmail.com>
 */
import { readFileSync, writeFileSync } from "node:fs";

const here = new URL("./", import.meta.url);
for (const [file, name] of [
  ["DcaExecutor.sol", "DcaExecutor"],
  ["FixtureToken.sol", "FixtureToken"],
  ["FixtureFeed.sol", "FixtureFeed"],
]) {
  const built = JSON.parse(readFileSync(new URL(`out/${file}/${name}.json`, here), "utf8"));
  const artifact = {
    abi: built.abi,
    bytecode: built.bytecode.object,
    deployedBytecode: built.deployedBytecode.object,
  };
  writeFileSync(new URL(`artifacts/${name}.json`, here), `${JSON.stringify(artifact)}\n`);
}
console.log("artifacts: DcaExecutor, FixtureToken, FixtureFeed");
