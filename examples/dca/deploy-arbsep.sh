#!/usr/bin/env bash
# Deploys the hosted DCA example market on Arbitrum Sepolia (421614) with the Foundry
# keystore account TEMP_ACCOUNT: fixture tUSD/tETH tokens, two fixed feeds, a seeded
# full-range pool on Uniswap's v3 deployment, and the shared DcaExecutor
# (contracts/script/DeployArbSep.s.sol). One forge run broadcasts every transaction,
# so the keystore password is asked once (twice when DEPLOYER is not set).
#
#   examples/dca/deploy-arbsep.sh             # deploy and broadcast
#   examples/dca/deploy-arbsep.sh --dry-run   # simulate against the chain, send nothing
#
# Afterwards it prints the addresses and writes dca-arbsep.deployed.json: the service
# definitions with the addresses filled in.
set -euo pipefail
RPC=${ARBSEP_RPC_URL:-https://sepolia-rollup.arbitrum.io/rpc}
ACCOUNT=${FOUNDRY_ACCOUNT:-TEMP_ACCOUNT}
HERE=$(cd "$(dirname "$0")" && pwd)

[ "$(cast chain-id --rpc-url "$RPC")" = "421614" ] || { echo "wrong chain: expected 421614" >&2; exit 1; }
DEPLOYER=${DEPLOYER:-$(cast wallet address --account "$ACCOUNT")}
echo "deployer: $DEPLOYER  balance: $(cast balance "$DEPLOYER" --ether --rpc-url "$RPC") ETH" >&2

BROADCAST=(--account "$ACCOUNT" --broadcast)
[ "${1:-}" = "--dry-run" ] && BROADCAST=()
cd "$HERE/contracts"
OUT=$(forge script script/DeployArbSep.s.sol:DeployArbSep --rpc-url "$RPC" --sender "$DEPLOYER" ${BROADCAST[@]+"${BROADCAST[@]}"} | tee /dev/stderr)

address() {
  local value
  value=$(echo "$OUT" | sed -n "s/^ *$1= *\(0x[0-9a-fA-F]\{40\}\)$/\1/p" | head -1)
  [ -n "$value" ] || { echo "no $1 in the forge output" >&2; exit 1; }
  echo "$value"
}
SELL_TOKEN=$(address SELL_TOKEN)
BUY_TOKEN=$(address BUY_TOKEN)
POOL=$(address POOL)
DCA_EXECUTOR=$(address DCA_EXECUTOR)

sed -e "s/REPLACE_SELL_TOKEN/$SELL_TOKEN/g" -e "s/REPLACE_DCA_EXECUTOR/$DCA_EXECUTOR/g" \
  "$HERE/dca-arbsep.automation.json" > "$HERE/dca-arbsep.deployed.json"

cat <<EOF

tUSD (sell token)  $SELL_TOKEN
tETH (buy token)   $BUY_TOKEN
Uniswap v3 pool    $POOL
DcaExecutor        $DCA_EXECUTOR

Service definitions: $HERE/dca-arbsep.deployed.json
dca/wrangler.jsonc vars:
  "DCA_SELL_TOKEN": "$SELL_TOKEN",
  "DCA_BUY_TOKEN": "$BUY_TOKEN",
  "DCA_EXECUTOR": "$DCA_EXECUTOR",
EOF
[ ${#BROADCAST[@]} -eq 0 ] && echo "(dry run: nothing was sent; these addresses are simulated)"
exit 0
