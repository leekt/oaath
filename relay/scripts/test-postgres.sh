#!/usr/bin/env bash
# Runs the relay's PostgreSQL tests against a throwaway local cluster.
#
# The cluster lives in a temp directory on a random port, listens only on
# loopback, and is stopped and removed on exit.
set -euo pipefail

PG_BIN="${PG_BIN:-/opt/homebrew/bin}"
CARGO="${CARGO:-$HOME/.cargo/bin/cargo}"
RELAY_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DATA_DIR="$(mktemp -d "${TMPDIR:-/tmp}/oaath-relay-pg.XXXXXX")"
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"

cleanup() {
  "$PG_BIN/pg_ctl" -D "$DATA_DIR/data" -m immediate stop >/dev/null 2>&1 || true
  if command -v trash >/dev/null 2>&1; then trash "$DATA_DIR"; else rm -R "$DATA_DIR"; fi
}
trap cleanup EXIT

"$PG_BIN/initdb" -D "$DATA_DIR/data" -U oaath --auth=trust --no-instructions >/dev/null
"$PG_BIN/pg_ctl" -D "$DATA_DIR/data" -l "$DATA_DIR/postgres.log" -w \
  -o "-p $PORT -k $DATA_DIR -c listen_addresses=127.0.0.1" start >/dev/null
"$PG_BIN/createdb" -h 127.0.0.1 -p "$PORT" -U oaath oaath_relay_test

export OAATH_TEST_POSTGRES=1
export OAATH_TEST_POSTGRES_URL="postgres://oaath@127.0.0.1:$PORT/oaath_relay_test"
cd "$RELAY_DIR"
"$CARGO" test -p oaath-relay --test postgres -- "$@"
