/**
 * A throwaway PostgreSQL cluster on a random loopback port, or the database
 * named by `OAATH_TEST_POSTGRES_URL`. Each call to `database()` creates a
 * fresh database so tests never share state. Without PostgreSQL binaries the
 * suites skip, unless `OAATH_REQUIRE_POSTGRES=1` makes that a failure.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import pg from "pg";

function binaries(): string | null {
  const candidates = [
    process.env.PG_BIN,
    "/opt/homebrew/bin",
    "/usr/local/bin",
    ...(existsSync("/usr/lib/postgresql")
      ? readdirSync("/usr/lib/postgresql")
          .sort()
          .reverse()
          .map((version) => `/usr/lib/postgresql/${version}/bin`)
      : []),
  ];
  for (const directory of candidates) {
    if (directory && existsSync(join(directory, "initdb")) && existsSync(join(directory, "pg_ctl")))
      return directory;
  }
  const found = spawnSync("sh", ["-c", "command -v initdb"], { encoding: "utf8" }).stdout.trim();
  return found ? found.replace(/\/initdb$/u, "") : null;
}

export const postgresAvailable =
  process.env.OAATH_TEST_POSTGRES_URL !== undefined || binaries() !== null;

if (!postgresAvailable && process.env.OAATH_REQUIRE_POSTGRES === "1")
  throw new Error("PostgreSQL is required but no binaries were found");

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as { port: number };
      server.close(() => resolve(port));
    });
  });
}

export interface TestCluster {
  /** A fresh, empty database URL. */
  readonly database: () => Promise<string>;
  readonly stop: () => void;
}

export async function startCluster(): Promise<TestCluster> {
  const external = process.env.OAATH_TEST_POSTGRES_URL;
  let admin: string;
  let stop = () => undefined as void;
  if (external !== undefined) {
    admin = external;
  } else {
    const bin = binaries() as string;
    const directory = mkdtempSync(join(tmpdir(), "oaath-automation-pg-"));
    const port = await freePort();
    execFileSync(
      join(bin, "initdb"),
      ["-D", join(directory, "data"), "-U", "oaath", "--auth=trust", "--no-instructions"],
      {
        stdio: "ignore",
      },
    );
    execFileSync(
      join(bin, "pg_ctl"),
      [
        "-D",
        join(directory, "data"),
        "-l",
        join(directory, "postgres.log"),
        "-w",
        "-o",
        `-p ${port} -k ${directory} -c listen_addresses=127.0.0.1`,
        "start",
      ],
      { stdio: "ignore" },
    );
    admin = `postgres://oaath@127.0.0.1:${port}/postgres`;
    stop = () => {
      spawnSync(join(bin, "pg_ctl"), ["-D", join(directory, "data"), "-m", "immediate", "stop"], {
        stdio: "ignore",
      });
      rmSync(directory, { recursive: true, force: true });
    };
  }
  let counter = 0;
  return {
    async database() {
      counter += 1;
      const name = `automation_test_${process.pid}_${Date.now()}_${counter}`;
      const client = new pg.Client({ connectionString: admin });
      await client.connect();
      try {
        await client.query(`CREATE DATABASE ${name}`);
      } finally {
        await client.end();
      }
      const url = new URL(admin);
      url.pathname = `/${name}`;
      return url.href;
    },
    stop,
  };
}
