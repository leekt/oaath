import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { expect, it } from "vitest";
import { DeploymentJournal, type DeploymentRecord } from "../src/journal.js";

const attempt: DeploymentRecord = {
  chainId: 143,
  component: "kernelUups",
  address: "0x1111111111111111111111111111111111111111",
  wallet: "0x2222222222222222222222222222222222222222",
  inputHash: `0x${"33".repeat(32)}`,
  transactionHash: `0x${"44".repeat(32)}`,
  nonce: 0,
  state: "attempted",
};

it("persists an attempt across connections and admits only one transaction per chain", async () => {
  const directory = await mkdtemp(join(tmpdir(), "oaath-deployment-journal-"));
  const path = join(directory, "journal.sqlite");
  const first = new DeploymentJournal(path);
  const concurrent = new DeploymentJournal(path);
  try {
    expect(first.reserve(attempt)).toEqual({ inserted: true, record: attempt });
    expect(concurrent.reserve({ ...attempt, component: "kernelFactory", nonce: 1 })).toEqual({
      inserted: false,
      record: attempt,
    });
    first.close();
    const reopened = new DeploymentJournal(path);
    try {
      expect(reopened.pending(143)).toEqual(attempt);
      reopened.finish(attempt, "confirmed");
      expect(concurrent.reserve(attempt)).toEqual({
        inserted: false,
        record: { ...attempt, state: "confirmed" },
      });
      expect(concurrent.reserve({ ...attempt, chainId: 480 })).toMatchObject({ inserted: true });
    } finally {
      reopened.close();
    }
  } finally {
    first.close();
    concurrent.close();
    await rm(directory, { recursive: true, force: true });
  }
});

it("rejects a foreign durable schema instead of replacing it", async () => {
  const directory = await mkdtemp(join(tmpdir(), "oaath-deployment-schema-"));
  const path = join(directory, "journal.sqlite");
  const db = new DatabaseSync(path);
  db.exec("CREATE TABLE unrelated (value TEXT); PRAGMA user_version=9");
  db.close();
  try {
    expect(() => new DeploymentJournal(path)).toThrow("deployment_journal_schema_invalid");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
