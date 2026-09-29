import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { Hex } from "viem";

export interface DeploymentRecord {
  readonly chainId: number;
  readonly component: string;
  readonly address: Hex;
  readonly wallet: Hex;
  readonly inputHash: Hex;
  readonly transactionHash: Hex;
  readonly nonce: number;
  readonly state: "attempted" | "confirmed" | "reverted";
}

function capture(row: unknown): DeploymentRecord | null {
  if (row === undefined) return null;
  if (!row || typeof row !== "object") throw new Error("deployment_journal_invalid");
  const value = row as Record<string, unknown>;
  if (
    !Number.isSafeInteger(value.chainId) ||
    Number(value.chainId) < 1 ||
    !Number.isSafeInteger(value.nonce) ||
    Number(value.nonce) < 0 ||
    typeof value.component !== "string" ||
    !/^[a-zA-Z][a-zA-Z0-9]{0,39}$/u.test(value.component) ||
    !["attempted", "confirmed", "reverted"].includes(String(value.state))
  )
    throw new Error("deployment_journal_invalid");
  for (const field of ["address", "wallet"])
    if (typeof value[field] !== "string" || !/^0x[0-9a-f]{40}$/u.test(value[field]))
      throw new Error("deployment_journal_invalid");
  for (const field of ["inputHash", "transactionHash"])
    if (typeof value[field] !== "string" || !/^0x[0-9a-f]{64}$/u.test(value[field]))
      throw new Error("deployment_journal_invalid");
  return Object.freeze({ ...value }) as unknown as DeploymentRecord;
}

/** Public attempt metadata only: never a private key or a signed transaction. */
export class DeploymentJournal {
  readonly #db: DatabaseSync;
  #closed = false;

  constructor(path: string) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.#db = new DatabaseSync(path);
    try {
      this.#db.exec("PRAGMA busy_timeout=5000; PRAGMA synchronous=FULL; BEGIN IMMEDIATE");
      const version = (this.#db.prepare("PRAGMA user_version").get() as Record<string, unknown>)
        ?.user_version;
      if (version === 0) {
        if (this.#db.prepare("SELECT name FROM sqlite_master WHERE type='table'").get())
          throw new Error("deployment_journal_schema_invalid");
        this.#db.exec(`CREATE TABLE deployments (
          chainId INTEGER NOT NULL, component TEXT NOT NULL, address TEXT NOT NULL,
          wallet TEXT NOT NULL, inputHash TEXT NOT NULL, transactionHash TEXT NOT NULL,
          nonce INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN ('attempted','confirmed','reverted')),
          PRIMARY KEY(chainId, component)
        );
        CREATE UNIQUE INDEX active_chain ON deployments(chainId) WHERE state='attempted';
        PRAGMA application_id=1329676628;
        PRAGMA user_version=1;`);
      } else if (
        version !== 1 ||
        (this.#db.prepare("PRAGMA application_id").get() as Record<string, unknown>)
          ?.application_id !== 1329676628
      )
        throw new Error("deployment_journal_schema_invalid");
      this.#db.exec("COMMIT");
    } catch (error) {
      this.#db.close();
      throw error;
    }
  }

  pending(chainId: number): DeploymentRecord | null {
    return capture(
      this.#db
        .prepare("SELECT * FROM deployments WHERE chainId=? AND state='attempted'")
        .get(chainId),
    );
  }

  get(chainId: number, component: string): DeploymentRecord | null {
    return capture(
      this.#db
        .prepare("SELECT * FROM deployments WHERE chainId=? AND component=?")
        .get(chainId, component),
    );
  }

  reserve(attempt: DeploymentRecord): { inserted: boolean; record: DeploymentRecord } {
    if (capture(attempt)?.state !== "attempted") throw new Error("deployment_journal_invalid");
    this.#db.exec("BEGIN IMMEDIATE");
    try {
      const existing =
        this.pending(attempt.chainId) ?? this.get(attempt.chainId, attempt.component);
      if (existing) {
        this.#db.exec("COMMIT");
        return { inserted: false, record: existing };
      }
      this.#db
        .prepare("INSERT INTO deployments VALUES (?,?,?,?,?,?,?,?)")
        .run(
          attempt.chainId,
          attempt.component,
          attempt.address,
          attempt.wallet,
          attempt.inputHash,
          attempt.transactionHash,
          attempt.nonce,
          attempt.state,
        );
      this.#db.exec("COMMIT");
      return { inserted: true, record: attempt };
    } catch (error) {
      this.#db.exec("ROLLBACK");
      throw error;
    }
  }

  finish(record: DeploymentRecord, state: "confirmed" | "reverted"): void {
    const result = this.#db
      .prepare(
        "UPDATE deployments SET state=? WHERE chainId=? AND component=? AND transactionHash=? AND state='attempted'",
      )
      .run(state, record.chainId, record.component, record.transactionHash);
    if (result.changes !== 1) {
      const existing = this.get(record.chainId, record.component);
      if (existing?.state !== state || existing.transactionHash !== record.transactionHash)
        throw new Error("deployment_journal_conflict");
    }
  }

  close(): void {
    if (!this.#closed) {
      this.#db.close();
      this.#closed = true;
    }
  }
}
