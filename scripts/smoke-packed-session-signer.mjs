/** Packed public APIs, independent PostgreSQL connections and actual process death.
 * Run only against an explicitly selected disposable PostgreSQL instance.
 */
import { createConsumer } from "./packed-consumer.mjs";

if (process.env.OAATH_REQUIRE_POSTGRES !== "1" || !process.env.OAATH_POSTGRES_URL) {
  throw new Error(
    "Set OAATH_REQUIRE_POSTGRES=1 and OAATH_POSTGRES_URL for the owned test database",
  );
}

const worker = String.raw`
import { createCipheriv, createDecipheriv, createHash } from "node:crypto";
import pg from "pg";
import { createKmsSessionSignerProvider } from "@oaath/server";
import { createPostgresSessionSignerRegistry } from "@oaath/server/postgres";
import { recoverAddress } from "cetane/utils";

process.once("message", async ({ schema, master, identity, expected, mode }) => {
  const pool = new pg.Pool({ connectionString: process.env.OAATH_POSTGRES_URL, options: "-c search_path=" + schema, max: 1 });
  const registry = createPostgresSessionSignerRegistry({ pool });
  let encryptions = 0;
  const kms = {
    async encrypt(plaintext) {
      encryptions++;
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const cipher = createCipheriv("aes-256-gcm", Buffer.from(master, "hex"), iv);
      const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
      return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString("base64");
    },
    async decrypt(reference) {
      const bytes = Buffer.from(reference, "base64");
      const cipher = createDecipheriv("aes-256-gcm", Buffer.from(master, "hex"), bytes.subarray(0, 12));
      cipher.setAuthTag(bytes.subarray(12, 28));
      return Buffer.concat([cipher.update(bytes.subarray(28)), cipher.final()]).toString("utf8");
    },
  };
  const provider = createKmsSessionSignerProvider({ providerId: "test-kms", kms,
    registry: mode === "interrupt" ? {
      read: registry.read,
      async create(key, produce) {
        await registry.create(key, produce);
        // Commit succeeded, but no credential acknowledgement reached the caller.
        process.send({ committed: true });
        await new Promise(() => {});
      },
    } : registry,
  });
  try {
    const credential = mode === "recover"
      ? await provider.credential({ ...identity, expectedCredential: expected })
      : await provider.createCredential(identity);
    const hash = "0x" + "12".repeat(32);
    const signature = await provider.sign({ ...identity, expectedCredential: credential, hash });
    if ((await recoverAddress({ hash, signature })).toLowerCase() !== credential.address) throw new Error();
    // Only public evidence and a comparison fingerprint cross IPC; never log signatures.
    process.send({ credential, encryptions, proof: createHash("sha256").update(signature).digest("hex") });
  } catch (error) {
    process.send({ code: typeof error?.code === "string" ? error.code : "test_failure", encryptions });
  } finally { await pool.end(); process.disconnect(); }
});
`;

const smoke = String.raw`
import { fork } from "node:child_process";
import { randomBytes } from "node:crypto";
import pg from "pg";
import { createPostgresSessionSignerSchema } from "@oaath/server/postgres";
const fail = (condition, message) => { if (!condition) throw new Error(message); };
const admin = new pg.Pool({ connectionString: process.env.OAATH_POSTGRES_URL, max: 1 });
const schema = "oaath_signer_" + crypto.randomUUID().replaceAll("-", "");
const master = randomBytes(32).toString("hex");
const identity = { clientId: "app", subject: "user", deviceId: "device" };
let pool;
const children = new Set();
async function run(mode, expected, selected = identity) {
  return new Promise((resolve, reject) => {
    const child = fork(new URL("./worker.mjs", import.meta.url), [], { stdio: ["ignore", "ignore", "ignore", "ipc"] });
    children.add(child);
    let result;
    const timeout = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("signer process timed out")); }, 15_000);
    child.on("message", (message) => {
      result = message;
      if (message.committed) child.kill("SIGKILL");
    });
    child.once("error", () => reject(new Error("signer process failed to start")));
    child.once("exit", (code, signal) => {
      clearTimeout(timeout); children.delete(child);
      if ((code === 0 || (signal === "SIGKILL" && result?.committed)) && result) resolve(result);
      else reject(new Error("signer process failed"));
    });
    child.send({ schema, master, identity: selected, expected, mode });
  });
}
try {
  await admin.query('CREATE SCHEMA "' + schema + '"');
  pool = new pg.Pool({ connectionString: process.env.OAATH_POSTGRES_URL, options: "-c search_path=" + schema });
  await createPostgresSessionSignerSchema(pool);
  const [first, raced] = await Promise.all([run("create"), run("create")]);
  fail(first.credential && JSON.stringify(first.credential) === JSON.stringify(raced.credential), "creation race did not retain one winner");
  fail(first.encryptions + raced.encryptions === 1, "creation race sealed multiple keys");
  const recovered = await run("recover", first.credential);
  fail(recovered.proof === first.proof && recovered.proof === raced.proof && recovered.encryptions === 0, "process recreation lost exact signing identity");
  const interruptedIdentity = { ...identity, deviceId: "interrupted" };
  fail((await run("interrupt", undefined, interruptedIdentity)).committed, "creation never committed");
  const before = await pool.query("SELECT binding FROM oaath_session_signers_v1 WHERE identity = $1", [JSON.stringify(Object.values(interruptedIdentity))]);
  const reconciled = await run("create", undefined, interruptedIdentity);
  fail(reconciled.encryptions === 0 && reconciled.credential.address === before.rows[0].binding.credential.address, "lost acknowledgement rotated custody");
  const restarted = await run("recover", reconciled.credential, interruptedIdentity);
  fail(restarted.proof === reconciled.proof && restarted.encryptions === 0, "interrupted identity could not recover");
  const key = JSON.stringify(Object.values(identity));
  const row = (await pool.query("SELECT binding FROM oaath_session_signers_v1 WHERE identity = $1", [key])).rows[0].binding;
  for (const altered of [
    { ...row, version: "unknown" },
    { ...row, providerId: "different" },
    { ...row, identity: { ...identity, subject: "foreign" } },
    { ...row, credential: { ...row.credential, address: "0x" + "11".repeat(20) } },
    { ...row, sealedReference: "unavailable" },
  ]) {
    await pool.query("UPDATE oaath_session_signers_v1 SET binding = $2::jsonb WHERE identity = $1", [key, JSON.stringify(altered)]);
    const refused = await run("recover", first.credential);
    fail(refused.code?.startsWith("session_signer_") && refused.encryptions === 0, "corrupt custody authorized recovery or rotation");
  }
  await pool.query("DELETE FROM oaath_session_signers_v1 WHERE identity = $1", [key]);
  const missing = await run("recover", first.credential);
  fail(missing.code === "session_signer_binding_unavailable" && missing.encryptions === 0, "missing custody created a replacement");
  console.log("smoke-packed-session-signer: race, process recreation, exact signing, lost acknowledgement and custody failures passed");
} finally {
  for (const child of children) child.kill("SIGKILL");
  await pool?.end();
  await admin.query('DROP SCHEMA IF EXISTS "' + schema + '" CASCADE');
  await admin.end();
}
`;

const consumer = await createConsumer({
  label: "session-signer",
  packages: ["@oaath/protocol", "@oaath/sdk", "@oaath/server"],
  dependencies: { pg: "8.22.0", "@types/pg": "8.20.3", "@types/node": "22.13.0" },
  types: ["node"],
  skipLibCheck: true,
  files: {
    "worker.mjs": worker,
    "smoke.mjs": smoke,
    "types.ts": `import { createKmsSessionSignerProvider, type RelayKms, type RelaySessionSignerProvider } from "@oaath/server";
import { createPostgresSessionSignerRegistry } from "@oaath/server/postgres";
import type { Pool } from "pg";
export function hosted(pool: Pool, kms: RelayKms): RelaySessionSignerProvider {
  return createKmsSessionSignerProvider({ providerId: "primary", registry: createPostgresSessionSignerRegistry({ pool }), kms });
}`,
  },
});
try {
  consumer.typecheck();
  process.stdout.write(consumer.node("smoke.mjs"));
} finally {
  await consumer.cleanup();
}
