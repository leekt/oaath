import { createOperation, type KernelV4RevocationSigningRequest } from "@oaath/protocol";
import {
  type OperationObserverReadRequest,
  OperationStore,
  type OperationStoreAdapter,
} from "@oaath/sdk/advanced";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  createOwnerPhoneRevocationExecutor,
  type OwnerPhoneRevocationExecutorInput,
} from "../src/kernel.js";
import { requestOwnerPhoneRevocation } from "../src/native.js";
import {
  createPostgresOperationSchema,
  createPostgresOperationStoreAdapter,
  createPostgresRelayStore,
} from "../src/postgres.js";
import { createTestClock, createTestKms, expectOk, OWNER_TOKEN, post } from "./support.js";
import {
  createPostgresFixture,
  type PostgresFixture,
  requirePostgres,
} from "./support-postgres.js";
import { setupRevocation } from "./support-revocation.js";

const unavailable = async () => {
  throw new Error("capability unavailable");
};
const noClose = async () => {};
function observation(request: KernelV4RevocationSigningRequest, finalized = false) {
  const tx = `0x${"44".repeat(32)}`;
  const hash = `0x${"55".repeat(32)}`;
  const parent = `0x${"66".repeat(32)}`;
  const zero = `0x${"00".repeat(20)}`;
  const word = (value: bigint) => value.toString(16).padStart(64, "0");
  const receipt = {
    userOperationHash: request.expectedDigest,
    entryPoint: request.entryPoint,
    sender: request.operation.sender,
    nonce: `0x${BigInt(request.operation.nonce).toString(16)}`,
    paymaster: zero,
    actualGasCost: "0x9",
    actualGasUsed: "0xa",
    success: true,
    transactionHash: tx,
    blockNumber: "0x14",
    blockHash: hash,
  };
  const common = {
    address: request.entryPoint,
    blockNumber: "0x14",
    blockHash: hash,
    transactionHash: tx,
    transactionIndex: "0x0",
    removed: false,
  };
  const logs = [
    {
      ...common,
      logIndex: "0x0",
      topics: ["0xbb47ee3e183a558b1a2ff0874b079f3fc5478b7454eacf2bfc5af2ff5878f972"],
      data: "0x",
    },
    {
      ...common,
      logIndex: "0x1",
      topics: [
        "0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f",
        request.expectedDigest,
        `0x${"0".repeat(24)}${request.operation.sender.slice(2)}`,
        `0x${"0".repeat(64)}`,
      ],
      data: `0x${word(BigInt(request.operation.nonce))}${word(1n)}${word(9n)}${word(10n)}`,
    },
  ];
  const block = { number: "0x14", hash, parentHash: parent, transactions: [tx] };
  return {
    close: noClose,
    read: vi.fn(async (input: OperationObserverReadRequest): Promise<unknown> => {
      if (input.type === "chain_id") return request.chainId;
      if (input.type === "user_operation_receipt") return finalized ? receipt : null;
      if (input.type === "replacement_candidate") return null;
      if (input.type === "transaction")
        return {
          hash: tx,
          to: request.entryPoint,
          blockNumber: "0x14",
          blockHash: hash,
          transactionIndex: "0x0",
        };
      if (input.type === "transaction_receipt")
        return {
          transactionHash: tx,
          blockNumber: "0x14",
          blockHash: hash,
          transactionIndex: "0x0",
          status: "0x1",
          gasUsed: "0x2a",
          logs,
        };
      if (["canonical_block", "finalized_block", "block_by_hash"].includes(input.type))
        return block;
      throw new Error("unexpected observation read");
    }),
  };
}

(requirePostgres ? describe : describe.skip)("phone revocation execution with PostgreSQL", () => {
  let fixture: PostgresFixture;
  beforeAll(async () => {
    fixture = await createPostgresFixture();
    await createPostgresOperationSchema(fixture.createPool());
  });
  afterAll(async () => {
    await fixture.end();
  });
  async function approved() {
    const pool = fixture.createPool();
    const f = await setupRevocation(createPostgresRelayStore({ pool }));
    const queued = await requestOwnerPhoneRevocation(f.input);
    await expectOk(
      await f.harness.handler(
        post(`/native/revocation-decisions/${queued.operationId}`, OWNER_TOKEN, {
          command: "approve",
          artifact: f.artifact(),
        }),
      ),
      200,
    );
    f.erase();
    await pool.end();
    return { queued, request: f.signingRequest };
  }
  async function open(
    value: Awaited<ReturnType<typeof approved>>,
    submission: OwnerPhoneRevocationExecutorInput["submission"],
    options: {
      finalized?: boolean;
      offline?: boolean;
      adapter?: (adapter: OperationStoreAdapter) => OperationStoreAdapter;
      now?: number;
    } = {},
  ) {
    const pool = fixture.createPool();
    const adapter = createPostgresOperationStoreAdapter({ pool });
    const executor = await createOwnerPhoneRevocationExecutor({
      store: createPostgresRelayStore({ pool }),
      kms: options.offline ? { encrypt: unavailable, decrypt: unavailable } : createTestKms(),
      operationId: value.queued.operationId,
      clock: createTestClock(options.now ?? 160_000),
      operations: options.adapter ? options.adapter(adapter) : adapter,
      observation: observation(value.request, options.finalized),
      submission,
    });
    return { executor, pool };
  }
  it("refuses pending custody before opening submission", async () => {
    const pool = fixture.createPool();
    const f = await setupRevocation(createPostgresRelayStore({ pool }));
    const queued = await requestOwnerPhoneRevocation(f.input);
    const submit = vi.fn(unavailable);
    await expect(
      createOwnerPhoneRevocationExecutor({
        store: f.harness.store,
        kms: f.harness.kms,
        clock: f.harness.clock,
        operationId: queued.operationId,
        operations: createPostgresOperationStoreAdapter({ pool }),
        observation: observation(f.signingRequest),
        submission: { openSubmission: submit, close: noClose },
      }),
    ).rejects.toMatchObject({ code: "relay_request_invalid" });
    expect(submit).not.toHaveBeenCalled();
    f.erase();
    await pool.end();
  });
  it("does not send when the attempted-state commit answer is lost", async () => {
    const value = await approved();
    const submit = vi.fn(unavailable);
    const a = await open(
      value,
      { openSubmission: submit, close: noClose },
      {
        adapter: (adapter) => ({
          ...adapter,
          async compareAndSwap(input) {
            const committed = await adapter.compareAndSwap(input);
            if ((input.next.value as { state: string }).state === "submission_attempted")
              throw new Error("commit answer lost");
            return committed;
          },
        }),
      },
    );
    await expect(a.executor.start(1000)).rejects.toBeDefined();
    expect(submit).not.toHaveBeenCalled();
    await a.executor.close();
    await a.pool.end();
    const b = await open(
      value,
      { openSubmission: submit, close: noClose },
      { offline: true, now: 999_000 },
    );
    expect((await b.executor.start(1000)).record.value.state).toBe("submission_attempted");
    await b.executor.observe(1000);
    expect(submit).not.toHaveBeenCalled();
    await b.executor.close();
    await b.pool.end();
  });
  it.each(["lost", "wrong-hash"])(
    "concurrent workers send once; %s answer recovers by observation",
    async (answer) => {
      const value = await approved();
      let sends = 0;
      const submit = vi.fn(async (prepared, signature) => {
        expect(prepared.userOperationHash).toBe(value.request.expectedDigest);
        expect(typeof signature === "string" && signature.length > 2).toBe(true);
        return {
          submit: async () => {
            sends += 1;
            if (answer === "lost") throw new Error("send answer lost");
            return { userOperationHash: `0x${"99".repeat(32)}` };
          },
          close: noClose,
        };
      });
      const a = await open(value, { openSubmission: submit, close: noClose });
      const b = await open(value, { openSubmission: submit, close: noClose });
      await Promise.all([a.executor.start(1000), b.executor.start(1000)]);
      expect(sends).toBe(1);
      expect(submit).toHaveBeenCalledTimes(1);
      await a.executor.close();
      await b.executor.close();
      await a.pool.end();
      await b.pool.end();
      const laterSubmit = vi.fn(unavailable);
      const c = await open(
        value,
        { openSubmission: laterSubmit, close: noClose },
        { offline: true, finalized: true, now: 999_000 },
      );
      expect((await c.executor.start(1000)).record.value.state).toBe("submission_attempted");
      const observed = await c.executor.observe(1000);
      expect(observed.record.value.state).toBe("finalized");
      expect(laterSubmit).not.toHaveBeenCalled();
      await c.executor.close();
      await c.pool.end();
      const d = await open(
        value,
        { openSubmission: laterSubmit, close: noClose },
        { offline: true, now: 1_000_000 },
      );
      expect((await d.executor.start(1000)).record.value.state).toBe("finalized");
      expect(laterSubmit).not.toHaveBeenCalled();
      const journal = new OperationStore(createPostgresOperationStoreAdapter({ pool: d.pool }));
      const key = {
        grantId: value.request.permissionRequest.requestId,
        chainId: value.request.chainId,
        kind: "revocation",
      };
      const current = await journal.get(key);
      if (!current) throw new Error("missing terminal operation");
      await journal.compareAndSwap({
        key,
        expectedStoreRevision: current.storeRevision,
        next: createOperation({
          identity: { ...current.value.identity, userOperationHash: `0x${"77".repeat(32)}` },
          preparedAt: 1001,
        }),
      });
      expect((await journal.getExact(key, value.request.expectedDigest))?.value.state).toBe(
        "finalized",
      );
      await expect(
        journal.compareAndSwap({
          key,
          expectedStoreRevision: current.storeRevision + 1,
          next: current.value,
        }),
      ).rejects.toMatchObject({ code: "store_identity_mismatch" });
      expect((await d.executor.start(1000)).record.value.state).toBe("finalized");
      await d.executor.close();
      await d.pool.end();
    },
  );
  it("refuses a fresh attempt after consent expiry", async () => {
    const value = await approved();
    const submit = vi.fn(unavailable);
    const a = await open(value, { openSubmission: submit, close: noClose }, { now: 999_000 });
    await expect(a.executor.start(1000)).rejects.toMatchObject({ code: "relay_expired" });
    expect(submit).not.toHaveBeenCalled();
    await a.executor.close();
    await a.pool.end();
  });
});
