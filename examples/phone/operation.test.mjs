import assert from "node:assert/strict";
import test from "node:test";
import { encodeAbiParameters, encodeEventTopics } from "viem";
import { entryPoint07Abi } from "viem/account-abstraction";
import {
  cacheImmutableKernelReads,
  canonicalDisplay,
  captureCanonicalDisplay,
  captureSponsorship,
  DOCUMENTED_LIVE_FLOW_REQUESTS,
  LIVE_RECEIPT_POLL_ATTEMPTS,
  LIVE_RPC_MAX_REQUESTS,
  LIVE_TRANSPORT_CONFIG,
  LiveRequestBudget,
  OneShotPairing,
  OperationLane,
  operationAction,
  pairingSecretMayRender,
  permissionMaterializedAfter,
  submitOnce,
  validateBundlerAcceptance,
  validateFinalizedUserOperation,
  withFreshSequence,
} from "./operation.mjs";

const validSponsorship = Object.freeze({
  callGasLimit: "0x1",
  verificationGasLimit: "0x2",
  preVerificationGas: "0x3",
  paymaster: `0x${"11".repeat(20)}`,
  paymasterVerificationGasLimit: "0x4",
  paymasterPostOpGasLimit: "0x5",
  paymasterData: "0x1234",
});

test("instruments the exact worst-case live RPC call graph under one hard budget", () => {
  const budget = new LiveRequestBudget();
  const call = (method) => budget.take(method);
  // Actual cache misses across owner bind, session bind, then the one deployed
  // state refresh: immutable successful evidence is reused, account state is not.
  for (const method of [
    "eth_getCode", // owner authority (also its initial module)
    "eth_chainId",
    "eth_getCode",
    "eth_getCode",
    "eth_getCode", // three runtime hashes
    "eth_call",
    "eth_call", // factory implementation/account
    "eth_getCode", // counterfactual account (not cached)
    "eth_getCode", // session signer
    "eth_getCode", // counterfactual account on session bind
    "eth_getCode", // deployed account refresh
    "eth_getStorageAt", // deployed implementation binding
  ])
    call(method);
  for (let operation = 0; operation < 3; operation += 1) {
    call("eth_call"); // EntryPoint getNonce, including enable mode.
    call("zd_sponsorUserOperation");
    call("eth_sendUserOperation");
    for (let poll = 0; poll < LIVE_RECEIPT_POLL_ATTEMPTS; poll += 1)
      call("eth_getUserOperationReceipt");
    call("eth_getTransactionReceipt");
    call("eth_getTransactionByHash");
    call("eth_getBlockByNumber:finalized");
    call("eth_getBlockByNumber:canonical");
  }
  assert.equal(budget.snapshot().count, DOCUMENTED_LIVE_FLOW_REQUESTS);
  assert.equal(DOCUMENTED_LIVE_FLOW_REQUESTS, 45);
  while (budget.snapshot().count < LIVE_RPC_MAX_REQUESTS) call("headroom");
  assert.throws(() => call("one-too-many"), {
    message: "zerodev_request_budget_exhausted",
  });
  assert.equal(budget.snapshot().count, 54);
});

test("binding cache reuses immutable success but refreshes account state", async () => {
  const calls = [];
  const reads = cacheImmutableKernelReads({
    async read(request) {
      calls.push(request);
      if (request.type === "code" && request.address === "account")
        return calls.filter((call) => call.address === "account").length < 2 ? "0x" : "0x12";
      return request.type === "chain_id" ? 421614 : "0x12";
    },
  });
  const chain = { type: "chain_id", chainId: 421614 };
  const module = { type: "code", chainId: 421614, address: "module" };
  const account = { type: "code", chainId: 421614, address: "account" };
  await reads.read(chain);
  await reads.read(chain);
  await reads.read(module);
  await reads.read(module);
  assert.equal(await reads.read(account), "0x");
  assert.equal(await reads.read(account), "0x12");
  assert.equal(await reads.read(account), "0x12");
  assert.equal(calls.length, 4);
});

test("live transport disables hidden retries", () => {
  assert.deepEqual(LIVE_TRANSPORT_CONFIG, { retryCount: 0 });
  assert.ok(Object.isFrozen(LIVE_TRANSPORT_CONFIG));
});

test("captures canonical sponsorship quantities before BigInt conversion", () => {
  const captured = captureSponsorship(validSponsorship);
  assert.equal(captured.callGasLimit, "1");
  assert.ok(Object.isFrozen(captured));
});

test("rejects malformed or ambiguous sponsorship wire values", () => {
  const malformed = [
    { callGasLimit: true },
    { callGasLimit: 1 },
    { callGasLimit: "1" },
    { callGasLimit: " 0x1" },
    { callGasLimit: "+0x1" },
    { callGasLimit: "0x01" },
    { callGasLimit: "0xA" },
    { callGasLimit: "0x" },
    { callGasLimit: `0x1${"0".repeat(64)}` },
    { paymaster: `0x${"AA".repeat(20)}` },
    { paymaster: "0x11" },
    { paymasterData: "0x1" },
    { paymasterData: "0xzz" },
    { extra: "0x0" },
  ];
  for (const change of malformed)
    assert.throws(() => captureSponsorship({ ...validSponsorship, ...change }), {
      message: "zerodev_sponsorship_response_invalid",
    });
});

test("canonical display pins every exact byte and binds the digest", () => {
  const digest = `0x${"4b".repeat(32)}`;
  const display = canonicalDisplay({ z: "last", digest, nested: { b: 2, a: 1 } });
  assert.equal(display, `{"digest":"${digest}","nested":{"a":1,"b":2},"z":"last"}`);
  assert.equal(captureCanonicalDisplay(display, digest), display);
  for (const drift of [
    ` ${display}`,
    display.replace('"z":"last"', '"z":"gone","z":"last"'),
    display.replace(digest, `0x${"4c".repeat(32)}`),
    display.replace('"a":1,"b":2', '"b":2,"a":1'),
  ])
    assert.throws(() => captureCanonicalDisplay(drift, digest), {
      message: "signature_display_invalid",
    });
});

test("one unresolved lane blocks concurrent prepare until terminal observation", () => {
  const lane = new OperationLane();
  lane.claim("preparing");
  assert.throws(() => lane.claim("other"), { message: "operation_lane_occupied" });
  lane.replace("preparing", "operation-1");
  assert.throws(() => lane.release("operation-1", "unresolved"), {
    message: "operation_not_terminal",
  });
  assert.equal(lane.active, "operation-1");
  lane.release("operation-1", "reverted");
  lane.claim("operation-2");
  lane.release("operation-2", "included");
  assert.equal(lane.active, null);
});

test("reverted Anvil evidence cannot materialize permission", () => {
  assert.equal(
    permissionMaterializedAfter({ current: false, installsPermission: true, status: "reverted" }),
    false,
  );
  assert.equal(
    permissionMaterializedAfter({ current: false, installsPermission: true, status: "included" }),
    true,
  );
});

test("unresolved retry is observation-only and sends zero new operations", () => {
  let sends = 0;
  let observations = 0;
  const retry = (status) => {
    const action = operationAction(status);
    if (action === "submit") sends += 1;
    if (action === "observe") observations += 1;
  };
  retry("unresolved");
  retry("submitted");
  assert.equal(sends, 0);
  assert.equal(observations, 2);
});

test("bundler acceptance must equal the prepared hash", () => {
  const prepared = `0x${"11".repeat(32)}`;
  assert.deepEqual(validateBundlerAcceptance(prepared, prepared), { userOperationHash: prepared });
  assert.throws(() => validateBundlerAcceptance(prepared, `0x${"22".repeat(32)}`), {
    message: "zerodev_submission_hash_mismatch",
  });
});

test("pairing secret renders only in the interactive non-simulation UI", () => {
  assert.equal(pairingSecretMayRender({ simulate: false, isTTY: true }), true);
  assert.equal(pairingSecretMayRender({ simulate: false, isTTY: false }), false);
  assert.equal(pairingSecretMayRender({ simulate: true, isTTY: true }), false);
});

test("pairing reservation is atomic across concurrent handlers", async () => {
  const pairing = new OneShotPairing({ hash: "expected", expiresAt: 100 });
  const credentials = [];
  const devices = new Map();
  const handle = async (index) => {
    pairing.reserve({ hash: "expected", now: 1 });
    await Promise.resolve();
    const credential = `credential-${index}`;
    credentials.push(credential);
    devices.set(credential, { index });
    return credential;
  };
  const settled = await Promise.allSettled([handle(1), handle(2)]);
  assert.equal(settled.filter(({ status }) => status === "fulfilled").length, 1);
  assert.equal(settled.filter(({ status }) => status === "rejected").length, 1);
  assert.equal(credentials.length, 1);
  assert.equal(devices.size, 1);
});

test("ambiguous receipt wait returns the same operation id and retry submits zero operations", async () => {
  const userOperationHash = `0x${"31".repeat(32)}`;
  const transactionHash = `0x${"32".repeat(32)}`;
  const operation = {
    operationId: "operation-ambiguous",
    status: "prepared",
    prepared: { userOperationHash },
  };
  let sends = 0;
  let observations = 0;
  const first = await submitOnce({
    operation,
    signature: "0x",
    send: async (_prepared, _signature, onTransactionHash) => {
      sends += 1;
      onTransactionHash(transactionHash);
      throw new Error("receipt wait failed");
    },
    observe: async () => {
      observations += 1;
    },
    terminalize: () => {},
  });
  assert.deepEqual(first, {
    status: "unresolved",
    operationId: "operation-ambiguous",
    userOperationHash,
    transactionHash,
  });
  assert.equal(operationAction(operation.status), "observe");
  // This is the GET boundary used by a second click: observe the occupied lane.
  if (operationAction(operation.status) === "observe") observations += 1;
  assert.equal(sends, 1);
  assert.equal(observations, 1);
});

const operationEvidence = ({ success = true, finalizedNumber = "0x8", eventCount = 1 } = {}) => {
  const userOperationHash = `0x${"41".repeat(32)}`;
  const transactionHash = `0x${"42".repeat(32)}`;
  const blockHash = `0x${"43".repeat(32)}`;
  const finalizedHash = `0x${"44".repeat(32)}`;
  const account = `0x${"45".repeat(20)}`;
  const entryPoint = `0x${"46".repeat(20)}`;
  const paymaster = `0x${"00".repeat(20)}`;
  const topics = encodeEventTopics({
    abi: entryPoint07Abi,
    eventName: "UserOperationEvent",
    args: { userOpHash: userOperationHash, sender: account, paymaster },
  });
  const log = {
    address: entryPoint,
    topics,
    data: encodeAbiParameters(
      [{ type: "uint256" }, { type: "bool" }, { type: "uint256" }, { type: "uint256" }],
      [7n, success, 1n, 1n],
    ),
    transactionHash,
    blockHash,
    blockNumber: "0x7",
    removed: false,
  };
  const operation = {
    chainId: 421614,
    prepared: {
      userOperationHash,
      entryPoint: { address: entryPoint },
      userOperation: { sender: account, nonce: "7" },
    },
  };
  const values = new Map([
    [
      "eth_getTransactionReceipt",
      {
        transactionHash,
        to: entryPoint,
        status: "0x1",
        blockHash,
        blockNumber: "0x7",
        logs: Array(eventCount).fill(log),
      },
    ],
    [
      "eth_getTransactionByHash",
      {
        hash: transactionHash,
        to: entryPoint,
        chainId: "0x66eee",
        blockHash,
        blockNumber: "0x7",
      },
    ],
  ]);
  const rpc = async (method, params) => {
    if (method === "eth_getBlockByNumber")
      return params[0] === "finalized"
        ? { number: finalizedNumber, hash: finalizedHash }
        : { number: "0x7", hash: blockHash };
    return values.get(method);
  };
  return { operation, transactionHash, rpc };
};

test("only a finalized EntryPoint event authorizes inclusion", async () => {
  const fixture = operationEvidence();
  const evidence = await validateFinalizedUserOperation(fixture);
  assert.equal(evidence.status, "included");
  assert.equal(evidence.userOperationHash, fixture.operation.prepared.userOperationHash);
  assert.equal(evidence.finalizedBlockNumber, "0x8");

  await assert.rejects(
    validateFinalizedUserOperation(operationEvidence({ finalizedNumber: "0x6" })),
    { message: "operation_finality_evidence_invalid" },
  );
});

test("missing or ambiguous EntryPoint events remain unresolved evidence", async () => {
  for (const eventCount of [0, 2])
    await assert.rejects(validateFinalizedUserOperation(operationEvidence({ eventCount })), {
      message: "operation_event_evidence_invalid",
    });
});

test("EntryPoint success=false is terminal reverted despite successful outer transaction", async () => {
  const evidence = await validateFinalizedUserOperation(operationEvidence({ success: false }));
  assert.equal(evidence.status, "reverted");
});

test("every enable retry reads a fresh EntryPoint sequence", async () => {
  const reads = ["1", "2"];
  const first = await withFreshSequence({ mode: "enable-replayable" }, async () => reads.shift());
  const second = await withFreshSequence({ mode: "enable-replayable" }, async () => reads.shift());
  assert.equal(first.sequence, "1");
  assert.equal(second.sequence, "2");
  assert.notEqual(second.sequence, "0");
});
