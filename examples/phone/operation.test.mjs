import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { encodeAbiParameters, encodeEventTopics } from "viem";
import { entryPoint07Abi } from "viem/account-abstraction";
import {
  AtomicPermissionReservation,
  AtomicReservationLane,
  cacheImmutableKernelReads,
  canonicalDisplay,
  captureCanonicalDisplay,
  captureOperationTransactionHash,
  captureSponsorship,
  DOCUMENTED_LIVE_FLOW_REQUESTS,
  LIVE_FINALITY_MAX_ANCESTRY_DEPTH,
  LIVE_RECEIPT_POLL_ATTEMPTS,
  LIVE_RPC_MAX_REQUESTS,
  LIVE_TRANSPORT_CONFIG,
  LiveRequestBudget,
  OneShotPairing,
  OperationLane,
  observeOnce,
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
    for (let depth = 0; depth < LIVE_FINALITY_MAX_ANCESTRY_DEPTH; depth += 1)
      call("eth_getBlockByHash:parent");
    call("eth_getBlockByNumber:rebound-finalized");
    call("eth_getBlockByNumber:rebound-inclusion");
  }
  assert.equal(budget.snapshot().count, DOCUMENTED_LIVE_FLOW_REQUESTS);
  assert.equal(DOCUMENTED_LIVE_FLOW_REQUESTS, 72);
  while (budget.snapshot().count < LIVE_RPC_MAX_REQUESTS) call("headroom");
  assert.throws(() => call("one-too-many"), {
    message: "zerodev_request_budget_exhausted",
  });
  assert.equal(budget.snapshot().count, 81);
});

test("README documents the exported live budget without drift", () => {
  const readme = readFileSync(new URL("./README.md", import.meta.url), "utf8");
  assert.match(
    readme,
    new RegExp(`up to \\*\\*${LIVE_FINALITY_MAX_ANCESTRY_DEPTH}\\*\\* ancestry\\s+parent reads`),
  );
  assert.match(readme, /\*\*2\*\* canonical endpoint rebounds per operation/u);
  assert.match(
    readme,
    new RegExp(
      `three-operation sponsored sequence\\s+is \\*\\*${DOCUMENTED_LIVE_FLOW_REQUESTS}\\*\\* requests`,
    ),
  );
  assert.match(readme, new RegExp(`hard cap of \\*\\*${LIVE_RPC_MAX_REQUESTS}\\*\\*`));
  assert.match(
    readme,
    new RegExp(
      `\\*\\*${LIVE_RPC_MAX_REQUESTS - DOCUMENTED_LIVE_FLOW_REQUESTS}\\*\\* requests of headroom`,
    ),
  );
  assert.match(readme, /at most \*\*four\*\* receipt\s+polls/u);
  assert.match(readme, /\*\*10 second\*\* timeout/u);
  assert.match(readme, /`retryCount: 0`/u);
  assert.match(readme, /no retry and no hidden fallback/u);
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

test("permission owner atomically reserves both lanes or mutates neither", async () => {
  const permissionLane = new AtomicReservationLane();
  const signatureLane = new AtomicReservationLane();
  const owner = new AtomicPermissionReservation(permissionLane, signatureLane);
  const created = [];
  const handle = async (token) => {
    owner.reserve(token, "session");
    await Promise.resolve();
    created.push(token);
  };
  const settled = await Promise.allSettled([handle("one"), handle("two")]);
  assert.equal(settled.filter(({ status }) => status === "fulfilled").length, 1);
  assert.deepEqual(permissionLane.active?.token, signatureLane.active?.token);
  assert.equal(created.length, 1);

  const occupiedSignature = new AtomicReservationLane();
  occupiedSignature.reserve("owner", { purpose: "owner-operation" });
  const absentPermission = new AtomicReservationLane();
  const blocked = new AtomicPermissionReservation(absentPermission, occupiedSignature);
  assert.throws(() => blocked.reserve("permission", "session"), {
    message: "signature_request_lane_occupied",
  });
  assert.equal(absentPermission.active, null);
  assert.deepEqual(occupiedSignature.active, {
    token: "owner",
    state: "pre-submit",
    requestId: null,
    purpose: "owner-operation",
  });
});

test("permission cleanup is token-owned and only definitely pre-submission", () => {
  const permissionLane = new AtomicReservationLane();
  const signatureLane = new AtomicReservationLane();
  const owner = new AtomicPermissionReservation(permissionLane, signatureLane);
  owner.reserve("clean", "session");
  assert.throws(() => owner.releasePreSubmission("other"), {
    message: "reservation_lane_mismatch",
  });
  owner.releasePreSubmission("clean");
  assert.equal(permissionLane.active, null);
  assert.equal(signatureLane.active, null);

  owner.reserve("ambiguous", "session");
  owner.markPossiblySubmitted("ambiguous");
  assert.throws(() => owner.releasePreSubmission("ambiguous"), {
    message: "reservation_not_pre_submission",
  });
  assert.equal(permissionLane.active?.state, "possibly-submitted");
  assert.equal(signatureLane.active?.state, "possibly-submitted");
});

test("ambiguous relay create retains a possibly-submitted reservation and forbids retry", async () => {
  const lane = new AtomicReservationLane();
  let creates = 0;
  const create = async (token) => {
    lane.reserve(token, { purpose: "permission" });
    try {
      creates += 1;
      await Promise.resolve();
      throw new Error("response_lost");
    } catch (error) {
      lane.markPossiblySubmitted(token);
      throw error;
    }
  };
  await assert.rejects(create("owned"), { message: "response_lost" });
  assert.equal(lane.active.state, "possibly-submitted");
  await assert.rejects(create("retry"), { message: "reservation_lane_occupied" });
  assert.equal(creates, 1);
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

test("Promise.all submit routes share one owner and send exactly once", async () => {
  const userOperationHash = `0x${"61".repeat(32)}`;
  const operation = {
    operationId: "concurrent-submit",
    status: "prepared",
    prepared: { userOperationHash },
  };
  let releaseSend;
  const sendGate = new Promise((resolve) => {
    releaseSend = resolve;
  });
  let signatures = 0;
  let sends = 0;
  const route = () =>
    submitOnce({
      operation,
      signature: async () => {
        signatures += 1;
        await Promise.resolve();
        return "0xsigned";
      },
      send: async () => {
        sends += 1;
        await sendGate;
        return { userOperationHash };
      },
      observe: async () => null,
      terminalize: () => assert.fail("missing evidence cannot terminalize"),
    });
  const first = route();
  const second = route();
  releaseSend();
  const results = await Promise.all([first, second]);
  assert.equal(signatures, 1);
  assert.equal(sends, 1);
  assert.deepEqual(results[0], results[1]);
  assert.equal(operation.status, "unresolved");
});

test("Promise.all observation routes coalesce and preserve the terminal transition", async () => {
  const userOperationHash = `0x${"62".repeat(32)}`;
  const operation = {
    operationId: "concurrent-observe",
    status: "unresolved",
    prepared: { userOperationHash },
  };
  let releaseObservation;
  const observationGate = new Promise((resolve) => {
    releaseObservation = resolve;
  });
  let observations = 0;
  const route = () =>
    observeOnce({
      operation,
      observe: async () => {
        observations += 1;
        return await observationGate;
      },
      terminalize: (current, evidence) => {
        current.status = evidence.status;
        current.result = Object.freeze({
          status: evidence.status,
          operationId: current.operationId,
        });
        return current.result;
      },
    });
  const first = route();
  const second = route();
  releaseObservation({ status: "included" });
  const results = await Promise.all([first, second]);
  assert.equal(observations, 1);
  assert.equal(operation.status, "included");
  assert.deepEqual(results, [operation.result, operation.result]);
});

test("submit and observe route race joins submission, never resubmits or downgrades terminal", async () => {
  const userOperationHash = `0x${"63".repeat(32)}`;
  const operation = {
    operationId: "submit-observe-race",
    status: "prepared",
    prepared: { userOperationHash },
  };
  let releaseSend;
  const sendGate = new Promise((resolve) => {
    releaseSend = resolve;
  });
  let sends = 0;
  let observations = 0;
  const terminalize = (current) => {
    current.status = "included";
    current.result = Object.freeze({ status: "included", operationId: current.operationId });
    return current.result;
  };
  const submitRoute = () =>
    submitOnce({
      operation,
      signature: "0xsigned",
      send: async () => {
        sends += 1;
        await sendGate;
        return { userOperationHash };
      },
      observe: async () => {
        observations += 1;
        return { status: "included" };
      },
      terminalize,
    });
  const observeRoute = () =>
    observeOnce({
      operation,
      observe: async () => assert.fail("joined observer must not start a second read"),
      terminalize,
    });
  const submitted = submitRoute();
  const observed = observeRoute();
  releaseSend();
  const [submitResult, observeResult] = await Promise.all([submitted, observed]);
  assert.equal(sends, 1);
  assert.equal(observations, 1);
  assert.deepEqual(submitResult, observeResult);
  assert.equal(operation.status, "included");

  const idempotent = await submitRoute();
  assert.deepEqual(idempotent, operation.result);
  assert.equal(sends, 1);
  assert.equal(operation.status, "included");
});

test("stale route catch after lane replacement mutates neither operation", async () => {
  const oldOperation = {
    operationId: "old-operation",
    status: "prepared",
    prepared: { userOperationHash: `0x${"64".repeat(32)}` },
  };
  const newOperation = {
    operationId: "new-operation",
    status: "prepared",
    prepared: { userOperationHash: `0x${"65".repeat(32)}` },
  };
  let activeOperationId = oldOperation.operationId;
  let rejectSend;
  const sendGate = new Promise((_, reject) => {
    rejectSend = reject;
  });
  const stale = submitOnce({
    operation: oldOperation,
    signature: "0xsigned",
    send: async () => await sendGate,
    observe: async () => null,
    terminalize: () => assert.fail("stale submit cannot terminalize"),
    ownsLane: (current) => activeOperationId === current.operationId,
  });
  activeOperationId = newOperation.operationId;
  oldOperation.status = "cancelled";
  oldOperation.result = Object.freeze({
    status: "cancelled",
    operationId: oldOperation.operationId,
  });
  rejectSend(new Error("operation_lane_mismatch"));
  assert.deepEqual(await stale, oldOperation.result);
  assert.equal(oldOperation.status, "cancelled");
  assert.equal(newOperation.status, "prepared");
  assert.equal(activeOperationId, newOperation.operationId);

  const idempotent = await submitOnce({
    operation: oldOperation,
    signature: "0xignored",
    send: async () => assert.fail("terminal retry cannot send"),
    observe: async () => assert.fail("terminal retry cannot observe"),
    terminalize: () => assert.fail("terminal retry cannot terminalize"),
  });
  assert.deepEqual(idempotent, oldOperation.result);
});

test("discovered transaction hash survives later provider failure and conflicts never overwrite", async () => {
  const first = `0x${"51".repeat(32)}`;
  const conflicting = `0x${"52".repeat(32)}`;
  const operation = {};
  assert.equal(captureOperationTransactionHash(operation, first), first);
  await assert.rejects(
    (async () => {
      captureOperationTransactionHash(operation, first);
      throw new Error("provider_failed_after_discovery");
    })(),
    { message: "provider_failed_after_discovery" },
  );
  assert.equal(operation.transactionHash, first);
  assert.throws(() => captureOperationTransactionHash(operation, conflicting), {
    message: "operation_transaction_hash_conflict",
  });
  assert.equal(operation.transactionHash, first);
  assert.equal(Object.getOwnPropertyDescriptor(operation, "transactionHash").writable, false);
});

const operationEvidence = ({ success = true, eventCount = 1, mutateLog, mutateRpc } = {}) => {
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
  const baseLog = {
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
  const log = mutateLog ? mutateLog(structuredClone(baseLog)) : baseLog;
  const operation = {
    chainId: 421614,
    prepared: {
      userOperationHash,
      entryPoint: { address: entryPoint },
      userOperation: { sender: account, nonce: "7" },
    },
  };
  const receipt = {
    transactionHash,
    to: entryPoint,
    status: "0x1",
    blockHash,
    blockNumber: "0x7",
    logs: Array(eventCount).fill(log),
  };
  const transaction = {
    hash: transactionHash,
    to: entryPoint,
    chainId: "0x66eee",
    blockHash,
    blockNumber: "0x7",
  };
  const inclusion = {
    number: "0x7",
    hash: blockHash,
    parentHash: `0x${"40".repeat(32)}`,
  };
  const finalized = {
    number: "0x8",
    hash: finalizedHash,
    parentHash: blockHash,
  };
  const rpc = async (method, params) => {
    let value;
    if (method === "eth_getTransactionReceipt") value = receipt;
    else if (method === "eth_getTransactionByHash") value = transaction;
    else if (method === "eth_getBlockByHash") value = inclusion;
    else if (method === "eth_getBlockByNumber")
      value = params[0] === "finalized" || params[0] === "0x8" ? finalized : inclusion;
    if (mutateRpc) value = mutateRpc(method, params, structuredClone(value));
    return value;
  };
  return { operation, transactionHash, rpc, baseLog };
};

test("only a parent-linked and canonically rebound finalized event authorizes inclusion", async () => {
  const fixture = operationEvidence();
  const evidence = await validateFinalizedUserOperation(fixture);
  assert.equal(evidence.status, "included");
  assert.equal(evidence.userOperationHash, fixture.operation.prepared.userOperationHash);
  assert.equal(evidence.finalizedBlockNumber, "0x8");
});

test("unrelated finalized heads and endpoint reorgs remain unresolved", async () => {
  await assert.rejects(
    validateFinalizedUserOperation(
      operationEvidence({
        mutateRpc(method, params, value) {
          if (method === "eth_getBlockByNumber" && params[0] === "finalized")
            return { ...value, parentHash: `0x${"55".repeat(32)}` };
          if (method === "eth_getBlockByHash") return { ...value, hash: `0x${"55".repeat(32)}` };
          return value;
        },
      }),
    ),
    { message: "operation_finality_evidence_invalid" },
  );
  await assert.rejects(
    validateFinalizedUserOperation(
      operationEvidence({
        mutateRpc(method, params, value) {
          if (method === "eth_getBlockByNumber" && params[0] === "0x7")
            return { ...value, hash: `0x${"56".repeat(32)}` };
          return value;
        },
      }),
    ),
    { message: "operation_finality_evidence_invalid" },
  );
});

test("missing, duplicate, and contradictory EntryPoint events remain unresolved", async () => {
  for (const eventCount of [0, 2])
    await assert.rejects(validateFinalizedUserOperation(operationEvidence({ eventCount })), {
      message: "operation_event_evidence_invalid",
    });
  const fixture = operationEvidence();
  const contradictory = {
    ...fixture.baseLog,
    data: fixture.baseLog.data.replace(/01$/u, "00"),
  };
  await assert.rejects(
    validateFinalizedUserOperation(
      operationEvidence({
        mutateRpc(method, _params, value) {
          return method === "eth_getTransactionReceipt"
            ? { ...value, logs: [fixture.baseLog, contradictory] }
            : value;
        },
      }),
    ),
    { message: "operation_event_evidence_invalid" },
  );
});

test("hostile noncanonical EntryPoint topic/data/quantity shapes fail closed", async () => {
  const mutations = [
    (log) => ({ ...log, topics: [...log.topics, `0x${"00".repeat(32)}`] }),
    (log) => ({ ...log, data: `${log.data}00` }),
    (log) => ({ ...log, topics: [log.topics[0].toUpperCase(), ...log.topics.slice(1)] }),
    (log) => ({ ...log, topics: [`0x${"11".repeat(31)}`, ...log.topics.slice(1)] }),
    (log) => ({ ...log, blockNumber: "0x07" }),
    (log) => ({ ...log, data: `${log.data.slice(0, -2)}0A` }),
  ];
  for (const mutateLog of mutations)
    await assert.rejects(validateFinalizedUserOperation(operationEvidence({ mutateLog })), {
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
