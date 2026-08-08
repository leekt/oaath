import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { p256 } from "@noble/curves/nist.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import {
  createKernelV4ReplayableInstallTypedData,
  hashCanonicalEip712TypedData,
  hashOwnerSigningRequest,
  OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
  OAATH_OWNER_SIGNING_ARTIFACT_VERSION,
  OAATH_OWNER_SIGNING_REQUEST_VERSION,
  serializeOwnerSigningArtifact,
} from "@oaath/protocol";
import { sponsorUserOperation as sponsorZeroDevUserOperation } from "@zerodev/sdk";
import { encodeAbiParameters, encodeEventTopics } from "viem";
import { entryPoint07Abi } from "viem/account-abstraction";
import {
  requireSameOwnedLocalTransactionInclusion,
  validateOwnedLocalTransactionInclusion,
} from "./local-anvil-evidence.mjs";
import {
  AtomicPermissionReservation,
  AtomicReservationLane,
  cacheImmutableKernelReads,
  captureOperationTransactionHash,
  captureZeroDevSponsorship,
  createLiveUserOperationObserver,
  createStackOperationObserver,
  DOCUMENTED_LIVE_FLOW_REQUESTS,
  LIVE_RECEIPT_POLL_ATTEMPTS,
  LIVE_RPC_MAX_REQUESTS,
  LIVE_TRANSPORT_CONFIG,
  LiveRequestBudget,
  LOCAL_FINALITY_MAX_ANCESTRY_DEPTH,
  OneShotPairing,
  OperationLane,
  observeOnce,
  operationAction,
  pairingSecretMayRender,
  permissionMaterializedAfter,
  submitOnce,
  validateBundlerAcceptance,
  validateOwnedLocalFinalizedUserOperation,
  withFreshSequence,
} from "./operation.mjs";
import { captureKernelOwnerSignature } from "./owner-signing.mjs";

const validSponsorship = Object.freeze({
  callGasLimit: 1n,
  verificationGasLimit: 2n,
  preVerificationGas: 3n,
  paymaster: `0x${"Ab".repeat(20)}`,
  paymasterVerificationGasLimit: 4n,
  paymasterPostOpGasLimit: 5n,
  paymasterData: "0xABCD",
  maxFeePerGas: 6n,
  maxPriorityFeePerGas: 7n,
});

function createKernelOwnerArtifactInput() {
  const privateKey = p256.utils.randomPrivateKey();
  try {
    const account = `0x${"66".repeat(20)}`;
    const typedData = createKernelV4ReplayableInstallTypedData({
      account,
      nonce: "0",
      packages: [
        {
          moduleType: 1,
          module: `0x${"77".repeat(20)}`,
          moduleData: "0x",
          internalData: "0x",
        },
      ],
    });
    const expectedDigest = hashCanonicalEip712TypedData(typedData);
    const request = Object.freeze({
      version: OAATH_OWNER_SIGNING_REQUEST_VERSION,
      kind: "eip712",
      purpose: "kernel-enable",
      signer: Object.freeze({
        account,
        ownerCredential: Object.freeze({
          version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
          kind: "p256",
          publicKey: `0x${bytesToHex(p256.getPublicKey(privateKey, false))}`,
        }),
      }),
      typedData,
      expectedDigest,
      replay: Object.freeze({ nonce: "0", deadline: null }),
    });
    const signature = `0x${p256
      .sign(hexToBytes(expectedDigest.slice(2)), privateKey, { lowS: true, prehash: false })
      .toCompactHex()}`;
    const artifact = Object.freeze({
      version: OAATH_OWNER_SIGNING_ARTIFACT_VERSION,
      kind: "p256",
      requestHash: hashOwnerSigningRequest(request),
      signature,
    });
    return Object.freeze({
      request,
      artifact,
      canonical: serializeOwnerSigningArtifact(artifact),
    });
  } finally {
    privateKey.fill(0);
  }
}

function rejectsKernelOwnerArtifact(request, artifact) {
  assert.throws(() => captureKernelOwnerSignature(request, artifact), {
    message: "owner_signing_artifact_invalid",
  });
}

test("captures only the canonical artifact bound to the exact Kernel request", () => {
  const input = createKernelOwnerArtifactInput();
  assert.equal(
    captureKernelOwnerSignature(input.request, input.canonical) === input.artifact.signature,
    true,
  );

  rejectsKernelOwnerArtifact(input.request, null);
  rejectsKernelOwnerArtifact(input.request, "not-json");
  rejectsKernelOwnerArtifact(input.request, ` ${input.canonical}`);
  rejectsKernelOwnerArtifact(
    input.request,
    JSON.stringify({
      kind: input.artifact.kind,
      version: input.artifact.version,
      requestHash: input.artifact.requestHash,
      signature: input.artifact.signature,
    }),
  );
  rejectsKernelOwnerArtifact(
    input.request,
    serializeOwnerSigningArtifact({
      ...input.artifact,
      requestHash: `0x${"55".repeat(32)}`,
    }),
  );
});

test("rejects non-Kernel and non-P256 request authority", () => {
  const input = createKernelOwnerArtifactInput();
  const application = structuredClone(input.request);
  application.purpose = "application";
  rejectsKernelOwnerArtifact(application, input.canonical);

  const ecdsa = structuredClone(input.request);
  ecdsa.signer.ownerCredential = {
    version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
    kind: "ecdsa",
    address: `0x${"44".repeat(20)}`,
  };
  rejectsKernelOwnerArtifact(ecdsa, input.canonical);

  const webauthn = structuredClone(input.request);
  webauthn.signer.ownerCredential = {
    version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
    kind: "webauthn",
    publicKey: input.request.signer.ownerCredential.publicKey,
    authenticatorIdHash: `0x${"33".repeat(32)}`,
  };
  rejectsKernelOwnerArtifact(webauthn, input.canonical);

  rejectsKernelOwnerArtifact(
    {
      version: OAATH_OWNER_SIGNING_REQUEST_VERSION,
      kind: "raw-digest",
      digest: input.request.expectedDigest,
      reason: "No device-side derivation is available",
      decision: "reject-only",
    },
    input.canonical,
  );
});

test("instruments the exact worst-case live RPC call graph under one hard budget", () => {
  const budget = new LiveRequestBudget();
  const call = (method) => budget.take(method);
  // Actual cache misses across owner and session binding before the single
  // submission. Unproved live evidence never permits a deployed-state refresh.
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
  ])
    call(method);
  call("eth_call"); // one fresh EntryPoint nonce read
  call("zd_sponsorUserOperation");
  call("eth_sendUserOperation");
  for (let poll = 0; poll < LIVE_RECEIPT_POLL_ATTEMPTS; poll += 1)
    call("eth_getUserOperationReceipt");
  assert.equal(budget.snapshot().count, DOCUMENTED_LIVE_FLOW_REQUESTS);
  assert.equal(DOCUMENTED_LIVE_FLOW_REQUESTS, 17);
  assert.equal(
    budget.snapshot().methods.some(([method]) => method === "zd_sponsorUserOperation"),
    true,
  );
  assert.equal(LOCAL_FINALITY_MAX_ANCESTRY_DEPTH, 8);
  while (budget.snapshot().count < LIVE_RPC_MAX_REQUESTS) call("headroom");
  assert.throws(() => call("one-too-many"), {
    message: "zerodev_request_budget_exhausted",
  });
  assert.equal(budget.snapshot().count, 26);
});

test("README documents the exported live budget without drift", () => {
  const readme = readFileSync(new URL("./README.md", import.meta.url), "utf8");
  assert.match(
    readme,
    new RegExp(
      `single-submission live sequence\\s+is \\*\\*${DOCUMENTED_LIVE_FLOW_REQUESTS}\\*\\* requests`,
    ),
  );
  assert.match(readme, new RegExp(`hard cap of \\*\\*${LIVE_RPC_MAX_REQUESTS}\\*\\*`));
  assert.match(
    readme,
    new RegExp(
      `\\*\\*${LIVE_RPC_MAX_REQUESTS - DOCUMENTED_LIVE_FLOW_REQUESTS}\\*\\* requests of headroom`,
    ),
  );
  assert.match(readme, /At most \*\*four\*\* one-second-spaced transaction-discovery/u);
  assert.match(readme, /standard ZeroDev bundler and paymaster/u);
  assert.doesNotMatch(readme, /provider=ULTRA_RELAY/u);
  assert.match(readme, /\*\*10 second\*\* timeout/u);
  assert.match(readme, /`retryCount: 0`/u);
  assert.match(readme, /no retry\s+and no\s+hidden fallback/u);
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

test("official ZeroDev SDK emits one structured v0.7 sponsorship request", async () => {
  let request;
  const entryPointAddress = "0x0000000071727de22e5e9d8baf0edac6f37da032";
  await sponsorZeroDevUserOperation(
    {
      chain: { id: 421614 },
      request: async (value) => {
        request = value;
        return {
          callGasLimit: "0x1",
          verificationGasLimit: "0x2",
          preVerificationGas: "0x3",
          paymaster: `0x${"11".repeat(20)}`,
          paymasterVerificationGasLimit: "0x4",
          paymasterPostOpGasLimit: "0x5",
          paymasterData: "0x1234",
          maxFeePerGas: "0x6",
          maxPriorityFeePerGas: "0x7",
        };
      },
    },
    {
      userOperation: {
        sender: `0x${"22".repeat(20)}`,
        nonce: 0n,
        callData: "0x",
        signature: `0x${"00".repeat(65)}`,
        chainId: 421614,
        entryPointAddress,
      },
    },
  );
  assert.equal(request.method, "zd_sponsorUserOperation");
  assert.equal(request.params.length, 1);
  assert.equal(request.params[0].chainId, 421614);
  assert.equal(request.params[0].entryPointAddress, entryPointAddress);
  assert.equal(request.params[0].shouldConsume, true);
  assert.equal("sponsorshipPolicyData" in request.params[0], false);
  assert.equal(request.params[0].userOp.signature, `0x${"00".repeat(65)}`);
});

test("captures the official SDK sponsorship result before hash binding", () => {
  const captured = captureZeroDevSponsorship(validSponsorship);
  assert.equal(captured.callGasLimit, "1");
  assert.equal(captured.maxFeePerGas, "6");
  assert.equal(captured.paymaster, `0x${"ab".repeat(20)}`);
  assert.equal(captured.paymasterData, "0xabcd");
  assert.ok(Object.isFrozen(captured));
});

test("rejects malformed SDK sponsorship results", () => {
  for (const change of [
    { callGasLimit: "1" },
    { callGasLimit: -1n },
    { callGasLimit: 1n << 256n },
    { paymaster: "0x11" },
    { paymasterData: "0x1" },
    { extra: 0n },
  ])
    assert.throws(() => captureZeroDevSponsorship({ ...validSponsorship, ...change }), {
      message: "zerodev_sponsorship_invalid",
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
  assert.equal(pairing.available(1), true);
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
  assert.equal(pairing.available(1), false);
  assert.equal(new OneShotPairing({ hash: "expected", expiresAt: 1 }).available(1), false);
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

test("coherent forged live views remain proof-unavailable and retry never resubmits", async () => {
  const userOperationHash = `0x${"53".repeat(32)}`;
  const transactionHash = `0x${"54".repeat(32)}`;
  const operation = {
    operationId: "live-forged-view",
    chainId: 421_614,
    status: "prepared",
    installsPermission: true,
    prepared: {
      userOperationHash,
      userOperation: { sender: `0x${"56".repeat(20)}` },
      entryPoint: { address: `0x${"57".repeat(20)}` },
    },
  };
  let claimedSuccess = true;
  const calls = [];
  const rpc = async (method, params) => {
    calls.push([method, params]);
    assert.equal(method, "eth_getUserOperationReceipt");
    return {
      userOpHash: userOperationHash,
      success: claimedSuccess,
      receipt: {
        transactionHash,
        status: claimedSuccess ? "0x1" : "0x0",
        blockHash: `0x${"58".repeat(32)}`,
        blockNumber: "0x7",
        logs: [{ claimedFinalizedEvent: true }],
      },
      finalizedBlock: { number: "0x8", hash: `0x${"59".repeat(32)}` },
    };
  };
  const observe = createStackOperationObserver({
    observe: createLiveUserOperationObserver({ rpc }),
  });
  await assert.rejects(observe(operation), { message: "operation_capture_callback_required" });
  let sends = 0;
  const first = await submitOnce({
    operation,
    signature: "0xsigned",
    send: async () => {
      sends += 1;
      return { userOperationHash };
    },
    observe,
    terminalize: () => assert.fail("ordinary live receipt data cannot terminalize"),
  });
  assert.deepEqual(first, {
    status: "unresolved",
    operationId: operation.operationId,
    userOperationHash,
    code: "receipt_proof_unavailable",
    transactionHash,
  });
  assert.equal(operation.transactionHash, transactionHash);
  assert.equal(
    permissionMaterializedAfter({ current: false, installsPermission: true, status: first.status }),
    false,
  );

  claimedSuccess = false;
  const retried = await observeOnce({
    operation,
    observe,
    terminalize: () => assert.fail("flipped provider success cannot terminalize"),
  });
  assert.deepEqual(retried, first);
  assert.equal(sends, 1, "observation retry must send zero additional user operations");
  assert.deepEqual(
    calls.map(([method]) => method),
    ["eth_getUserOperationReceipt", "eth_getUserOperationReceipt"],
  );
});

test("missing and unreadable live provider views share the proof-unavailable class", async () => {
  for (const providerView of ["missing", "unreadable"]) {
    const userOperationHash = `0x${(providerView === "missing" ? "5c" : "5d").repeat(32)}`;
    const operation = {
      operationId: `live-${providerView}`,
      status: "prepared",
      prepared: { userOperationHash },
    };
    let reads = 0;
    const observe = createLiveUserOperationObserver({
      rpc: async () => {
        reads += 1;
        if (providerView === "unreadable") throw new Error("private_provider_failure");
        return null;
      },
      sleep: (resolve) => resolve(),
    });
    const result = await submitOnce({
      operation,
      signature: "0xsigned",
      send: async () => ({ userOperationHash }),
      observe,
      terminalize: () => assert.fail("missing/unreadable live provider cannot terminalize"),
    });
    assert.equal(result.status, "unresolved");
    assert.equal(result.code, "receipt_proof_unavailable");
    assert.equal(operation.transactionHash, undefined);
    assert.equal(reads, providerView === "missing" ? LIVE_RECEIPT_POLL_ATTEMPTS : 1);
  }
});

test("stale production observer cannot capture discovered transaction evidence", async () => {
  const transactionHash = `0x${"58".repeat(32)}`;
  const operation = {
    operationId: "stale-live-observer",
    chainId: 421_614,
    status: "unresolved",
    prepared: {
      userOperationHash: `0x${"59".repeat(32)}`,
      userOperation: { sender: `0x${"5a".repeat(20)}` },
      entryPoint: { address: `0x${"5b".repeat(20)}` },
    },
  };
  let releaseReceipt;
  const receiptGate = new Promise((resolve) => {
    releaseReceipt = resolve;
  });
  const methods = [];
  const observe = createLiveUserOperationObserver({
    rpc: async (method) => {
      methods.push(method);
      if (method === "eth_getUserOperationReceipt") return await receiptGate;
      assert.fail("stale observer must stop before downstream validation");
    },
  });
  let activeOperationId = operation.operationId;
  const pending = observeOnce({
    operation,
    observe,
    terminalize: () => assert.fail("stale observer cannot terminalize"),
    ownsLane: (current) => activeOperationId === current.operationId,
  });
  activeOperationId = "replacement-operation";
  releaseReceipt({ receipt: { transactionHash } });
  assert.deepEqual(await pending, {
    status: "unresolved",
    operationId: operation.operationId,
    userOperationHash: operation.prepared.userOperationHash,
    code: "receipt_proof_unavailable",
  });
  assert.equal(operation.transactionHash, undefined);
  assert.deepEqual(methods, ["eth_getUserOperationReceipt"]);
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
    transactionIndex: "0x0",
    logIndex: "0x0",
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
    transactionIndex: "0x0",
    logs: Array(eventCount)
      .fill(null)
      .map((_, index) => ({ ...log, logIndex: `0x${index.toString(16)}` })),
  };
  const transaction = {
    hash: transactionHash,
    to: entryPoint,
    chainId: "0x66eee",
    blockHash,
    blockNumber: "0x7",
    transactionIndex: "0x0",
  };
  const inclusion = {
    number: "0x7",
    hash: blockHash,
    parentHash: `0x${"40".repeat(32)}`,
    transactions: [transactionHash],
  };
  const finalized = {
    number: "0x8",
    hash: finalizedHash,
    parentHash: blockHash,
    transactions: [],
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
  return {
    operation,
    transactionHash,
    rpc,
    baseLog,
    localInclusionInput: {
      entryPoint,
      userOperationHash,
      transactionHash,
      transactionReceipt: receipt,
      transaction,
      canonicalBlock: inclusion,
    },
  };
};

test("local inclusion rebound compares every immutable event field", () => {
  const captured = validateOwnedLocalTransactionInclusion(operationEvidence().localInclusionInput);
  const changedHash = `0x${"6a".repeat(32)}`;
  const changedAddress = `0x${"6b".repeat(20)}`;
  const mutations = [
    ["address", (log) => ({ ...log, address: changedAddress })],
    ["blockNumber", (log) => ({ ...log, blockNumber: "0x8" })],
    ["blockHash", (log) => ({ ...log, blockHash: changedHash })],
    ["transactionHash", (log) => ({ ...log, transactionHash: changedHash })],
    ["transactionIndex", (log) => ({ ...log, transactionIndex: "0x1" })],
    ["logIndex", (log) => ({ ...log, logIndex: "0x1" })],
    ["removed", (log) => ({ ...log, removed: true })],
    ["data", (log) => ({ ...log, data: `${log.data.slice(0, -2)}00` })],
    ["topics length", (log) => ({ ...log, topics: log.topics.slice(0, -1) })],
    [
      "topics order",
      (log) => ({ ...log, topics: [log.topics[0], log.topics[1], log.topics[3], log.topics[2]] }),
    ],
    ["topics content", (log) => ({ ...log, topics: [changedHash, ...log.topics.slice(1)] })],
  ];
  for (const [field, mutate] of mutations) {
    const rebound = structuredClone(captured);
    rebound.eventLog = mutate(rebound.eventLog);
    assert.throws(
      () => requireSameOwnedLocalTransactionInclusion(captured, rebound),
      {
        message: "owned_local_transaction_inclusion_invalid",
      },
      field,
    );
  }
});

test("only repository-owned local Anvil evidence authorizes inclusion", async () => {
  const fixture = operationEvidence();
  const evidence = await validateOwnedLocalFinalizedUserOperation(fixture);
  assert.equal(evidence.status, "included");
  assert.equal(evidence.userOperationHash, fixture.operation.prepared.userOperationHash);
  assert.equal(evidence.finalizedBlockNumber, "0x8");
});

test("unrelated finalized heads and endpoint reorgs remain unresolved", async () => {
  await assert.rejects(
    validateOwnedLocalFinalizedUserOperation(
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
    validateOwnedLocalFinalizedUserOperation(
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

test("canonical transaction membership rejects absent, duplicate, and ambiguous hashes", async () => {
  const otherHash = `0x${"47".repeat(32)}`;
  for (const transactions of [
    [],
    [operationEvidence().transactionHash, operationEvidence().transactionHash],
    [otherHash],
    [otherHash, operationEvidence().transactionHash],
    [{ hash: operationEvidence().transactionHash }],
  ])
    await assert.rejects(
      validateOwnedLocalFinalizedUserOperation(
        operationEvidence({
          mutateRpc(method, params, value) {
            const inclusionBlock =
              method === "eth_getBlockByHash" ||
              (method === "eth_getBlockByNumber" && params[0] === "0x7");
            return inclusionBlock ? { ...value, transactions } : value;
          },
        }),
      ),
      { message: "operation_finality_evidence_invalid" },
    );
});

test("transaction, receipt, and event indexes must be present, equal, canonical, and bounded", async () => {
  const cases = [
    (method, value) =>
      method === "eth_getTransactionReceipt" ? { ...value, transactionIndex: "0x1" } : value,
    (method, value) =>
      method === "eth_getTransactionByHash" ? { ...value, transactionIndex: "0x1" } : value,
    (method, value) =>
      method === "eth_getTransactionReceipt"
        ? { ...value, logs: value.logs.map((log) => ({ ...log, transactionIndex: "0x1" })) }
        : value,
    (method, value) => {
      if (method !== "eth_getTransactionReceipt") return value;
      const { transactionIndex: _missing, ...receipt } = value;
      return receipt;
    },
    (method, value) => {
      if (method !== "eth_getTransactionByHash") return value;
      const { transactionIndex: _missing, ...transaction } = value;
      return transaction;
    },
    (method, value) => {
      if (method !== "eth_getTransactionReceipt") return value;
      return {
        ...value,
        logs: value.logs.map(({ transactionIndex: _missing, ...log }) => log),
      };
    },
    (method, value) =>
      method === "eth_getTransactionReceipt" ? { ...value, transactionIndex: "0x01" } : value,
    (method, value) =>
      method === "eth_getTransactionByHash"
        ? { ...value, transactionIndex: "0x20000000000000" }
        : value,
    (method, value) =>
      method === "eth_getTransactionReceipt"
        ? {
            ...value,
            logs: value.logs.map((log) => ({ ...log, logIndex: "0x20000000000000" })),
          }
        : value,
  ];
  for (const mutate of cases)
    await assert.rejects(
      validateOwnedLocalFinalizedUserOperation(
        operationEvidence({
          mutateRpc(method, _params, value) {
            return mutate(method, value);
          },
        }),
      ),
      /operation_(?:transaction|event)_evidence_invalid/u,
    );
});

test("canonical inclusion block changes on number rebound remain unresolved", async () => {
  await assert.rejects(
    validateOwnedLocalFinalizedUserOperation(
      operationEvidence({
        mutateRpc(method, params, value) {
          return method === "eth_getBlockByNumber" && params[0] === "0x7"
            ? { ...value, transactions: [`0x${"48".repeat(32)}`] }
            : value;
        },
      }),
    ),
    { message: "operation_finality_evidence_invalid" },
  );
});

test("missing, duplicate, and contradictory EntryPoint events remain unresolved", async () => {
  for (const eventCount of [0, 2])
    await assert.rejects(
      validateOwnedLocalFinalizedUserOperation(operationEvidence({ eventCount })),
      {
        message: "operation_event_evidence_invalid",
      },
    );
  const fixture = operationEvidence();
  const contradictory = {
    ...fixture.baseLog,
    data: fixture.baseLog.data.replace(/01$/u, "00"),
  };
  await assert.rejects(
    validateOwnedLocalFinalizedUserOperation(
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
    await assert.rejects(
      validateOwnedLocalFinalizedUserOperation(operationEvidence({ mutateLog })),
      {
        message: "operation_event_evidence_invalid",
      },
    );
});

test("EntryPoint success=false is terminal reverted despite successful outer transaction", async () => {
  const evidence = await validateOwnedLocalFinalizedUserOperation(
    operationEvidence({ success: false }),
  );
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
