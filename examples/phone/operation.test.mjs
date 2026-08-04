import assert from "node:assert/strict";
import test from "node:test";
import {
  canonicalDisplay,
  captureCanonicalDisplay,
  captureSponsorship,
  DOCUMENTED_LIVE_FLOW_REQUESTS,
  LIVE_RPC_MAX_REQUESTS,
  LIVE_TRANSPORT_CONFIG,
  LiveRequestBudget,
  OperationLane,
  operationAction,
  pairingSecretMayRender,
  permissionMaterializedAfter,
  validateBundlerAcceptance,
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

test("instruments the documented live flow under one hard request budget", () => {
  const budget = new LiveRequestBudget();
  const flow = [
    ...Array(12).fill("eth_call"),
    ...Array(3).fill("zd_sponsorUserOperation"),
    ...Array(3).fill("eth_sendUserOperation"),
    ...Array(3)
      .fill(null)
      .flatMap(() => [
        ...Array(4).fill("eth_getUserOperationReceipt"),
        "eth_getTransactionReceipt",
        "eth_getTransactionByHash",
      ]),
  ];
  for (const method of flow) budget.take(method);
  assert.equal(flow.length, DOCUMENTED_LIVE_FLOW_REQUESTS);
  assert.equal(budget.snapshot().count, 36);
  while (budget.snapshot().count < LIVE_RPC_MAX_REQUESTS) budget.take("headroom");
  assert.throws(() => budget.take("one-too-many"), {
    message: "zerodev_request_budget_exhausted",
  });
  assert.equal(budget.snapshot().count, 48);
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
