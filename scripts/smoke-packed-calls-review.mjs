/**
 * Packed call-review contract consumer.
 *
 * `consumer.mjs` is the whole consumer boundary: it checks `version` and the
 * semantic fields, and only fingerprints identity. It must accept a Kernel v3.3
 * owner bundler review, a Kernel v3.3 owner review with a handleOps fallback and
 * a Kernel v4 Grant review, and its source holds no Kernel-version or route
 * literal. Reviews come from the packed `@oaath/testing` Anvil fixtures.
 *
 * @author taek <leekt216@gmail.com>
 */
import { assert, createConsumer } from "./packed-consumer.mjs";

const CONSUMER = `
import { OAATH_CALLS_REVIEW_VERSION, parseOaathCallsReview } from "@oaath/sdk";

const SIGNERS = new Set(["session", "owner"]);
const VALIDATION = new Set(["not-estimated", "estimated", "account-rejected"]);

/** Accepts one review by contract version and semantic fields; returns its identity fingerprint. */
export function acceptReview(value) {
  const review = parseOaathCallsReview(value);
  if (review.version !== OAATH_CALLS_REVIEW_VERSION) throw new Error("review version");
  if (!SIGNERS.has(review.signer) || !VALIDATION.has(review.validation)) throw new Error("review semantics");
  if (review.signer === "session" && review.enforcement.calls !== "onchain") throw new Error("session enforcement");
  if (review.fallback !== null && review.fallback.condition !== "conclusive_bundler_rejection")
    throw new Error("fallback condition");
  return JSON.stringify([
    review.chainId,
    review.account.address,
    review.account.implementation,
    review.route,
    review.fallback === null ? null : [review.fallback.route, review.fallback.feePayer],
    review.calls,
  ]);
}
`;

const SMOKE = `
import assert from "node:assert/strict";
import { createLocalAnvilFixture, createLocalOwnerAnvilFixture } from "@oaath/testing/anvil";
import { acceptReview } from "./consumer.mjs";

const fingerprints = [];
const calls = [{ target: "0x4444444444444444444444444444444444444444", data: "0x12345678", value: "1" }];
let rejected = null;

const owner = await createLocalOwnerAnvilFixture();
try {
  const handle = (await owner.openClient()).account(owner.address).owner(owner.wallet);
  const direct = await handle.reviewCalls({ chain: owner.chainId, calls });
  assert.equal(direct.fallback, null);
  fingerprints.push(acceptReview(direct));
  const fallback = await handle.reviewCalls({
    chain: owner.chainId,
    calls,
    payer: { kind: "connected-eoa", wallet: owner.wallet },
  });
  assert.notEqual(fallback.fallback, null);
  fingerprints.push(acceptReview(fallback));
  try {
    acceptReview({ ...fallback, version: "oaath-calls-review-v2" });
  } catch (error) {
    rejected = error.code;
  }
  assert.equal(owner.signatureCount, 0);
  assert.equal(owner.bundlerSubmissionCount, 0);
} finally {
  await owner.close();
}

const grants = await createLocalAnvilFixture();
try {
  const connection = await (await grants.openClient()).connect();
  const grant = await connection.requestPermission({
    chainScope: "all", expiresIn: 1800, perChainOperationLimit: 1,
    permissions: [{ calls: [
      { target: "0x4444444444444444444444444444444444444444", selectors: ["0x12345678"], valueLimit: "1" },
    ] }],
  });
  const review = await grant.reviewCalls({ chain: grants.chainIds[0], calls });
  assert.equal(review.signer, "session");
  fingerprints.push(acceptReview(review));
  assert.equal(grants.submissionCount, 0);
  await grants.closeClient();
} finally {
  await grants.close();
}

assert.equal(rejected, "oaath_client_review_version_unsupported");
assert.equal(new Set(fingerprints).size, 3);
console.log("packed calls review: one contract version accepts v3.3 bundler, v3.3 fallback and v4 reviews; another version is rejected");
`;

const TYPES = `
import type { OaathCallsReview, OaathCallsReviewContract, OaathOwnerCallsReview } from "@oaath/sdk";
export function contract(review: Readonly<OaathCallsReview> | Readonly<OaathOwnerCallsReview>): Readonly<OaathCallsReviewContract> {
  return review;
}
`;

const FORBIDDEN = /kernel|\d+\.\d+\.\d+|erc4337|handleops|entrypoint|"bundler/iu;
assert(!FORBIDDEN.test(CONSUMER), "the review consumer names a Kernel version or a route");

const consumer = await createConsumer({
  label: "calls-review",
  packages: ["@oaath/protocol", "@oaath/sdk", "@oaath/server", "@oaath/testing"],
  files: { "consumer.mjs": CONSUMER, "smoke.mjs": SMOKE, "types.ts": TYPES },
});
try {
  consumer.typecheck();
  process.stdout.write(consumer.node("smoke.mjs"));
} finally {
  await consumer.cleanup();
}
