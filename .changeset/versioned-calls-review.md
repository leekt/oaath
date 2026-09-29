---
"@oaath/sdk": minor
---

Grant and owner call reviews share one versioned contract,
`OAATH_CALLS_REVIEW_VERSION` (`oaath-calls-review-v1`), exported from the
package root with `parseOaathCallsReview` and the `OaathCallsReviewContract`
type. Semantic fields (`signer`, `enforcement`, `validation`,
`fallback.condition`, `fallback.feePayer`) stay closed enums. Identity fields
are opaque, bounded strings: `account: { address, implementation }` (for example
`kernel:0.3.3`), `route` and `fallback.route`. A new Kernel version or transport
adds identity values without changing the version. The parser rejects any other
version with `oaath_client_review_version_unsupported`.
`OaathOperationExecution.route` is an opaque string too.

Breaking changes: a review's `account` is now `{ address, implementation }`.
The owner review drops `kernelVersion`, adds `version`, `enforcement` (all
`none`) and `validation: "estimated"`, and reports
`capacity: { kind: "single-operation", detail }`. `detail` is transport-specific
and outside the contract.
