---
"@oaath/sdk": minor
"@oaath/testing": patch
---

Service-approved Grants join the one `createOAAth` options shape.
`createOAAth({ url, fetch?, authorization?, origin?, stores?, now?, session? })`
is now `createOAAth({ approvals: { kind: "service", url?, fetch?, authorization? }, origin?, stores?, now?, session? })`.
Top-level `url` is removed with no alias. `createOAAth()` no longer defaults to
the local development service, but `approvals: { kind: "service" }` without a
`url` still does. The new `OaathServiceOptions` and `OaathServiceApprovals`
types describe the shape, and service approvals return `Oaath`. The catch-all
`unknown` overload is gone, so a misspelled option is now a type error. The
injected `binding` composition is unchanged.
