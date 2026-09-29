---
"@oaath/protocol": minor
"@oaath/sdk": minor
"@oaath/testing": minor
---

Send independent jobs on caller-reserved lanes:
`grant.sendCalls({ chain, calls, lane: { id, nonceKey } })`. Each lane keeps
its own journal, its own "never resubmit on timeout" rule, and its own single
unresolved operation. `grant.getOperation({ chain, id, lane })` recovers the
exact operation on that lane. Lanes are never allocated for the caller; the
default lane is unchanged.

- A lane key must be one the runtime can represent (Kernel: 1 to 65535).
  Anything else fails with `oaath_client_input_invalid`.
- A lane is refused with `oaath_client_state_conflict` and source
  `operation_lane_permission_not_installed` until the permission is observed
  installed on that chain. Only the default lane enables on first use, so two
  lanes never race the install.
- `revoke()` leaves the Grant `revoking` while any execution lane on a target
  chain is unresolved or unreadable. Observe that operation to a terminal
  state, then call `revoke()` again.

Breaking advanced API change: `OaathQuoteRequest` carries `nonceKey`. Custom
quote ports must quote exactly that namespace and return it unchanged.
`createLocalAnvilFixture` accepts a test-only `submission` interposer.
`parseOperationLane` is exported from `@oaath/protocol`.
