# @oaath/sdk

OAAth browser client and Kernel/ZeroDev runtime. See the
[repository README](https://github.com/leekt/oaath#readme).

The Draft ERC-7836 prepared-call profile accepts only the approved operator's
`secp256k1` or `webauthn-p256` external signature. Custody must be `frontend`
or `application_backend`; `oaath_hosted` is rejected before preparation.

Its opaque five-minute context is current-version-only, durable, and consumed
once. A recreated IndexedDB realm resumes the retained prepared operation and
any ambiguous send without preparing, signing, or submitting another operation;
older, unreadable, stale, and already-consumed contexts do not authorize a new
operation.
