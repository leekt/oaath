# Security

OAAth handles smart-account authority and operation submission. Please do not
open a public issue for a suspected vulnerability.

Report security issues privately through GitHub's security advisory flow for
`leekt/oaath`. Do not include production private keys, signatures, session
material, bearer tokens, approval artifacts, credential-bearing URLs, request
bodies, or raw provider errors in a report. Use minimal synthetic evidence.

The packages are pre-release and have not yet been authorized for production
use.

Owner signing is a closed experimental preview. Raw-digest requests are
reject-only. The account root signs in the OAAth portal with its wallet or
passkey, and only two profiles: the exact Kernel v4 replayable-install EIP-712
request of a Grant, which the portal derives with the SDK and compares with the
relay's before signing, and one exact owner-operation UserOperation hash. The
relay and the SDK each verify the root's signature before a Grant or operation
is used.

Generic ERC-7871 `wallet_sign`, ERC-7730 or application-supplied display
metadata, Permit/Permit2/application-purpose signing, and signing simulation
remain unsupported and deferred.
