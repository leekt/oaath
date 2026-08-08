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
reject-only. The only owner-signing request that can be approved is the exact
current Kernel v4 replayable-install EIP-712 profile with its bound P-256
owner. The native app derives and binds that digest locally and passes only the
verified digest to user-presence-capable custody. Host and simulator evidence
does not prove a physical-device prompt or provide a released physical-custody
guarantee.

Generic ERC-7871 `wallet_sign`, ERC-7730 or application-supplied display
metadata, Permit/Permit2/application-purpose signing, and signing simulation
remain unsupported and deferred.
