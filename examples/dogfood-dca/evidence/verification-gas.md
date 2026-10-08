# Verification gas evidence — 8 October 2026

OAAth's Cetane quote port rejects zero effective Kernel verification gas before
signing or operation publication. The runtime's explicitly configured floor is
still respected. No estimate retry, gas guess, submission retry, or new nonce
allocator was added. This is upstream commit `d7c38d5`, retained as patch 12 and
an exact local SDK archive; the main OAAth checkout remains untouched.

The negative regression first reproduced the old behavior (a zero-gas quote
was accepted). After the change, the positive and negative estimation cases,
transport and read-only tests passed: 25 tests. SDK typecheck, build and focused
lint passed. A packed public wallet consumer completed one real Kernel v4 owner
operation on Anvil, then repeated approval with zero additional sends. Product
checks passed: typecheck, lint, 39 tests and workspace builds. The packed
consumer dependency check still finds no viem production dependency.

Separate, explicitly authorized Arbitrum Sepolia diagnosis found that the
ZeroDev endpoint returned both zero and positive verification estimates. An
unsigned validation probe rejected zero with JSON-RPC -32602 and a minimum of
10,000 gas. Diagnostics intercepted signed operations without forwarding them;
no replacement of the previously attempted public operation was submitted.
Changing fee quotes and selecting a provider did not establish a reliable fix.
The public setup operation remains unresolved, and no finalized public purchase
is claimed. These checks are compatibility evidence, not a performance benchmark.
