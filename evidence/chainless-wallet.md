The connected-wallet adapter admits signing against the reviewed plan's chain. Kernel's permission-enable typed data intentionally uses a chainless domain; the domain must not be treated as the wallet network selector. A domain that does supply another chain is rejected before signing.

The packed-wallet regression failed before the fix with `RangeError: Not an integer` on the chainless permission. After the fix, the exact local SDK tarball signed both typed payloads and submitted one real Kernel v4 owner setup on owned Anvil. Repeating approval recovered the journal without another submission. Wrong wallet chain and conflicting typed-data chain both failed before another signature or send. Typecheck, lint, 39 TypeScript tests and workspace builds passed.

This evidence proves the local packed wallet path; hosted public-chain results are recorded separately.
