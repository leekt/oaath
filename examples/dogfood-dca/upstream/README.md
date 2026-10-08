# Upstream ownership and reproducible prerequisites

The product consumes Cetane 0.0.3 and Moesi 0.15.3 from npm, plus exact local
OAAth tarballs. No sibling's uncommitted
work is imported. The original OAAth checkout and its RPC dedup change remain
untouched. DCA codec/contracts belong in this repository; the old DCA-specific
upstream patches are replaced by the authority/operation/custody series here.

OAAth source: clean `automation-foundation` branch at `d7c38d5`, based on
`2f12e82` (merged Cetane protocol prerequisite). Patches in `oaath/` apply in
order. Each commit stays within 25 non-generated files and 2,000 added lines.

```sh
git -C ../oaath worktree add -b automation-replay "$PWD/.local/oaath-automation" 2f12e82
git -C .local/oaath-automation am "$PWD"/upstream/oaath/*.patch
bun install --cwd .local/oaath-automation
```

Use a different path/branch if the working tree already exists. The OAAth prerequisites remain local changes, not merged upstream PRs.

| Repository | Owned capability | Issue / source |
| --- | --- | --- |
| OAAth | Cetane runtime adapter and neutral wallet types; no viem production dependency | [#385](https://github.com/leekt/oaath/issues/385) |
| OAAth | Stable scoped signer registry, sealed custody, PostgreSQL atomic creation/recovery | [#386](https://github.com/leekt/oaath/issues/386) |
| OAAth | Durable keyed execution over existing Grant publication owner | First patch in this series |
| Cetane | Key generation/address, ABI, typed data, operation hash, receipt codecs | [#7](https://github.com/leekt/cetane/issues/7), [npm 0.0.3](https://www.npmjs.com/package/cetane/v/0.0.3) |
| Moesi | Finalized/safe snapshots and shared per-method admission | [#89](https://github.com/leekt/moesi/issues/89), [#90](https://github.com/leekt/moesi/issues/90), [npm 0.15.3](https://www.npmjs.com/package/moesi/v/0.15.3) |

Cetane and Moesi already contain those capabilities; no duplicate product-owned
observer or cryptographic library is introduced. Rebuild with
`scripts/pack-dependencies.mjs` after preparing the OAAth source worktree
and building `recipes/dca/contracts`. Cetane and Moesi are downloaded from npm, checked
against registry integrity and retained with SHA-256 provenance. The product
and packed consumer install exact registry versions; other prerequisites
use file overrides. No Cetane or Moesi source checkout is required.

The eleventh patch removes OAAth's temporary source-artifact override now that
Cetane 0.0.3 is published. Package contents are byte-for-byte identical to the
previous source-built 0.0.3 artifact; archive checksums differ.

The twelfth patch rejects zero effective verification gas from a bundler before signing or publication. It adds no automatic submission retries.
