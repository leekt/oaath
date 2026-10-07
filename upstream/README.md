# Upstream ownership and reproducible prerequisites

The current product consumes exact local tarballs. No sibling's uncommitted
work is imported. The original OAAth checkout and its RPC dedup change remain
untouched. DCA codec/contracts belong in this repository; the old DCA-specific
upstream patches are replaced by the authority/operation/custody series here.

OAAth source: clean `automation-foundation` branch at `ac05f79`, based on
`2f12e82` (merged Cetane protocol prerequisite). Patches in `oaath/` apply in
order. Each commit stays within 25 non-generated files and 2,000 added lines.

```sh
git -C ../oaath worktree add -b automation-replay "$PWD/.local/oaath-automation" 2f12e82
git -C .local/oaath-automation am "$PWD"/upstream/oaath/*.patch
bun install --cwd .local/oaath-automation
```

Use a different path/branch if the working tree already exists. These are local
prerequisites, not published package versions or merged upstream PRs.

| Repository | Owned capability | Issue / source |
| --- | --- | --- |
| OAAth | Cetane runtime adapter and neutral wallet types; no viem production dependency | [#385](https://github.com/leekt/oaath/issues/385) |
| OAAth | Stable scoped signer registry, sealed custody, PostgreSQL atomic creation/recovery | [#386](https://github.com/leekt/oaath/issues/386) |
| OAAth | Durable keyed execution over existing Grant publication owner | First patch in this series |
| Cetane | Key generation/address, ABI, typed data, operation hash, receipt codecs | [#7](https://github.com/leekt/cetane/issues/7), committed source `9862f7c` |
| Moesi | Finalized/safe snapshots and shared per-method admission | [#89](https://github.com/leekt/moesi/issues/89), [#90](https://github.com/leekt/moesi/issues/90), committed source `0ef5be6` |

Cetane and Moesi already contain those capabilities; no duplicate product-owned
observer or cryptographic library is introduced. Their clean worktrees are
`.local/cetane-automation` and `.local/moesi-automation`. Rebuild with
`scripts/pack-dependencies.mjs` after preparing these source worktrees and
building `recipes/dca/contracts`. `vendor/provenance.json` records exact hashes.
The product uses file overrides so package consumers resolve those exact
artifacts, not a similarly numbered registry package.
