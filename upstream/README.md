# OAAth prerequisites

The three focused patches apply in order to
`895bc93b6408537d736100ac20d577711313717c`. They keep canonical DCA terms in
protocol, executor enforcement in contracts, and keyed publication in SDK.
No Moesi dependency enters OAAth. Each patch stays under the repository's
25-file / 2,000-added-line limit.

These are isolated prerequisites; the sibling checkout's RPC deduplication
change is untouched. The transfer-only `IMPLEMENTATION_PLAN.md` at that
baseline is superseded for this milestone by this repository's
[implementation plan](../IMPLEMENTATION_PLAN.md).

To recreate the exact source worktree, from this repository:

```sh
git -C ../oaath worktree add -b dogfood-dca-foundation "$PWD/.local/oaath-dca" \
  895bc93b6408537d736100ac20d577711313717c
git -C .local/oaath-dca am "$PWD"/upstream/oaath/*.patch
bun install --cwd .local/oaath-dca
forge build --root .local/oaath-dca/packages/contracts
```

Normal product installation uses the retained tarballs and requires no source
worktree. `scripts/pack-dependencies.mjs` is a maintainer command: it rebuilds
from `.local/oaath-dca`, `.local/moesi-dca` and `../cetane`, then records artifact
checksums. Repacking a changed sibling source requires rerunning the proof.
