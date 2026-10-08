---
version: 1
slug: "hosted-app"
primary_target: "examples/dca/hosted/app.tsx"
related_targets: ["deploy/build.mjs", "sdk/src/react.tsx"]
---

# Hosted wallet entry

Mode: Operate. Extend the approved account-statement composition and React/shadcn components to a public Arbitrum Sepolia wallet flow. The user selected connected wallets and direct implementation in code.

## Direction contract

THESIS: A recurring purchase begins with a wallet-owned account and ends in retained, confirmed activity.
OWN-WORLD: Inherit the creator's cool white, slate type, blue actions, thin rules and tabular amounts. Keep funding addresses behind a disclosure.
STORY: Connect and sign a login message, set up a smart account if needed, fund it with test assets, then use the existing exact-plan review and activity flow.
FIRST VIEWPORT: The existing header identifies the testnet. The left column explains wallet authorization and holds Connect wallet; the right statement lists the pair, daily cadence, test funds and missed-slot behavior. A connected wallet replaces this with account balances, funding disclosure and setup state above the supplied creator. Mobile stacks both regions.
FORM: Extension of the user-approved account-statement direction; no new visual-world selection. The immutable review remains the signature interaction.
FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance

## Implemented surface

The public example is authorized for `https://dca.taek.tech` on Arbitrum Sepolia with connected wallets and ZeroDev. The gateway's one-use login challenge binds the domain, chain, owner, nonce and expiry. Account setup creates the derived counterfactual smart account; funding and the supplied creator's exact-plan approval follow as separate steps.

The wallet entry uses the existing shadcn Button and account-statement styling. Connected balances, the funding disclosure and setup state occupy a ruled account region above the original creator. The testnet label remains visible in the header, and the funding disclosure distinguishes the smart-account address from the connected wallet.

Pending setup now persists in the browser journal and replaces the setup button with a status message, optional transaction link and explicit account refresh. Login focuses the account-setup or creator heading when the account data is ready; disconnect focuses the entry heading. These changes retain the established palette, typography and mobile reading order.

## Finish review and evidence

The Impeccable finish reviewer returned **ship** after the persistent pending-setup status and heading-focus transitions were corrected. Root `PRODUCT.md` records the hosted scope; `DESIGN.md` records the inherited visual system and these component behaviors. No raster assets ship.

Review captures are in the repository-root `.impeccable/review/` directory:

- `hosted-desktop.png` and `hosted-mobile.png`: wallet entry.
- `hosted-connected.png` and `hosted-connected-mobile.png`: connected account and creator composition.
- `hosted-pending-setup.png` and `hosted-pending-setup-mobile.png`: retained pending-setup presentation, produced with local intercepted API fixtures.

The pending captures demonstrate UI state, not an onchain transaction or finality. Live checks cover wallet login, smart-account setup and funding. Plan owner setup/approval finality remains under verification, and the review does not establish a completed public purchase.
