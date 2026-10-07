---
name: "Automation"
description: "Clear instructions and retained activity for recurring purchases."
colors:
  background: "#ffffff"
  foreground: "#192c3d"
  primary: "#2255be"
  muted: "#edf2f7"
  muted-foreground: "#526578"
  border: "#d6e0e8"
  input: "#a9bac8"
  statement-surface: "#edf3fa"
  row-hover: "#f3f7fb"
  destructive: "#a93030"
  error: "#982b2b"
  error-surface: "#fff0ef"
  notice: "#195c45"
  notice-surface: "#e9f6f0"
  active: "#176746"
  pending: "#80590b"
  selection: "#dbe8ff"
  selection-foreground: "#153978"
typography:
  page-title:
    fontFamily: "ui-sans-serif, system-ui, sans-serif"
    fontSize: "clamp(28px, 3.2vw, 42px)"
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: "-0.025em"
  section-title:
    fontFamily: "ui-sans-serif, system-ui, sans-serif"
    fontSize: "21px"
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: "-0.015em"
  statement:
    fontFamily: "ui-sans-serif, system-ui, sans-serif"
    fontSize: "25px"
    fontWeight: 400
    lineHeight: 1.4
    letterSpacing: "-0.015em"
  subheading:
    fontFamily: "ui-sans-serif, system-ui, sans-serif"
    fontSize: "16px"
    fontWeight: 600
    lineHeight: 1.2
  body:
    fontFamily: "ui-sans-serif, system-ui, sans-serif"
    fontSize: "16px"
    fontWeight: 400
    lineHeight: 1.6
  help:
    fontFamily: "ui-sans-serif, system-ui, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.55
  label:
    fontFamily: "ui-sans-serif, system-ui, sans-serif"
    fontSize: "14px"
    fontWeight: 500
    lineHeight: 1
  button:
    fontFamily: "ui-sans-serif, system-ui, sans-serif"
    fontSize: "14px"
    fontWeight: 500
    lineHeight: "20px"
  amount:
    fontFamily: "ui-sans-serif, system-ui, sans-serif"
    fontSize: "15px"
    fontWeight: 600
    lineHeight: 1.6
  status:
    fontFamily: "ui-sans-serif, system-ui, sans-serif"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.6
  technical:
    fontFamily: "ui-monospace, monospace"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.6
rounded:
  control: "6px"
  notice: "8px"
  statement: "12px"
spacing:
  icon-gap: "8px"
  action-gap: "10px"
  row: "12px"
  inline: "16px"
  field-pair: "20px"
  field: "24px"
  panel: "28px"
  section-inset: "32px"
  section: "64px"
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.background}"
    typography: "{typography.button}"
    rounded: "{rounded.control}"
    padding: "8px 16px"
    height: "42px"
  button-outline:
    backgroundColor: "{colors.background}"
    textColor: "{colors.foreground}"
    typography: "{typography.button}"
    rounded: "{rounded.control}"
    padding: "8px 16px"
    height: "42px"
  button-ghost:
    backgroundColor: "transparent"
    textColor: "{colors.foreground}"
    typography: "{typography.button}"
    rounded: "{rounded.control}"
    padding: "8px 16px"
    height: "42px"
  input:
    backgroundColor: "{colors.background}"
    textColor: "{colors.foreground}"
    rounded: "{rounded.control}"
    padding: "4px 12px"
    height: "48px"
    width: "100%"
  statement-panel:
    backgroundColor: "{colors.statement-surface}"
    textColor: "{colors.foreground}"
    rounded: "{rounded.statement}"
    padding: "28px"
  notice-error:
    backgroundColor: "{colors.error-surface}"
    textColor: "{colors.error}"
    rounded: "{rounded.notice}"
    padding: "16px 20px"
  notice-success:
    backgroundColor: "{colors.notice-surface}"
    textColor: "{colors.notice}"
    rounded: "{rounded.notice}"
    padding: "16px 20px"
  disclosure:
    textColor: "{colors.foreground}"
    padding: "16px 0"
  activity-row:
    textColor: "{colors.foreground}"
    padding: "22px 4px"
    width: "100%"
  dialog:
    backgroundColor: "{colors.background}"
    textColor: "{colors.foreground}"
    padding: "24px"
    width: "min(100%, 32rem)"
---

# Design System: Automation

## Overview

**Creative North Star: "The Account Statement"**

A calm, daylight interface built from cool white, slate ink, aligned figures, and fine horizontal rules. The visual language makes instructions and their limits easy to read before an action, then gives retained activity the same orderly treatment.

React and the supplied shadcn/ui primitives provide the interaction foundation. Open regions carry the main content; pale blue panels group a summary or its next action. The character is restrained and practical: sans-serif text, legible controls, and short motion that acknowledges a change of view.

**Key Characteristics:**

- Slate text on white, with deep blue reserved for actions and focus.
- Tabular financial figures and quiet, aligned statement rows.
- Open content regions with a single tonal panel for supporting context.
- Readable body copy, explicit labels, and technical detail behind disclosures.

This record is derived from `sdk/src/styles.css`, `sdk/src/react.tsx`, the supplied `sdk/src/ui` components, the compiled `sdk/dist/styles.css`, and the DCA example shells. The hosted wallet entry in `examples/dca/hosted/app.tsx` and its generated shell styles in `deploy/build.mjs` extend the same system without adding a new token palette. Creation/review and hosted desktop/mobile captures in `.impeccable/review` document the composition. The hosted surface brief records the review verdict and evidence limits. The interface ships no raster imagery; screenshots are review evidence.

## Colors

The palette uses one deep blue accent against cool, low-chroma surfaces and slate text. Frontmatter values are normative.

### Primary

- **Deep Action Blue** (`primary`): primary buttons, keyboard focus, and the insertion caret. Primary hover lowers the background opacity to 90% over its current surface.

### Neutral

- **Paper White** (`background`): page canvas, controls, popovers, and dialogs.
- **Slate Ink** (`foreground`): headings, selected terms, and amounts.
- **Slate Text** (`muted-foreground`): explanatory text, row labels, secondary status, and metadata.
- **Cool Mist** (`muted`): quiet hover fills and technical code blocks.
- **Statement Blue** (`statement-surface`): the supporting statement/action panel.
- **Rule Gray** (`border`): horizontal separators and container borders.
- **Control Gray** (`input`): field and outline-button borders.
- **Row Wash** (`row-hover`): hover feedback across an activity row.
- **Selection Blue** and **Selection Ink** (`selection`, `selection-foreground`): selected text inside the creator.

### State colors

The error pair (`error`, `error-surface`) and notice pair (`notice`, `notice-surface`) put a readable message inside a tinted strip. `active` and `pending` color textual plan states. `destructive` remains available in the shared destructive button primitive; the current cancellation confirmation uses the normal primary action treatment.

**The Action Color Rule.** Use deep blue for primary actions, caret, and focus. Keep routine labels and values in slate; status colors accompany explicit status text.

## Typography

Use the system sans-serif stack for task titles and ordinary UI. This is a utilitarian application hierarchy; the implementation does not establish a separate brand display face. Technical values use the system monospace stack.

The frontmatter records the observed page-title, section-title, statement, subheading, body, help, label, button, amount, status, and technical roles. Body paragraphs stop at a comfortable maximum measure (68ch). Headings balance their lines and use semibold weight; statement sentences emphasize only their changing amounts and assets with semibold text. Labels stay in sentence case.

**The Financial Figure Rule.** Use tabular numerals throughout the creator and keep statement amounts aligned to the right. Reserve monospace for technical values and serialized data.

## Layout

The DCA shell centers the header, main content, and footer in a maximum-width container (1100px) with horizontal insets (36px). The header is a quiet brand row (100px high) above a fine divider. The local demonstration notice is ordinary contextual copy, not a new display-text role.

The creator uses two flexible tracks in a 1.25:1 ratio with a generous column gap (64px). This is the implemented ratio, rather than the provisional two-thirds description in the surface brief. Main content remains open; the supporting panel aligns to its top. The main heading region leaves a clear pause before the task. Activity is separated by a horizontal rule, a top inset (32px), and a section gap (64px).

The hosted wallet entry reuses the two-track composition for the introductory copy and testnet statement. After connection, a full-width account region holds balances, funding details and setup state above the supplied creator, separated by a fine rule. Its mobile columns use a 32px gap, and the connected heading/action row can wrap. The public testnet label stays in the quiet environment position in the header.

At the creator breakpoint (720px and below), the main grid becomes one column with a smaller gap (28px), and the statement/action panel follows the main content. Shell insets reduce to 22px; the header reduces to 78px. The field pair stays two equal columns with a 14px gap. Activity spacing reduces to 40px. Title rows and activity buttons may wrap. Values can use at most 56% of a statement row, and history tables scroll inside their own wrapper.

Use the frontmatter spacing steps for form rhythm and component interiors. Keep section-scale whitespace larger than field-scale whitespace; do not fill it with additional panels. The shared dialog switches its footer to a horizontal arrangement and gains rounded corners at the library breakpoint (640px).

## Elevation & Depth

The main page is flat and uses tone, whitespace, and fine dividers for separation. Inputs explicitly remove the primitive's shadow. Primary and outline buttons retain the shared shallow shadow; select popovers use a medium shadow and the cancellation dialog a larger one. The dialog overlay dims the page with black at 80% opacity. Exact shadow values are recorded in the sidecar from the compiled stylesheet.

**The Quiet Surface Rule.** Keep page regions flat. Use fine rules and pale surfaces to separate information; retain shallow control shadows and stronger elevation only for floating UI.

## Shapes

Controls use gently rounded corners; message strips use a slightly larger radius; the supporting panel uses the largest radius in the shared vocabulary. The frontmatter owns those radii. Statement and activity rows stay rectangular and rely on one-pixel rules. The current interface has no pill-chip vocabulary and no decorative clipped geometry. Lucide line icons accompany text actions or indicate a disclosure.

## Components

### Buttons

Use the supplied shadcn `Button` with primary, outline, and ghost variants. The creator gives buttons a minimum target height (42px) and keeps compact icons beside explicit labels. Primary hover changes the blue opacity; outline and ghost hover use the muted surface. Keyboard focus uses the primary ring and a visible outline (2px, offset 4px). Disabled controls reduce opacity, prevent duplicate interaction, and retain busy wording when an action is pending.

### Inputs and selection

Fields have white fills, fine control-gray borders, and the shared control radius. The creator increases inputs and the select trigger to a comfortable height (48px) and readable text size. Amount inputs reserve space for an adjacent currency unit. Labels use the actual Label primitive; the price-tolerance chooser is a Radix-backed Select. The fieldset disables editing while a create outcome is unresolved. A definitive create rejection releases the stored intent and restores editing; an uncertain outcome retains the same saved request.

### Statement and action panel

The pale supporting panel groups a live purchase statement, or the next owner action. Its padding follows the panel token on desktop and reduces to 24px on mobile. The panel has no border or drop shadow. Statements use larger text with selective emphasis, followed by ruled rows: muted labels on the left, stronger amounts on the right. Fees and signing explanations stay in ordinary body copy below their own rule.

### View changes and motion

Moving into review, another instruction, status, or back to creation focuses the page heading programmatically. The heading is focusable without entering the normal Tab order. The selected view enters with a brief opacity animation (0.92 to 1 over 180ms, ease-out), keyed by the selected instruction and review commitment. The panel also has a background-color transition (200ms, ease-out). The creator's reduced-motion media rule suppresses its descendant transitions and animations. Preserve these behaviors when extending the flow; do not add motion to financial values.

The hosted login transition waits for account data before focusing the account-setup heading or, for an already deployed account, the creator heading. Disconnect returns focus to the wallet-entry heading. The connected account heading becomes subordinate when the creator is present, preserving one primary task heading.

### Navigation, disclosures, and history

The example shell uses a compact text brand link and quiet environment text. Returning to the list uses a ghost action with a left arrow. Technical addresses and onchain terms use a native disclosure with a labeled summary, line icon, and ruled boundaries. Its technical values wrap anywhere; serialized data wraps inside a bounded scroll region (260px maximum height).

Saved automations are full-width clickable rows, with a thin lower divider, descriptive secondary text, explicit state, and a pale hover wash. Execution history uses a semantic table with fine horizontal rules and horizontal overflow when needed. Empty states are short text in the normal reading flow.

The hosted account region keeps funding addresses behind a native disclosure and shows balances in ordinary readable text. Once account setup is requested, persistent status text replaces the setup button; an available transaction hash adds a labeled explorer link. Refresh account remains the explicit confirmation check. Retain this state across reloads, and do not offer another setup send while its result is unresolved.

### Messages and cancellation

Errors use an alert role and the red message pair; confirmations use a status role and the green message pair. Both are padded, softly rounded strips above the content. Their text explains what happened and what remains possible. Cancellation uses the supplied AlertDialog with a title, explanation, a keep action, and a stop action. Preserve its Radix focus management and the distinction between requesting cancellation and displaying confirmed cancellation.

## Do's and Don'ts

### Do:

- Do use the shared React/shadcn controls and their keyboard behavior.
- Do align statement labels and values, keeping units adjacent to their amounts.
- Do let body copy wrap naturally and retain the mobile reading order.
- Do keep addresses and serialized authorization detail inside the technical disclosure.
- Do preserve the focus transfer, visible focus treatments, explicit status text, and reduced-motion override.

### Don't:

- Don't replace financial amounts or pending states with decorative graphics.
- Don't turn every content region into a bordered or elevated card.
- Don't use monospace for ordinary headings, labels, or explanatory prose.
- Don't present a saved instruction as approved while its authorization or chain confirmation is pending.
- Don't unlock an uncertain create request for editing or issue it again under a new identity.
