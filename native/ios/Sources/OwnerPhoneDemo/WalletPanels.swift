/**
 EXPERIMENTAL PREVIEW — the Device tab.

 Live facts only: real custody state, the registered public material, the
 bound account and configured chains, the paired relay, and the real unpair
 effect. The signing rules are rendered as the fixed invariants they are,
 never as toggles. Unpairing asks for confirmation because it forgets the
 bound credential on this phone.

 @author taek <leekt216@gmail.com>
 */
#if canImport(SwiftUI)
import OwnerPhone
import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

struct WalletDeviceScreen: View {
    @ObservedObject var model: DemoModel
    @State private var confirmingUnpair = false
    @State private var copied = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    WalletOwnerKeyCard(ownerKey: model.ownerKey)
                    accountSection
                    relaySection
                    rulesSection
                    recoveryNote
                }
                .padding(.horizontal, 20)
                .padding(.top, 8)
                .padding(.bottom, 24)
            }
            .walletScreen()
            .navigationTitle("Device")
        }
    }

    private var accountSection: some View {
        VStack(alignment: .leading, spacing: 9) {
            WalletSectionLabel(text: "Account")
            WalletCard {
                VStack(alignment: .leading, spacing: 14) {
                    WalletFactRow(
                        label: "Smart account · same address on every configured chain",
                        value: model.account ?? "Not derived")
                    #if canImport(UIKit)
                    if let account = model.account {
                        Button {
                            UIPasteboard.general.string = account
                            copied = true
                        } label: {
                            Label(copied ? "Copied" : "Copy address",
                                  systemImage: copied ? "checkmark" : "doc.on.doc")
                                .font(WalletTheme.speech(.subheadline, .medium))
                                .frame(minHeight: 44)
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(WalletTheme.teal)
                    }
                    #endif
                    WalletTheme.hairline.frame(height: 1)
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Configured chains")
                            .font(WalletTheme.speech(.footnote))
                            .foregroundStyle(WalletTheme.muted)
                        if model.chainIds.isEmpty {
                            Text("None").font(WalletTheme.speech(.body)).foregroundStyle(WalletTheme.ink)
                        } else {
                            WalletChipRow(items: model.chainIds.map { "Chain \($0)" })
                        }
                        Text("The service may run approved jobs on these chains. Revocation is confirmed chain by chain.")
                            .font(WalletTheme.speech(.footnote))
                            .foregroundStyle(WalletTheme.muted)
                    }
                }
            }
        }
    }

    private var relaySection: some View {
        VStack(alignment: .leading, spacing: 9) {
            WalletSectionLabel(text: "Paired relay")
            WalletCard {
                VStack(alignment: .leading, spacing: 14) {
                    WalletFactRow(
                        label: "Relay",
                        value: model.baseURLText.isEmpty ? "Not paired" : model.baseURLText)
                    Text("Requests arrive from this relay using this phone's credential. If the relay refuses the credential, the pairing clears itself.")
                        .font(WalletTheme.speech(.footnote))
                        .foregroundStyle(WalletTheme.muted)
                    if !model.statusLine.isEmpty {
                        WalletNotice(text: model.statusLine) { model.clearStatusLine() }
                    }
                    WalletSecondaryButton(title: "Unpair this phone", destructive: true) {
                        confirmingUnpair = true
                    }
                    .confirmationDialog(
                        "Unpair this phone?",
                        isPresented: $confirmingUnpair,
                        titleVisibility: .visible
                    ) {
                        Button("Unpair", role: .destructive) { model.unpair() }
                        Button("Cancel", role: .cancel) {}
                    } message: {
                        Text("This phone forgets the relay and its credential. Pending requests can no longer be approved here. To pair again you need a fresh pairing code.")
                    }
                }
            }
        }
    }

    private var rulesSection: some View {
        VStack(alignment: .leading, spacing: 9) {
            WalletSectionLabel(text: "Signing rules")
            WalletCard(padding: 0) {
                VStack(spacing: 0) {
                    ruleRow("hand.tap", "You decide every request",
                            "A notification or a tap only opens a review. Nothing is approved on open.")
                    WalletTheme.hairline.frame(height: 1).padding(.leading, 52)
                    ruleRow("number.square", "Match codes on every request",
                            "Each request carries eight characters. If the requesting app shows a code, it must match.")
                    WalletTheme.hairline.frame(height: 1).padding(.leading, 52)
                    ruleRow("xmark.shield", "Unverifiable requests are reject-only",
                            "If this phone can't rebuild what it would sign, it offers Reject only.")
                }
            }
            Text("These are fixed rules of this build, not settings.")
                .font(WalletTheme.speech(.footnote))
                .foregroundStyle(WalletTheme.muted)
        }
    }

    private var recoveryNote: some View {
        VStack(alignment: .leading, spacing: 9) {
            WalletSectionLabel(text: "If you lose this phone")
            Text("The owner key can't leave this device, so recovery needs another owner credential registered on the account. This preview doesn't manage owner registrations.")
                .font(WalletTheme.speech(.subheadline))
                .foregroundStyle(WalletTheme.ink)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func ruleRow(_ icon: String, _ title: String, _ detail: String) -> some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: icon)
                .font(WalletTheme.speech(.body, .medium))
                .foregroundStyle(WalletTheme.teal)
                .frame(width: 24)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(WalletTheme.speech(.subheadline, .semibold))
                    .foregroundStyle(WalletTheme.ink)
                Text(detail)
                    .font(WalletTheme.speech(.footnote))
                    .foregroundStyle(WalletTheme.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(14)
        .accessibilityElement(children: .combine)
    }
}

/// The custody fact this launch resolved: Enclave, simulator key, or none.
struct WalletOwnerKeyCard: View {
    let ownerKey: (any DemoOwnerSigning)?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Circle().fill(dot).frame(width: 8, height: 8)
                Text(title)
                    .font(WalletTheme.speech(.subheadline, .semibold))
                    .foregroundStyle(WalletTheme.inkText)
            }
            Text(detail)
                .font(WalletTheme.speech(.subheadline))
                .foregroundStyle(WalletTheme.inkText.opacity(0.82))
                .fixedSize(horizontal: false, vertical: true)
            if let material {
                Text("Public key \(material)")
                    .font(WalletTheme.mono(.caption))
                    .foregroundStyle(WalletTheme.inkText.opacity(0.7))
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(WalletTheme.ink)
        .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
        .accessibilityElement(children: .combine)
    }

    private var dot: Color {
        guard let ownerKey else { return WalletTheme.red }
        return ownerKey.secureEnclave ? WalletTheme.mint : WalletTheme.amber
    }

    private var title: String {
        guard let ownerKey else { return "Owner key unavailable" }
        return ownerKey.secureEnclave ? "Owner key in the Secure Enclave" : "Simulator owner key"
    }

    private var detail: String {
        guard let ownerKey else {
            return "This device could not create or load its P-256 key. Nothing can be signed until it can."
        }
        return ownerKey.secureEnclave
            ? "Generated inside this iPhone's Secure Enclave. It can't be exported, and every signature asks for your presence."
            : "No Secure Enclave here, so the key is a regular keychain P-256 key. A physical iPhone uses the Enclave."
    }

    private var material: String? {
        guard let ownerKey, let hex = try? ownerKey.publicMaterialHex() else { return nil }
        return "\(hex.prefix(10))…\(hex.suffix(6))"
    }
}

/// Wrapping row of small bordered chips.
struct WalletChipRow: View {
    let items: [String]

    var body: some View {
        WalletFlowLayout(spacing: 8) {
            ForEach(items, id: \.self) { item in
                Text(item)
                    .font(WalletTheme.mono(.footnote, .medium))
                    .foregroundStyle(WalletTheme.ink)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    .background(WalletTheme.chip)
                    .clipShape(Capsule())
            }
        }
    }
}

/// Minimal left-to-right wrapping layout.
struct WalletFlowLayout: Layout {
    var spacing: CGFloat

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width ?? .infinity
        var x: CGFloat = 0, y: CGFloat = 0, rowHeight: CGFloat = 0, maxX: CGFloat = 0
        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x > 0, x + size.width > width {
                x = 0
                y += rowHeight + spacing
                rowHeight = 0
            }
            x += size.width + spacing
            maxX = max(maxX, x - spacing)
            rowHeight = max(rowHeight, size.height)
        }
        return CGSize(width: maxX, height: y + rowHeight)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX, y = bounds.minY, rowHeight: CGFloat = 0
        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x > bounds.minX, x + size.width > bounds.maxX {
                x = bounds.minX
                y += rowHeight + spacing
                rowHeight = 0
            }
            subview.place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(size))
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
    }
}
#endif
