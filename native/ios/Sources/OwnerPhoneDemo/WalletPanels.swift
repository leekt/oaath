/**
 EXPERIMENTAL PREVIEW — Activity (design 1c) and Security (design 1e).

 Activity: this build keeps no durable operation history — the web half owns
 operations and their evidence — so the feed is a labeled sample of the
 vocabulary (in-flight steps, chain-local receipts, honest missing-receipt
 language). Security renders live facts only: real custody state, the real
 registered public material, the real paired relay, and the real unpair
 effect. The signing rules are rendered as the fixed invariants they are,
 never as toggles.

 @author taek <leekt216@gmail.com>
 */
#if canImport(SwiftUI)
import OwnerPhone
import SwiftUI

struct WalletActivityView: View {
    @ObservedObject var model: DemoModel
    @State private var filter = "All"
    private let filters = ["All", "Arbitrum", "Robinhood", "Ethereum"]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                Text("Activity")
                    .font(WalletTheme.speech(30, .semibold))
                    .foregroundStyle(WalletTheme.ink)
                HStack(spacing: 7) {
                    ForEach(filters, id: \.self) { name in
                        Button {
                            filter = name
                        } label: {
                            Text(name)
                                .font(WalletTheme.speech(12.5, .medium))
                                .foregroundStyle(filter == name ? WalletTheme.inkText : WalletTheme.muted)
                                .padding(.horizontal, 13)
                                .padding(.vertical, 7)
                                .background(filter == name ? WalletTheme.ink : WalletTheme.card)
                                .clipShape(Capsule())
                                .overlay(
                                    Capsule().stroke(
                                        filter == name ? Color.clear : WalletTheme.border, lineWidth: 1)
                                )
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(.top, 14)

                HStack(spacing: 8) {
                    WalletSectionLabel(text: "In flight")
                    WalletSampleBadge()
                }
                .padding(.top, 22)
                .padding(.bottom, 9)
                Text("This preview keeps no operation history; the web half owns operations and their evidence. Rows below illustrate the vocabulary.")
                    .font(WalletTheme.speech(11))
                    .foregroundStyle(WalletTheme.faint)
                    .padding(.bottom, 9)

                WalletCard(emphasized: true) {
                    VStack(alignment: .leading, spacing: 13) {
                        HStack(alignment: .top, spacing: 12) {
                            VStack(alignment: .leading, spacing: 3) {
                                Text("Swap 250 USDC → ETH")
                                    .font(WalletTheme.speech(15, .semibold))
                                    .foregroundStyle(WalletTheme.ink)
                                Text("app.example · session key · Arbitrum One")
                                    .font(WalletTheme.speech(12))
                                    .foregroundStyle(WalletTheme.muted)
                            }
                            Spacer()
                            WalletStatusPill.submitted()
                        }
                        VStack(alignment: .leading, spacing: 9) {
                            step("Prepared · identity bound", "14:02:11", done: true)
                            step("Submitted to bundler", "14:02:13", done: true)
                            step("Waiting for inclusion", "—", done: false)
                        }
                        VStack(alignment: .leading, spacing: 6) {
                            Text("userOpHash 0x8c31…f7a2")
                                .font(WalletTheme.mono(11))
                                .foregroundStyle(WalletTheme.muted)
                            Text("No receipt yet. A missing receipt is not proof it dropped — nothing is resubmitted automatically.")
                                .font(WalletTheme.speech(11.5))
                                .foregroundStyle(WalletTheme.muted)
                        }
                        .padding(.top, 12)
                        .overlay(alignment: .top) {
                            WalletDashedDivider()
                        }
                    }
                }

                HStack(spacing: 8) {
                    WalletSectionLabel(text: "Today")
                    WalletSampleBadge()
                }
                .padding(.top, 24)
                .padding(.bottom, 9)
                WalletCard(padding: 0) {
                    VStack(spacing: 0) {
                        historyRow(
                            "Batch · 2 calls", "approve + swap · wallet_sendCalls",
                            pill: .included(), note: "block 284,119,204")
                        WalletTheme.hairline.frame(height: 1)
                        historyRow(
                            "Sent 40 USDC", "to 0x4b0c…9d21 · Robinhood Chain",
                            pill: .included(), note: "fee sponsored")
                        WalletTheme.hairline.frame(height: 1)
                        historyRow(
                            "Rejected signing request", "raw digest · no device derivation",
                            pill: .rejected(), note: nil)
                    }
                }
            }
            .padding(.horizontal, 20)
            .padding(.top, 12)
            .padding(.bottom, 24)
        }
    }

    private func step(_ label: String, _ time: String, done: Bool) -> some View {
        HStack(spacing: 9) {
            Circle()
                .fill(done ? WalletTheme.teal : WalletTheme.dash)
                .frame(width: 7, height: 7)
            Text(label)
                .font(WalletTheme.speech(12.5))
                .foregroundStyle(done ? WalletTheme.ink : WalletTheme.muted)
            Spacer()
            Text(time)
                .font(WalletTheme.mono(11))
                .foregroundStyle(WalletTheme.muted)
        }
    }

    private func historyRow(
        _ title: String, _ detail: String, pill: WalletStatusPill, note: String?
    ) -> some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(WalletTheme.speech(14.5, .medium))
                    .foregroundStyle(WalletTheme.ink)
                Text(detail)
                    .font(WalletTheme.speech(12))
                    .foregroundStyle(WalletTheme.muted)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 5) {
                pill
                if let note {
                    Text(note)
                        .font(WalletTheme.mono(11))
                        .foregroundStyle(WalletTheme.muted)
                }
            }
        }
        .padding(14)
    }
}

struct WalletDashedDivider: View {
    var body: some View {
        Line()
            .stroke(WalletTheme.dash, style: StrokeStyle(lineWidth: 1, dash: [4, 4]))
            .frame(height: 1)
    }

    private struct Line: Shape {
        func path(in rect: CGRect) -> Path {
            var path = Path()
            path.move(to: CGPoint(x: 0, y: rect.midY))
            path.addLine(to: CGPoint(x: rect.width, y: rect.midY))
            return path
        }
    }
}

struct WalletSecurityView: View {
    @ObservedObject var model: DemoModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                Text("Security")
                    .font(WalletTheme.speech(30, .semibold))
                    .foregroundStyle(WalletTheme.ink)

                ownerKeyCard.padding(.top, 18)

                WalletSectionLabel(text: "Signing policy")
                    .padding(.top, 22)
                    .padding(.bottom, 9)
                WalletCard(padding: 0) {
                    VStack(spacing: 0) {
                        policyRow(
                            "Reject un-derivable digests",
                            "Raw digests this device can't rebuild are always reject-only")
                        WalletTheme.hairline.frame(height: 1).padding(.leading, 14)
                        policyRow(
                            "Require match-code check",
                            "Every request shows eight characters the web page must match")
                        WalletTheme.hairline.frame(height: 1).padding(.leading, 14)
                        policyRow(
                            "Explicit taps decide",
                            "A push or tap only opens review; nothing approves on open")
                    }
                }
                Text("These are this build's invariants, not options.")
                    .font(WalletTheme.speech(11))
                    .foregroundStyle(WalletTheme.faint)
                    .padding(.top, 7)

                WalletSectionLabel(text: "Paired relay")
                    .padding(.top, 22)
                    .padding(.bottom, 9)
                WalletCard(padding: 14) {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(model.baseURLText.isEmpty ? "Not paired" : model.baseURLText)
                            .font(WalletTheme.mono(14, .medium))
                            .foregroundStyle(WalletTheme.ink)
                        Text("Bound with this device's credential. If the relay ever refuses it, pairing clears itself and you start over.")
                            .font(WalletTheme.speech(11.5))
                            .foregroundStyle(WalletTheme.muted)
                        WalletSecondaryButton(title: "Unpair this device", destructive: true, height: 40) {
                            model.unpair()
                        }
                    }
                }

                VStack(alignment: .leading, spacing: 8) {
                    WalletSectionLabel(text: "If you lose this phone")
                    Text("The Enclave key cannot leave this device, so recovery is another registered owner credential on the account. This preview does not read owner registrations — review them in the web half.")
                        .font(WalletTheme.speech(12.5))
                        .foregroundStyle(WalletTheme.ink)
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .overlay(
                    RoundedRectangle(cornerRadius: 18, style: .continuous)
                        .strokeBorder(WalletTheme.dash, style: StrokeStyle(lineWidth: 1, dash: [4, 4]))
                )
                .padding(.top, 14)
            }
            .padding(.horizontal, 20)
            .padding(.top, 12)
            .padding(.bottom, 24)
        }
    }

    private var ownerKeyCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Circle().fill(custodyDot).frame(width: 7, height: 7)
                Text(custodyTitle)
                    .font(WalletTheme.mono(10, .semibold))
                    .kerning(1.1)
                    .foregroundStyle(WalletTheme.inkText)
            }
            Text(custodyBody)
                .font(WalletTheme.speech(13))
                .foregroundStyle(WalletTheme.inkText.opacity(0.75))
            if let material = registeredMaterial {
                Text("\(material) · registered as owner credential")
                    .font(WalletTheme.mono(11))
                    .foregroundStyle(WalletTheme.inkText.opacity(0.5))
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(WalletTheme.ink)
        .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
    }

    private var custodyDot: Color {
        guard let ownerKey = model.ownerKey else { return WalletTheme.red }
        return ownerKey.secureEnclave ? WalletTheme.mint : WalletTheme.amber
    }

    private var custodyTitle: String {
        guard let ownerKey = model.ownerKey else { return "OWNER KEY · UNAVAILABLE" }
        return ownerKey.secureEnclave
            ? "OWNER KEY · SECURE ENCLAVE"
            : "OWNER KEY · SIMULATOR FALLBACK"
    }

    private var custodyBody: String {
        guard let ownerKey = model.ownerKey else {
            return "This device could not create or load a P-256 key. Nothing can be signed until it can."
        }
        return ownerKey.secureEnclave
            ? "P-256, generated inside the Enclave with user presence required. The private key never leaves this iPhone and cannot be exported."
            : "A regular keychain P-256 key. No Secure Enclave is available here; a physical iPhone uses the Enclave."
    }

    private var registeredMaterial: String? {
        guard let ownerKey = model.ownerKey,
              let material = try? ownerKey.publicMaterialHex()
        else { return nil }
        return "\(material.prefix(8))…\(material.suffix(4))"
    }

    private func policyRow(_ title: String, _ detail: String) -> some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(WalletTheme.speech(14.5, .medium))
                    .foregroundStyle(WalletTheme.ink)
                Text(detail)
                    .font(WalletTheme.speech(11.5))
                    .foregroundStyle(WalletTheme.muted)
            }
            Spacer()
            Text("ALWAYS")
                .font(WalletTheme.mono(9.5, .semibold))
                .foregroundStyle(WalletTheme.teal)
                .padding(.horizontal, 8)
                .padding(.vertical, 5)
                .background(WalletTheme.tealWash)
                .clipShape(Capsule())
        }
        .padding(14)
    }
}
#endif
