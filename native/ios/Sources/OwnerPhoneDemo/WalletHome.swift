/**
 EXPERIMENTAL PREVIEW — wallet home (design 1a) plus the Send preview (1b)
 and a Receive sheet.

 Live facts: the paired account address, custody state (Enclave or fallback),
 and the pending-authority card driven by the real inbox — Review opens the
 real consent flow; nothing on this screen decides anything. Balances, asset
 rows, and the Send flow have no live source in this build and carry the
 SAMPLE badge; the Send preview exposes no signing control at all.

 @author taek <leekt216@gmail.com>
 */
#if canImport(SwiftUI)
import OwnerPhone
import SwiftUI

struct WalletHomeView: View {
    @ObservedObject var model: DemoModel
    let openApprovals: () -> Void
    @State private var showingSend = false
    @State private var showingReceive = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                header
                totals
                actions
                if let item = model.inbox.first {
                    pendingCard(item)
                }
                assets
            }
            .padding(.horizontal, 20)
            .padding(.top, 12)
            .padding(.bottom, 24)
        }
        .sheet(isPresented: $showingSend) { WalletSendPreview() }
        .sheet(isPresented: $showingReceive) { WalletReceiveSheet(account: model.account) }
    }

    private var header: some View {
        HStack {
            HStack(spacing: 9) {
                Text("M")
                    .font(WalletTheme.mono(10, .bold))
                    .foregroundStyle(WalletTheme.inkText)
                    .frame(width: 22, height: 22)
                    .background(WalletTheme.ink)
                    .clipShape(Circle())
                Text("Main account")
                    .font(WalletTheme.speech(13, .medium))
                    .foregroundStyle(WalletTheme.ink)
                Text(shortAccount)
                    .font(WalletTheme.mono(11))
                    .foregroundStyle(WalletTheme.muted)
            }
            .padding(.vertical, 6)
            .padding(.leading, 8)
            .padding(.trailing, 12)
            .background(WalletTheme.card)
            .overlay(Capsule().stroke(WalletTheme.border, lineWidth: 1))
            .clipShape(Capsule())

            Spacer()

            HStack(spacing: 6) {
                Circle()
                    .fill(custody.color)
                    .frame(width: 6, height: 6)
                Text(custody.label)
                    .font(WalletTheme.mono(11, .medium))
                    .foregroundStyle(custody.color)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(WalletTheme.chip)
            .clipShape(Capsule())
        }
    }

    private var shortAccount: String {
        guard let account = model.account, account.count > 10 else { return "not derived" }
        return "\(account.prefix(6))…\(account.suffix(4))"
    }

    private var custody: (label: String, color: Color) {
        guard let ownerKey = model.ownerKey else { return ("KEY UNAVAILABLE", WalletTheme.red) }
        return ownerKey.secureEnclave
            ? ("ENCLAVE", WalletTheme.teal)
            : ("SIM FALLBACK", WalletTheme.amber)
    }

    private var totals: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                WalletSectionLabel(text: "Total · 3 chains")
                WalletSampleBadge()
            }
            HStack(alignment: .firstTextBaseline, spacing: 2) {
                Text("$4,182")
                    .font(WalletTheme.speech(46))
                    .foregroundStyle(WalletTheme.ink)
                Text(".65")
                    .font(WalletTheme.speech(26))
                    .foregroundStyle(WalletTheme.muted)
            }
            Text("This preview reads no balances; totals and assets are illustrative.")
                .font(WalletTheme.speech(10.5))
                .foregroundStyle(WalletTheme.faint)
        }
        .padding(.top, 26)
    }

    private var actions: some View {
        HStack(spacing: 10) {
            Button {
                showingSend = true
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "arrow.up").font(.system(size: 14, weight: .medium))
                    Text("Send").font(WalletTheme.speech(15, .medium))
                }
                .foregroundStyle(WalletTheme.inkText)
                .frame(maxWidth: .infinity)
                .frame(height: 48)
                .background(WalletTheme.ink)
                .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
            }
            .buttonStyle(.plain)
            Button {
                showingReceive = true
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "arrow.down").font(.system(size: 14, weight: .medium))
                    Text("Receive").font(WalletTheme.speech(15, .medium))
                }
                .foregroundStyle(WalletTheme.ink)
                .frame(maxWidth: .infinity)
                .frame(height: 48)
                .background(WalletTheme.card)
                .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .stroke(WalletTheme.border, lineWidth: 1)
                )
            }
            .buttonStyle(.plain)
        }
        .padding(.top, 20)
    }

    private func pendingCard(_ item: DemoInboxItem) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 8) {
                Text("AWAITING YOUR APPROVAL")
                    .font(WalletTheme.mono(10, .semibold))
                    .kerning(1.2)
                    .foregroundStyle(WalletTheme.inkText)
                Spacer()
                Text("\(model.inbox.count)")
                    .font(WalletTheme.mono(10))
                    .foregroundStyle(WalletTheme.inkText.opacity(0.6))
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 9)
            .background(WalletTheme.ink)

            VStack(alignment: .leading, spacing: 13) {
                WalletPendingRow(item: item) {
                    Task { await model.openInboxItem(item) }
                    openApprovals()
                }
            }
            .padding(14)
            .background(WalletTheme.card)
        }
        .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .stroke(WalletTheme.ink, lineWidth: 1)
        )
        .padding(.top, 22)
    }

    private var assets: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                WalletSectionLabel(text: "Assets")
                WalletSampleBadge()
                Spacer()
                Text("All chains")
                    .font(WalletTheme.speech(12, .medium))
                    .foregroundStyle(WalletTheme.teal)
            }
            WalletCard(padding: 0) {
                VStack(spacing: 0) {
                    assetRow("ETH", "Ether", "Arbitrum One · Ethereum", "0.842", "$2,946.11")
                    WalletTheme.hairline.frame(height: 1).padding(.leading, 60)
                    assetRow("USDC", "USD Coin", "Arbitrum One · Robinhood Chain", "1,056.54", "$1,056.54")
                    WalletTheme.hairline.frame(height: 1).padding(.leading, 60)
                    assetRow("ARB", "Arbitrum", "Arbitrum One", "180.00", "$180.00")
                }
            }
        }
        .padding(.top, 26)
    }

    private func assetRow(
        _ symbol: String, _ name: String, _ chains: String, _ amount: String, _ fiat: String
    ) -> some View {
        HStack(spacing: 12) {
            Text(symbol)
                .font(WalletTheme.mono(symbol.count > 3 ? 10 : 11, .medium))
                .foregroundStyle(WalletTheme.ink)
                .frame(width: 34, height: 34)
                .background(WalletTheme.chip)
                .clipShape(Circle())
                .overlay(Circle().stroke(WalletTheme.border, lineWidth: 1))
            VStack(alignment: .leading, spacing: 2) {
                Text(name).font(WalletTheme.speech(15, .medium)).foregroundStyle(WalletTheme.ink)
                Text(chains).font(WalletTheme.speech(11.5)).foregroundStyle(WalletTheme.muted)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 2) {
                Text(amount).font(WalletTheme.mono(15, .medium)).foregroundStyle(WalletTheme.ink)
                Text(fiat).font(WalletTheme.speech(11.5)).foregroundStyle(WalletTheme.muted)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 13)
    }
}

/// Send review (design 1b) as a labeled preview: this build reviews and
/// approves operations prepared by the web half; it does not originate sends,
/// so no signing control is rendered.
struct WalletSendPreview: View {
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    HStack {
                        Button("Cancel") { dismiss() }
                            .font(WalletTheme.speech(15, .medium))
                            .foregroundStyle(WalletTheme.teal)
                            .buttonStyle(.plain)
                        Spacer()
                        Text("Send").font(WalletTheme.speech(16, .semibold))
                            .foregroundStyle(WalletTheme.ink)
                        Spacer()
                        Text("Cancel").font(WalletTheme.speech(15, .medium)).opacity(0)
                    }
                    HStack {
                        WalletSampleBadge()
                        Text("Preview only — this build cannot originate sends.")
                            .font(WalletTheme.speech(11))
                            .foregroundStyle(WalletTheme.muted)
                    }

                    WalletCard(padding: 16) {
                        VStack(alignment: .leading, spacing: 0) {
                            WalletSectionLabel(text: "To")
                            Text("0x4b0c…9d21")
                                .font(WalletTheme.mono(14, .medium))
                                .foregroundStyle(WalletTheme.ink)
                                .padding(.top, 7)
                            Text("First time you've sent here")
                                .font(WalletTheme.speech(12))
                                .foregroundStyle(WalletTheme.muted)
                                .padding(.top, 3)
                            WalletTheme.hairline.frame(height: 1).padding(.vertical, 14)
                            WalletSectionLabel(text: "Amount")
                            HStack(alignment: .firstTextBaseline, spacing: 8) {
                                Text("250.00")
                                    .font(WalletTheme.speech(38))
                                    .foregroundStyle(WalletTheme.ink)
                                Text("USDC")
                                    .font(WalletTheme.mono(16, .medium))
                                    .foregroundStyle(WalletTheme.muted)
                            }
                            .padding(.top, 8)
                            Text("on Arbitrum One · balance 1,056.54")
                                .font(WalletTheme.speech(12.5))
                                .foregroundStyle(WalletTheme.muted)
                                .padding(.top, 6)
                        }
                    }

                    WalletCard(padding: 16) {
                        VStack(alignment: .leading, spacing: 0) {
                            HStack(spacing: 8) {
                                Text("SIMULATED RESULT")
                                    .font(WalletTheme.mono(10, .semibold))
                                    .kerning(1.1)
                                    .foregroundStyle(WalletTheme.ink)
                                Text("eth_simulateV1")
                                    .font(WalletTheme.mono(10))
                                    .foregroundStyle(WalletTheme.muted)
                            }
                            moveRow("You send", "−250.00 USDC", WalletTheme.red)
                                .padding(.top, 12)
                            moveRow("0x4b0c…9d21 receives", "+250.00 USDC", WalletTheme.teal)
                                .padding(.top, 9)
                            WalletTheme.hairline.frame(height: 1).padding(.vertical, 14)
                            HStack {
                                Text("Network fee")
                                    .font(WalletTheme.speech(13.5))
                                    .foregroundStyle(WalletTheme.muted)
                                Spacer()
                                Text("Sponsored")
                                    .font(WalletTheme.mono(13.5, .medium))
                                    .foregroundStyle(WalletTheme.teal)
                            }
                            Text("Paid by the app's paymaster (ERC-7677). You pay no ETH; the paymaster address is shown in full facts.")
                                .font(WalletTheme.speech(11.5))
                                .foregroundStyle(WalletTheme.muted)
                                .padding(.top, 6)
                        }
                    }

                    VStack(alignment: .leading, spacing: 8) {
                        WalletSectionLabel(text: "How this executes")
                        Text("One transfer call, submitted as a UserOperation through EntryPoint 0.7 from your Kernel account. This device signs with the Secure Enclave key — no session key is involved.")
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
                }
                .padding(20)
            }
            VStack(spacing: 9) {
                Text("Simulation is a prediction, not a guarantee.")
                    .font(WalletTheme.speech(11))
                    .foregroundStyle(WalletTheme.muted)
            }
            .padding(.vertical, 12)
            .frame(maxWidth: .infinity)
            .background(WalletTheme.card)
            .overlay(alignment: .top) { WalletTheme.border.frame(height: 1) }
        }
        .background(WalletTheme.paper)
    }

    private func moveRow(_ label: String, _ amount: String, _ color: Color) -> some View {
        HStack(spacing: 10) {
            Text(label).font(WalletTheme.speech(14)).foregroundStyle(WalletTheme.ink)
            Spacer()
            Text(amount).font(WalletTheme.mono(14, .medium)).foregroundStyle(color)
        }
    }
}

/// Receive: the one real fact a receive screen needs — the account address
/// the relay derived at pairing, shown in full.
struct WalletReceiveSheet: View {
    let account: String?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("Receive").font(WalletTheme.speech(16, .semibold))
                    .foregroundStyle(WalletTheme.ink)
                Spacer()
                Button("Done") { dismiss() }
                    .font(WalletTheme.speech(15, .medium))
                    .foregroundStyle(WalletTheme.teal)
                    .buttonStyle(.plain)
            }
            WalletCard(padding: 16) {
                VStack(alignment: .leading, spacing: 8) {
                    WalletSectionLabel(text: "Your account · same address on every chain")
                    Text(account ?? "Not derived yet — the relay derives it at pairing.")
                        .font(account == nil ? WalletTheme.speech(13) : WalletTheme.mono(14, .medium))
                        .foregroundStyle(WalletTheme.ink)
                    Text("Chain-independent CREATE2 derivation from this device's registered owner key. Verify the first characters with the sender.")
                        .font(WalletTheme.speech(11.5))
                        .foregroundStyle(WalletTheme.muted)
                }
            }
            Spacer()
        }
        .padding(20)
        .background(WalletTheme.paper)
    }
}
#endif
