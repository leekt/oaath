/**
 EXPERIMENTAL PREVIEW — the wallet shell: four tabs over one DemoModel.

 TURN-1 design, screens 1a–1e: Wallet, Activity, Approvals, Settings. The
 shell adds chrome only — pairing, inbox polling, review, decisions, delivery,
 and unpairing stay exactly the DemoModel behavior the wiring tests pin. The
 Approvals tab is the real consent path; every other surface renders live
 facts where the app holds them and says "SAMPLE" where it does not.

 @author taek <leekt216@gmail.com>
 */
#if canImport(SwiftUI)
import OwnerPhone
import SwiftUI

enum WalletTab: String, CaseIterable {
    case wallet = "Wallet"
    case activity = "Activity"
    case approvals = "Approvals"
    case settings = "Settings"

    var icon: String {
        switch self {
        case .wallet: return "creditcard"
        case .activity: return "waveform.path.ecg"
        case .approvals: return "shield"
        case .settings: return "gearshape"
        }
    }
}

struct WalletShellView: View {
    @ObservedObject var model: DemoModel
    @State private var tab: WalletTab = .wallet

    var body: some View {
        VStack(spacing: 0) {
            ZStack {
                WalletTheme.paper.ignoresSafeArea()
                switch tab {
                case .wallet:
                    WalletHomeView(model: model) { tab = .approvals }
                case .activity:
                    WalletActivityView(model: model)
                case .approvals:
                    WalletApprovalsView(model: model)
                case .settings:
                    WalletSecurityView(model: model)
                }
            }
            tabBar
        }
        .background(WalletTheme.paper)
        .task(id: model.pollingIdentity) { await model.pollInbox() }
    }

    private var tabBar: some View {
        HStack(spacing: 0) {
            ForEach(WalletTab.allCases, id: \.self) { entry in
                Button {
                    tab = entry
                } label: {
                    VStack(spacing: 4) {
                        ZStack(alignment: .topTrailing) {
                            Image(systemName: entry.icon)
                                .font(.system(size: 20, weight: .regular))
                            if entry == .approvals, !model.inbox.isEmpty {
                                Text("\(model.inbox.count)")
                                    .font(WalletTheme.mono(9, .semibold))
                                    .foregroundStyle(.white)
                                    .frame(width: 16, height: 16)
                                    .background(WalletTheme.red)
                                    .clipShape(Circle())
                                    .offset(x: 10, y: -6)
                            }
                        }
                        Text(entry.rawValue).font(WalletTheme.speech(10, .medium))
                    }
                    .foregroundStyle(tab == entry ? WalletTheme.ink : WalletTheme.faint)
                    .frame(maxWidth: .infinity)
                    .padding(.top, 8)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.bottom, 2)
        .background(WalletTheme.card.opacity(0.94))
        .overlay(alignment: .top) { WalletTheme.border.frame(height: 1) }
    }
}

/// The real approval surface: pending requests, the consent flow, manual open,
/// delivery lines — plus the granted-authority section (1d) beneath it.
struct WalletApprovalsView: View {
    @ObservedObject var model: DemoModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text("Approvals")
                    .font(WalletTheme.speech(30, .semibold))
                    .foregroundStyle(WalletTheme.ink)

                HStack {
                    WalletSectionLabel(text: "Awaiting your approval")
                    Spacer()
                    Button("Refresh") { Task { await model.refreshInbox() } }
                        .font(WalletTheme.speech(12, .medium))
                        .foregroundStyle(WalletTheme.teal)
                        .buttonStyle(.plain)
                }

                if model.inbox.isEmpty {
                    WalletCard {
                        Text("No pending requests.")
                            .font(WalletTheme.speech(13))
                            .foregroundStyle(WalletTheme.muted)
                    }
                } else {
                    ForEach(model.inbox) { item in
                        WalletCard(emphasized: true) {
                            WalletPendingRow(item: item) {
                                Task { await model.openInboxItem(item) }
                            }
                        }
                    }
                }
                if !model.inboxStatusLine.isEmpty {
                    Text(model.inboxStatusLine)
                        .font(WalletTheme.speech(11))
                        .foregroundStyle(WalletTheme.muted)
                }

                if let approval = model.approval {
                    ApprovalView(model: approval)
                }
                if !model.deliveryLine.isEmpty {
                    Text(model.deliveryLine)
                        .font(WalletTheme.speech(12))
                        .foregroundStyle(WalletTheme.muted)
                }

                manualOpen

                WalletGrantsSection()

                if !model.statusLine.isEmpty {
                    Text(model.statusLine)
                        .font(WalletTheme.speech(12))
                        .foregroundStyle(WalletTheme.muted)
                }
            }
            .padding(.horizontal, 20)
            .padding(.top, 12)
            .padding(.bottom, 24)
        }
    }

    private var manualOpen: some View {
        WalletCard {
            VStack(alignment: .leading, spacing: 9) {
                WalletSectionLabel(text: "Open by operation id")
                Text("Inbox unavailable? Paste the operation id from the web example.")
                    .font(WalletTheme.speech(11.5))
                    .foregroundStyle(WalletTheme.muted)
                TextField("operation id", text: $model.operationIdText)
                    .textFieldStyle(.plain)
                    .autocorrectionDisabled()
                    .font(WalletTheme.mono(12))
                    .padding(10)
                    .background(WalletTheme.paper)
                    .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                WalletSecondaryButton(title: "Open request", height: 40) {
                    Task { await model.openManually() }
                }
            }
        }
    }
}

/// One pending authorization: match code first, then the exact identifiers.
struct WalletPendingRow: View {
    let item: DemoInboxItem
    let review: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 12) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Authorization request")
                        .font(WalletTheme.speech(15, .semibold))
                        .foregroundStyle(WalletTheme.ink)
                    Text(item.operationId)
                        .font(WalletTheme.mono(10.5))
                        .foregroundStyle(WalletTheme.muted)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Spacer(minLength: 8)
                VStack(alignment: .trailing, spacing: 4) {
                    Text("MATCH")
                        .font(WalletTheme.mono(9.5))
                        .kerning(1)
                        .foregroundStyle(WalletTheme.muted)
                    Text(item.matchCode.display)
                        .font(WalletTheme.mono(15, .bold))
                        .foregroundStyle(WalletTheme.ink)
                }
            }
            Button(action: review) {
                Text("Review")
                    .font(WalletTheme.speech(14, .medium))
                    .foregroundStyle(.white)
                    .frame(maxWidth: .infinity)
                    .frame(height: 40)
                    .background(WalletTheme.teal)
                    .clipShape(RoundedRectangle(cornerRadius: 11, style: .continuous))
            }
            .buttonStyle(.plain)
            Text("Expires \(Date(timeIntervalSince1970: Double(item.expiresAt) / 1000).formatted()) · nothing is decided until you tap")
                .font(WalletTheme.speech(11))
                .foregroundStyle(WalletTheme.muted)
        }
    }
}

/// Granted authority (1d). This phone reviews and revokes through the web
/// half; it holds no grant records itself, so the cards are labeled samples.
struct WalletGrantsSection: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack {
                WalletSectionLabel(text: "Granted authority")
                WalletSampleBadge()
            }
            Text("Apps you let act for you without asking each time. Revoking is chain-local: each chain is revoked where it was materialized. This preview holds no grant records — the web half owns them.")
                .font(WalletTheme.speech(12))
                .foregroundStyle(WalletTheme.muted)

            WalletCard(emphasized: true, padding: 0) {
                VStack(alignment: .leading, spacing: 0) {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack(alignment: .top, spacing: 12) {
                            Text("A")
                                .font(WalletTheme.speech(13, .semibold))
                                .foregroundStyle(WalletTheme.ink)
                                .frame(width: 38, height: 38)
                                .background(WalletTheme.chip)
                                .clipShape(RoundedRectangle(cornerRadius: 11, style: .continuous))
                            VStack(alignment: .leading, spacing: 3) {
                                Text("app.example")
                                    .font(WalletTheme.speech(15.5, .semibold))
                                    .foregroundStyle(WalletTheme.ink)
                                Text("demo-web-app · all chains")
                                    .font(WalletTheme.mono(11.5))
                                    .foregroundStyle(WalletTheme.muted)
                            }
                            Spacer()
                            WalletStatusPill.active()
                        }
                        VStack(alignment: .leading, spacing: 7) {
                            Text("May call swap() on the router")
                            Text("May not move ETH — value limit 0")
                            Text("7 of 10 operations used per chain")
                        }
                        .font(WalletTheme.speech(13))
                        .foregroundStyle(WalletTheme.ink)
                        GeometryReader { proxy in
                            ZStack(alignment: .leading) {
                                Capsule().fill(WalletTheme.chip)
                                Capsule().fill(WalletTheme.ink)
                                    .frame(width: proxy.size.width * 0.7)
                            }
                        }
                        .frame(height: 6)
                        HStack {
                            Text("EXPIRES IN 22 MIN")
                            Spacer()
                            Text("SESSION KEY 0x44…4444")
                        }
                        .font(WalletTheme.mono(10.5))
                        .foregroundStyle(WalletTheme.muted)
                    }
                    .padding(15)
                    WalletTheme.hairline.frame(height: 1)
                    VStack(alignment: .leading, spacing: 10) {
                        WalletSectionLabel(text: "Materialized on")
                        HStack(spacing: 7) {
                            grantChain("Arbitrum One", live: true)
                            grantChain("Robinhood Chain", live: true)
                            grantChain("Ethereum · not yet", live: false)
                        }
                        HStack(spacing: 8) {
                            WalletSecondaryButton(title: "Revoke everywhere", destructive: true) {}
                            WalletSecondaryButton(title: "Full facts") {}
                                .frame(width: 110)
                        }
                    }
                    .padding(15)
                    .background(WalletTheme.paper.opacity(0.55))
                }
            }
        }
        .padding(.top, 10)
    }

    private func grantChain(_ name: String, live: Bool) -> some View {
        Text(name)
            .font(WalletTheme.speech(11.5, .medium))
            .foregroundStyle(live ? WalletTheme.ink : WalletTheme.muted)
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(live ? WalletTheme.card : Color.clear)
            .overlay(
                Capsule().strokeBorder(
                    live ? WalletTheme.border : WalletTheme.dash,
                    style: StrokeStyle(lineWidth: 1, dash: live ? [] : [3, 3])
                )
            )
    }
}
#endif
