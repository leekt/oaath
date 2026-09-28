/**
 EXPERIMENTAL PREVIEW — the paired shell: Requests and Device over one DemoModel.

 This app is an owner approval device, so the shell shows only what the phone
 actually holds: pending requests from the authenticated inbox, the bound
 account and configured chains, the owner key custody state, and the pairing.
 It invents no balances, history, or grants. The shell adds chrome only —
 pairing, inbox polling, review, decisions, and unpairing stay exactly the
 DemoModel behavior the wiring tests pin. Opening a request pushes the review
 screen; approving and rejecting stay explicit buttons inside `ApprovalView`.

 @author taek <leekt216@gmail.com>
 */
#if canImport(SwiftUI)
import OwnerPhone
import SwiftUI

struct WalletShellView: View {
    @ObservedObject var model: DemoModel

    var body: some View {
        TabView {
            WalletRequestsScreen(model: model)
                .tabItem { Label("Requests", systemImage: "tray.full") }
                .badge(model.inbox.count)
            WalletDeviceScreen(model: model)
                .tabItem { Label("Device", systemImage: "key.horizontal") }
        }
        .task(id: model.pollingIdentity) { await model.pollInbox() }
    }
}

/// Pending requests. Selecting one opens the review; nothing here decides.
struct WalletRequestsScreen: View {
    @ObservedObject var model: DemoModel
    @State private var showingManualOpen = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    WalletAccountStrip(model: model)

                    if !model.statusLine.isEmpty {
                        WalletNotice(text: model.statusLine) { model.clearStatusLine() }
                    }
                    if model.inboxUnavailable {
                        WalletNotice(
                            text: "Can't reach the relay. Showing the last requests received; pull down to try again.",
                            tone: .warning)
                    }

                    if model.inbox.isEmpty {
                        emptyState
                    } else {
                        WalletSectionLabel(text: model.inbox.count == 1
                            ? "1 waiting for you" : "\(model.inbox.count) waiting for you")
                            .padding(.top, 4)
                        ForEach(model.inbox) { item in
                            WalletPendingRow(item: item) {
                                Task { await model.openInboxItem(item) }
                            }
                        }
                        Text("Opening a request only shows it. Nothing is approved until you tap Approve.")
                            .font(WalletTheme.speech(.footnote))
                            .foregroundStyle(WalletTheme.muted)
                    }
                }
                .padding(.horizontal, 20)
                .padding(.top, 8)
                .padding(.bottom, 24)
            }
            .refreshable { await model.refreshInbox() }
            .walletScreen()
            .navigationTitle("Requests")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Menu {
                        Button {
                            Task { await model.refreshInbox() }
                        } label: {
                            Label("Refresh", systemImage: "arrow.clockwise")
                        }
                        Button {
                            showingManualOpen = true
                        } label: {
                            Label("Open by operation ID", systemImage: "number")
                        }
                    } label: {
                        Label("More", systemImage: "ellipsis")
                    }
                }
            }
            .navigationDestination(isPresented: $model.reviewPresented) {
                WalletReviewScreen(model: model)
            }
            .sheet(isPresented: $showingManualOpen) {
                WalletManualOpenSheet(model: model) { showingManualOpen = false }
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "checkmark.shield")
                .font(.system(.largeTitle).weight(.light))
                .foregroundStyle(WalletTheme.teal)
                .accessibilityHidden(true)
            Text("Nothing waiting")
                .font(WalletTheme.speech(.title3, .semibold))
                .foregroundStyle(WalletTheme.ink)
            Text("When an app asks for authority over your account, the request appears here within a few seconds.")
                .font(WalletTheme.speech(.subheadline))
                .foregroundStyle(WalletTheme.muted)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 40)
        .padding(.horizontal, 16)
        .background(WalletTheme.card)
        .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .stroke(WalletTheme.border, lineWidth: 1)
        )
    }
}

/// The paired account in one line: address, chains, and key custody.
struct WalletAccountStrip: View {
    @ObservedObject var model: DemoModel
    @Environment(\.dynamicTypeSize) private var typeSize

    var body: some View {
        let layout = typeSize.isAccessibilitySize
            ? AnyLayout(VStackLayout(alignment: .leading, spacing: 10))
            : AnyLayout(HStackLayout(spacing: 12))
        layout {
            Image(systemName: "person.crop.circle")
                .font(.system(.title2))
                .foregroundStyle(WalletTheme.ink)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(shortAddress(model.account))
                    .font(WalletTheme.mono(.subheadline, .medium))
                    .foregroundStyle(WalletTheme.ink)
                Text(chainSummary(model.chainIds))
                    .font(WalletTheme.speech(.footnote))
                    .foregroundStyle(WalletTheme.muted)
            }
            if !typeSize.isAccessibilitySize { Spacer(minLength: 8) }
            WalletCustodyPill(ownerKey: model.ownerKey)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(WalletTheme.card)
        .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .stroke(WalletTheme.border, lineWidth: 1)
        )
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Account \(model.account ?? "not derived"), \(chainSummary(model.chainIds))")
    }
}

struct WalletCustodyPill: View {
    let ownerKey: (any DemoOwnerSigning)?

    var body: some View {
        if let ownerKey {
            ownerKey.secureEnclave
                ? WalletStatusPill(text: "ENCLAVE", color: WalletTheme.teal, background: WalletTheme.tealWash)
                : WalletStatusPill(text: "SIMULATOR KEY", color: WalletTheme.amber, background: WalletTheme.amberWash)
        } else {
            WalletStatusPill(text: "NO KEY", color: WalletTheme.red, background: WalletTheme.redWash)
        }
    }
}

/// One pending request: match code first, then expiry. The whole row opens it.
struct WalletPendingRow: View {
    let item: DemoInboxItem
    let review: () -> Void

    private var expiry: Date { Date(timeIntervalSince1970: Double(item.expiresAt) / 1000) }

    var body: some View {
        Button(action: review) {
            HStack(alignment: .center, spacing: 14) {
                VStack(alignment: .leading, spacing: 6) {
                    Text(item.matchCode.display)
                        .font(WalletTheme.mono(.title2, .bold))
                        .foregroundStyle(WalletTheme.ink)
                    Text(item.operationId)
                        .font(WalletTheme.mono(.caption))
                        .foregroundStyle(WalletTheme.muted)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    WalletExpiryText(expiry: expiry)
                }
                Spacer(minLength: 8)
                HStack(spacing: 4) {
                    Text("Review").font(WalletTheme.speech(.subheadline, .semibold))
                    Image(systemName: "chevron.right").font(WalletTheme.speech(.footnote, .semibold))
                }
                .foregroundStyle(WalletTheme.teal)
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(WalletTheme.card)
            .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .stroke(WalletTheme.ink, lineWidth: 1)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(WalletPressStyle())
        .accessibilityLabel("Request with match code \(item.matchCode.display)")
        .accessibilityHint("Opens the review. Nothing is decided until you approve or reject.")
    }
}

/// "Expires in 4 min" that keeps counting, or "Expired".
struct WalletExpiryText: View {
    let expiry: Date

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            if context.date < expiry {
                (Text("Expires in ") + Text(expiry, style: .relative))
                    .font(WalletTheme.speech(.footnote))
                    .foregroundStyle(WalletTheme.muted)
            } else {
                Text("Expired")
                    .font(WalletTheme.speech(.footnote, .medium))
                    .foregroundStyle(WalletTheme.red)
            }
        }
    }
}

/// The pushed consent screen. `ApprovalView` owns every decision control.
struct WalletReviewScreen: View {
    @ObservedObject var model: DemoModel

    var body: some View {
        Group {
            if let approval = model.approval {
                ApprovalView(model: approval) { model.reviewPresented = false }
            } else {
                Text("This pairing ended. Pair again to review requests.")
                    .font(WalletTheme.speech(.body))
                    .foregroundStyle(WalletTheme.muted)
                    .padding()
            }
        }
        .background(WalletTheme.paper.ignoresSafeArea())
        .navigationTitle("Review request")
        #if os(iOS)
        .toolbar(.hidden, for: .tabBar)
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(WalletTheme.paper, for: .navigationBar)
        #endif
    }
}

/// Fallback when the inbox is unavailable: open one request by its ID.
struct WalletManualOpenSheet: View {
    @ObservedObject var model: DemoModel
    let close: () -> Void

    private var trimmed: String {
        model.operationIdText.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 14) {
                Text("Use this only if a request doesn't appear in Requests. Paste the operation ID shown by the service.")
                    .font(WalletTheme.speech(.subheadline))
                    .foregroundStyle(WalletTheme.muted)
                TextField("Operation ID", text: $model.operationIdText)
                    .textFieldStyle(.plain)
                    .autocorrectionDisabled()
                    #if os(iOS)
                    .textInputAutocapitalization(.never)
                    #endif
                    .font(WalletTheme.mono(.body))
                    .padding(12)
                    .background(WalletTheme.card)
                    .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                    .overlay(
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .stroke(WalletTheme.border, lineWidth: 1)
                    )
                WalletPrimaryButton(title: "Open request", enabled: !trimmed.isEmpty) {
                    close()
                    Task { await model.openManually() }
                }
                Spacer()
            }
            .padding(20)
            .background(WalletTheme.paper.ignoresSafeArea())
            .navigationTitle("Open by ID")
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: close)
                }
            }
        }
        .presentationDetents([.medium])
    }
}

func shortAddress(_ account: String?) -> String {
    guard let account, account.count > 12 else { return account ?? "Account not derived" }
    return "\(account.prefix(6))…\(account.suffix(4))"
}

func chainSummary(_ chainIds: [Int]) -> String {
    switch chainIds.count {
    case 0: return "No configured chains"
    case 1: return "Chain \(chainIds[0])"
    default: return "\(chainIds.count) chains · " + chainIds.map(String.init).joined(separator: ", ")
    }
}
#endif
