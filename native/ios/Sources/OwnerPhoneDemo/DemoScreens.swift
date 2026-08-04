/**
 EXPERIMENTAL PREVIEW — the demo app's screens over the OwnerPhone library.

 First launch pairs: relay base URL + the one-shot code the example provides. The
 normalized relay endpoint and returned device credential are persisted as one
 bound identity and used together for every later call; a refused credential
 (HTTP 401) clears that whole identity and returns to pairing.

 The authenticated pull inbox is the default chooser. Polling, selecting an
 item, or tapping an optional push notification NEVER approves anything: each
 only opens the consent screen, which presents Approve and Reject as explicit
 buttons (the library's `ApprovalView`).

 @author taek <leekt216@gmail.com>
 */
#if canImport(SwiftUI)
import Combine
import Foundation
import OwnerPhone
import SwiftUI

@MainActor
public final class DemoModel: ObservableObject {
    /// Transient candidate before pairing; while paired this mirrors the bound
    /// endpoint and is never an independent persisted authority input. Editing
    /// either candidate invalidates any request made from the prior snapshot.
    @Published public var baseURLText = "" {
        didSet { invalidatePairingAttempt() }
    }
    @Published public var pairingCodeText = "" {
        didSet { invalidatePairingAttempt() }
    }
    @Published public var operationIdText = ""
    @Published public private(set) var paired = false
    @Published public private(set) var statusLine = ""
    @Published public private(set) var approval: ApprovalModel?
    @Published public private(set) var deliveryLine = ""
    /// Opaque pending summaries from the authenticated example-owned inbox.
    @Published public private(set) var inbox: [DemoInboxItem] = []
    /// Bounded status codes/prose only; transport bodies and errors never enter UI state.
    @Published public private(set) var inboxStatusLine = ""
    /// Changes whenever polling ownership changes so SwiftUI cancels the old task.
    @Published public private(set) var pollingIdentity = UUID()
    /// The smart account address the relay derived from this key at pairing.
    @Published public private(set) var account: String?

    /// Set by APNs registration; until then a random placeholder keeps pairing
    /// usable (pushes to it go nowhere — manual operation-id entry still works).
    public var deviceToken: String

    /// The on-device owner P-256 key: Secure Enclave when available, honest
    /// keychain fallback otherwise. Nil only when key creation itself failed.
    public let ownerKey: (any DemoOwnerSigning)?

    private let pairings: any DevicePairingStore
    private let http: any DemoHTTP
    /// Latest-wins attempt ownership: a second explicit pair, candidate edit,
    /// link application, or unpair invalidates every older completion.
    private var pairingAttempt: UUID?
    private var pairingIdentity: PersistedPairing?
    private var inboxRefreshToken: UUID?
    private var phaseSink: AnyCancellable?
    private var delivered: Set<String> = []

    public init(
        pairings: any DevicePairingStore,
        http: any DemoHTTP = URLSession.shared,
        ownerKey: (any DemoOwnerSigning)? = resolveDemoOwnerKey()
    ) {
        self.pairings = pairings
        self.http = http
        self.ownerKey = ownerKey
        self.deviceToken = Self.placeholderDeviceToken()
        if let pairing = pairings.load() {
            pairingIdentity = pairing
            baseURLText = pairing.endpoint.baseURL.absoluteString
            account = pairing.account
            paired = true
            rebuildApproval(pairing)
        }
    }

    static func placeholderDeviceToken() -> String {
        (0..<32).map { _ in String(format: "%02x", UInt8.random(in: 0...255)) }.joined()
    }

    /// Fills the pairing screen from a scanned/tapped/pasted
    /// `oaath-demo://pair?...` link. Filling only — pairing stays a button.
    public func apply(link: PairingLink) {
        guard !paired else {
            statusLine = "Already paired. Clear the bound relay before using another pairing link."
            return
        }
        guard let endpoint = try? DemoRelayEndpoint(baseURLText: link.relayURL) else { return }
        baseURLText = endpoint.baseURL.absoluteString
        pairingCodeText = link.pairingCode
        statusLine = "Pairing link read. Review and tap \"Pair this device\"."
    }

    /// `onOpenURL` entry: a tapped or camera-scanned pairing link.
    public func open(url: URL) {
        if let link = parsePairingLink(url.absoluteString) {
            apply(link: link)
        }
    }

    public func pair() async {
        guard !paired else {
            statusLine = "Already paired. Clear the bound relay before pairing again."
            return
        }
        statusLine = ""
        // A pasted full pairing link works in the code field too.
        if let link = parsePairingLink(pairingCodeText) {
            apply(link: link)
        }
        guard let ownerKey else {
            statusLine = "Owner key unavailable: this device could not create a P-256 key."
            return
        }
        // Capture the complete candidate and install latest-wins ownership
        // before the first suspension point. Response order has no authority.
        let candidateURL = baseURLText
        let code = pairingCodeText.trimmingCharacters(in: .whitespacesAndNewlines)
        let capturedDeviceToken = deviceToken
        let token = UUID()
        pairingAttempt = token
        do {
            let endpoint = try DemoRelayEndpoint(baseURLText: candidateURL)
            let publicKey = try ownerKey.publicMaterialHex()
            let device = try await OwnerPhoneDemo.pair(
                endpoint: endpoint,
                pairingCode: code,
                deviceToken: capturedDeviceToken,
                publicKey: publicKey,
                http: http)
            guard pairingAttempt == token, !paired, pairings.load() == nil else { return }
            let pairing = try PersistedPairing(
                endpoint: endpoint,
                credential: device.deviceCredential,
                account: device.account)
            // The response must succeed before the single bound value is stored;
            // model state changes only after that atomic store operation succeeds.
            try pairings.save(pairing)
            pairingAttempt = nil
            pairingIdentity = pairing
            account = pairing.account
            baseURLText = pairing.endpoint.baseURL.absoluteString
            pairingCodeText = ""
            paired = true
            pollingIdentity = UUID()
            rebuildApproval(pairing)
            statusLine = "Paired. Relay and owner credential are now bound together."
        } catch DemoPairingError.refused {
            guard pairingAttempt == token, !paired else { return }
            pairingAttempt = nil
            statusLine = "Pairing refused: the code is unknown, already used, or expired."
        } catch {
            guard pairingAttempt == token, !paired else { return }
            pairingAttempt = nil
            statusLine = "Pairing failed: check the relay URL (same network as the Mac?)."
        }
    }

    public func unpair() {
        invalidatePairingAttempt()
        pairings.clear()
        resetPairingUI()
        statusLine = "Bound relay and credential cleared. Pair again with a fresh code."
    }

    public func openManually() async {
        guard let approval else { return }
        deliveryLine = ""
        await approval.open(
            operationId: operationIdText.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    /// Latest-wins authenticated inbox read. A completion owns model state only
    /// while the exact captured pairing and refresh token are still current.
    public func refreshInbox() async {
        guard let capturedPairing = pairingIdentity, paired else { return }
        let token = UUID()
        inboxRefreshToken = token
        do {
            let items = try await fetchDemoInbox(
                pairing: capturedPairing,
                http: http,
                onUnauthorized: { [weak self] rejectedPairing in
                    await self?.rejectInboxIfOwned(
                        rejectedPairing, refreshToken: token)
                })
            guard inboxRefreshToken == token,
                  pairingIdentity == capturedPairing,
                  paired,
                  !Task.isCancelled
            else { return }
            inboxRefreshToken = nil
            inbox = items
            inboxStatusLine = items.isEmpty ? "No pending requests." : "Pending requests refreshed."
        } catch {
            guard inboxRefreshToken == token,
                  pairingIdentity == capturedPairing,
                  paired,
                  !Task.isCancelled
            else { return }
            inboxRefreshToken = nil
            inboxStatusLine = "Inbox unavailable (refresh_failed)."
        }
    }

    /// Polls only while this paired-screen task owns the current identity.
    public func pollInbox() async {
        let owner = pollingIdentity
        while !Task.isCancelled, paired, pollingIdentity == owner {
            await refreshInbox()
            guard !Task.isCancelled, paired, pollingIdentity == owner else { return }
            do {
                try await Task.sleep(for: .seconds(2))
            } catch {
                return
            }
        }
    }

    /// Selection opens the existing full projection flow and never decides.
    public func openInboxItem(_ item: DemoInboxItem) async {
        guard inbox.contains(item), pairingIdentity != nil, let approval else { return }
        operationIdText = item.operationId
        deliveryLine = ""
        await approval.open(operationId: item.operationId)
    }

    public func receive(push: OwnerPhonePush) async {
        guard let approval else { return }
        deliveryLine = ""
        await approval.receive(push: push)
    }

    private func rebuildApproval(_ pairing: PersistedPairing? = nil) {
        guard let boundPairing = pairing ?? pairings.load() else {
            approval = nil
            paired = false
            return
        }
        pairingIdentity = boundPairing
        baseURLText = boundPairing.endpoint.baseURL.absoluteString
        account = boundPairing.account
        let client = demoRelayClient(
            pairing: boundPairing,
            http: http,
            onUnauthorized: { [weak self] rejectedPairing in
                await self?.rejectIfCurrent(rejectedPairing)
            })
        // The signing boundary: a signature-request approval signs the
        // projected digest with the on-device owner key (Secure Enclave when
        // available) — the artifact IS the signature. Every other scope keeps
        // the demo's opaque placeholder artifact.
        let ownerKey = self.ownerKey
        let model = ApprovalModel(relay: client, approvalArtifact: { projection in
            if case let .signatureRequest(scope) = projection.scope, let ownerKey {
                return try ownerKey.signDigestHex(scope.digest)
            }
            return demoApprovalArtifact()
        })
        approval = model
        phaseSink = model.$phase
            .receive(on: RunLoop.main)
            .sink { [weak self] phase in self?.observe(phase: phase) }
    }

    private func invalidatePairingAttempt() {
        pairingAttempt = nil
    }

    /// A stale or cancelled inbox response has no authority even when it used
    /// the same pairing as a newer successful refresh.
    private func rejectInboxIfOwned(
        _ rejectedPairing: PersistedPairing,
        refreshToken: UUID
    ) {
        guard inboxRefreshToken == refreshToken,
              pairingIdentity == rejectedPairing,
              paired,
              !Task.isCancelled
        else { return }
        rejectIfCurrent(rejectedPairing)
    }

    /// Compare-and-clear both authority owners. A delayed request made by A
    /// cannot change persistence or UI after A was replaced by B.
    private func rejectIfCurrent(_ rejectedPairing: PersistedPairing) {
        guard pairingIdentity == rejectedPairing,
              pairings.clear(ifCurrent: rejectedPairing)
        else { return }
        resetPairingUI()
        statusLine = "The relay refused this device's credential. Pair again."
    }

    private func resetPairingUI() {
        pairingIdentity = nil
        inboxRefreshToken = nil
        inbox = []
        inboxStatusLine = ""
        pollingIdentity = UUID()
        approval = nil
        phaseSink = nil
        paired = false
        account = nil
        baseURLText = ""
        pairingCodeText = ""
    }

    /// Delivers the released code exactly once per decided approval, the OAuth
    /// way: GET `redirectUri?code=…`. A replayed settlement releases nothing,
    /// so nothing is ever delivered for it — `ApprovalView` says so honestly.
    private func observe(phase: ApprovalModel.Phase) {
        guard case let .review(review) = phase,
              case let .settled(decision) = review.state,
              decision.settlement == .decided,
              case let .approved(code, _, redirectUri, _) = decision.release ?? .rejected,
              !delivered.contains(decision.operationId)
        else {
            if case .review(let review) = phase,
               case .settled(let decision) = review.state,
               decision.settlement == .replayed {
                deliveryLine = "Replayed outcome: nothing was released, nothing to deliver."
            }
            return
        }
        delivered.insert(decision.operationId)
        deliveryLine = "Delivering the code to the web app…"
        let http = self.http
        Task { @MainActor in
            do {
                let status = try await deliverCode(redirectUri: redirectUri, code: code, http: http)
                deliveryLine = status < 400
                    ? "Code delivered to \(redirectUri) (HTTP \(status))."
                    : "The web app refused the code (HTTP \(status))."
            } catch {
                deliveryLine = "Code delivery failed: is the web example still waiting?"
            }
        }
    }
}

public struct DemoRootView: View {
    @ObservedObject private var model: DemoModel

    public init(model: DemoModel) {
        self.model = model
    }

    public var body: some View {
        NavigationStack {
            if model.paired {
                pairedBody
            } else {
                pairingBody
            }
        }
    }

    @ViewBuilder
    private var pairingBody: some View {
        Form {
            Section("Relay") {
                TextField("http://<your-mac-lan-ip>:8787", text: $model.baseURLText)
                    .autocorrectionDisabled()
                    .font(.body.monospaced())
            }
            Section("Pairing code (shown by the browser Pair action)") {
                TextField("ABCD-EFGH-IJ or oaath-demo:// link", text: $model.pairingCodeText)
                    .autocorrectionDisabled()
                    .font(.body.monospaced())
                Button("Pair this device") { Task { await model.pair() } }
            }
            Section {
                Text(
                    "On the Mac, open the printed loopback browser URL and choose Pair phone. "
                    + "Scan its transient QR (system camera), tap the oaath-demo:// link, or paste "
                    + "it above — pairing is still this button.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            ownerKeyBanner
            if !model.statusLine.isEmpty {
                Text(model.statusLine).font(.footnote)
            }
            Section {
                Text(
                    "The one-shot code shown by the loopback browser (or interactive terminal fallback) "
                    + "is this demo's trust root, on a trusted network only. A production deployment "
                    + "owns pairing UX (QR, attestation).")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Pair with the relay")
    }

    /// The custody truth, said out loud: Enclave, honest fallback, or failure.
    @ViewBuilder
    private var ownerKeyBanner: some View {
        if let ownerKey = model.ownerKey {
            if ownerKey.secureEnclave {
                Text("Owner key: P-256, generated inside the Secure Enclave. The private key never leaves it.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            } else {
                Text("Owner key: SIMULATOR FALLBACK — a regular keychain P-256 key. No Secure Enclave is available here; a physical iPhone uses the Enclave.")
                    .font(.caption2)
                    .foregroundStyle(.orange)
            }
        } else {
            Text("Owner key unavailable: this device could not create a P-256 key.")
                .font(.caption2)
                .foregroundStyle(.red)
        }
    }

    @ViewBuilder
    private var accountBody: some View {
        VStack(spacing: 4) {
            Text("Smart account (CREATE2, chain-independent — Arbitrum Sepolia profile)")
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(model.account ?? "not derived yet — the relay derives it at pairing")
                .font(.caption.monospaced())
            Text("Derived by the web half from this key's registered public material; this screen displays what the relay derived.")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var pairedBody: some View {
        ScrollView {
            VStack(spacing: 16) {
                accountBody
                ownerKeyBanner
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("Pending requests").font(.headline)
                        Spacer()
                        Button("Refresh") { Task { await model.refreshInbox() } }
                    }
                    Text("Pull inbox is the default Simulator/free-account path. APNs is an optional physical-device enhancement.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    if model.inbox.isEmpty {
                        Text("No pending requests.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(model.inbox) { item in
                            Button {
                                Task { await model.openInboxItem(item) }
                            } label: {
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(item.matchCode.display)
                                        .font(.body.monospaced().bold())
                                    Text("Expires \(Date(timeIntervalSince1970: Double(item.expiresAt) / 1000).formatted())")
                                        .font(.caption)
                                    Text(item.operationId)
                                        .font(.caption2.monospaced())
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                            }
                            .buttonStyle(.bordered)
                        }
                    }
                    if !model.inboxStatusLine.isEmpty {
                        Text(model.inboxStatusLine).font(.caption)
                    }
                }
                if let approval = model.approval {
                    ApprovalView(model: approval)
                }
                if !model.deliveryLine.isEmpty {
                    Text(model.deliveryLine).font(.footnote)
                }
                Divider()
                VStack(spacing: 8) {
                    Text("Inbox unavailable? Paste the operation id from the web example.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    TextField("operation id", text: $model.operationIdText)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .font(.caption.monospaced())
                    Button("Open request") { Task { await model.openManually() } }
                }
                if !model.statusLine.isEmpty {
                    Text(model.statusLine).font(.footnote)
                }
                Button("Clear pairing", role: .destructive) { model.unpair() }
                    .font(.footnote)
            }
            .padding()
        }
        .navigationTitle("OAAth approvals")
        .task(id: model.pollingIdentity) {
            await model.pollInbox()
        }
    }
}
#endif
