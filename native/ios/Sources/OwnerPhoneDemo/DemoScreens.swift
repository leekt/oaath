/**
 EXPERIMENTAL PREVIEW — the demo app's screens over the OwnerPhone library.

 First launch pairs: relay base URL + the pairing code the example prints. The
 returned device-scoped credential is persisted and used for every later call;
 a refused credential (HTTP 401) clears it and returns to pairing.

 A push notification tap NEVER approves anything: it only opens the consent
 screen, which presents Approve and Reject as explicit buttons (the library's
 `ApprovalView`). Nothing decides on tap, foreground, or notification action.

 @author taek <leekt216@gmail.com>
 */
#if canImport(SwiftUI)
import Combine
import Foundation
import OwnerPhone
import SwiftUI

/// The transport records the last HTTP status so the model can distinguish a
/// refused credential (401 → re-pair) from an unavailable relay.
final class LastStatusBox: @unchecked Sendable {
    private let lock = NSLock()
    private var status: Int?

    func record(_ value: Int?) {
        lock.lock()
        status = value
        lock.unlock()
    }

    func read() -> Int? {
        lock.lock()
        defer { lock.unlock() }
        return status
    }
}

@MainActor
public final class DemoModel: ObservableObject {
    @Published public var baseURLText: String {
        didSet { defaults.set(baseURLText, forKey: Self.baseURLKey) }
    }
    @Published public var pairingCodeText = ""
    @Published public var operationIdText = ""
    @Published public private(set) var paired = false
    @Published public private(set) var statusLine = ""
    @Published public private(set) var approval: ApprovalModel?
    @Published public private(set) var deliveryLine = ""

    /// Set by APNs registration; until then a random placeholder keeps pairing
    /// usable (pushes to it go nowhere — manual operation-id entry still works).
    public var deviceToken: String

    static let baseURLKey = "oaath.demo.baseURL"

    private let credentials: any DeviceCredentialStore
    private let http: any DemoHTTP
    private let defaults: UserDefaults
    private let lastStatus = LastStatusBox()
    private var phaseSink: AnyCancellable?
    private var delivered: Set<String> = []

    public init(
        credentials: any DeviceCredentialStore,
        http: any DemoHTTP = URLSession.shared,
        defaults: UserDefaults = .standard
    ) {
        self.credentials = credentials
        self.http = http
        self.defaults = defaults
        self.baseURLText = defaults.string(forKey: Self.baseURLKey) ?? ""
        self.deviceToken = Self.placeholderDeviceToken()
        if credentials.load() != nil {
            paired = true
            rebuildApproval()
        }
    }

    static func placeholderDeviceToken() -> String {
        (0..<32).map { _ in String(format: "%02x", UInt8.random(in: 0...255)) }.joined()
    }

    public func pair() async {
        statusLine = ""
        do {
            let endpoint = try DemoRelayEndpoint(baseURLText: baseURLText)
            let credential = try await OwnerPhoneDemo.pair(
                endpoint: endpoint,
                pairingCode: pairingCodeText.trimmingCharacters(in: .whitespacesAndNewlines),
                deviceToken: deviceToken,
                http: http)
            credentials.save(credential)
            pairingCodeText = ""
            paired = true
            rebuildApproval()
            statusLine = "Paired. This device now holds its own owner credential."
        } catch DemoPairingError.refused {
            statusLine = "Pairing refused: the code is unknown, already used, or expired."
        } catch {
            statusLine = "Pairing failed: check the relay URL (same network as the Mac?)."
        }
    }

    public func unpair() {
        credentials.clear()
        approval = nil
        phaseSink = nil
        paired = false
        statusLine = "Credential cleared. Pair again with a fresh code."
    }

    public func openManually() async {
        guard let approval else { return }
        deliveryLine = ""
        await approval.open(
            operationId: operationIdText.trimmingCharacters(in: .whitespacesAndNewlines))
        failBackToPairingOn401()
    }

    public func receive(push: OwnerPhonePush) async {
        guard let approval else { return }
        deliveryLine = ""
        await approval.receive(push: push)
        failBackToPairingOn401()
    }

    private func rebuildApproval() {
        guard let credential = credentials.load(),
              let endpoint = try? DemoRelayEndpoint(baseURLText: baseURLText)
        else {
            statusLine = "Set a valid relay URL first."
            paired = credentials.load() != nil
            return
        }
        let box = lastStatus
        let client = demoRelayClient(
            endpoint: endpoint,
            credential: credential,
            http: http,
            onStatus: { box.record($0) })
        let model = ApprovalModel(relay: client, approvalArtifact: { demoApprovalArtifact() })
        approval = model
        phaseSink = model.$phase
            .receive(on: RunLoop.main)
            .sink { [weak self] phase in self?.observe(phase: phase) }
    }

    private func failBackToPairingOn401() {
        if lastStatus.read() == 401 {
            unpair()
            statusLine = "The relay refused this device's credential. Pair again."
        }
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
            Section("Pairing code (printed by examples/phone)") {
                TextField("ABCD-EFGH-IJ", text: $model.pairingCodeText)
                    .autocorrectionDisabled()
                    .font(.body.monospaced())
                Button("Pair this device") { Task { await model.pair() } }
            }
            if !model.statusLine.isEmpty {
                Text(model.statusLine).font(.footnote)
            }
            Section {
                Text("The pairing code printed to the terminal is this demo's trust root, on a trusted network only. A production deployment owns pairing UX (QR, attestation).")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Pair with the relay")
    }

    @ViewBuilder
    private var pairedBody: some View {
        ScrollView {
            VStack(spacing: 16) {
                if let approval = model.approval {
                    ApprovalView(model: approval)
                }
                if !model.deliveryLine.isEmpty {
                    Text(model.deliveryLine).font(.footnote)
                }
                Divider()
                VStack(spacing: 8) {
                    Text("No notification? Paste the operation id the web example printed.")
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
                Button("Unpair this device", role: .destructive) { model.unpair() }
                    .font(.footnote)
            }
            .padding()
        }
        .navigationTitle("OAAth approvals")
    }
}
#endif
