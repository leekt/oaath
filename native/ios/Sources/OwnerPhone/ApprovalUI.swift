/**
 EXPERIMENTAL PREVIEW — owner approval UI over the review state machine.

 The view is the consent surface: it renders the projection exactly as the
 relay sends it — application, client, origin, redirect target, device,
 account, credentials, custody, every permitted call and argument constraint,
 validity window, and operation limit — so the owner sees exactly the
 authority they grant before tapping approve. An unstructured scope is
 rendered as an explicit "review the raw text" state, never silently. The
 approve artifact is deployment-injected: composing what the client will claim
 is not this app's job.

 Approval is always an explicit tap on this screen. A push notification only
 opens the review; nothing decides on tap, foreground, or notification action.

 Replay honesty: when a settlement is `replayed`, the UI says the stored
 outcome answered — and says so louder when that stored outcome differs from
 the command this device sent.

 @author taek <leekt216@gmail.com>
 */
#if canImport(SwiftUI)
import SwiftUI

/// One immutable fact rendered from an already-decoded permission projection.
/// The value remains typed until the view formats it, so tests can prove that
/// every authority-defining field reaches the consent surface without relying
/// on locale-specific rendered date strings.
struct PermissionConsentFact: Equatable, Identifiable, Sendable {
    enum Value: Equatable, Sendable {
        case text(String)
        case unixSeconds(Int)

        var display: String {
            switch self {
            case let .text(value):
                return value
            case let .unixSeconds(value):
                let date = Date(timeIntervalSince1970: Double(value)).formatted()
                return "\(date) (\(value) Unix seconds)"
            }
        }
    }

    let id: String
    let label: String
    let value: Value
}

/// A titled group of permission facts. Stable identifiers make repeated calls
/// and argument rules distinct even when their displayed values are identical.
struct PermissionConsentSection: Equatable, Identifiable, Sendable {
    let id: String
    let title: String
    let facts: [PermissionConsentFact]
}

/// The single presentation owner for a structured permission request. It is a
/// pure projection of authenticated wire facts: it derives labels and ordering,
/// but never adds authority, drops constraints, or rewrites credential bytes.
struct PermissionConsentPresentation: Equatable, Sendable {
    let sections: [PermissionConsentSection]

    init(client: OwnerPhoneClientIdentity, scope: OwnerPhonePermissionScope) {
        var sections = [
            PermissionConsentSection(
                id: "application",
                title: "Application",
                facts: [
                    .init(
                        id: "application.applicationId",
                        label: "Application ID",
                        value: .text(scope.application.applicationId)),
                    .init(
                        id: "application.permissionClientId",
                        label: "Permission client ID",
                        value: .text(scope.application.clientId)),
                    .init(
                        id: "application.authenticatedClientId",
                        label: "Authenticated client ID",
                        value: .text(client.clientId)),
                    .init(
                        id: "application.origin",
                        label: "Origin",
                        value: .text(scope.application.origin)),
                    .init(
                        id: "application.redirectUri",
                        label: "Code delivery",
                        value: .text(client.redirectUri)),
                    .init(
                        id: "application.deviceFingerprint",
                        label: "Device fingerprint",
                        value: .text(scope.application.deviceFingerprint)),
                ]),
            PermissionConsentSection(
                id: "account",
                title: "Kernel account",
                facts: [
                    .init(
                        id: "account.accountIndex",
                        label: "Account index",
                        value: .text(scope.account.accountIndex)),
                    .init(
                        id: "account.kernelVersion",
                        label: "Kernel version",
                        value: .text(scope.account.kernelVersion)),
                    .init(
                        id: "account.factoryRoute",
                        label: "Factory route",
                        value: .text(scope.account.factoryRoute)),
                    .init(
                        id: "account.entryPointVersion",
                        label: "EntryPoint version",
                        value: .text(scope.account.entryPointVersion)),
                ] + Self.credentialFacts(
                    prefix: "account.ownerCredential",
                    label: "Owner credential",
                    credential: scope.account.ownerCredential)),
            PermissionConsentSection(
                id: "authority",
                title: "Session authority",
                facts: Self.credentialFacts(
                    prefix: "authority.operatorCredential",
                    label: "Operator credential",
                    credential: scope.operatorCredential
                ) + [
                    .init(
                        id: "authority.custody",
                        label: "Session custody",
                        value: .text(scope.sessionSigner?.mode ?? "frontend")),
                    .init(
                        id: "authority.providerId",
                        label: "Session provider",
                        value: .text(scope.sessionSigner?.providerId ?? "none")),
                    .init(
                        id: "authority.chainScope",
                        label: "Chain scope",
                        value: .text(scope.chainScope)),
                ]),
        ]

        for (callIndex, call) in scope.calls.enumerated() {
            var facts = [
                PermissionConsentFact(
                    id: "call.\(callIndex).target",
                    label: "Target",
                    value: .text(call.target)),
                PermissionConsentFact(
                    id: "call.\(callIndex).selector",
                    label: "Selector",
                    value: .text(call.selector)),
                PermissionConsentFact(
                    id: "call.\(callIndex).valueLimit",
                    label: "Value limit (wei)",
                    value: .text(call.valueLimit)),
            ]
            for (ruleIndex, rule) in call.argumentEquals.enumerated() {
                facts.append(contentsOf: [
                    PermissionConsentFact(
                        id: "call.\(callIndex).argument.\(ruleIndex).index",
                        label: "Argument constraint \(ruleIndex + 1) word index",
                        value: .text(String(rule.index))),
                    PermissionConsentFact(
                        id: "call.\(callIndex).argument.\(ruleIndex).value",
                        label: "Argument constraint \(ruleIndex + 1) equals",
                        value: .text(rule.value)),
                ])
            }
            sections.append(PermissionConsentSection(
                id: "call.\(callIndex)",
                title: "Permitted call \(callIndex + 1)",
                facts: facts))
        }

        sections.append(PermissionConsentSection(
            id: "validity",
            title: "Validity and limits",
            facts: [
                .init(
                    id: "validity.requestedAt",
                    label: "Requested at",
                    value: .unixSeconds(scope.requestedAt)),
                .init(
                    id: "validity.expiresAt",
                    label: "Permission request expires",
                    value: .unixSeconds(scope.expiresAt)),
                .init(
                    id: "validity.policyValidAfter",
                    label: "Policy valid after",
                    value: .unixSeconds(scope.policyValidAfter)),
                .init(
                    id: "validity.policyValidUntil",
                    label: "Policy valid until",
                    value: scope.policyValidUntil.map(PermissionConsentFact.Value.unixSeconds)
                        ?? .text("no upper bound")),
                .init(
                    id: "validity.perChainOperationLimit",
                    label: "Operations per chain",
                    value: .text(String(scope.perChainOperationLimit))),
            ]))

        self.sections = sections
    }

    private static func credentialFacts(
        prefix: String,
        label: String,
        credential: OwnerPhoneCredential
    ) -> [PermissionConsentFact] {
        switch credential {
        case let .ecdsa(address):
            return [
                .init(id: "\(prefix).kind", label: "\(label) kind", value: .text("ECDSA")),
                .init(id: "\(prefix).address", label: "\(label) address", value: .text(address)),
            ]
        case let .p256(publicKey):
            return [
                .init(id: "\(prefix).kind", label: "\(label) kind", value: .text("P-256")),
                .init(
                    id: "\(prefix).publicKey",
                    label: "\(label) public key",
                    value: .text(publicKey)),
            ]
        case let .webauthn(publicKey, authenticatorIdHash):
            return [
                .init(id: "\(prefix).kind", label: "\(label) kind", value: .text("WebAuthn")),
                .init(
                    id: "\(prefix).publicKey",
                    label: "\(label) public key",
                    value: .text(publicKey)),
                .init(
                    id: "\(prefix).authenticatorIdHash",
                    label: "Authenticator ID hash",
                    value: .text(authenticatorIdHash)),
            ]
        }
    }
}

@MainActor
public final class ApprovalModel: ObservableObject {
    public enum Phase {
        case idle
        case loading
        case review(OwnerPhoneReview)
        /// Structured code only; never provider or transport prose.
        case failed(String)
    }

    @Published public private(set) var phase: Phase = .idle
    /// Set when a submission ended ambiguously; retrying is explicit and safe
    /// because a retry answers the stored outcome, never decides again.
    @Published public private(set) var unresolvedNotice = false

    private let relay: any OwnerPhoneRelayClient
    /// Produces the artifact an approval hands over for the reviewed
    /// projection; deployment-injected. For a signature-request scope the demo
    /// signs the projected digest with the on-device owner key — the artifact
    /// IS the signature.
    private let approvalArtifact: @Sendable (OwnerPhoneRequestProjection) async throws -> String
    private let now: @Sendable () -> Int

    /// Immutable ownership for one exact authenticated projection. Async UI
    /// actions may finish only while this token still owns the displayed review.
    private struct ReviewToken: Equatable {
        let id: UUID
        let projection: OwnerPhoneRequestProjection
    }

    private var activeLoadToken: UUID?
    private var currentReviewToken: ReviewToken?

    public init(
        relay: any OwnerPhoneRelayClient,
        approvalArtifact: @escaping @Sendable (OwnerPhoneRequestProjection) async throws -> String,
        now: @escaping @Sendable () -> Int = { Int(Date().timeIntervalSince1970 * 1000) }
    ) {
        self.relay = relay
        self.approvalArtifact = approvalArtifact
        self.now = now
    }

    public func receive(push: OwnerPhonePush) async {
        let loadToken = beginLoading()
        do {
            let projection = try await relay.projection(operationId: push.operationId)
            guard activeLoadToken == loadToken else { return }
            // The push and the authenticated projection must agree exactly.
            guard push.matches(projection) else {
                activeLoadToken = nil
                phase = .failed("projection_mismatch")
                return
            }
            install(projection, loadToken: loadToken)
        } catch {
            failLoading(loadToken, code: "projection_unavailable")
        }
    }

    /// Manual entry: opens a review from a pasted operation id when no push was
    /// delivered. There is no push to cross-check, so the owner compares the
    /// match code against the browser instead. Opening never decides anything.
    public func open(operationId: String) async {
        let loadToken = beginLoading()
        do {
            let projection = try await relay.projection(operationId: operationId)
            install(projection, loadToken: loadToken)
        } catch {
            failLoading(loadToken, code: "projection_unavailable")
        }
    }

    public func approve() async {
        guard let (token, review) = capturedReview() else { return }
        let request = review.projection
        guard let artifact = try? await approvalArtifact(request) else {
            return // artifact composition failed before any submission; still pending
        }
        // Artifact generation suspended. It may be sent only if this exact
        // pending review still owns the consent surface.
        guard owns(token, displayedReview: review) else { return }
        await decide(.approved(artifact: artifact), token: token, review: review)
    }

    public func reject() async {
        guard let (token, review) = capturedReview() else { return }
        await decide(.rejected, token: token, review: review)
    }

    private func beginLoading() -> UUID {
        let token = UUID()
        activeLoadToken = token
        // Arrival of a newer request immediately revokes every action owner for
        // the older consent surface, even while projection loading suspends.
        currentReviewToken = nil
        unresolvedNotice = false
        phase = .loading
        return token
    }

    private func install(_ projection: OwnerPhoneRequestProjection, loadToken: UUID) {
        guard activeLoadToken == loadToken else { return }
        activeLoadToken = nil
        let token = ReviewToken(id: UUID(), projection: projection)
        currentReviewToken = token
        phase = .review(OwnerPhoneReview(projection: projection))
    }

    private func failLoading(_ loadToken: UUID, code: String) {
        guard activeLoadToken == loadToken else { return }
        activeLoadToken = nil
        phase = .failed(code)
    }

    private func capturedReview() -> (ReviewToken, OwnerPhoneReview)? {
        guard let token = currentReviewToken,
              case let .review(review) = phase,
              review.projection == token.projection
        else { return nil }
        return (token, review)
    }

    private func owns(_ token: ReviewToken, displayedReview: OwnerPhoneReview? = nil) -> Bool {
        guard currentReviewToken == token,
              case let .review(current) = phase,
              current.projection == token.projection
        else { return false }
        return displayedReview == nil || current == displayedReview
    }

    private func decide(
        _ command: OwnerPhoneDecisionCommand,
        token: ReviewToken,
        review capturedReview: OwnerPhoneReview
    ) async {
        guard owns(token, displayedReview: capturedReview) else { return }
        var review = capturedReview
        do {
            try review.beginSubmission(command.outcome, now: now())
        } catch {
            return // forbidden transition; the current state already renders why
        }
        phase = .review(review)
        let operationId = capturedReview.projection.operationId
        do {
            let decision = try await relay.submit(operationId: operationId, command: command)
            guard owns(token) else { return }
            try review.settle(decision)
            unresolvedNotice = false
        } catch let error as OwnerPhoneWireError {
            guard owns(token) else { return }
            // The command never encoded or the answer was unreadable. An
            // unreadable answer is still an ambiguous submission.
            let ambiguous = !isEncodingFailure(error)
            try? review.submissionFailed(ambiguous: ambiguous)
            unresolvedNotice = ambiguous
        } catch {
            guard owns(token) else { return }
            try? review.submissionFailed(ambiguous: true)
            unresolvedNotice = true
        }
        guard owns(token) else { return }
        phase = .review(review)
    }

    private func isEncodingFailure(_ error: OwnerPhoneWireError) -> Bool {
        if case .invalidField("artifact") = error { return true }
        return false
    }
}

public struct ApprovalView: View {
    @ObservedObject private var model: ApprovalModel

    public init(model: ApprovalModel) {
        self.model = model
    }

    public var body: some View {
        VStack(spacing: 16) {
            Text("EXPERIMENTAL PREVIEW")
                .font(.caption2)
                .foregroundStyle(.secondary)
            switch model.phase {
            case .idle:
                Text("Waiting for an approval request.")
            case .loading:
                ProgressView()
            case let .failed(code):
                Text("Request unavailable (\(code)).")
            case let .review(review):
                reviewBody(review)
            }
        }
        .padding()
    }

    @ViewBuilder
    private func reviewBody(_ review: OwnerPhoneReview) -> some View {
        Text(review.projection.matchCode.display)
            .font(.system(.largeTitle, design: .monospaced))
            .bold()
        Text("Compare this code with the one your browser shows.")
            .font(.footnote)
        consentBody(review.projection)
        Text(review.projection.operationId)
            .font(.caption2.monospaced())
            .foregroundStyle(.secondary)
        Text("Request expires \(Date(timeIntervalSince1970: Double(review.projection.expiresAt) / 1000).formatted())")
            .font(.footnote)
            .foregroundStyle(.secondary)

        switch review.state {
        case .pending:
            if model.unresolvedNotice, let intent = review.unresolvedIntent {
                Text("The previous \(intent == .approved ? "approval" : "rejection") outcome is unknown. Retrying is safe: a retry answers the stored outcome and never decides again.")
                    .font(.footnote)
            }
            HStack(spacing: 24) {
                Button("Reject", role: .destructive) { Task { await model.reject() } }
                Button("Approve") { Task { await model.approve() } }
                    .buttonStyle(.borderedProminent)
            }
        case .submitting:
            ProgressView("Submitting…")
        case let .settled(decision):
            settledBody(decision, overridden: review.storedOutcomeOverrodeCommand)
        }
    }

    /// The consent facts: who is asking, and exactly what they may do.
    @ViewBuilder
    private func consentBody(_ projection: OwnerPhoneRequestProjection) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 6) {
                Text("\(projection.client.clientId) requests authority")
                    .font(.subheadline)
                    .bold()
                Text("Code delivery: \(projection.client.redirectUri)")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                switch projection.scope {
                case let .permissionRequest(scope):
                    permissionBody(PermissionConsentPresentation(
                        client: projection.client,
                        scope: scope))
                case let .signatureRequest(scope):
                    // The signing consent: the FULL authenticated canonical
                    // display bytes plus the exact digest the owner key signs. Approve
                    // signs; Reject signs nothing. Nothing decides on tap.
                    Text("Signature request — Approve signs this with the owner key on this device:")
                        .font(.footnote)
                        .bold()
                    ScrollView {
                        // Render the exact authenticated canonical UTF-8 text.
                        // Parse/reserialize would create a second consent surface.
                        Text(scope.display)
                            .font(.caption2.monospaced())
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(maxHeight: 180)
                    Text("digest \(scope.digest)")
                        .font(.caption2.monospaced())
                        .foregroundStyle(.secondary)
                case let .raw(text):
                    // Explicit unstructured state: the owner reviews the raw
                    // text or rejects; nothing is summarized that was not parsed.
                    Text("Unstructured scope — review the raw text:")
                        .font(.footnote)
                        .bold()
                        .foregroundStyle(.orange)
                    ScrollView {
                        Text(text)
                            .font(.caption2.monospaced())
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(maxHeight: 120)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    @ViewBuilder
    private func permissionBody(_ presentation: PermissionConsentPresentation) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                ForEach(presentation.sections) { section in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(section.title)
                            .font(.footnote)
                            .bold()
                        ForEach(section.facts) { fact in
                            VStack(alignment: .leading, spacing: 1) {
                                Text(fact.label)
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                                Text(fact.value.display)
                                    .font(.caption.monospaced())
                                    .textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .frame(maxHeight: 320)
    }

    @ViewBuilder
    private func settledBody(_ decision: OwnerPhoneDecision, overridden: Bool) -> some View {
        Text(decision.outcome == .approved ? "Approved" : "Rejected")
            .font(.title2)
            .bold()
        switch decision.settlement {
        case .decided:
            Text("This device decided the request.")
                .font(.footnote)
        case .replayed:
            Text("Already decided: this is the stored outcome. Nothing was released to this call.")
                .font(.footnote)
            if overridden {
                Text("The stored outcome differs from the command this device sent.")
                    .font(.footnote)
                    .foregroundStyle(.red)
            }
        }
    }
}
#endif
