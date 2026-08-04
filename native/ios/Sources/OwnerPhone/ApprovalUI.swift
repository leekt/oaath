/**
 EXPERIMENTAL PREVIEW — owner approval UI over the review state machine.

 The view is the consent surface: it renders the projection exactly as the
 relay sends it — the match code, the requesting client and its redirect
 target, every permitted call with its value limit, the operation limit, and
 the expiries — so the owner sees exactly the authority they grant before
 tapping approve. An unstructured scope is rendered as an explicit "review the
 raw text" state, never silently. The approve artifact is deployment-injected:
 composing what the client will claim is not this app's job.

 Approval is always an explicit tap on this screen. A push notification only
 opens the review; nothing decides on tap, foreground, or notification action.

 Replay honesty: when a settlement is `replayed`, the UI says the stored
 outcome answered — and says so louder when that stored outcome differs from
 the command this device sent.

 @author taek <leekt216@gmail.com>
 */
#if canImport(SwiftUI)
import SwiftUI

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
                    Text("Chain scope: \(scope.chainScope == "all" ? "all chains" : scope.chainScope)")
                        .font(.footnote)
                    ForEach(Array(scope.calls.enumerated()), id: \.offset) { _, call in
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Call \(call.target)")
                                .font(.caption.monospaced())
                            Text("selector \(call.selector), value limit \(call.valueLimit) wei")
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                        }
                    }
                    Text("Up to \(scope.perChainOperationLimit) operations per chain")
                        .font(.footnote)
                    Text("Permission expires \(Date(timeIntervalSince1970: Double(scope.expiresAt)).formatted())")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
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
