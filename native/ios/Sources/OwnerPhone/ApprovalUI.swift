/**
 EXPERIMENTAL PREVIEW — owner approval UI over the review state machine.

 The view renders the projection exactly as the relay sends it: the match code,
 the operation id, and the expiry. Nothing else exists in the projection by
 design, so nothing else is shown. The approve artifact is deployment-injected:
 composing what the client will claim is not this app's job.

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
    /// Produces the artifact an approval hands over; deployment-injected.
    private let approvalArtifact: @Sendable () async throws -> String
    private let now: @Sendable () -> Int

    public init(
        relay: any OwnerPhoneRelayClient,
        approvalArtifact: @escaping @Sendable () async throws -> String,
        now: @escaping @Sendable () -> Int = { Int(Date().timeIntervalSince1970 * 1000) }
    ) {
        self.relay = relay
        self.approvalArtifact = approvalArtifact
        self.now = now
    }

    public func receive(push: OwnerPhonePush) async {
        phase = .loading
        do {
            let projection = try await relay.projection(operationId: push.operationId)
            // The push and the authenticated projection must agree exactly.
            guard push.matches(projection) else {
                phase = .failed("projection_mismatch")
                return
            }
            phase = .review(OwnerPhoneReview(projection: projection))
        } catch {
            phase = .failed("projection_unavailable")
        }
    }

    public func approve() async {
        guard case .review = phase else { return }
        guard let artifact = try? await approvalArtifact() else {
            return // artifact composition failed before any submission; still pending
        }
        await decide(.approved(artifact: artifact))
    }

    public func reject() async {
        await decide(.rejected)
    }

    private func decide(_ command: OwnerPhoneDecisionCommand) async {
        guard case var .review(review) = phase else { return }
        do {
            try review.beginSubmission(command.outcome, now: now())
        } catch {
            return // forbidden transition; the current state already renders why
        }
        phase = .review(review)
        do {
            let decision = try await relay.submit(
                operationId: review.projection.operationId, command: command)
            try review.settle(decision)
            unresolvedNotice = false
        } catch let error as OwnerPhoneWireError {
            // The command never encoded or the answer was unreadable. An
            // unreadable answer is still an ambiguous submission.
            let ambiguous = !isEncodingFailure(error)
            try? review.submissionFailed(ambiguous: ambiguous)
            unresolvedNotice = ambiguous
        } catch {
            try? review.submissionFailed(ambiguous: true)
            unresolvedNotice = true
        }
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
        // The projection is opaque by design: match code, operation id, expiry.
        Text(review.projection.matchCode.display)
            .font(.system(.largeTitle, design: .monospaced))
            .bold()
        Text("Compare this code with the one your browser shows.")
            .font(.footnote)
        Text(review.projection.operationId)
            .font(.caption2.monospaced())
            .foregroundStyle(.secondary)
        Text("Expires \(Date(timeIntervalSince1970: Double(review.projection.expiresAt) / 1000).formatted())")
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
