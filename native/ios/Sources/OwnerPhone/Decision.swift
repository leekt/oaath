/**
 EXPERIMENTAL PREVIEW — the approve/reject decision keyed by the stable
 operation id, mirroring `packages/server/src/native/decision.ts`.

 Replayed-outcome semantics, exactly as the server documents them:

 - A second decide answers the *stored* outcome, not the resubmitted command.
   If a rejected request is retried as approved, the answer is `rejected`.
 - The one-time code and artifact are released to the deciding call only. A
   replay reports the outcome and no release material.

 The review state machine below is the phone-local pure part: it enforces the
 allowed transitions, keeps an ambiguous submission as an explicit unresolved
 intent (never auto-resubmitted — a retry is safe only because the saga is
 replay-only), and fails closed on contradictory evidence.

 @author taek <leekt216@gmail.com>
 */
import Foundation

public enum OwnerPhoneOutcome: String, Equatable, Sendable {
    case approved
    case rejected
}

public enum OwnerPhoneSettlement: String, Equatable, Sendable {
    /// This call performed the transition.
    case decided
    /// The call answered the already-stored outcome; no release material.
    case replayed
}

/// Mirrors the native phone body parsed by `phoneDecisionCommand` in
/// `packages/server/src/relay/handler.ts`. This is deliberately not the
/// authorization route's `{outcome}` envelope.
public enum OwnerPhoneDecisionCommand: Equatable, Sendable {
    /// The owner approves and hands over the artifact the client will claim once.
    case approved(artifact: String)
    case rejected

    public var outcome: OwnerPhoneOutcome {
        switch self {
        case .approved: return .approved
        case .rejected: return .rejected
        }
    }

    /// Strict JSON encoding of the command body.
    public func encode() throws -> Data {
        let object: [String: Any]
        switch self {
        case let .approved(artifact):
            _ = try Wire.text(artifact, maximum: WireLimits.artifactPlaintext, label: "artifact")
            object = ["command": "approve", "artifact": artifact]
        case .rejected:
            object = ["command": "reject"]
        }
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        guard data.count <= WireLimits.requestBody else {
            throw OwnerPhoneWireError.invalidField("artifact")
        }
        return data
    }
}

/// Mirrors `SubmittedAuthorizationDecision`: released exactly once, to the
/// deciding call only.
public enum OwnerPhoneRelease: Equatable, Sendable {
    case approved(code: String, artifactId: String, redirectUri: String, codeExpiresAt: Int)
    case rejected

    public var outcome: OwnerPhoneOutcome {
        switch self {
        case .approved: return .approved
        case .rejected: return .rejected
        }
    }
}

/// Mirrors `OwnerPhoneDecision` in `native/decision.ts`.
public struct OwnerPhoneDecision: Equatable, Sendable {
    public let operationId: String
    /// The stored outcome, which on a replay may differ from the command sent.
    public let outcome: OwnerPhoneOutcome
    public let decidedAt: Int
    public let settlement: OwnerPhoneSettlement
    /// One-time release material, on the deciding call only.
    public let release: OwnerPhoneRelease?

    public init(
        operationId: String,
        outcome: OwnerPhoneOutcome,
        decidedAt: Int,
        settlement: OwnerPhoneSettlement,
        release: OwnerPhoneRelease?
    ) {
        self.operationId = operationId
        self.outcome = outcome
        self.decidedAt = decidedAt
        self.settlement = settlement
        self.release = release
    }

    /// Strict decode enforcing the documented one-shot semantics: `decided`
    /// carries a release agreeing with the outcome and timestamp; `replayed`
    /// carries `release: null`. Anything else is contradictory evidence.
    public static func decode(_ data: Data) throws -> OwnerPhoneDecision {
        let object = try Wire.object(data, label: "owner phone decision")
        try Wire.exactKeys(
            object,
            ["operationId", "outcome", "decidedAt", "settlement", "release"],
            label: "owner phone decision")
        guard let outcome = (object["outcome"] as? String).flatMap(OwnerPhoneOutcome.init) else {
            throw OwnerPhoneWireError.invalidField("outcome")
        }
        guard let settlement = (object["settlement"] as? String).flatMap(OwnerPhoneSettlement.init) else {
            throw OwnerPhoneWireError.invalidField("settlement")
        }
        let decidedAt = try Wire.timestamp(object["decidedAt"], label: "decidedAt")
        // release.decidedAt is required present by the exact-key check but its
        // value is deliberately unused here: the server guarantees it equals the
        // outer decidedAt, and the phone renders only the outer one. Nothing on
        // this device decides anything from it.
        let release = try decodeRelease(object["release"])

        switch settlement {
        case .replayed:
            guard release == nil else {
                throw OwnerPhoneWireError.invalidField("release")
            }
        case .decided:
            guard let release, release.outcome == outcome else {
                throw OwnerPhoneWireError.invalidField("release")
            }
        }
        return OwnerPhoneDecision(
            operationId: try Wire.identifier(
                object["operationId"], maximum: WireLimits.operationId, label: "operationId"),
            outcome: outcome,
            decidedAt: decidedAt,
            settlement: settlement,
            release: release
        )
    }

    private static func decodeRelease(_ value: Any?) throws -> OwnerPhoneRelease? {
        if value is NSNull {
            return nil
        }
        let object = try Wire.object(value, label: "release")
        switch object["outcome"] as? String {
        case "approved":
            try Wire.exactKeys(
                object,
                ["outcome", "decidedAt", "code", "artifactId", "redirectUri", "codeExpiresAt"],
                label: "release")
            return .approved(
                code: try Wire.identifier(object["code"], label: "code"),
                artifactId: try Wire.identifier(object["artifactId"], label: "artifactId"),
                redirectUri: try Wire.text(
                    object["redirectUri"], maximum: WireLimits.redirectUri, label: "redirectUri"),
                codeExpiresAt: try Wire.timestamp(object["codeExpiresAt"], label: "codeExpiresAt")
            )
        case "rejected":
            try Wire.exactKeys(object, ["outcome", "decidedAt"], label: "release")
            return .rejected
        default:
            throw OwnerPhoneWireError.invalidField("release")
        }
    }
}

/// Pure phone-local review state machine for one projected request.
public struct OwnerPhoneReview: Equatable, Sendable {
    public enum State: Equatable, Sendable {
        case pending
        case submitting(OwnerPhoneOutcome)
        case settled(OwnerPhoneDecision)
    }

    public enum TransitionError: Error, Equatable, Sendable {
        case expired
        case notPending
        case notSubmitting
        /// An unresolved intent exists for the opposite outcome; the stored
        /// outcome must be learned before the owner may switch commands.
        case conflictingUnresolvedIntent
        case operationMismatch
        /// A `decided` settlement whose outcome differs from the command this
        /// call sent: the server documents that as impossible, so fail closed.
        case contradictoryEvidence
    }

    public let projection: OwnerPhoneRequestProjection
    public private(set) var state: State = .pending
    /// The command whose submission ended ambiguously. Never auto-resubmitted;
    /// an explicit retry is safe because a retry answers the stored outcome.
    public private(set) var unresolvedIntent: OwnerPhoneOutcome?
    /// The last command this device sent, kept to render replay honesty.
    public private(set) var submittedOutcome: OwnerPhoneOutcome?

    public init(projection: OwnerPhoneRequestProjection) {
        self.projection = projection
    }

    /// `now` is epoch milliseconds; the relay itself refuses to decide an
    /// expired request, so the phone does not start a doomed submission.
    public mutating func beginSubmission(_ outcome: OwnerPhoneOutcome, now: Int) throws {
        guard case .pending = state else { throw TransitionError.notPending }
        guard now < projection.expiresAt else { throw TransitionError.expired }
        if let unresolvedIntent, unresolvedIntent != outcome {
            throw TransitionError.conflictingUnresolvedIntent
        }
        submittedOutcome = outcome
        state = .submitting(outcome)
    }

    public mutating func settle(_ decision: OwnerPhoneDecision) throws {
        guard case let .submitting(sent) = state else { throw TransitionError.notSubmitting }
        guard decision.operationId == projection.operationId else {
            throw TransitionError.operationMismatch
        }
        if decision.settlement == .decided, decision.outcome != sent {
            throw TransitionError.contradictoryEvidence
        }
        unresolvedIntent = nil
        state = .settled(decision)
    }

    /// `ambiguous: true` means the transport failed after the command may have
    /// reached the relay; the intent is kept so the retry stays explicit.
    /// `ambiguous: false` means the command provably never left this device.
    public mutating func submissionFailed(ambiguous: Bool) throws {
        guard case let .submitting(sent) = state else { throw TransitionError.notSubmitting }
        unresolvedIntent = ambiguous ? sent : nil
        state = .pending
    }

    /// True when the stored outcome answered a differing retried command —
    /// the honest replay case the UI must say out loud.
    public var storedOutcomeOverrodeCommand: Bool {
        guard case let .settled(decision) = state, let submittedOutcome else { return false }
        return decision.outcome != submittedOutcome
    }
}
