/**
 EXPERIMENTAL PREVIEW — owner approval UI over the review state machine.

 The view is the consent surface: it renders the projection exactly as the
 relay sends it — application, client, origin, redirect target, device,
 account, credentials, custody, every permitted call and argument constraint,
 validity window, and operation limit — so the owner sees exactly the
 authority they grant before tapping approve. Unstructured and current v3
 owner-signing scopes are rendered for explicit rejection, never silently,
 and expose no approval action. The permission approval artifact is
 deployment-injected: composing what the client will claim is not this app's
 job.

 Approval is always an explicit tap on this screen. A push notification only
 opens the review; nothing decides on tap, foreground, or notification action.

 Replay honesty: when a settlement is `replayed`, the UI says the stored
 outcome answered — and says so louder when that stored outcome differs from
 the command this device sent.

 @author taek <leekt216@gmail.com>
 */
#if canImport(SwiftUI)
import SwiftUI

/// Closed provenance/assurance vocabulary for the existing permission review.
/// This projection carries no materialization, installation, or simulation
/// evidence, so there is deliberately no `onchainEnforced`/`guaranteed` case.
enum PermissionConsentEvidence: Equatable, Sendable {
    /// The relay bound this fact to the authenticated authorization request.
    case relayBound
    /// The fact is part of the application's requested permission scope.
    case requestedScope
    /// The application requested this constraint, but this projection does not
    /// prove that it has been materialized or installed onchain.
    case requestedConstraint

    var display: String {
        switch self {
        case .relayBound:
            return "Relay-bound"
        case .requestedScope:
            return "Requested scope"
        case .requestedConstraint:
            return "Requested constraint · enforcement unproven"
        }
    }
}

/// One immutable fact rendered from an already-decoded permission projection.
/// The value remains typed until the view formats it, so tests can prove that
/// every authority-defining field reaches the consent surface without relying
/// on locale-specific rendered date strings. `evidence` is non-optional so no
/// rendered fact can silently omit its provenance/assurance state.
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
    let evidence: PermissionConsentEvidence
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
    static let evidenceNotice =
        "Evidence labels distinguish relay-bound facts from the requested scope. "
        + "This review has no materialization, onchain-install, or simulation evidence; "
        + "requested constraints are not guaranteed."

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
                        evidence: .requestedScope,
                        value: .text(scope.application.applicationId)),
                    .init(
                        id: "application.permissionClientId",
                        label: "Permission client ID",
                        evidence: .requestedScope,
                        value: .text(scope.application.clientId)),
                    .init(
                        id: "application.authenticatedClientId",
                        label: "Authenticated client ID",
                        evidence: .relayBound,
                        value: .text(client.clientId)),
                    .init(
                        id: "application.origin",
                        label: "Origin",
                        evidence: .requestedScope,
                        value: .text(scope.application.origin)),
                    .init(
                        id: "application.redirectUri",
                        label: "Code delivery",
                        evidence: .relayBound,
                        value: .text(client.redirectUri)),
                    .init(
                        id: "application.deviceFingerprint",
                        label: "Device fingerprint",
                        evidence: .requestedScope,
                        value: .text(scope.application.deviceFingerprint)),
                ]),
            PermissionConsentSection(
                id: "account",
                title: "Kernel account",
                facts: [
                    .init(
                        id: "account.accountIndex",
                        label: "Account index",
                        evidence: .requestedScope,
                        value: .text(scope.account.accountIndex)),
                    .init(
                        id: "account.kernelVersion",
                        label: "Kernel version",
                        evidence: .requestedScope,
                        value: .text(scope.account.kernelVersion)),
                    .init(
                        id: "account.factoryRoute",
                        label: "Factory route",
                        evidence: .requestedScope,
                        value: .text(scope.account.factoryRoute)),
                    .init(
                        id: "account.entryPointVersion",
                        label: "EntryPoint version",
                        evidence: .requestedScope,
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
                        evidence: .requestedScope,
                        value: .text(scope.sessionSigner?.mode ?? "frontend")),
                    .init(
                        id: "authority.providerId",
                        label: "Session provider",
                        evidence: .requestedScope,
                        value: .text(scope.sessionSigner?.providerId ?? "none")),
                    .init(
                        id: "authority.chainScope",
                        label: "Chain scope",
                        evidence: .requestedConstraint,
                        value: .text(scope.chainScope)),
                ]),
        ]

        for (callIndex, call) in scope.calls.enumerated() {
            var facts = [
                PermissionConsentFact(
                    id: "call.\(callIndex).target",
                    label: "Target",
                    evidence: .requestedConstraint,
                    value: .text(call.target)),
                PermissionConsentFact(
                    id: "call.\(callIndex).selector",
                    label: "Selector",
                    evidence: .requestedConstraint,
                    value: .text(call.selector)),
                PermissionConsentFact(
                    id: "call.\(callIndex).valueLimit",
                    label: "Value limit (wei)",
                    evidence: .requestedConstraint,
                    value: .text(call.valueLimit)),
            ]
            for (ruleIndex, rule) in call.argumentEquals.enumerated() {
                facts.append(contentsOf: [
                    PermissionConsentFact(
                        id: "call.\(callIndex).argument.\(ruleIndex).index",
                        label: "Argument constraint \(ruleIndex + 1) word index",
                        evidence: .requestedConstraint,
                        value: .text(String(rule.index))),
                    PermissionConsentFact(
                        id: "call.\(callIndex).argument.\(ruleIndex).value",
                        label: "Argument constraint \(ruleIndex + 1) equals",
                        evidence: .requestedConstraint,
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
                    evidence: .requestedScope,
                    value: .unixSeconds(scope.requestedAt)),
                .init(
                    id: "validity.expiresAt",
                    label: "Permission request expires",
                    evidence: .requestedScope,
                    value: .unixSeconds(scope.expiresAt)),
                .init(
                    id: "validity.policyValidAfter",
                    label: "Policy valid after",
                    evidence: .requestedConstraint,
                    value: .unixSeconds(scope.policyValidAfter)),
                .init(
                    id: "validity.policyValidUntil",
                    label: "Policy valid until",
                    evidence: .requestedConstraint,
                    value: scope.policyValidUntil.map(PermissionConsentFact.Value.unixSeconds)
                        ?? .text("no upper bound")),
                .init(
                    id: "validity.perChainOperationLimit",
                    label: "Operations per chain",
                    evidence: .requestedConstraint,
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
                .init(
                    id: "\(prefix).kind",
                    label: "\(label) kind",
                    evidence: .requestedScope,
                    value: .text("ECDSA")),
                .init(
                    id: "\(prefix).address",
                    label: "\(label) address",
                    evidence: .requestedScope,
                    value: .text(address)),
            ]
        case let .p256(publicKey):
            return [
                .init(
                    id: "\(prefix).kind",
                    label: "\(label) kind",
                    evidence: .requestedScope,
                    value: .text("P-256")),
                .init(
                    id: "\(prefix).publicKey",
                    label: "\(label) public key",
                    evidence: .requestedScope,
                    value: .text(publicKey)),
            ]
        case let .webauthn(publicKey, authenticatorIdHash):
            return [
                .init(
                    id: "\(prefix).kind",
                    label: "\(label) kind",
                    evidence: .requestedScope,
                    value: .text("WebAuthn")),
                .init(
                    id: "\(prefix).publicKey",
                    label: "\(label) public key",
                    evidence: .requestedScope,
                    value: .text(publicKey)),
                .init(
                    id: "\(prefix).authenticatorIdHash",
                    label: "Authenticator ID hash",
                    evidence: .requestedScope,
                    value: .text(authenticatorIdHash)),
            ]
        }
    }
}

/// One exact, immutable fact from the captured owner-signing request. Strings
/// are rendered with quotes so control characters cannot masquerade as UI.
struct OwnerSigningConsentFact: Equatable, Identifiable, Sendable {
    let id: String
    let label: String
    let value: String
}

struct OwnerSigningConsentSection: Equatable, Identifiable, Sendable {
    let id: String
    let title: String
    let facts: [OwnerSigningConsentFact]
}

/// Pure presentation of every captured owner-signing fact. It does not derive
/// requestHash, authorize, sign, predict an outcome, or create an artifact.
struct OwnerSigningConsentPresentation: Equatable, Sendable {
    let sections: [OwnerSigningConsentSection]

    init(scope: OwnerPhoneSigningRequestScope) {
        var sections = [OwnerSigningConsentSection(
            id: "request",
            title: "Reject-only owner-signing request",
            facts: [
                .init(
                    id: "request.decision",
                    label: "Decision capability",
                    value: "reject only"),
                .init(
                    id: "request.requestHash",
                    label: "Server/protocol request hash (not device-derived)",
                    value: scope.requestHash),
            ])]

        switch scope.request {
        case let .eip712(request):
            sections.append(contentsOf: Self.eip712Sections(request))
        case let .rawDigest(request):
            sections.append(OwnerSigningConsentSection(
                id: "rawDigest",
                title: "Raw digest — cannot be independently derived",
                facts: [
                    .init(
                        id: "rawDigest.version",
                        label: "Protocol version",
                        value: request.version),
                    .init(id: "rawDigest.kind", label: "Request kind", value: "raw-digest"),
                    .init(id: "rawDigest.digest", label: "Supplied digest", value: request.digest),
                    .init(
                        id: "rawDigest.reason",
                        label: "Reject-only reason",
                        value: String(reflecting: request.reason)),
                ]))
        }
        self.sections = sections
    }

    private static func eip712Sections(
        _ request: OwnerPhoneEIP712SigningRequest
    ) -> [OwnerSigningConsentSection] {
        let derived: String
        let comparison: String
        switch request.digestComparison {
        case let .matches(value):
            derived = value.canonicalHex
            comparison = "matches expected digest"
        case let .mismatch(_, value):
            derived = value.canonicalHex
            comparison = "MISMATCH — reject"
        }

        var result = [
            OwnerSigningConsentSection(
                id: "identity",
                title: "Request and signer",
                facts: [
                    .init(
                        id: "identity.version",
                        label: "Protocol version",
                        value: request.version),
                    .init(id: "identity.kind", label: "Request kind", value: "eip712"),
                    .init(
                        id: "identity.purpose",
                        label: "Purpose",
                        value: request.purpose.rawValue),
                    .init(
                        id: "identity.account",
                        label: "Signer account",
                        value: request.signer.account),
                ] + credentialFacts(request.signer.ownerCredential)),
            OwnerSigningConsentSection(
                id: "digest",
                title: "Device-derived EIP-712 comparison",
                facts: [
                    .init(
                        id: "digest.expected",
                        label: "Expected digest",
                        value: request.expectedDigest),
                    .init(
                        id: "digest.derived",
                        label: "Device-derived digest",
                        value: derived),
                    .init(id: "digest.comparison", label: "Comparison", value: comparison),
                ]),
            OwnerSigningConsentSection(
                id: "replay",
                title: "Replay facts (request metadata)",
                facts: [
                    .init(
                        id: "replay.nonce",
                        label: "Nonce",
                        value: request.replay.nonce ?? "absent"),
                    .init(
                        id: "replay.deadline",
                        label: "Deadline",
                        value: request.replay.deadline ?? "absent"),
                ]),
            OwnerSigningConsentSection(
                id: "typedData",
                title: "EIP-712 typed data",
                facts: [
                    .init(
                        id: "typedData.primaryType",
                        label: "Primary type",
                        value: request.typedData.primaryType)
                ]),
        ]

        for typeName in request.typedData.types.keys.sorted() {
            let fields = request.typedData.types[typeName] ?? []
            var facts = [OwnerSigningConsentFact(
                id: "type.\(typeName).fieldCount",
                label: "Field count",
                value: String(fields.count))]
            for (index, field) in fields.enumerated() {
                facts.append(contentsOf: [
                    .init(
                        id: "type.\(typeName).field.\(index).name",
                        label: "Field \(index + 1) name",
                        value: field.name),
                    .init(
                        id: "type.\(typeName).field.\(index).type",
                        label: "Field \(index + 1) type",
                        value: field.type),
                ])
            }
            result.append(OwnerSigningConsentSection(
                id: "type.\(typeName)",
                title: "Type \(typeName)",
                facts: facts))
        }

        result.append(OwnerSigningConsentSection(
            id: "domain",
            title: "Domain values",
            facts: valueFacts(
                id: "domain",
                label: "domain",
                value: .object(request.typedData.domain))))
        result.append(OwnerSigningConsentSection(
            id: "message",
            title: "Message values",
            facts: valueFacts(
                id: "message",
                label: "message",
                value: .object(request.typedData.message))))
        return result
    }

    private static func credentialFacts(
        _ profile: OwnerPhoneSigningCredential
    ) -> [OwnerSigningConsentFact] {
        var facts = [OwnerSigningConsentFact(
            id: "identity.credential.version",
            label: "Owner credential version",
            value: profile.version)]
        switch profile.credential {
        case let .ecdsa(address):
            facts.append(contentsOf: [
                .init(
                    id: "identity.credential.kind",
                    label: "Owner credential kind",
                    value: "ecdsa"),
                .init(
                    id: "identity.credential.address",
                    label: "Owner credential address",
                    value: address),
            ])
        case let .p256(publicKey):
            facts.append(contentsOf: [
                .init(
                    id: "identity.credential.kind",
                    label: "Owner credential kind",
                    value: "p256"),
                .init(
                    id: "identity.credential.publicKey",
                    label: "Owner credential public key",
                    value: publicKey),
            ])
        case let .webauthn(publicKey, authenticatorIdHash):
            facts.append(contentsOf: [
                .init(
                    id: "identity.credential.kind",
                    label: "Owner credential kind",
                    value: "webauthn"),
                .init(
                    id: "identity.credential.publicKey",
                    label: "Owner credential public key",
                    value: publicKey),
                .init(
                    id: "identity.credential.authenticatorIdHash",
                    label: "Authenticator ID hash",
                    value: authenticatorIdHash),
            ])
        }
        return facts
    }

    private static func valueFacts(
        id: String,
        label: String,
        value: CanonicalEIP712Value
    ) -> [OwnerSigningConsentFact] {
        switch value {
        case let .string(text):
            return [.init(id: id, label: label, value: String(reflecting: text))]
        case let .boolean(flag):
            return [.init(id: id, label: label, value: flag ? "true" : "false")]
        case let .array(entries):
            var facts = [OwnerSigningConsentFact(
                id: "\(id).meta.count", label: "\(label) count", value: String(entries.count))]
            for (index, entry) in entries.enumerated() {
                facts.append(contentsOf: valueFacts(
                    id: "\(id).index.\(index)",
                    label: "\(label)[\(index)]",
                    value: entry))
            }
            return facts
        case let .object(entries):
            var facts = [OwnerSigningConsentFact(
                id: "\(id).meta.fieldCount",
                label: "\(label) field count",
                value: String(entries.count))]
            for key in entries.keys.sorted() {
                guard let entry = entries[key] else { continue }
                facts.append(contentsOf: valueFacts(
                    id: "\(id).field.\(key)",
                    label: "\(label).\(key)",
                    value: entry))
            }
            return facts
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
    /// Produces the artifact an approval hands over for the reviewed structured
    /// permission projection. Reject-only scopes are gated before this
    /// deployment-injected boundary.
    private let approvalArtifact: @Sendable (OwnerPhoneRequestProjection) async throws -> String
    private let kernelP256ApprovalBinding: OwnerPhoneKernelP256ApprovalBinding?
    private let now: @Sendable () -> Int

    /// Immutable ownership for one exact authenticated projection. Async UI
    /// actions may finish only while this token still owns the displayed review.
    private struct ReviewToken: Equatable {
        let id: UUID
        let projection: OwnerPhoneRequestProjection
    }

    /// Memory-only evidence for the exact review that produced it. A candidate
    /// survives only once a submission becomes ambiguous; an older ambiguous
    /// artifact is never discarded by a later proven-unsent retry.
    private struct RetainedKernelArtifact {
        let reviewTokenId: UUID
        let canonical: String
        var ambiguouslySubmitted: Bool
    }

    private var activeLoadToken: UUID?
    private var currentReviewToken: ReviewToken?
    private var activeAuthorizationToken: UUID?
    private var retainedKernelArtifact: RetainedKernelArtifact?
    private var isForeground = false
    private var foregroundGeneration = 0

    public init(
        relay: any OwnerPhoneRelayClient,
        approvalArtifact: @escaping @Sendable (OwnerPhoneRequestProjection) async throws -> String,
        kernelP256ApprovalBinding: OwnerPhoneKernelP256ApprovalBinding? = nil,
        now: @escaping @Sendable () -> Int = { Int(Date().timeIntervalSince1970 * 1000) }
    ) {
        self.relay = relay
        self.approvalArtifact = approvalArtifact
        self.kernelP256ApprovalBinding = kernelP256ApprovalBinding
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
        switch approvalAvailability(for: review.projection) {
        case .permission:
            await approvePermission(token: token, review: review)
        case .kernelP256OwnerSigning:
            guard let binding = kernelP256ApprovalBinding else { return }
            await approveKernel(
                token: token,
                review: review,
                binding: binding)
        case .rejectOnly:
            return
        }
    }

    /// The sole UI/action approval discriminator: authenticated scope semantics
    /// privately intersected with the one deployment-provided custody binding.
    func approvalAvailability(
        for projection: OwnerPhoneRequestProjection
    ) -> OwnerPhoneApprovalAvailability {
        switch projection.scope {
        case .permissionRequest:
            return .permission
        case let .ownerSigningRequest(scope):
            guard scope.decisionCapability == .approveOrReject,
                  let binding = kernelP256ApprovalBinding,
                  binding.semanticallyMatches(projection)
            else { return .rejectOnly }
            return .kernelP256OwnerSigning
        case .raw:
            return .rejectOnly
        }
    }

    public func reject() async {
        guard let (token, review) = capturedReview() else { return }
        await decide(.rejected, token: token, review: review)
    }

    /// ApprovalView is the sole lifecycle driver. Permission approvals do not
    /// consult this state; only user-presence owner signing is foreground-bound.
    func setForeground(_ foreground: Bool) {
        if isForeground, !foreground {
            foregroundGeneration &+= 1
        }
        isForeground = foreground
    }

    private func approvePermission(
        token: ReviewToken,
        review: OwnerPhoneReview
    ) async {
        let request = review.projection
        guard let artifact = try? await approvalArtifact(request) else {
            return // artifact composition failed before any submission; still pending
        }
        // Artifact generation suspended. It may be sent only if this exact
        // pending review still owns the consent surface.
        guard owns(token, displayedReview: review) else { return }
        await decide(.approved(artifact: artifact), token: token, review: review)
    }

    private func approveKernel(
        token: ReviewToken,
        review capturedReview: OwnerPhoneReview,
        binding: OwnerPhoneKernelP256ApprovalBinding
    ) async {
        let startedAt = now()
        guard owns(token, displayedReview: capturedReview),
              !Task.isCancelled,
              isForeground,
              binding.pairingIsCurrent(),
              binding.validates(capturedReview, now: startedAt)
        else { return }

        var review = capturedReview
        do {
            try review.beginAuthorization(
                availability: .kernelP256OwnerSigning,
                now: startedAt)
        } catch {
            return
        }
        let authorizationToken = UUID()
        let capturedForegroundGeneration = foregroundGeneration
        activeAuthorizationToken = authorizationToken
        phase = .review(review)

        let artifact: String
        if let retained = retainedKernelArtifact,
           retained.reviewTokenId == token.id,
           retained.ambiguouslySubmitted
        {
            artifact = retained.canonical
        } else {
            let signingTask = Task.detached {
                try Task.checkCancellation()
                return try binding.makeArtifact(capturedReview, now: startedAt)
            }
            do {
                artifact = try await withTaskCancellationHandler(
                    operation: { try await signingTask.value },
                    onCancel: { signingTask.cancel() })
            } catch {
                cancelAuthorizationIfOwned(
                    token: token,
                    authorizationToken: authorizationToken)
                return
            }
            guard ownsAuthorization(token, authorizationToken: authorizationToken) else {
                return
            }
            retainedKernelArtifact = RetainedKernelArtifact(
                reviewTokenId: token.id,
                canonical: artifact,
                ambiguouslySubmitted: false)
        }

        let finishedAt = now()
        guard ownsAuthorization(token, authorizationToken: authorizationToken),
              !Task.isCancelled,
              isForeground,
              foregroundGeneration == capturedForegroundGeneration,
              finishedAt < capturedReview.projection.expiresAt,
              binding.pairingIsCurrent(),
              binding.validates(capturedReview, now: finishedAt)
        else {
            cancelAuthorizationIfOwned(
                token: token,
                authorizationToken: authorizationToken)
            return
        }

        do {
            try review.finishAuthorization(now: finishedAt)
        } catch {
            cancelAuthorizationIfOwned(
                token: token,
                authorizationToken: authorizationToken)
            return
        }
        activeAuthorizationToken = nil
        phase = .review(review)
        await submit(
            .approved(artifact: artifact),
            token: token,
            submittingReview: review,
            retainsKernelArtifact: true)
    }

    private func beginLoading() -> UUID {
        let token = UUID()
        activeLoadToken = token
        // Arrival of a newer request immediately revokes every action owner for
        // the older consent surface, even while projection loading suspends.
        currentReviewToken = nil
        activeAuthorizationToken = nil
        retainedKernelArtifact = nil
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

    private func ownsAuthorization(
        _ token: ReviewToken,
        authorizationToken: UUID
    ) -> Bool {
        guard activeAuthorizationToken == authorizationToken,
              currentReviewToken == token,
              case let .review(current) = phase,
              current.projection == token.projection,
              case .authorizing = current.state
        else { return false }
        return true
    }

    private func cancelAuthorizationIfOwned(
        token: ReviewToken,
        authorizationToken: UUID
    ) {
        guard ownsAuthorization(token, authorizationToken: authorizationToken),
              case let .review(current) = phase
        else { return }
        var review = current
        try? review.authorizationFailed()
        activeAuthorizationToken = nil
        clearKernelCandidate(for: token)
        phase = .review(review)
    }

    private func clearKernelCandidate(for token: ReviewToken) {
        guard let retained = retainedKernelArtifact,
              retained.reviewTokenId == token.id,
              !retained.ambiguouslySubmitted
        else { return }
        retainedKernelArtifact = nil
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
        await submit(
            command,
            token: token,
            submittingReview: review,
            retainsKernelArtifact: false)
    }

    private func submit(
        _ command: OwnerPhoneDecisionCommand,
        token: ReviewToken,
        submittingReview: OwnerPhoneReview,
        retainsKernelArtifact: Bool
    ) async {
        var review = submittingReview
        let operationId = review.projection.operationId
        do {
            let decision = try await relay.submit(operationId: operationId, command: command)
            guard owns(token) else { return }
            try review.settle(decision)
            unresolvedNotice = false
            if retainsKernelArtifact {
                retainedKernelArtifact = nil
            }
        } catch let error as OwnerPhoneWireError {
            guard owns(token) else { return }
            // The command never encoded or the answer was unreadable. An
            // unreadable answer is still an ambiguous submission.
            let ambiguous = !isEncodingFailure(error)
            try? review.submissionFailed(ambiguous: ambiguous)
            unresolvedNotice = review.unresolvedIntent != nil
            updateKernelArtifactAfterFailure(
                for: token,
                retainedByThisSubmission: retainsKernelArtifact,
                ambiguous: ambiguous)
        } catch {
            guard owns(token) else { return }
            try? review.submissionFailed(ambiguous: true)
            unresolvedNotice = true
            updateKernelArtifactAfterFailure(
                for: token,
                retainedByThisSubmission: retainsKernelArtifact,
                ambiguous: true)
        }
        guard owns(token) else { return }
        phase = .review(review)
    }

    private func updateKernelArtifactAfterFailure(
        for token: ReviewToken,
        retainedByThisSubmission: Bool,
        ambiguous: Bool
    ) {
        guard retainedByThisSubmission,
              var retained = retainedKernelArtifact,
              retained.reviewTokenId == token.id
        else { return }
        if ambiguous {
            retained.ambiguouslySubmitted = true
            retainedKernelArtifact = retained
        } else if !retained.ambiguouslySubmitted {
            retainedKernelArtifact = nil
        }
    }

    private func isEncodingFailure(_ error: OwnerPhoneWireError) -> Bool {
        if case .invalidField("artifact") = error { return true }
        return false
    }
}

public struct ApprovalView: View {
    @Environment(\.scenePhase) private var scenePhase
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
        .onAppear { model.setForeground(scenePhase == .active) }
        .onChange(of: scenePhase) { phase in
            model.setForeground(phase == .active)
        }
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
                switch model.approvalAvailability(for: review.projection) {
                case .permission, .kernelP256OwnerSigning:
                    Button("Approve") { Task { await model.approve() } }
                        .buttonStyle(.borderedProminent)
                case .rejectOnly:
                    EmptyView()
                }
            }
        case .authorizing:
            ProgressView("Authorizing…")
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
                case let .ownerSigningRequest(scope):
                    switch model.approvalAvailability(for: projection) {
                    case .kernelP256OwnerSigning:
                        Text("Kernel owner-signing request — approve only while this exact review, pairing, and foreground consent remain current.")
                            .font(.footnote)
                            .bold()
                    case .permission, .rejectOnly:
                        Text("Owner-signing request — reject only. This build can inspect structured input and derive EIP-712 digests, but it cannot sign, approve, or guarantee an outcome.")
                            .font(.footnote)
                            .bold()
                            .foregroundStyle(.orange)
                    }
                    ownerSigningBody(OwnerSigningConsentPresentation(scope: scope))
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
                Text(PermissionConsentPresentation.evidenceNotice)
                    .font(.footnote)
                    .foregroundStyle(.orange)
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
                                Text(fact.evidence.display)
                                    .font(.caption2)
                                    .bold()
                                    .foregroundStyle(
                                        fact.evidence == .relayBound ? Color.blue : Color.orange)
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
    private func ownerSigningBody(_ presentation: OwnerSigningConsentPresentation) -> some View {
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
                                Text(fact.value)
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
        .frame(maxHeight: 360)
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
