/**
 EXPERIMENTAL PREVIEW — owner approval UI over the review state machine.

 The view is the consent surface: it renders the projection exactly as the
 relay sends it — application, client, origin, redirect target, device,
 account, credentials, custody, every permitted call and argument constraint,
 validity window, and operation limit — so the owner sees exactly the
 authority they grant before tapping approve. Exact Kernel/P-256 owner signing
 is labeled approvable only while the local verified binding agrees; every
 other owner-signing scope is rendered for explicit rejection and exposes no
 approval action. The permission approval artifact is deployment-injected:
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

/// One plain-language line summarizing a requested constraint.
struct PermissionConsentHighlight: Equatable, Identifiable, Sendable {
    enum Detail: Equatable, Sendable {
        case text(String)
        case window(from: Int, until: Int)
    }

    let id: String
    let title: String
    let detail: Detail
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
    /// Every authority-defining requested constraint, in reading order: each
    /// permitted call with its value limit and argument constraints, the
    /// per-chain operation limit with chain scope, and the policy window.
    let highlights: [PermissionConsentHighlight]

    /// Who is asking and for which workspace/account, in display order. The
    /// same immutable facts also appear in `sections`.
    var identityFacts: [PermissionConsentFact] {
        let order = [
            "application.applicationId", "application.origin", "application.redirectUri",
            "context.workspaceId", "context.workspaceKind", "context.accountId",
        ]
        let facts = sections.flatMap(\.facts)
        return order.compactMap { id in facts.first { $0.id == id } }
    }

    init(client: OwnerPhoneClientIdentity, scope: OwnerPhonePermissionScope) {
        var highlights = scope.calls.enumerated().map { index, call in
            var detail = call.valueLimit == "0"
                ? "No native value"
                : "Up to \(call.valueLimit) wei per call"
            if !call.argumentEquals.isEmpty {
                let count = call.argumentEquals.count
                detail += " · \(count) argument constraint\(count == 1 ? "" : "s")"
            }
            return PermissionConsentHighlight(
                id: "call.\(index)",
                title: "Call \(call.selector) on \(call.target)",
                detail: .text(detail))
        }
        let limit = scope.perChainOperationLimit
        highlights.append(PermissionConsentHighlight(
            id: "limit",
            title: "Up to \(limit) operation\(limit == 1 ? "" : "s") per chain",
            detail: .text("Chain scope: \(scope.chainScope)")))
        highlights.append(PermissionConsentHighlight(
            id: "window",
            title: scope.policyValidUntil == nil ? "No end date" : "Time limited",
            detail: scope.policyValidUntil.map {
                .window(from: scope.policyValidAfter, until: $0)
            } ?? .text("Valid from the policy start with no upper bound")))
        self.highlights = highlights

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
                        value: .text(client.redirectUri ?? "No code delivery")),
                    .init(
                        id: "application.deviceFingerprint",
                        label: "Device fingerprint",
                        evidence: .requestedScope,
                        value: .text(scope.application.deviceFingerprint)),
                ]),
            PermissionConsentSection(
                id: "context",
                title: "Workspace and account",
                facts: [
                    .init(
                        id: "context.workspaceId",
                        label: "Workspace ID",
                        evidence: .requestedScope,
                        value: .text(scope.context.workspaceId)),
                    .init(
                        id: "context.workspaceKind",
                        label: "Workspace kind",
                        evidence: .requestedScope,
                        value: .text(scope.context.workspaceKind == .personal ? "Personal" : "Team")),
                    .init(
                        id: "context.accountId",
                        label: "Account ID",
                        evidence: .requestedScope,
                        value: .text(scope.context.accountId)),
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
        let title: String
        let decision: String
        switch scope.decisionCapability {
        case .approveOrReject:
            title = "Kernel owner-signing request"
            decision = "approve or reject"
        case .rejectOnly:
            title = "Reject-only owner-signing request"
            decision = "reject only"
        }
        var sections = [OwnerSigningConsentSection(
            id: "request",
            title: title,
            facts: [
                .init(
                    id: "request.decision",
                    label: "Decision capability",
                    value: decision),
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

        var domainFacts = valueFacts(
            id: "domain",
            label: "domain",
            value: .object(request.typedData.domain))
        for field in ["chainId", "verifyingContract"]
        where request.typedData.domain[field] == nil {
            domainFacts.append(.init(
                id: "domain.field.\(field)",
                label: "domain.\(field)",
                value: "absent"))
        }
        result.append(OwnerSigningConsentSection(
            id: "domain",
            title: "Domain values",
            facts: domainFacts))
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

/// Why the last explicit Approve or Reject tap did not proceed. Display only:
/// a notice never authorizes, retries, or decides anything.
public enum ApprovalActionNotice: Equatable, Sendable {
    /// The request expired before the decision could start.
    case expired
    /// An earlier submission is unresolved; only that same decision may retry.
    case conflictingIntent
    /// The signing packet could not be fetched from the relay.
    case signingUnavailable
    /// The signing packet did not match the displayed consent.
    case signingMismatch
    /// This phone's pairing, foreground state, or verification no longer agrees.
    case cannotSign
    /// Signing was cancelled or interrupted before a signature existed.
    case signingCancelled
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
    /// Feedback for the latest tap that could not proceed; cleared on the
    /// next tap or request.
    @Published public private(set) var actionNotice: ApprovalActionNotice?

    private let relay: any OwnerPhoneRelayClient
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
        let signingProjection: OwnerPhoneRequestProjection
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
        kernelP256ApprovalBinding: OwnerPhoneKernelP256ApprovalBinding? = nil,
        now: @escaping @Sendable () -> Int = { Int(Date().timeIntervalSince1970 * 1000) }
    ) {
        self.relay = relay
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
        actionNotice = nil
        guard now() < review.projection.expiresAt else {
            notice(.expired, token: token)
            return
        }
        guard approvalAvailability(for: review.projection) == .kernelP256OwnerSigning,
              let binding = kernelP256ApprovalBinding
        else { return }
        switch review.projection.scope {
        case .permissionRequest:
            await approvePermission(token: token, review: review, binding: binding)
        case .ownerSigningRequest, .kernelRevocation:
            await approveKernel(token: token, review: review, binding: binding,
                                signingProjection: review.projection)
        case .raw:
            return
        }
    }

    /// The sole UI/action approval discriminator: authenticated scope semantics
    /// privately intersected with the one deployment-provided custody binding.
    func approvalAvailability(
        for projection: OwnerPhoneRequestProjection
    ) -> OwnerPhoneApprovalAvailability {
        switch projection.scope {
        case let .permissionRequest(scope):
            guard kernelP256ApprovalBinding != nil,
                  case .p256 = scope.account.ownerCredential,
                  scope.account.factoryRoute == "kernel_factory"
            else { return .rejectOnly }
            return .kernelP256OwnerSigning
        case let .ownerSigningRequest(scope):
            guard scope.decisionCapability == .approveOrReject,
                  let binding = kernelP256ApprovalBinding,
                  binding.semanticallyMatches(projection)
            else { return .rejectOnly }
            return .kernelP256OwnerSigning
        case .kernelRevocation:
            guard let binding = kernelP256ApprovalBinding,
                  binding.semanticallyMatches(projection)
            else { return .rejectOnly }
            return .kernelP256OwnerSigning
        case .raw:
            return .rejectOnly
        }
    }

    public func reject() async {
        guard let (token, review) = capturedReview() else { return }
        actionNotice = nil
        await decide(.rejected, token: token, review: review)
    }

    /// ApprovalView is the sole lifecycle driver for user-presence owner signing.
    func setForeground(_ foreground: Bool) {
        if isForeground, !foreground {
            foregroundGeneration &+= 1
        }
        isForeground = foreground
    }

    private func approvePermission(
        token: ReviewToken,
        review: OwnerPhoneReview,
        binding: OwnerPhoneKernelP256ApprovalBinding
    ) async {
        guard case let .permissionRequest(consent) = review.projection.scope,
              case .pending = review.state,
              !Task.isCancelled, isForeground, binding.pairingIsCurrent(),
              now() < review.projection.expiresAt
        else {
            notice(.cannotSign, token: token)
            return
        }
        let capturedForegroundGeneration = foregroundGeneration
        let signing: OwnerPhoneRequestProjection
        if let retained = retainedKernelArtifact,
           retained.reviewTokenId == token.id, retained.ambiguouslySubmitted
        {
            signing = retained.signingProjection
        } else {
            guard let fetched = try? await relay.permissionSigningProjection(
                operationId: review.projection.operationId)
            else {
                notice(.signingUnavailable, token: token)
                return
            }
            signing = fetched
        }
        // Coming back to this review cannot revive an Approve tap that was
        // interrupted while the relay was preparing its signing packet.
        guard !Task.isCancelled, isForeground,
              foregroundGeneration == capturedForegroundGeneration
        else {
            notice(.signingCancelled, token: token)
            return
        }
        // The authenticated signing packet belongs to the exact consent still
        // displayed. The Kernel binding separately proves paired account/key.
        guard owns(token, displayedReview: review),
              signing.operationId == review.projection.operationId,
              signing.client == review.projection.client,
              signing.matchCode == review.projection.matchCode,
              signing.expiresAt == review.projection.expiresAt,
              case let .ownerSigningRequest(scope) = signing.scope,
              scope.decisionCapability == .approveOrReject,
              case let .eip712(request) = scope.request,
              request.signer.ownerCredential.credential == consent.account.ownerCredential
        else {
            notice(.signingMismatch, token: token)
            return
        }
        await approveKernel(token: token, review: review, binding: binding,
                            signingProjection: signing)
    }

    private func approveKernel(
        token: ReviewToken,
        review capturedReview: OwnerPhoneReview,
        binding: OwnerPhoneKernelP256ApprovalBinding,
        signingProjection: OwnerPhoneRequestProjection
    ) async {
        let signingReview = OwnerPhoneReview(projection: signingProjection)
        let startedAt = now()
        guard owns(token, displayedReview: capturedReview),
              !Task.isCancelled,
              isForeground,
              binding.pairingIsCurrent(),
              binding.validates(signingReview, now: startedAt)
        else {
            notice(.cannotSign, token: token)
            return
        }

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
                return try binding.makeArtifact(signingReview, now: startedAt)
            }
            do {
                artifact = try await withTaskCancellationHandler(
                    operation: { try await signingTask.value },
                    onCancel: { signingTask.cancel() })
            } catch {
                cancelAuthorizationIfOwned(
                    token: token,
                    authorizationToken: authorizationToken)
                notice(.signingCancelled, token: token)
                return
            }
            guard ownsAuthorization(token, authorizationToken: authorizationToken) else {
                return
            }
            retainedKernelArtifact = RetainedKernelArtifact(
                reviewTokenId: token.id,
                canonical: artifact,
                signingProjection: signingProjection,
                ambiguouslySubmitted: false)
        }

        let finishedAt = now()
        guard ownsAuthorization(token, authorizationToken: authorizationToken),
              !Task.isCancelled,
              isForeground,
              foregroundGeneration == capturedForegroundGeneration,
              finishedAt < capturedReview.projection.expiresAt,
              binding.pairingIsCurrent(),
              binding.validates(signingReview, now: finishedAt)
        else {
            cancelAuthorizationIfOwned(
                token: token,
                authorizationToken: authorizationToken)
            notice(.signingCancelled, token: token)
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
        actionNotice = nil
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

    /// Records feedback only while the tapped review still owns the screen.
    private func notice(_ value: ApprovalActionNotice, token: ReviewToken) {
        guard owns(token) else { return }
        actionNotice = value
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
        } catch OwnerPhoneReview.TransitionError.expired {
            notice(.expired, token: token)
            return
        } catch OwnerPhoneReview.TransitionError.conflictingUnresolvedIntent {
            notice(.conflictingIntent, token: token)
            return
        } catch {
            return // other forbidden transitions expose no control for this tap
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
            let decision = try await relay.submit(operationId: operationId, command: command,
                                                  domain: review.projection.decisionDomain)
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
    @State private var isVisible = false
    @ObservedObject private var model: ApprovalModel
    private let onDone: (() -> Void)?

    /// `onDone` leaves a settled, failed, or expired review; it never decides.
    public init(model: ApprovalModel, onDone: (() -> Void)? = nil) {
        self.model = model
        self.onDone = onDone
    }

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                switch model.phase {
                case .idle:
                    stateMessage(
                        icon: "tray",
                        title: "No request open",
                        detail: "Choose a pending request to review it.")
                case .loading:
                    HStack(spacing: 12) {
                        ProgressView()
                        Text("Loading the request…")
                            .font(.body)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, minHeight: 200)
                case let .failed(code):
                    failure(code)
                case let .review(review):
                    reviewBody(review)
                }
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 16)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .safeAreaInset(edge: .bottom) {
            switch model.phase {
            case let .review(review):
                actionBar(review)
            case .failed:
                if let onDone { bar { doneButton(onDone) } }
            case .idle, .loading:
                EmptyView()
            }
        }
        .onAppear {
            isVisible = true
            model.setForeground(scenePhase == .active)
        }
        .onDisappear {
            isVisible = false
            model.setForeground(false)
        }
        .onChange(of: scenePhase) { phase in
            model.setForeground(isVisible && phase == .active)
        }
    }

    // MARK: Review content

    @ViewBuilder
    private func reviewBody(_ review: OwnerPhoneReview) -> some View {
        let projection = review.projection
        VStack(alignment: .leading, spacing: 6) {
            Text(title(for: projection))
                .font(.title2.bold())
                .fixedSize(horizontal: false, vertical: true)
            Text("Experimental preview. Review every fact before you decide.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }

        matchCodeCard(projection)

        switch projection.scope {
        case let .permissionRequest(scope):
            permissionBody(
                PermissionConsentPresentation(client: projection.client, scope: scope),
                redirectUri: projection.client.redirectUri)
        case let .ownerSigningRequest(scope):
            switch model.approvalAvailability(for: projection) {
            case .kernelP256OwnerSigning:
                callout(
                    "Approve only if you started this. This phone signs only while this exact review, pairing, and screen stay current.",
                    icon: "signature", color: .accentColor)
            case .rejectOnly:
                callout(
                    "Reject only. This phone can inspect this request but can't verify it well enough to sign, approve, or predict its outcome.",
                    icon: "exclamationmark.triangle", color: .orange)
            }
            factSections(OwnerSigningConsentPresentation(scope: scope).sections.map(FactGroup.init))
        case let .kernelRevocation(scope):
            callout(
                "Approving lets the service submit this removal on one configured chain. It is finished only when the service confirms it onchain.",
                icon: "arrow.uturn.backward.circle", color: .accentColor)
            if model.approvalAvailability(for: projection) == .rejectOnly {
                callout(
                    "This request doesn't match this phone's paired account, key, or configured chain. Reject only.",
                    icon: "exclamationmark.triangle", color: .orange)
            }
            factSections(KernelRevocationConsentPresentation(scope: scope).sections.map(FactGroup.init))
        case let .raw(text):
            // Explicit unstructured state: the owner reviews the raw text or
            // rejects; nothing is summarized that was not parsed.
            callout(
                "This request isn't structured, so this phone can't summarize it. Review the raw text below, or reject it.",
                icon: "exclamationmark.triangle", color: .orange)
            Text(text)
                .font(.caption.monospaced())
                .textSelection(.enabled)
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(groupBackground)
        }

        VStack(alignment: .leading, spacing: 3) {
            Text("Operation ID")
                .font(.footnote)
                .foregroundStyle(.secondary)
            Text(projection.operationId)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
        }
    }

    private func title(for projection: OwnerPhoneRequestProjection) -> String {
        switch projection.scope {
        case .permissionRequest:
            return "\(projection.client.clientId) is asking for permission"
        case let .kernelRevocation(scope):
            return "Remove the permission for \(projection.client.clientId) on chain \(scope.operation.chainId)"
        case .ownerSigningRequest:
            return "\(projection.client.clientId) is asking for an owner signature"
        case .raw:
            return "\(projection.client.clientId) sent an unstructured request"
        }
    }

    private func matchCodeCard(_ projection: OwnerPhoneRequestProjection) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Match code")
                .font(.footnote.weight(.medium))
                .foregroundStyle(.secondary)
            Text(projection.matchCode.display)
                .font(.system(.largeTitle, design: .monospaced).weight(.bold))
                .textSelection(.enabled)
                .accessibilityLabel("Match code \(projection.matchCode.value.map(String.init).joined(separator: " "))")
            Text("If the requesting app shows a code, it must match this one exactly.")
                .font(.footnote)
                .foregroundStyle(.secondary)
            ExpiryLine(expiresAt: projection.expiresAt)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(groupBackground)
    }

    @ViewBuilder
    private func permissionBody(
        _ presentation: PermissionConsentPresentation,
        redirectUri: String?
    ) -> some View {
        group("What this allows") {
            VStack(alignment: .leading, spacing: 14) {
                ForEach(presentation.highlights) { highlight in
                    HStack(alignment: .firstTextBaseline, spacing: 10) {
                        Image(systemName: "checkmark.circle")
                            .foregroundStyle(Color.accentColor)
                            .accessibilityHidden(true)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(highlight.title)
                                .font(.subheadline.monospaced().weight(.medium))
                                .textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                            Text(detailText(highlight.detail))
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    .accessibilityElement(children: .combine)
                }
            }
        }

        callout(PermissionConsentPresentation.evidenceNotice,
                icon: "exclamationmark.triangle", color: .orange)

        group("Requested by") {
            VStack(alignment: .leading, spacing: 12) {
                ForEach(presentation.identityFacts) { fact in
                    factRow(fact.label, fact.value.display, evidence: fact.evidence)
                }
            }
        }

        DisclosureGroup {
            VStack(alignment: .leading, spacing: 18) {
                ForEach(presentation.sections) { section in
                    VStack(alignment: .leading, spacing: 10) {
                        Text(section.title)
                            .font(.subheadline.weight(.semibold))
                            .accessibilityAddTraits(.isHeader)
                        ForEach(section.facts) { fact in
                            factRow(fact.label, fact.value.display, evidence: fact.evidence)
                        }
                    }
                }
            }
            .padding(.top, 12)
        } label: {
            Text("All request details")
                .font(.subheadline.weight(.semibold))
        }
        .padding(16)
        .background(groupBackground)
    }

    private func detailText(_ detail: PermissionConsentHighlight.Detail) -> String {
        switch detail {
        case let .text(text):
            return text
        case let .window(from, until):
            let start = Date(timeIntervalSince1970: Double(from))
            let end = Date(timeIntervalSince1970: Double(until))
            return "From \(start.formatted(date: .abbreviated, time: .shortened)) until \(end.formatted(date: .abbreviated, time: .shortened))"
        }
    }

    /// Owner-signing and revocation facts are the substance of the request,
    /// so they render expanded.
    private struct FactGroup: Identifiable {
        let id: String
        let title: String
        let facts: [(id: String, label: String, value: String)]

        init(_ section: OwnerSigningConsentSection) {
            id = section.id
            title = section.title
            facts = section.facts.map { ($0.id, $0.label, $0.value) }
        }
    }

    private func factSections(_ groups: [FactGroup]) -> some View {
        ForEach(groups) { entry in
            group(entry.title) {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(entry.facts, id: \.id) { fact in
                        factRow(fact.label, fact.value, evidence: nil)
                    }
                }
            }
        }
    }

    private func factRow(
        _ label: String, _ value: String, evidence: PermissionConsentEvidence?
    ) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                Text(label)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                if let evidence {
                    Text(evidence.shortDisplay)
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(evidence == .relayBound ? Color.accentColor : .orange)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .overlay(
                            Capsule().stroke(
                                (evidence == .relayBound ? Color.accentColor : .orange).opacity(0.5),
                                lineWidth: 1))
                        .accessibilityLabel(evidence.display)
                }
            }
            Text(value)
                .font(.subheadline.monospaced())
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
    }

    // MARK: Decision bar

    @ViewBuilder
    private func actionBar(_ review: OwnerPhoneReview) -> some View {
        bar {
            switch review.state {
            case .pending:
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    let expired = Int(context.date.timeIntervalSince1970 * 1000)
                        >= review.projection.expiresAt
                    pendingControls(review, expired: expired)
                }
            case .authorizing:
                progress("Signing your approval…")
            case let .submitting(outcome):
                progress(outcome == .approved ? "Sending your approval…" : "Sending your rejection…")
            case let .settled(decision):
                settledBody(decision, overridden: review.storedOutcomeOverrodeCommand,
                            domain: review.projection.decisionDomain)
                if let onDone { doneButton(onDone) }
            }
        }
    }

    @ViewBuilder
    private func pendingControls(_ review: OwnerPhoneReview, expired: Bool) -> some View {
        if expired {
            Label("This request expired. Nothing was decided.", systemImage: "clock.badge.xmark")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
            if let onDone { doneButton(onDone) }
        } else {
            if let notice = model.actionNotice {
                noticeLine(noticeText(notice))
            }
            if model.unresolvedNotice, let intent = review.unresolvedIntent {
                noticeLine("We couldn't confirm your \(intent == .approved ? "approval" : "rejection") reached the relay. Retrying is safe: it returns the stored outcome and never decides twice.")
                decisionButton(
                    intent == .approved ? "Retry approval" : "Retry rejection",
                    prominent: intent == .approved,
                    destructive: intent == .rejected
                ) {
                    Task { intent == .approved ? await model.approve() : await model.reject() }
                }
            } else {
                switch model.approvalAvailability(for: review.projection) {
                case .kernelP256OwnerSigning:
                    HStack(spacing: 12) {
                        decisionButton("Reject", prominent: false, destructive: true) {
                            Task { await model.reject() }
                        }
                        decisionButton("Approve", prominent: true, destructive: false) {
                            Task { await model.approve() }
                        }
                    }
                case .rejectOnly:
                    Text("This phone can't verify this request, so it can only be rejected.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    decisionButton("Reject", prominent: false, destructive: true) {
                        Task { await model.reject() }
                    }
                }
            }
        }
    }

    private func noticeText(_ notice: ApprovalActionNotice) -> String {
        switch notice {
        case .expired:
            return "This request expired, so nothing was sent."
        case .conflictingIntent:
            return "An earlier decision is still unresolved. Retry that same decision."
        case .signingUnavailable:
            return "Couldn't get the signing details from the relay. Nothing was signed; try Approve again."
        case .signingMismatch:
            return "The relay's signing details don't match this request. Nothing was signed. Reject it."
        case .cannotSign:
            return "This phone can't sign right now. Keep the app open and paired, then try again. Nothing was signed."
        case .signingCancelled:
            return "Signing was cancelled. Nothing was sent; you can try again."
        }
    }

    @ViewBuilder
    private func settledBody(_ decision: OwnerPhoneDecision, overridden: Bool,
                             domain: OwnerPhoneDecisionDomain) -> some View {
        let approved = decision.outcome == .approved
        VStack(alignment: .leading, spacing: 6) {
            Label(approved ? "Approved" : "Rejected",
                  systemImage: approved ? "checkmark.circle.fill" : "xmark.circle.fill")
                .font(.title3.bold())
                .foregroundStyle(approved ? Color.accentColor : .red)
            if domain == .revocation, approved {
                Text("The service can now submit the removal. This phone hasn't confirmed it onchain.")
                    .font(.subheadline)
            }
            switch decision.settlement {
            case .decided:
                Text("Your decision was recorded.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            case .replayed:
                Text("This request was already decided. This is the stored outcome; nothing new was released.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                if overridden {
                    Text("The stored outcome differs from the decision this phone just sent.")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.red)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
    }

    // MARK: Building blocks

    private func failure(_ code: String) -> some View {
        stateMessage(
            icon: "exclamationmark.triangle",
            title: code == "projection_mismatch"
                ? "This notification doesn't match the request"
                : "This request couldn't be opened",
            detail: code == "projection_mismatch"
                ? "The relay returned a different request than the notification described. Don't approve it."
                : "It may have expired or already been decided, or the relay can't be reached right now.",
            code: code)
    }

    private func stateMessage(
        icon: String, title: String, detail: String, code: String? = nil
    ) -> some View {
        VStack(spacing: 10) {
            Image(systemName: icon)
                .font(.largeTitle.weight(.light))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text(title)
                .font(.title3.weight(.semibold))
                .multilineTextAlignment(.center)
            Text(detail)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            if let code {
                Text(code)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 48)
    }

    private func group<Content: View>(
        _ title: String, @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title)
                .font(.headline)
                .accessibilityAddTraits(.isHeader)
            content()
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(groupBackground)
    }

    private var groupBackground: some View {
        RoundedRectangle(cornerRadius: 16, style: .continuous)
            .fill(Color.primary.opacity(0.04))
            .overlay(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .stroke(Color.primary.opacity(0.1), lineWidth: 1))
    }

    private func callout(_ text: String, icon: String, color: Color) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: icon)
                .foregroundStyle(color)
                .accessibilityHidden(true)
            Text(text)
                .font(.footnote)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(color.opacity(0.1)))
        .accessibilityElement(children: .combine)
    }

    private func noticeLine(_ text: String) -> some View {
        Label(text, systemImage: "info.circle")
            .font(.footnote)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func bar<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        VStack(spacing: 12) {
            content()
        }
        .padding(.horizontal, 20)
        .padding(.top, 14)
        .padding(.bottom, 10)
        .frame(maxWidth: .infinity)
        .background(.bar)
        .overlay(alignment: .top) { Divider() }
    }

    private func progress(_ text: String) -> some View {
        HStack(spacing: 12) {
            ProgressView()
            Text(text).font(.body)
        }
        .frame(maxWidth: .infinity, minHeight: 50)
    }

    private func decisionButton(
        _ title: String, prominent: Bool, destructive: Bool, action: @escaping () -> Void
    ) -> some View {
        Group {
            if prominent {
                Button(action: action) {
                    Text(title).font(.body.weight(.semibold)).frame(maxWidth: .infinity, minHeight: 36)
                }
                .buttonStyle(.borderedProminent)
            } else {
                Button(role: destructive ? .destructive : nil, action: action) {
                    Text(title).font(.body.weight(.semibold)).frame(maxWidth: .infinity, minHeight: 36)
                }
                .buttonStyle(.bordered)
                .tint(destructive ? .red : nil)
            }
        }
        .controlSize(.large)
    }

    private func doneButton(_ action: @escaping () -> Void) -> some View {
        decisionButton("Done", prominent: true, destructive: false, action: action)
    }
}

/// "Expires in 4:12" that keeps counting, then "Expired".
private struct ExpiryLine: View {
    let expiresAt: Int

    private var expiry: Date { Date(timeIntervalSince1970: Double(expiresAt) / 1000) }

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            if context.date < expiry {
                (Text("Expires in ") + Text(expiry, style: .timer)
                    + Text(" · \(expiry.formatted(date: .omitted, time: .shortened))"))
                    .font(.footnote.monospacedDigit())
                    .foregroundStyle(.secondary)
            } else {
                Text("Expired")
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(.red)
            }
        }
    }
}

extension PermissionConsentEvidence {
    /// Compact tag text; `display` stays the full accessible statement.
    var shortDisplay: String {
        switch self {
        case .relayBound: return "Relay-bound"
        case .requestedScope: return "Requested"
        case .requestedConstraint: return "Unproven limit"
        }
    }
}
#endif
