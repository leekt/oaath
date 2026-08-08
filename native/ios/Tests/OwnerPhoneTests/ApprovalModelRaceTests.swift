/**
 EXPERIMENTAL PREVIEW — ownership races for the owner-phone consent surface.

 @author taek <leekt216@gmail.com>
 */
import CryptoKit
import Foundation
import XCTest
@testable import OwnerPhone

private enum DeferredFailure: Error {
    case endpoint
}

private actor DeferredApprovalRelay: OwnerPhoneRelayClient {
    struct Submission: Equatable {
        let operationId: String
        let command: OwnerPhoneDecisionCommand
    }

    private let projections: [String: OwnerPhoneRequestProjection]
    private var submissions: [Submission] = []
    private var continuation: CheckedContinuation<OwnerPhoneDecision, Error>?

    init(_ projections: [OwnerPhoneRequestProjection]) {
        self.projections = Dictionary(uniqueKeysWithValues: projections.map { ($0.operationId, $0) })
    }

    func projection(operationId: String) async throws -> OwnerPhoneRequestProjection {
        guard let projection = projections[operationId] else { throw DeferredFailure.endpoint }
        return projection
    }

    func submit(
        operationId: String,
        command: OwnerPhoneDecisionCommand
    ) async throws -> OwnerPhoneDecision {
        submissions.append(Submission(operationId: operationId, command: command))
        return try await withCheckedThrowingContinuation { continuation = $0 }
    }

    func waitForSubmission() async {
        while submissions.isEmpty || continuation == nil { await Task.yield() }
    }

    func recordedSubmissions() -> [Submission] {
        submissions
    }

    func complete(_ decision: OwnerPhoneDecision) {
        continuation?.resume(returning: decision)
        continuation = nil
    }

    func fail() {
        continuation?.resume(throwing: DeferredFailure.endpoint)
        continuation = nil
    }
}

private actor DeferredArtifact {
    private var projections: [OwnerPhoneRequestProjection] = []
    private var continuation: CheckedContinuation<String, Error>?

    func generate(_ projection: OwnerPhoneRequestProjection) async throws -> String {
        projections.append(projection)
        return try await withCheckedThrowingContinuation { continuation = $0 }
    }

    func waitForGeneration() async {
        while projections.isEmpty || continuation == nil { await Task.yield() }
    }

    func recordedProjections() -> [OwnerPhoneRequestProjection] {
        projections
    }

    func complete(with artifact: String) {
        continuation?.resume(returning: artifact)
        continuation = nil
    }
}

private actor RecordingArtifact {
    private var projections: [OwnerPhoneRequestProjection] = []

    func generate(_ projection: OwnerPhoneRequestProjection) -> String {
        projections.append(projection)
        return "artifact-for-\(projection.operationId)"
    }

    func recordedProjections() -> [OwnerPhoneRequestProjection] {
        projections
    }
}

private actor ImmediateDecisionRelay: OwnerPhoneRelayClient {
    private let projections: [String: OwnerPhoneRequestProjection]
    private var submissions: [DeferredApprovalRelay.Submission] = []

    init(_ projection: OwnerPhoneRequestProjection) {
        projections = [projection.operationId: projection]
    }

    init(_ projections: [OwnerPhoneRequestProjection]) {
        self.projections = Dictionary(
            uniqueKeysWithValues: projections.map { ($0.operationId, $0) })
    }

    func projection(operationId: String) async throws -> OwnerPhoneRequestProjection {
        guard let projection = projections[operationId] else { throw DeferredFailure.endpoint }
        return projection
    }

    func submit(
        operationId: String,
        command: OwnerPhoneDecisionCommand
    ) async throws -> OwnerPhoneDecision {
        submissions.append(.init(operationId: operationId, command: command))
        return OwnerPhoneDecision(
            operationId: operationId,
            outcome: command.outcome,
            decidedAt: 1_900_000_000_000,
            settlement: .decided,
            release: command.outcome == .approved
                ? .approved(
                    code: "code-\(operationId)",
                    artifactId: "artifact-\(operationId)",
                    redirectUri: "https://app.example/\(operationId)",
                    codeExpiresAt: 1_900_000_010_000
                )
                : .rejected
        )
    }

    func recordedSubmissions() -> [DeferredApprovalRelay.Submission] {
        submissions
    }
}

private actor CountingArtifact {
    private var calls = 0

    func generate(_ projection: OwnerPhoneRequestProjection) -> String {
        calls += 1
        return "artifact-for-\(projection.operationId)"
    }

    func count() -> Int { calls }
}

private final class KernelSignerProbe: @unchecked Sendable {
    private let condition = NSCondition()
    private let key: P256.Signing.PrivateKey
    private var calls = 0
    private var blocked: Bool

    init(key: P256.Signing.PrivateKey, blocked: Bool = false) {
        self.key = key
        self.blocked = blocked
    }

    func sign(_ digest: VerifiedSignableDigest) throws -> Data {
        condition.lock()
        calls += 1
        condition.broadcast()
        while blocked { condition.wait() }
        condition.unlock()
        return try key.signature(for: digest.cryptoKitDigest).derRepresentation
    }

    func callCount() -> Int {
        condition.lock()
        defer { condition.unlock() }
        return calls
    }

    func release() {
        condition.lock()
        blocked = false
        condition.broadcast()
        condition.unlock()
    }

    func waitForCallCount(_ expected: Int) async {
        while callCount() < expected { await Task.yield() }
    }
}

private final class MutableApprovalFacts: @unchecked Sendable {
    private let lock = NSLock()
    private var currentValue: Bool
    private var nowValue: Int

    init(current: Bool = true, now: Int = 1_800_000_000_000) {
        currentValue = current
        nowValue = now
    }

    func isCurrent() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return currentValue
    }

    func now() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return nowValue
    }

    func setCurrent(_ current: Bool) {
        lock.lock()
        currentValue = current
        lock.unlock()
    }

    func setNow(_ now: Int) {
        lock.lock()
        nowValue = now
        lock.unlock()
    }
}

private actor KernelDecisionRelay: OwnerPhoneRelayClient {
    enum PlannedResult: Sendable {
        case decided
        case ambiguous
        case provenUnsent
    }

    private let projectionValue: OwnerPhoneRequestProjection
    private var plannedResults: [PlannedResult]
    private var submissions = 0
    private var firstArtifact: String?
    private var everyArtifactMatches = true

    init(
        projection: OwnerPhoneRequestProjection,
        plannedResults: [PlannedResult]
    ) {
        projectionValue = projection
        self.plannedResults = plannedResults
    }

    func projection(operationId: String) async throws -> OwnerPhoneRequestProjection {
        guard operationId == projectionValue.operationId else {
            throw DeferredFailure.endpoint
        }
        return projectionValue
    }

    func submit(
        operationId: String,
        command: OwnerPhoneDecisionCommand
    ) async throws -> OwnerPhoneDecision {
        guard operationId == projectionValue.operationId,
              case let .approved(artifact) = command,
              !plannedResults.isEmpty
        else { throw DeferredFailure.endpoint }
        submissions += 1
        if let firstArtifact {
            everyArtifactMatches = everyArtifactMatches && firstArtifact == artifact
        } else {
            firstArtifact = artifact
        }
        switch plannedResults.removeFirst() {
        case .ambiguous:
            throw DeferredFailure.endpoint
        case .provenUnsent:
            throw OwnerPhoneWireError.invalidField("artifact")
        case .decided:
            return OwnerPhoneDecision(
                operationId: operationId,
                outcome: .approved,
                decidedAt: 1_900_000_000_000,
                settlement: .decided,
                release: .approved(
                    code: "code-kernel",
                    artifactId: "artifact-kernel",
                    redirectUri: "https://app.example/kernel",
                    codeExpiresAt: 1_900_000_010_000))
        }
    }

    func submissionCount() -> Int { submissions }
    func submittedArtifactsWereIdentical() -> Bool {
        submissions > 1 && everyArtifactMatches
    }
}

private struct KernelApprovalHarness {
    let projection: OwnerPhoneRequestProjection
    let binding: OwnerPhoneKernelP256ApprovalBinding
    let signer: KernelSignerProbe
    let facts: MutableApprovalFacts
}

@MainActor
final class ApprovalModelRaceTests: XCTestCase {
    private func projection(_ operationId: String) -> OwnerPhoneRequestProjection {
        .fixture(
            operationId: operationId,
            matchCode: operationId == "request-A" ? "AAAA1111" : "BBBB2222",
            expiresAt: 2_000_000_000_000
        )
    }

    private func decision(
        _ operationId: String,
        outcome: OwnerPhoneOutcome = .approved
    ) -> OwnerPhoneDecision {
        OwnerPhoneDecision(
            operationId: operationId,
            outcome: outcome,
            decidedAt: 1_900_000_000_000,
            settlement: .decided,
            release: outcome == .approved
                ? .approved(
                    code: "code-\(operationId)",
                    artifactId: "artifact-\(operationId)",
                    redirectUri: "https://app.example/\(operationId)",
                    codeExpiresAt: 1_900_000_010_000
                )
                : .rejected
        )
    }

    private func displayedReview(_ model: ApprovalModel) -> OwnerPhoneReview? {
        guard case let .review(review) = model.phase else { return nil }
        return review
    }

    private func kernelApprovalHarness(
        blockedSigner: Bool = false
    ) throws -> KernelApprovalHarness {
        let key = P256.Signing.PrivateKey()
        let signer = KernelSignerProbe(key: key, blocked: blockedSigner)
        let facts = MutableApprovalFacts()
        let source = try makeReviewHarness(
            publicKeyX963: key.publicKey.x963Representation).review.projection
        guard case let .ownerSigningRequest(scope) = source.scope,
              case let .eip712(request) = scope.request
        else {
            throw OwnerPhoneWireError.invalidField("Kernel approval test projection")
        }
        let projection = replacingScope(
            source,
            with: .ownerSigningRequest(OwnerPhoneSigningRequestScope(
                requestHash: scope.requestHash,
                request: scope.request,
                decisionCapability: .approveOrReject)))
        let binding = try OwnerPhoneKernelP256ApprovalBinding(
            account: request.signer.account,
            p256PublicMaterial: hexEncode(Data(key.publicKey.x963Representation.dropFirst())),
            pairingIsCurrent: { facts.isCurrent() },
            sign: { try signer.sign($0) })
        return KernelApprovalHarness(
            projection: projection,
            binding: binding,
            signer: signer,
            facts: facts)
    }

    private func replacingScope(
        _ projection: OwnerPhoneRequestProjection,
        with scope: OwnerPhoneScope
    ) -> OwnerPhoneRequestProjection {
        OwnerPhoneRequestProjection(
            operationId: projection.operationId,
            matchCode: projection.matchCode,
            expiresAt: projection.expiresAt,
            client: projection.client,
            scope: scope)
    }

    private func wrongSemanticProjections(
        from valid: OwnerPhoneRequestProjection
    ) throws -> [OwnerPhoneRequestProjection] {
        guard case let .ownerSigningRequest(scope) = valid.scope,
              case let .eip712(request) = scope.request,
              let derived = try? deriveEIP712Digest(from: request.typedData)
        else {
            throw OwnerPhoneWireError.invalidField("Kernel approval test projection")
        }
        let raw = OwnerPhoneSigningRequest.rawDigest(OwnerPhoneRawDigestSigningRequest(
            version: ownerPhoneSigningRequestVersion,
            digest: request.expectedDigest,
            reason: "No device-side derivation is available"))
        let application = OwnerPhoneSigningRequest.eip712(OwnerPhoneEIP712SigningRequest(
            version: request.version,
            purpose: .application,
            signer: request.signer,
            typedData: request.typedData,
            expectedDigest: request.expectedDigest,
            digestComparison: request.digestComparison,
            replay: request.replay))
        let substituted = "0x" + String(repeating: "55", count: 32)
        let mismatch = OwnerPhoneSigningRequest.eip712(OwnerPhoneEIP712SigningRequest(
            version: request.version,
            purpose: request.purpose,
            signer: request.signer,
            typedData: request.typedData,
            expectedDigest: substituted,
            digestComparison: .mismatch(
                expectedCanonicalHex: substituted,
                derived: derived),
            replay: request.replay))
        return [raw, application, mismatch].map { signingRequest in
            replacingScope(
                valid,
                with: .ownerSigningRequest(OwnerPhoneSigningRequestScope(
                    requestHash: scope.requestHash,
                    request: signingRequest,
                    decisionCapability: .approveOrReject)))
        }
    }

    private func mismatchedEIP712Scope() throws -> OwnerPhoneScope {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("packages/server/test/fixtures/owner-phone-golden.json")
        guard let fixture = try JSONSerialization.jsonObject(
            with: Data(contentsOf: url)) as? [String: Any],
            let projections = fixture["projection"] as? [String: Any],
            var projection = projections["ownerSigningRequest"] as? [String: Any],
            var scope = projection["scope"] as? [String: Any],
            var request = scope["request"] as? [String: Any]
        else {
            throw OwnerPhoneWireError.invalidField("owner signing test fixture")
        }
        request["expectedDigest"] = "0x" + String(repeating: "55", count: 32)
        scope["request"] = request
        projection["scope"] = scope
        return try OwnerPhoneRequestProjection.decode(
            JSONSerialization.data(withJSONObject: projection)).scope
    }

    private func kernelEnableScope() throws -> OwnerPhoneScope {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("packages/server/test/fixtures/owner-phone-golden.json")
        guard let fixture = try JSONSerialization.jsonObject(
            with: Data(contentsOf: url)) as? [String: Any],
            let projections = fixture["projection"] as? [String: Any],
            let projection = projections["kernelEnableOwnerSigningRequest"] as? [String: Any]
        else {
            throw OwnerPhoneWireError.invalidField("Kernel enable test fixture")
        }
        return try OwnerPhoneRequestProjection.decode(
            JSONSerialization.data(withJSONObject: projection)).scope
    }

    func testRejectOnlyScopesGenerateNoArtifactAndSendOnlyExplicitRejection() async throws {
        let digest = "0x" + String(repeating: "a1", count: 32)
        let scopes: [OwnerPhoneScope] = [
            .raw(#"{"chainScope":"all"}"#),
            .rawDigestSigningFixture(digest: digest),
            try mismatchedEIP712Scope(),
            try kernelEnableScope(),
        ]

        for (index, scope) in scopes.enumerated() {
            let request = OwnerPhoneRequestProjection.fixture(
                operationId: "reject-only-\(index)",
                matchCode: index == 0 ? "AAAA1111" : "BBBB2222",
                expiresAt: 2_000_000_000_000,
                scope: scope
            )
            let relay = ImmediateDecisionRelay(request)
            let artifact = CountingArtifact()
            let model = ApprovalModel(
                relay: relay,
                approvalArtifact: { await artifact.generate($0) },
                now: { 1_800_000_000_000 }
            )

            await model.open(operationId: request.operationId)
            await model.approve()
            let artifactCallsAfterApproval = await artifact.count()
            let submissionsAfterApproval = await relay.recordedSubmissions()
            XCTAssertEqual(artifactCallsAfterApproval, 0)
            XCTAssertEqual(submissionsAfterApproval, [])
            XCTAssertEqual(displayedReview(model)?.state, .pending)

            await model.reject()
            let artifactCallsAfterRejection = await artifact.count()
            let submissionsAfterRejection = await relay.recordedSubmissions()
            XCTAssertEqual(artifactCallsAfterRejection, 0)
            XCTAssertEqual(
                submissionsAfterRejection,
                [.init(operationId: request.operationId, command: .rejected)]
            )
            XCTAssertEqual(
                displayedReview(model)?.state,
                .settled(OwnerPhoneDecision(
                    operationId: request.operationId,
                    outcome: .rejected,
                    decidedAt: 1_900_000_000_000,
                    settlement: .decided,
                    release: .rejected
                ))
            )
        }
    }

    func testV3DecisionAndWrongSemanticsStayRejectOnlyWithAValidBinding() async throws {
        let harness = try kernelApprovalHarness()
        guard case let .ownerSigningRequest(scope) = harness.projection.scope else {
            return XCTFail("Kernel approval test projection changed shape")
        }
        let v3Projection = replacingScope(
            harness.projection,
            with: .ownerSigningRequest(OwnerPhoneSigningRequestScope(
                requestHash: scope.requestHash,
                request: scope.request,
                decisionCapability: .rejectOnly)))
        let projections = [v3Projection] +
            (try wrongSemanticProjections(from: harness.projection))

        for projection in projections {
            let relay = ImmediateDecisionRelay(projection)
            let permissionArtifact = CountingArtifact()
            let model = ApprovalModel(
                relay: relay,
                approvalArtifact: { await permissionArtifact.generate($0) },
                kernelP256ApprovalBinding: harness.binding,
                now: { harness.facts.now() })
            model.setForeground(true)
            await model.open(operationId: projection.operationId)

            XCTAssertEqual(model.approvalAvailability(for: projection), .rejectOnly)
            await model.approve()
            let permissionArtifactCalls = await permissionArtifact.count()
            let submissions = await relay.recordedSubmissions()
            XCTAssertEqual(harness.signer.callCount(), 0)
            XCTAssertEqual(permissionArtifactCalls, 0)
            XCTAssertEqual(submissions, [])
            XCTAssertEqual(displayedReview(model)?.state, .pending)
        }
    }

    func testDormantKernelApprovalSignsAndSubmitsExactlyOnce() async throws {
        let harness = try kernelApprovalHarness()
        let relay = KernelDecisionRelay(
            projection: harness.projection,
            plannedResults: [.decided])
        let permissionArtifact = CountingArtifact()
        let model = ApprovalModel(
            relay: relay,
            approvalArtifact: { await permissionArtifact.generate($0) },
            kernelP256ApprovalBinding: harness.binding,
            now: { harness.facts.now() })
        model.setForeground(true)
        await model.open(operationId: harness.projection.operationId)

        XCTAssertEqual(
            model.approvalAvailability(for: harness.projection),
            .kernelP256OwnerSigning)
        await model.approve()

        let permissionArtifactCalls = await permissionArtifact.count()
        let submissions = await relay.submissionCount()
        XCTAssertEqual(harness.signer.callCount(), 1)
        XCTAssertEqual(permissionArtifactCalls, 0)
        XCTAssertEqual(submissions, 1)
        guard case .settled = displayedReview(model)?.state else {
            return XCTFail("Kernel approval did not settle")
        }
        XCTAssertFalse(model.unresolvedNotice)
    }

    func testAmbiguousKernelRetryReusesTheExactArtifactWithoutResigning() async throws {
        let harness = try kernelApprovalHarness()
        let relay = KernelDecisionRelay(
            projection: harness.projection,
            plannedResults: [.ambiguous, .decided])
        let model = ApprovalModel(
            relay: relay,
            approvalArtifact: { _ in throw DeferredFailure.endpoint },
            kernelP256ApprovalBinding: harness.binding,
            now: { harness.facts.now() })
        model.setForeground(true)
        await model.open(operationId: harness.projection.operationId)

        await model.approve()
        let firstSubmissionCount = await relay.submissionCount()
        XCTAssertEqual(harness.signer.callCount(), 1)
        XCTAssertEqual(firstSubmissionCount, 1)
        XCTAssertEqual(displayedReview(model)?.state, .pending)
        XCTAssertTrue(model.unresolvedNotice)

        await model.approve()
        let secondSubmissionCount = await relay.submissionCount()
        let artifactsMatched = await relay.submittedArtifactsWereIdentical()
        XCTAssertEqual(harness.signer.callCount(), 1)
        XCTAssertEqual(secondSubmissionCount, 2)
        XCTAssertTrue(artifactsMatched)
        guard case .settled = displayedReview(model)?.state else {
            return XCTFail("retried Kernel approval did not settle")
        }
    }

    func testProvenUnsentRetryPreservesAnOlderAmbiguousKernelArtifact() async throws {
        let harness = try kernelApprovalHarness()
        let relay = KernelDecisionRelay(
            projection: harness.projection,
            plannedResults: [.ambiguous, .provenUnsent, .decided])
        let model = ApprovalModel(
            relay: relay,
            approvalArtifact: { _ in throw DeferredFailure.endpoint },
            kernelP256ApprovalBinding: harness.binding,
            now: { harness.facts.now() })
        model.setForeground(true)
        await model.open(operationId: harness.projection.operationId)

        await model.approve()
        await model.approve()
        let provenUnsentSubmissionCount = await relay.submissionCount()
        XCTAssertEqual(harness.signer.callCount(), 1)
        XCTAssertEqual(provenUnsentSubmissionCount, 2)
        XCTAssertTrue(model.unresolvedNotice)
        XCTAssertEqual(displayedReview(model)?.unresolvedIntent, .approved)

        await model.approve()
        let finalSubmissionCount = await relay.submissionCount()
        let artifactsMatched = await relay.submittedArtifactsWereIdentical()
        XCTAssertEqual(harness.signer.callCount(), 1)
        XCTAssertEqual(finalSubmissionCount, 3)
        XCTAssertTrue(artifactsMatched)
        guard case .settled = displayedReview(model)?.state else {
            return XCTFail("preserved Kernel retry did not settle")
        }
    }

    func testProvenUnsentKernelAttemptClearsItsUnsubmittedCandidate() async throws {
        let harness = try kernelApprovalHarness()
        let relay = KernelDecisionRelay(
            projection: harness.projection,
            plannedResults: [.provenUnsent, .decided])
        let model = ApprovalModel(
            relay: relay,
            approvalArtifact: { _ in throw DeferredFailure.endpoint },
            kernelP256ApprovalBinding: harness.binding,
            now: { harness.facts.now() })
        model.setForeground(true)
        await model.open(operationId: harness.projection.operationId)

        await model.approve()
        XCTAssertEqual(harness.signer.callCount(), 1)
        XCTAssertFalse(model.unresolvedNotice)
        XCTAssertNil(displayedReview(model)?.unresolvedIntent)

        await model.approve()
        let submissions = await relay.submissionCount()
        XCTAssertEqual(harness.signer.callCount(), 2)
        XCTAssertEqual(submissions, 2)
        guard case .settled = displayedReview(model)?.state else {
            return XCTFail("proven-unsent retry did not settle")
        }
    }

    func testReplacingAnAmbiguousReviewClearsItsKernelArtifact() async throws {
        let harness = try kernelApprovalHarness()
        let relay = KernelDecisionRelay(
            projection: harness.projection,
            plannedResults: [.ambiguous, .decided])
        let model = ApprovalModel(
            relay: relay,
            approvalArtifact: { _ in throw DeferredFailure.endpoint },
            kernelP256ApprovalBinding: harness.binding,
            now: { harness.facts.now() })
        model.setForeground(true)
        await model.open(operationId: harness.projection.operationId)
        await model.approve()
        XCTAssertEqual(harness.signer.callCount(), 1)
        XCTAssertTrue(model.unresolvedNotice)

        // Reinstalling even the same projection creates a new exact review
        // owner and clears the older review's memory-only artifact.
        await model.open(operationId: harness.projection.operationId)
        await model.approve()
        let submissions = await relay.submissionCount()
        XCTAssertEqual(harness.signer.callCount(), 2)
        XCTAssertEqual(submissions, 2)
        guard case .settled = displayedReview(model)?.state else {
            return XCTFail("replacement review did not settle")
        }
    }

    func testRecreatedModelPerformsNoAutomaticKernelEffect() async throws {
        let harness = try kernelApprovalHarness()
        let relay = KernelDecisionRelay(
            projection: harness.projection,
            plannedResults: [.ambiguous, .decided])
        let first = ApprovalModel(
            relay: relay,
            approvalArtifact: { _ in throw DeferredFailure.endpoint },
            kernelP256ApprovalBinding: harness.binding,
            now: { harness.facts.now() })
        first.setForeground(true)
        await first.open(operationId: harness.projection.operationId)
        await first.approve()
        XCTAssertEqual(harness.signer.callCount(), 1)

        let recreated = ApprovalModel(
            relay: relay,
            approvalArtifact: { _ in throw DeferredFailure.endpoint },
            kernelP256ApprovalBinding: harness.binding,
            now: { harness.facts.now() })
        recreated.setForeground(true)
        await recreated.open(operationId: harness.projection.operationId)
        let submissionsBeforeTap = await relay.submissionCount()
        XCTAssertEqual(harness.signer.callCount(), 1)
        XCTAssertEqual(submissionsBeforeTap, 1)
        XCTAssertEqual(displayedReview(recreated)?.state, .pending)

        await recreated.approve()
        let submissionsAfterTap = await relay.submissionCount()
        XCTAssertEqual(harness.signer.callCount(), 2)
        XCTAssertEqual(submissionsAfterTap, 2)
    }

    func testKernelPreSignLivenessFailuresHaveNoEffects() async throws {
        enum Failure: Equatable {
            case background
            case expired
            case pairing
            case cancellation
        }

        for failure in [Failure.background, .expired, .pairing, .cancellation] {
            let harness = try kernelApprovalHarness()
            let relay = ImmediateDecisionRelay(harness.projection)
            let permissionArtifact = CountingArtifact()
            let model = ApprovalModel(
                relay: relay,
                approvalArtifact: { await permissionArtifact.generate($0) },
                kernelP256ApprovalBinding: harness.binding,
                now: { harness.facts.now() })
            model.setForeground(failure != .background)
            if failure == .expired {
                harness.facts.setNow(harness.projection.expiresAt)
            }
            if failure == .pairing {
                harness.facts.setCurrent(false)
            }
            await model.open(operationId: harness.projection.operationId)

            if failure == .cancellation {
                let approval = Task {
                    withUnsafeCurrentTask { $0?.cancel() }
                    await model.approve()
                }
                await approval.value
            } else {
                await model.approve()
            }

            let permissionArtifactCalls = await permissionArtifact.count()
            let submissions = await relay.recordedSubmissions()
            XCTAssertEqual(harness.signer.callCount(), 0)
            XCTAssertEqual(permissionArtifactCalls, 0)
            XCTAssertEqual(submissions, [])
            XCTAssertEqual(displayedReview(model)?.state, .pending)
        }
    }

    func testKernelDuringSignInvalidationsInvokeAtMostOneSignerAndNeverPost() async throws {
        enum Invalidation {
            case background
            case expiry
            case pairing
            case cancellation
        }

        for invalidation in [
            Invalidation.background,
            .expiry,
            .pairing,
            .cancellation,
        ] {
            let harness = try kernelApprovalHarness(blockedSigner: true)
            let relay = ImmediateDecisionRelay(harness.projection)
            let model = ApprovalModel(
                relay: relay,
                approvalArtifact: { _ in throw DeferredFailure.endpoint },
                kernelP256ApprovalBinding: harness.binding,
                now: { harness.facts.now() })
            model.setForeground(true)
            await model.open(operationId: harness.projection.operationId)
            let approval = Task { await model.approve() }
            await harness.signer.waitForCallCount(1)
            XCTAssertEqual(displayedReview(model)?.state, .authorizing)

            switch invalidation {
            case .background:
                model.setForeground(false)
            case .expiry:
                harness.facts.setNow(harness.projection.expiresAt)
            case .pairing:
                harness.facts.setCurrent(false)
            case .cancellation:
                approval.cancel()
            }
            harness.signer.release()
            await approval.value

            let submissions = await relay.recordedSubmissions()
            XCTAssertEqual(harness.signer.callCount(), 1)
            XCTAssertEqual(submissions, [])
            XCTAssertEqual(displayedReview(model)?.state, .pending)
        }
    }

    func testKernelSignerCompletionCannotCrossAReplacementReview() async throws {
        let harness = try kernelApprovalHarness(blockedSigner: true)
        let requestB = projection("request-B")
        let relay = ImmediateDecisionRelay([harness.projection, requestB])
        let model = ApprovalModel(
            relay: relay,
            approvalArtifact: { _ in "permission-artifact" },
            kernelP256ApprovalBinding: harness.binding,
            now: { harness.facts.now() })
        model.setForeground(true)
        await model.open(operationId: harness.projection.operationId)
        let staleApproval = Task { await model.approve() }
        await harness.signer.waitForCallCount(1)

        await model.open(operationId: requestB.operationId)
        harness.signer.release()
        await staleApproval.value

        let submissions = await relay.recordedSubmissions()
        XCTAssertEqual(harness.signer.callCount(), 1)
        XCTAssertEqual(submissions, [])
        XCTAssertEqual(displayedReview(model)?.projection, requestB)
        XCTAssertEqual(displayedReview(model)?.state, .pending)
    }

    func testApproveArtifactForAIsDiscardedWhenBReplacesItsReview() async throws {
        let requestA = projection("request-A")
        let requestB = projection("request-B")
        let relay = DeferredApprovalRelay([requestA, requestB])
        let artifact = DeferredArtifact()
        let model = ApprovalModel(
            relay: relay,
            approvalArtifact: { try await artifact.generate($0) },
            now: { 1_800_000_000_000 }
        )

        await model.open(operationId: requestA.operationId)
        let staleApproval = Task { await model.approve() }
        await artifact.waitForGeneration()
        await model.open(operationId: requestB.operationId)
        await artifact.complete(with: "artifact-for-request-A")
        await staleApproval.value

        let generated = await artifact.recordedProjections()
        let submissions = await relay.recordedSubmissions()
        XCTAssertEqual(generated.map(\.operationId), [requestA.operationId])
        XCTAssertEqual(submissions, [])
        XCTAssertEqual(displayedReview(model)?.projection, requestB)
        XCTAssertEqual(displayedReview(model)?.state, .pending)
        XCTAssertFalse(model.unresolvedNotice)
    }

    func testACompletedSubmissionCannotOverwriteBReview() async throws {
        let requestA = projection("request-A")
        let requestB = projection("request-B")
        let relay = DeferredApprovalRelay([requestA, requestB])
        let artifact = RecordingArtifact()
        let model = ApprovalModel(
            relay: relay,
            approvalArtifact: { await artifact.generate($0) },
            now: { 1_800_000_000_000 }
        )

        await model.open(operationId: requestA.operationId)
        let staleApproval = Task { await model.approve() }
        await relay.waitForSubmission()
        await model.open(operationId: requestB.operationId)
        await relay.complete(decision(requestA.operationId))
        await staleApproval.value

        let submissions = await relay.recordedSubmissions()
        XCTAssertEqual(submissions, [
            .init(
                operationId: requestA.operationId,
                command: .approved(artifact: "artifact-for-request-A")
            )
        ])
        XCTAssertEqual(displayedReview(model)?.projection, requestB)
        XCTAssertEqual(displayedReview(model)?.state, .pending)
        XCTAssertFalse(model.unresolvedNotice)
    }

    func testAFailedSubmissionCannotSetErrorOrUnresolvedStatusOnB() async throws {
        let requestA = projection("request-A")
        let requestB = projection("request-B")
        let relay = DeferredApprovalRelay([requestA, requestB])
        let artifact = RecordingArtifact()
        let model = ApprovalModel(
            relay: relay,
            approvalArtifact: { await artifact.generate($0) },
            now: { 1_800_000_000_000 }
        )

        await model.open(operationId: requestA.operationId)
        let staleApproval = Task { await model.approve() }
        await relay.waitForSubmission()
        await model.open(operationId: requestB.operationId)
        await relay.fail()
        await staleApproval.value

        XCTAssertEqual(displayedReview(model)?.projection, requestB)
        XCTAssertEqual(displayedReview(model)?.state, .pending)
        XCTAssertFalse(model.unresolvedNotice)
    }

    func testExplicitBApprovalGeneratesAndSubmitsOnlyB() async throws {
        let requestB = projection("request-B")
        let relay = DeferredApprovalRelay([requestB])
        let artifact = RecordingArtifact()
        let model = ApprovalModel(
            relay: relay,
            approvalArtifact: { await artifact.generate($0) },
            now: { 1_800_000_000_000 }
        )

        await model.open(operationId: requestB.operationId)
        let approval = Task { await model.approve() }
        await relay.waitForSubmission()

        let generated = await artifact.recordedProjections()
        let submissions = await relay.recordedSubmissions()
        XCTAssertEqual(generated, [requestB])
        XCTAssertEqual(submissions, [
            .init(
                operationId: requestB.operationId,
                command: .approved(artifact: "artifact-for-request-B")
            )
        ])
        await relay.complete(decision(requestB.operationId))
        await approval.value
        XCTAssertEqual(displayedReview(model)?.state, .settled(decision(requestB.operationId)))
    }

    func testStaleRejectCompletionCannotClearB() async throws {
        let requestA = projection("request-A")
        let requestB = projection("request-B")
        let relay = DeferredApprovalRelay([requestA, requestB])
        let model = ApprovalModel(
            relay: relay,
            approvalArtifact: { _ in XCTFail("reject must not create an artifact"); return "" },
            now: { 1_800_000_000_000 }
        )

        await model.open(operationId: requestA.operationId)
        let staleReject = Task { await model.reject() }
        await relay.waitForSubmission()
        await model.open(operationId: requestB.operationId)
        await relay.complete(decision(requestA.operationId, outcome: .rejected))
        await staleReject.value

        let submissions = await relay.recordedSubmissions()
        XCTAssertEqual(submissions, [
            .init(operationId: requestA.operationId, command: .rejected)
        ])
        XCTAssertEqual(displayedReview(model)?.projection, requestB)
        XCTAssertEqual(displayedReview(model)?.state, .pending)
        XCTAssertFalse(model.unresolvedNotice)
    }
}
