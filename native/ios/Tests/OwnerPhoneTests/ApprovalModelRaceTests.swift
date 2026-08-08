/**
 EXPERIMENTAL PREVIEW — ownership races for the owner-phone consent surface.

 @author taek <leekt216@gmail.com>
 */
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
    private let projectionValue: OwnerPhoneRequestProjection
    private var submissions: [DeferredApprovalRelay.Submission] = []

    init(_ projection: OwnerPhoneRequestProjection) {
        projectionValue = projection
    }

    func projection(operationId: String) async throws -> OwnerPhoneRequestProjection {
        guard operationId == projectionValue.operationId else { throw DeferredFailure.endpoint }
        return projectionValue
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
