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
        guard case let .signatureRequest(scope) = projection.scope else { return "unexpected" }
        return "signature-for-\(scope.digest)"
    }

    func recordedProjections() -> [OwnerPhoneRequestProjection] {
        projections
    }
}

@MainActor
final class ApprovalModelRaceTests: XCTestCase {
    private let digestA = "0x" + String(repeating: "a1", count: 32)
    private let digestB = "0x" + String(repeating: "b2", count: 32)

    private func projection(
        _ operationId: String,
        digest: String
    ) throws -> OwnerPhoneRequestProjection {
        OwnerPhoneRequestProjection(
            operationId: operationId,
            matchCode: try MatchCode(operationId == "request-A" ? "AAAA1111" : "BBBB2222"),
            expiresAt: 2_000_000_000_000,
            client: OwnerPhoneClientIdentity(
                clientId: "exact-client-\(operationId)",
                redirectUri: "https://app.example/\(operationId)"
            ),
            scope: .signatureRequest(OwnerPhoneSignatureRequestScope(
                digest: digest,
                display: #"{"digest":"\#(digest)","kind":"owner-operation"}"#
            ))
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

    func testApproveArtifactForAIsDiscardedWhenBReplacesItsReview() async throws {
        let requestA = try projection("request-A", digest: digestA)
        let requestB = try projection("request-B", digest: digestB)
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
        await artifact.complete(with: "signature-for-\(digestA)")
        await staleApproval.value

        let generated = await artifact.recordedProjections()
        let submissions = await relay.recordedSubmissions()
        XCTAssertEqual(generated.map(\.operationId), [requestA.operationId])
        XCTAssertEqual(generated.compactMap { projection in
            guard case let .signatureRequest(scope) = projection.scope else { return nil }
            return scope.digest
        }, [digestA])
        XCTAssertEqual(submissions, [])
        XCTAssertEqual(displayedReview(model)?.projection, requestB)
        XCTAssertEqual(displayedReview(model)?.state, .pending)
        XCTAssertFalse(model.unresolvedNotice)
    }

    func testACompletedSubmissionCannotOverwriteBReview() async throws {
        let requestA = try projection("request-A", digest: digestA)
        let requestB = try projection("request-B", digest: digestB)
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
                command: .approved(artifact: "signature-for-\(digestA)")
            )
        ])
        XCTAssertEqual(displayedReview(model)?.projection, requestB)
        XCTAssertEqual(displayedReview(model)?.state, .pending)
        XCTAssertFalse(model.unresolvedNotice)
    }

    func testAFailedSubmissionCannotSetErrorOrUnresolvedStatusOnB() async throws {
        let requestA = try projection("request-A", digest: digestA)
        let requestB = try projection("request-B", digest: digestB)
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

    func testExplicitBApprovalSignsAndSubmitsOnlyB() async throws {
        let requestB = try projection("request-B", digest: digestB)
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
                command: .approved(artifact: "signature-for-\(digestB)")
            )
        ])
        await relay.complete(decision(requestB.operationId))
        await approval.value
        XCTAssertEqual(displayedReview(model)?.state, .settled(decision(requestB.operationId)))
    }

    func testStaleRejectCompletionCannotClearB() async throws {
        let requestA = try projection("request-A", digest: digestA)
        let requestB = try projection("request-B", digest: digestB)
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
