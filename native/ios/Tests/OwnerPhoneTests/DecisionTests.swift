/**
 EXPERIMENTAL PREVIEW — decision decode and review state machine tests
 against `packages/server/src/native/decision.ts` semantics: a retry answers
 the STORED outcome, release goes only to the deciding call.

 @author taek <leekt216@gmail.com>
 */
import XCTest
@testable import OwnerPhone

final class DecisionTests: XCTestCase {
    private func json(_ object: [String: Any]) -> Data {
        try! JSONSerialization.data(withJSONObject: object)
    }

    private var decidedApproved: [String: Any] {
        [
            "operationId": "req-1",
            "outcome": "approved",
            "decidedAt": 1_753_999_000_000,
            "settlement": "decided",
            "release": [
                "outcome": "approved",
                "decidedAt": 1_753_999_000_000,
                "code": "one-time-code",
                "artifactId": "artifact-1",
                "redirectUri": "https://app.example/callback",
                "codeExpiresAt": 1_754_000_000_000
            ] as [String: Any]
        ]
    }

    private var replayedRejected: [String: Any] {
        [
            "operationId": "req-1",
            "outcome": "rejected",
            "decidedAt": 1_753_999_000_000,
            "settlement": "replayed",
            "release": NSNull()
        ]
    }

    private var projection: OwnerPhoneRequestProjection {
        .fixture()
    }

    // MARK: decode

    func testDecodesADecidedApprovalWithItsOneTimeRelease() throws {
        let decision = try OwnerPhoneDecision.decode(json(decidedApproved))
        XCTAssertEqual(decision.settlement, .decided)
        XCTAssertEqual(decision.outcome, .approved)
        XCTAssertEqual(
            decision.release,
            .approved(
                code: "one-time-code",
                artifactId: "artifact-1",
                redirectUri: "https://app.example/callback",
                codeExpiresAt: 1_754_000_000_000
            )
        )
    }

    func testDecodesAReplayWithNoReleaseMaterial() throws {
        let decision = try OwnerPhoneDecision.decode(json(replayedRejected))
        XCTAssertEqual(decision.settlement, .replayed)
        XCTAssertEqual(decision.outcome, .rejected)
        XCTAssertNil(decision.release)
    }

    func testRejectsAReplayCarryingRelease() {
        // Releasing twice is exactly what one-shot semantics forbid.
        var object = decidedApproved
        object["settlement"] = "replayed"
        XCTAssertThrowsError(try OwnerPhoneDecision.decode(json(object))) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .invalidField("release"))
        }
    }

    func testRejectsADecidedAnswerWithoutRelease() {
        var object = replayedRejected
        object["settlement"] = "decided"
        XCTAssertThrowsError(try OwnerPhoneDecision.decode(json(object))) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .invalidField("release"))
        }
    }

    func testRejectsAReleaseDisagreeingWithTheOutcome() {
        var object = decidedApproved
        object["outcome"] = "rejected"
        XCTAssertThrowsError(try OwnerPhoneDecision.decode(json(object))) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .invalidField("release"))
        }
    }

    func testRejectsUnknownOutcomeSettlementAndReleaseFields() {
        var object = decidedApproved
        object["outcome"] = "maybe"
        XCTAssertThrowsError(try OwnerPhoneDecision.decode(json(object))) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .invalidField("outcome"))
        }
        object = decidedApproved
        object["settlement"] = "pending"
        XCTAssertThrowsError(try OwnerPhoneDecision.decode(json(object))) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .invalidField("settlement"))
        }
        object = decidedApproved
        var release = object["release"] as! [String: Any]
        release["artifact"] = "never on this wire"
        object["release"] = release
        XCTAssertThrowsError(try OwnerPhoneDecision.decode(json(object))) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .unexpectedFields("release"))
        }
        object = decidedApproved
        object["extra"] = 1
        XCTAssertThrowsError(try OwnerPhoneDecision.decode(json(object))) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .unexpectedFields("owner phone decision"))
        }
    }

    func testCommandEncodingIsClosedAndBounded() throws {
        XCTAssertEqual(
            String(data: try OwnerPhoneDecisionCommand.rejected.encode(), encoding: .utf8),
            #"{"outcome":"rejected"}"#
        )
        XCTAssertEqual(
            String(data: try OwnerPhoneDecisionCommand.approved(artifact: "artifact").encode(), encoding: .utf8),
            #"{"artifact":"artifact","outcome":"approved"}"#
        )
        XCTAssertThrowsError(try OwnerPhoneDecisionCommand.approved(artifact: "").encode()) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .invalidField("artifact"))
        }
        let oversized = String(repeating: "a", count: 32_769)
        XCTAssertThrowsError(try OwnerPhoneDecisionCommand.approved(artifact: oversized).encode()) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .invalidField("artifact"))
        }
    }

    // MARK: review state machine

    func testHappyPathApproveDecides() throws {
        var review = OwnerPhoneReview(projection: projection)
        try review.beginSubmission(.approved, now: 1_753_999_000_000)
        XCTAssertEqual(review.state, .submitting(.approved))
        let decision = try OwnerPhoneDecision.decode(json(decidedApproved))
        try review.settle(decision)
        XCTAssertEqual(review.state, .settled(decision))
        XCTAssertFalse(review.storedOutcomeOverrodeCommand)
        XCTAssertNil(review.unresolvedIntent)
    }

    func testExpiredRequestCannotStartASubmission() {
        var review = OwnerPhoneReview(projection: projection)
        XCTAssertThrowsError(try review.beginSubmission(.approved, now: projection.expiresAt)) {
            XCTAssertEqual($0 as? OwnerPhoneReview.TransitionError, .expired)
        }
        XCTAssertEqual(review.state, .pending)
    }

    func testForbiddenTransitions() throws {
        var review = OwnerPhoneReview(projection: projection)
        // Settle before submitting.
        let decision = try OwnerPhoneDecision.decode(json(decidedApproved))
        XCTAssertThrowsError(try review.settle(decision)) {
            XCTAssertEqual($0 as? OwnerPhoneReview.TransitionError, .notSubmitting)
        }
        XCTAssertThrowsError(try review.submissionFailed(ambiguous: true)) {
            XCTAssertEqual($0 as? OwnerPhoneReview.TransitionError, .notSubmitting)
        }
        // Double begin.
        try review.beginSubmission(.approved, now: 0)
        XCTAssertThrowsError(try review.beginSubmission(.approved, now: 0)) {
            XCTAssertEqual($0 as? OwnerPhoneReview.TransitionError, .notPending)
        }
        // Terminal is terminal.
        try review.settle(decision)
        XCTAssertThrowsError(try review.beginSubmission(.rejected, now: 0)) {
            XCTAssertEqual($0 as? OwnerPhoneReview.TransitionError, .notPending)
        }
        XCTAssertThrowsError(try review.settle(decision)) {
            XCTAssertEqual($0 as? OwnerPhoneReview.TransitionError, .notSubmitting)
        }
    }

    func testSettleRejectsAForeignOperationId() throws {
        var review = OwnerPhoneReview(projection: projection)
        try review.beginSubmission(.rejected, now: 0)
        var object = replayedRejected
        object["operationId"] = "req-other"
        let decision = try OwnerPhoneDecision.decode(json(object))
        XCTAssertThrowsError(try review.settle(decision)) {
            XCTAssertEqual($0 as? OwnerPhoneReview.TransitionError, .operationMismatch)
        }
    }

    func testAmbiguousFailureKeepsAnExplicitIntentAndForbidsSwitching() throws {
        var review = OwnerPhoneReview(projection: projection)
        try review.beginSubmission(.approved, now: 0)
        try review.submissionFailed(ambiguous: true)
        XCTAssertEqual(review.state, .pending)
        XCTAssertEqual(review.unresolvedIntent, .approved)
        // The opposite command is forbidden while the outcome is unknown.
        XCTAssertThrowsError(try review.beginSubmission(.rejected, now: 0)) {
            XCTAssertEqual($0 as? OwnerPhoneReview.TransitionError, .conflictingUnresolvedIntent)
        }
        // The same command may be retried explicitly.
        try review.beginSubmission(.approved, now: 0)
        XCTAssertEqual(review.state, .submitting(.approved))
    }

    func testProvenNonSubmissionClearsTheIntent() throws {
        var review = OwnerPhoneReview(projection: projection)
        try review.beginSubmission(.approved, now: 0)
        try review.submissionFailed(ambiguous: false)
        XCTAssertNil(review.unresolvedIntent)
        // Switching is allowed: the command provably never left the device.
        try review.beginSubmission(.rejected, now: 0)
        XCTAssertEqual(review.state, .submitting(.rejected))
    }

    func testReplayAnswersTheStoredOutcomeEvenWhenItDiffers() throws {
        // Retried as approved after an ambiguous first attempt, but the store
        // says rejected: the stored outcome wins and the UI must say so.
        var review = OwnerPhoneReview(projection: projection)
        try review.beginSubmission(.approved, now: 0)
        try review.submissionFailed(ambiguous: true)
        try review.beginSubmission(.approved, now: 0)
        let stored = try OwnerPhoneDecision.decode(json(replayedRejected))
        try review.settle(stored)
        XCTAssertEqual(review.state, .settled(stored))
        XCTAssertTrue(review.storedOutcomeOverrodeCommand)
        XCTAssertNil(review.unresolvedIntent)
    }

    func testADecidedSettlementMustAgreeWithTheSentCommand() throws {
        var review = OwnerPhoneReview(projection: projection)
        try review.beginSubmission(.approved, now: 0)
        var object = replayedRejected
        object["settlement"] = "decided"
        object["release"] = ["outcome": "rejected", "decidedAt": 1_753_999_000_000] as [String: Any]
        let contradiction = try OwnerPhoneDecision.decode(json(object))
        XCTAssertThrowsError(try review.settle(contradiction)) {
            XCTAssertEqual($0 as? OwnerPhoneReview.TransitionError, .contradictoryEvidence)
        }
    }
}
