/**
 EXPERIMENTAL PREVIEW — the shared golden wire fixture, decoded byte for byte.

 ONE committed fixture, two consumers: `exactSignatureProjectionBytes` is one
 exact JSON string whose UTF-8 bytes the relay route test and this Swift test
 both consume before decoding. The object entries cover every remaining closed
 union branch. A byte or shape drift fails at least one consumer.

 @author taek <leekt216@gmail.com>
 */
import XCTest
@testable import OwnerPhone

final class GoldenFixtureTests: XCTestCase {
    private func fixture() throws -> [String: Any] {
        // native/ios/Tests/OwnerPhoneTests/GoldenFixtureTests.swift → repo root.
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // GoldenFixtureTests.swift → OwnerPhoneTests
            .deletingLastPathComponent() // → Tests
            .deletingLastPathComponent() // → ios
            .deletingLastPathComponent() // → native
            .deletingLastPathComponent() // → repository root
            .appendingPathComponent("packages/server/test/fixtures/owner-phone-golden.json")
        let object = try JSONSerialization.jsonObject(with: try Data(contentsOf: url))
        guard let fixture = object as? [String: Any] else {
            throw OwnerPhoneWireError.notAnObject("golden fixture")
        }
        return fixture
    }

    private func bytes(_ fixture: [String: Any], _ group: String, _ name: String) throws -> Data {
        guard let entries = fixture[group] as? [String: Any], let entry = entries[name] else {
            throw OwnerPhoneWireError.invalidField("\(group).\(name)")
        }
        return try JSONSerialization.data(withJSONObject: entry)
    }

    func testDecodesEveryGoldenProjectionVariant() throws {
        let fixture = try self.fixture()

        let permission = try OwnerPhoneRequestProjection.decode(
            try bytes(fixture, "projection", "permissionRequest"))
        guard case let .permissionRequest(scope) = permission.scope else {
            return XCTFail("golden permissionRequest did not decode structurally")
        }
        XCTAssertEqual(permission.operationId, "fixture-operation-id")
        XCTAssertEqual(permission.matchCode.value, "Ab1-_9Zz")
        XCTAssertEqual(permission.client.clientId, "client-a")
        XCTAssertEqual(scope.chainScope, "all")
        XCTAssertEqual(scope.calls.count, 1)
        XCTAssertEqual(scope.perChainOperationLimit, 10)

        guard let exactText = fixture["exactSignatureProjectionBytes"] as? String else {
            return XCTFail("golden exact signature projection bytes are missing")
        }
        let exactBytes = Data(exactText.utf8)
        XCTAssertEqual(String(decoding: exactBytes, as: UTF8.self), exactText)
        let signature = try OwnerPhoneRequestProjection.decode(exactBytes)
        guard case let .signatureRequest(request) = signature.scope else {
            return XCTFail("golden signatureRequest did not decode structurally")
        }
        XCTAssertEqual(request.digest, "0x" + String(repeating: "4b", count: 32))
        XCTAssertTrue(request.display.contains("kernel-enable-digest"))

        let raw = try OwnerPhoneRequestProjection.decode(try bytes(fixture, "projection", "raw"))
        guard case .raw = raw.scope else {
            return XCTFail("golden raw scope did not decode as the labeled raw branch")
        }
    }

    func testDecodesEveryGoldenDecisionVariant() throws {
        let fixture = try self.fixture()

        let decided = try OwnerPhoneDecision.decode(
            try bytes(fixture, "decision", "decidedApproved"))
        XCTAssertEqual(decided.settlement, .decided)
        XCTAssertEqual(decided.outcome, .approved)
        guard case let .approved(code, artifactId, redirectUri, _) = decided.release else {
            return XCTFail("golden decided approval carries no release")
        }
        XCTAssertEqual(code.count, 43)
        XCTAssertEqual(artifactId.count, 43)
        XCTAssertEqual(redirectUri, "https://app.example/callback")

        let replayed = try OwnerPhoneDecision.decode(try bytes(fixture, "decision", "replayed"))
        XCTAssertEqual(replayed.settlement, .replayed)
        XCTAssertNil(replayed.release)

        let rejected = try OwnerPhoneDecision.decode(
            try bytes(fixture, "decision", "decidedRejected"))
        XCTAssertEqual(rejected.settlement, .decided)
        XCTAssertEqual(rejected.release, .rejected)
    }
}
