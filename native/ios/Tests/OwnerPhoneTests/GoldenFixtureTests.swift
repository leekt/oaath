/**
 EXPERIMENTAL PREVIEW — the shared golden wire fixture, decoded byte for byte.

 ONE committed fixture, two consumers: `exactOwnerSigningProjectionBytes` is one
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

        guard let exactText = fixture["exactOwnerSigningProjectionBytes"] as? String else {
            return XCTFail("golden exact owner-signing projection bytes are missing")
        }
        let exactBytes = Data(exactText.utf8)
        XCTAssertEqual(String(decoding: exactBytes, as: UTF8.self), exactText)
        let signing = try OwnerPhoneRequestProjection.decode(exactBytes)
        guard case let .ownerSigningRequest(scope) = signing.scope,
              case let .eip712(request) = scope.request
        else {
            return XCTFail("golden ownerSigningRequest did not decode structurally")
        }
        XCTAssertEqual(
            scope.requestHash,
            "0x1588b0d137ab76a1f63adc58befd1137642312ea71cdca34659851e4796488ba")
        XCTAssertEqual(request.purpose, .application)
        XCTAssertEqual(request.signer.account, "0x1111111111111111111111111111111111111111")
        XCTAssertEqual(request.typedData.primaryType, "Mail")
        XCTAssertEqual(
            request.expectedDigest,
            "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2")
        guard case let .matches(derived) = request.digestComparison else {
            return XCTFail("golden owner-signing digest did not match locally")
        }
        XCTAssertEqual(derived.canonicalHex, request.expectedDigest)
        XCTAssertFalse(signing.scope.approvable)

        let kernelEnable = try OwnerPhoneRequestProjection.decode(
            try bytes(fixture, "projection", "kernelEnableOwnerSigningRequest"))
        guard case let .ownerSigningRequest(kernelScope) = kernelEnable.scope,
              case let .eip712(kernelRequest) = kernelScope.request
        else {
            return XCTFail("golden kernelEnableOwnerSigningRequest did not decode structurally")
        }
        XCTAssertEqual(
            kernelScope.requestHash,
            "0xa00d9d6245f9adb00f254c6ea1295c9fb7e6bba1adfd479e6dc51fe4fa5538e4")
        XCTAssertEqual(kernelRequest.purpose, .kernelEnable)
        XCTAssertEqual(kernelRequest.typedData.primaryType, "InstallPackages")
        XCTAssertEqual(
            kernelRequest.expectedDigest,
            "0x72781421bec5030685dd2cde6d64eb4e63ea204ddb9951bd74986b0edd69ed03")
        guard case let .matches(kernelDerived) = kernelRequest.digestComparison else {
            return XCTFail("golden Kernel enable digest did not match locally")
        }
        XCTAssertEqual(kernelDerived.canonicalHex, kernelRequest.expectedDigest)
        XCTAssertFalse(kernelEnable.scope.approvable)

        let rawDigest = try OwnerPhoneRequestProjection.decode(
            try bytes(fixture, "projection", "rawDigestOwnerSigningRequest"))
        guard case let .ownerSigningRequest(rawScope) = rawDigest.scope,
              case let .rawDigest(rawRequest) = rawScope.request
        else {
            return XCTFail("golden raw-digest request did not decode structurally")
        }
        XCTAssertEqual(
            rawScope.requestHash,
            "0xc54b4026d0a405712135675831934bf49451ca293a1d0d528d26979e7c0fc40a")
        XCTAssertEqual(rawRequest.digest, "0x" + String(repeating: "44", count: 32))
        XCTAssertEqual(rawRequest.reason, "No device-side derivation is available")
        XCTAssertFalse(rawDigest.scope.approvable)

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
