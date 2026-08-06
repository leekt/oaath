/**
 EXPERIMENTAL PREVIEW — transport-injected relay client tests. The transport
 here is a fake byte mover; the real one is deployment-wired onto the relay's
 preview routes (the demo app maps it with URLSession).

 @author taek <leekt216@gmail.com>
 */
import XCTest
@testable import OwnerPhone
#if canImport(Security)
import Security
#endif

func projectionJson(operationId: String) -> [String: Any] {
    [
        "version": "oaath.native-projection/v1",
        "operationId": operationId,
        "displayPayload": "Ab1-_9Zz",
        "expiresAt": 1_754_000_000_000,
        "client": ["clientId": "demo-web-app", "redirectUri": "http://192.168.1.20:8788/callback"],
        "scope": ["kind": "raw", "decision": "reject-only", "text": #"{"chainScope":"all"}"#]
    ]
}

final class RelayClientTests: XCTestCase {
    private final class Recorder: @unchecked Sendable {
        var calls: [OwnerPhoneRelayCall] = []
    }

    func testFetchesAndBindsTheProjection() async throws {
        let recorder = Recorder()
        let client = TransportRelayClient { call in
            recorder.calls.append(call)
            return try JSONSerialization.data(withJSONObject: projectionJson(operationId: "req-1"))
        }
        let projection = try await client.projection(operationId: "req-1")
        XCTAssertEqual(projection.operationId, "req-1")
        XCTAssertEqual(recorder.calls, [
            OwnerPhoneRelayCall(kind: .fetchProjection, operationId: "req-1", body: nil)
        ])
    }

    func testRejectsAProjectionForADifferentOperation() async {
        let client = TransportRelayClient { _ in
            try JSONSerialization.data(withJSONObject: projectionJson(operationId: "req-other"))
        }
        do {
            _ = try await client.projection(operationId: "req-1")
            XCTFail("foreign projection must fail closed")
        } catch {
            XCTAssertEqual(error as? OwnerPhoneWireError, .invalidField("operationId"))
        }
    }

    func testSubmitsTheEncodedCommandAndBindsTheDecision() async throws {
        let recorder = Recorder()
        let client = TransportRelayClient { call in
            recorder.calls.append(call)
            return try JSONSerialization.data(withJSONObject: [
                "operationId": "req-1",
                "outcome": "rejected",
                "decidedAt": 1_753_999_000_000,
                "settlement": "decided",
                "release": ["outcome": "rejected", "decidedAt": 1_753_999_000_000]
            ])
        }
        let decision = try await client.submit(operationId: "req-1", command: .rejected)
        XCTAssertEqual(decision.outcome, .rejected)
        XCTAssertEqual(decision.settlement, .decided)
        XCTAssertEqual(recorder.calls.count, 1)
        XCTAssertEqual(recorder.calls[0].kind, .submitDecision)
        XCTAssertEqual(
            recorder.calls[0].body.flatMap { String(data: $0, encoding: .utf8) },
            #"{"command":"reject"}"#
        )
    }

    func testAMalformedOperationIdNeverReachesTheTransport() async {
        let recorder = Recorder()
        let client = TransportRelayClient { call in
            recorder.calls.append(call)
            return Data()
        }
        do {
            _ = try await client.projection(operationId: "not url safe!")
            XCTFail("malformed operation id must fail before transport")
        } catch {
            XCTAssertEqual(error as? OwnerPhoneWireError, .invalidField("operationId"))
        }
        XCTAssertTrue(recorder.calls.isEmpty)
    }

    func testADecisionForADifferentOperationFailsClosed() async {
        let client = TransportRelayClient { _ in
            try JSONSerialization.data(withJSONObject: [
                "operationId": "req-other",
                "outcome": "rejected",
                "decidedAt": 1_753_999_000_000,
                "settlement": "replayed",
                "release": NSNull()
            ])
        }
        do {
            _ = try await client.submit(operationId: "req-1", command: .rejected)
            XCTFail("foreign decision must fail closed")
        } catch {
            XCTAssertEqual(error as? OwnerPhoneWireError, .invalidField("operationId"))
        }
    }
}

#if canImport(Security)
final class KeyCustodyTests: XCTestCase {
    func testSoftwareFallbackPinsNonExtractableDeviceOnlyUnlockedAttributes() {
        let attributes = KeychainKeyCustodyStub.softwarePrivateKeyAttributes(
            applicationTag: Data("test".utf8))
        XCTAssertEqual(attributes[kSecAttrIsExtractable] as? Bool, false)
        XCTAssertEqual(
            attributes[kSecAttrAccessible] as? String,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
    }

    func testReloadRejectsSoftwareKeyForSecureEnclaveClaim() {
        let base: [CFString: Any] = [
            kSecAttrIsExtractable: false,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        XCTAssertFalse(KeychainKeyCustodyStub.storedAttributesMatchClaim(
            base, useSecureEnclave: true))
        XCTAssertFalse(KeychainKeyCustodyStub.storedAttributesMatchClaim(
            base.merging([kSecAttrTokenID: "software"] as [CFString: Any]) { _, new in new },
            useSecureEnclave: true))
        XCTAssertTrue(KeychainKeyCustodyStub.storedAttributesMatchClaim(
            base.merging([kSecAttrTokenID: kSecAttrTokenIDSecureEnclave]) { _, new in new },
            useSecureEnclave: true))
        XCTAssertFalse(KeychainKeyCustodyStub.storedAttributesMatchClaim(
            base.merging([kSecAttrTokenID: kSecAttrTokenIDSecureEnclave]) { _, new in new },
            useSecureEnclave: false))
    }

    func testANonDigestInputFailsBeforeAnyKeychainAccess() {
        let custody = KeychainKeyCustodyStub()
        XCTAssertThrowsError(try custody.signDigest(Data(count: 31))) {
            XCTAssertEqual($0 as? OwnerPhoneKeyCustodyError, .invalidDigest)
        }
        XCTAssertThrowsError(try custody.signDigest(Data())) {
            XCTAssertEqual($0 as? OwnerPhoneKeyCustodyError, .invalidDigest)
        }
    }
}
#endif
