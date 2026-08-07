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
    func testSoftwareFallbackPinsDeviceOnlyUnlockedAttributes() {
        let attributes = KeychainKeyCustodyStub.softwarePrivateKeyAttributes(
            applicationTag: Data("test".utf8))
        XCTAssertNil(attributes[kSecAttrIsExtractable])
        XCTAssertEqual(
            attributes[kSecAttrAccessible] as? String,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
    }

    func testEnclaveLookupPinsIdentityWithoutFilteringOnReturnedToken() {
        let tag = Data("test".utf8)
        let query = KeychainKeyCustodyStub.privateKeyQuery(applicationTag: tag)

        XCTAssertEqual(query[kSecAttrKeyType] as? String, kSecAttrKeyTypeECSECPrimeRandom as String)
        XCTAssertEqual(query[kSecAttrKeyClass] as? String, kSecAttrKeyClassPrivate as String)
        XCTAssertEqual(query[kSecAttrApplicationTag] as? Data, tag)
        XCTAssertEqual(query[kSecMatchLimit] as? String, kSecMatchLimitAll as String)
        XCTAssertNil(query[kSecAttrTokenID])
    }

    func testSecureEnclaveClaimRequiresAnExactPrivateSigningP256Key() {
        let enclaveKey: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits: 256,
            kSecAttrCanSign: true,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave
        ]

        XCTAssertTrue(KeychainKeyCustodyStub.keyAttributesMatchClaim(
            enclaveKey, useSecureEnclave: true))
        for mutation: (inout [CFString: Any]) -> Void in [
            { $0.removeValue(forKey: kSecAttrTokenID) },
            { $0[kSecAttrTokenID] = "software" },
            { $0[kSecAttrKeyType] = kSecAttrKeyTypeRSA },
            { $0[kSecAttrKeyClass] = kSecAttrKeyClassPublic },
            { $0[kSecAttrKeySizeInBits] = 384 },
            { $0[kSecAttrCanSign] = false }
        ] {
            var invalid = enclaveKey
            mutation(&invalid)
            XCTAssertFalse(KeychainKeyCustodyStub.keyAttributesMatchClaim(
                invalid, useSecureEnclave: true))
        }
    }

    func testSoftwareClaimRejectsOnlyTheSecureEnclaveToken() {
        let software: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits: 256,
            kSecAttrCanSign: true
        ]

        XCTAssertTrue(KeychainKeyCustodyStub.keyAttributesMatchClaim(
            software, useSecureEnclave: false))
        var otherToken = software
        otherToken[kSecAttrTokenID] = "software-token"
        XCTAssertTrue(KeychainKeyCustodyStub.keyAttributesMatchClaim(
            otherToken,
            useSecureEnclave: false))
        var enclave = software
        enclave[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave
        XCTAssertFalse(KeychainKeyCustodyStub.keyAttributesMatchClaim(
            enclave,
            useSecureEnclave: false))
        var malformed = software
        malformed[kSecAttrTokenID] = NSNull()
        XCTAssertFalse(KeychainKeyCustodyStub.keyAttributesMatchClaim(
            malformed,
            useSecureEnclave: false))
    }

    func testLoadOnlyCustodyDoesNotCreateAMissingKey() {
        let custody = KeychainKeyCustodyStub(
            applicationTag: "org.oaath.tests.missing.\(UUID().uuidString)",
            createIfMissing: false)
        XCTAssertThrowsError(try custody.publicKey()) {
            XCTAssertEqual($0 as? OwnerPhoneKeyCustodyError, .keyUnavailable)
        }
    }

    func testAProvisionedSoftwareKeyReloadsWithTheSamePublicMaterial() throws {
        let tag = "org.oaath.tests.reload.\(UUID().uuidString)"
        let applicationTag = Data(tag.utf8)
        defer {
            let query: [CFString: Any] = [
                kSecClass: kSecClassKey,
                kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeyClass: kSecAttrKeyClassPrivate,
                kSecAttrApplicationTag: applicationTag
            ]
            XCTAssertEqual(SecItemDelete(query as CFDictionary), errSecSuccess)
        }

        let provisioned = KeychainKeyCustodyStub(applicationTag: tag)
        let originalPublicKey = try provisioned.publicKey()
        let reloaded = KeychainKeyCustodyStub(
            applicationTag: tag,
            createIfMissing: false)

        XCTAssertEqual(try reloaded.publicKey(), originalPublicKey)
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
