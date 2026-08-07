/**
 EXPERIMENTAL PREVIEW — consent projection decode and match-code rendering
 tests against `packages/server/src/native/projection.ts`. The JSON fixtures
 here mirror the relay's golden route tests
 (`packages/server/test/native.test.ts`) byte-shape for byte-shape.

 @author taek <leekt216@gmail.com>
 */
import XCTest
@testable import OwnerPhone

final class ProjectionTests: XCTestCase {
    private func json(_ object: [String: Any]) -> Data {
        (try? JSONSerialization.data(withJSONObject: object)) ?? Data()
    }

    private let rawScope: [String: Any] = [
        "kind": "raw",
        "decision": "reject-only",
        "text": #"{"permission":"erc20-transfer","chainScope":"all"}"#
    ]

    private let permissionScope: [String: Any] = [
        "kind": "permission-request",
        "decision": "approve-or-reject",
        "application": [
            "applicationId": "app-a",
            "clientId": "demo-web-app",
            "origin": "https://app.example",
            "deviceFingerprint": "8sWHndmh"
        ],
        "account": [
            "accountIndex": "7",
            "kernelVersion": "0.4.0",
            "factoryRoute": "meta_factory",
            "entryPointVersion": "0.7",
            "ownerCredential": [
                "kind": "ecdsa",
                "address": "0x" + String(repeating: "33", count: 20)
            ]
        ],
        "operatorCredential": [
            "kind": "ecdsa",
            "address": "0x" + String(repeating: "44", count: 20)
        ],
        "sessionSigner": NSNull(),
        "chainScope": "all",
        "calls": [
            [
                "target": "0x" + String(repeating: "11", count: 20),
                "selector": "0x12345678",
                "valueLimit": "100",
                "argumentEquals": [["index": 0, "value": "0x" + String(repeating: "22", count: 32)]]
            ]
        ],
        "requestedAt": 1_753_000_000,
        "expiresAt": 1_754_000_000,
        "policyValidAfter": 1_753_000_000,
        "policyValidUntil": NSNull(),
        "perChainOperationLimit": 10
    ]

    private var valid: [String: Any] {
        [
            "version": "oaath.native-projection/v2",
            "operationId": "req-1",
            "displayPayload": "Ab1-_9Zz",
            "expiresAt": 1_754_000_000_000,
            "client": ["clientId": "demo-web-app", "redirectUri": "http://192.168.1.20:8788/callback"],
            "scope": rawScope
        ]
    }

    func testDecodesTheExactConsentProjection() throws {
        let projection = try OwnerPhoneRequestProjection.decode(json(valid))
        XCTAssertEqual(projection.operationId, "req-1")
        XCTAssertEqual(projection.matchCode.value, "Ab1-_9Zz")
        XCTAssertEqual(projection.expiresAt, 1_754_000_000_000)
        XCTAssertEqual(projection.client.clientId, "demo-web-app")
        XCTAssertEqual(projection.client.redirectUri, "http://192.168.1.20:8788/callback")
        XCTAssertEqual(
            projection.scope,
            .raw(#"{"permission":"erc20-transfer","chainScope":"all"}"#))
    }

    func testDecodesAStructuredPermissionScope() throws {
        var object = valid
        object["scope"] = permissionScope
        let projection = try OwnerPhoneRequestProjection.decode(json(object))
        XCTAssertEqual(projection.scope, .permissionRequest(OwnerPhonePermissionScope(
            application: OwnerPhoneApplicationIdentity(
                applicationId: "app-a",
                clientId: "demo-web-app",
                origin: "https://app.example",
                deviceFingerprint: "8sWHndmh"
            ),
            account: OwnerPhoneAccountIdentity(
                accountIndex: "7",
                kernelVersion: "0.4.0",
                factoryRoute: "meta_factory",
                entryPointVersion: "0.7",
                ownerCredential: .ecdsa(address: "0x" + String(repeating: "33", count: 20))
            ),
            operatorCredential: .ecdsa(address: "0x" + String(repeating: "44", count: 20)),
            sessionSigner: nil,
            chainScope: "all",
            calls: [OwnerPhonePermittedCall(
                target: "0x" + String(repeating: "11", count: 20),
                selector: "0x12345678",
                valueLimit: "100",
                argumentEquals: [OwnerPhoneArgumentEquality(
                    index: 0,
                    value: "0x" + String(repeating: "22", count: 32)
                )]
            )],
            requestedAt: 1_753_000_000,
            expiresAt: 1_754_000_000,
            policyValidAfter: 1_753_000_000,
            policyValidUntil: nil,
            perChainOperationLimit: 10
        )))
        XCTAssertTrue(projection.scope.approvable)
    }

    func testDecodesRemoteSessionCustodyAndRejectsUnknownModes() throws {
        // Remote custody is a consent fact: it decodes, displays, and stays
        // approvable — the request hash the decision commits to binds it.
        var custody = permissionScope
        custody["sessionSigner"] = ["mode": "oaath_hosted", "providerId": "kms-primary"]
        var object = valid
        object["scope"] = custody
        let projection = try OwnerPhoneRequestProjection.decode(json(object))
        guard case .permissionRequest(let scope) = projection.scope else {
            return XCTFail("expected a permission-request scope")
        }
        XCTAssertEqual(
            scope.sessionSigner,
            OwnerPhoneSessionSigner(mode: "oaath_hosted", providerId: "kms-primary"))
        XCTAssertTrue(projection.scope.approvable)

        // A custody model this decoder cannot name is never rendered partially.
        for hostile: Any in [
            ["mode": "owner_hosted", "providerId": "kms-primary"],
            ["mode": "frontend", "providerId": NSNull()],
            ["mode": "oaath_hosted"],
            ["mode": "oaath_hosted", "providerId": "kms-primary", "extra": 1],
            "oaath_hosted",
        ] {
            custody["sessionSigner"] = hostile
            object["scope"] = custody
            XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(json(object)))
        }
    }

    func testARawScopeIsRejectOnly() throws {
        let projection = try OwnerPhoneRequestProjection.decode(json(valid))
        XCTAssertFalse(projection.scope.approvable)
    }

    func testRejectsAnUnknownScopeKindInsteadOfRenderingPartially() {
        var object = valid
        object["scope"] = ["kind": "delegation-request", "detail": "everything"]
        XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(json(object))) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .invalidField("scope kind"))
        }
    }

    func testDecodesASignatureRequestScope() throws {
        let digest = "0x" + String(repeating: "4b", count: 32)
        let display = #"{"chainId":421614,"digest":"\#(digest)","kind":"user-operation"}"#
        var object = valid
        object["scope"] = ["kind": "signature-request", "decision": "reject-only", "digest": digest, "display": display]
        let projection = try OwnerPhoneRequestProjection.decode(json(object))
        XCTAssertEqual(
            projection.scope,
            .signatureRequest(OwnerPhoneSignatureRequestScope(digest: digest, display: display)))
        XCTAssertFalse(projection.scope.approvable)
    }

    func testRejectsMalformedSignatureRequestScopes() {
        let digest = "0x" + String(repeating: "4b", count: 32)
        let malformed: [[String: Any]] = [
            // a legacy digest can be reviewed but never claim approval capability
            ["kind": "signature-request", "decision": "approve-or-reject", "digest": digest, "display": #"{"digest":"\#(digest)","kind":"user-operation"}"#],
            // short digest
            ["kind": "signature-request", "decision": "reject-only", "digest": "0x4b", "display": "{}"],
            // uppercase digest
            ["kind": "signature-request", "decision": "reject-only", "digest": digest.uppercased(), "display": "{}"],
            // missing display
            ["kind": "signature-request", "decision": "reject-only", "digest": digest],
            // empty display
            ["kind": "signature-request", "decision": "reject-only", "digest": digest, "display": ""],
            // control character in display
            ["kind": "signature-request", "decision": "reject-only", "digest": digest, "display": "line\nbreak"],
            // extra field
            ["kind": "signature-request", "decision": "reject-only", "digest": digest, "display": "{}", "extra": 1],
            // valid JSON that omits the independently supplied digest
            ["kind": "signature-request", "decision": "reject-only", "digest": digest, "display": #"{"kind":"user-operation"}"#],
            // duplicate key ambiguity must not collapse before consent
            ["kind": "signature-request", "decision": "reject-only", "digest": digest,
             "display": #"{"digest":"\#(digest)","kind":"gone","kind":"user-operation"}"#],
            // same fields, different bytes/order
            ["kind": "signature-request", "decision": "reject-only", "digest": digest,
             "display": #"{"kind":"user-operation","digest":"\#(digest)"}"#]
        ]
        for scope in malformed {
            var object = valid
            object["scope"] = scope
            XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(json(object)))
        }
    }

    func testRejectsMalformedStructuredScopeFields() {
        let malformed: [[String: Any]] = [
            // chainScope other than the pinned "all"
            permissionScope.merging(["chainScope": "one"]) { _, new in new },
            // empty calls: the protocol never issues an empty policy
            permissionScope.merging(["calls": [Any]()]) { _, new in new },
            // uppercase hex target
            permissionScope.merging(["calls": [[
                "target": "0x" + String(repeating: "AA", count: 20),
                "selector": "0x12345678",
                "valueLimit": "100",
                "argumentEquals": [Any]()
            ]]]) { _, new in new },
            // short selector
            permissionScope.merging(["calls": [[
                "target": "0x" + String(repeating: "11", count: 20),
                "selector": "0x1234567",
                "valueLimit": "100",
                "argumentEquals": [Any]()
            ]]]) { _, new in new },
            // non-canonical decimal value limit
            permissionScope.merging(["calls": [[
                "target": "0x" + String(repeating: "11", count: 20),
                "selector": "0x12345678",
                "valueLimit": "0100",
                "argumentEquals": [Any]()
            ]]]) { _, new in new },
            // a raw decision on an approvable kind is contradictory evidence
            permissionScope.merging(["decision": "reject-only"]) { _, new in new },
            // an unknown owner credential kind never renders partially
            permissionScope.merging(["account": [
                "accountIndex": "7",
                "kernelVersion": "0.4.0",
                "factoryRoute": "meta_factory",
                "entryPointVersion": "0.7",
                "ownerCredential": ["kind": "quantum", "address": "0x"]
            ]]) { _, new in new },
            // extra call field
            permissionScope.merging(["calls": [[
                "target": "0x" + String(repeating: "11", count: 20),
                "selector": "0x12345678",
                "valueLimit": "100",
                "argumentEquals": [Any](),
                "extra": 1
            ]]]) { _, new in new }
        ]
        for scope in malformed {
            var object = valid
            object["scope"] = scope
            XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(json(object)))
        }
    }

    func testRejectsUnknownAndMissingFields() {
        var object = valid
        object["permissionDetail"] = "everything"
        XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(json(object))) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .unexpectedFields("owner phone projection"))
        }
        object = valid
        object.removeValue(forKey: "displayPayload")
        XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(json(object))) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .unexpectedFields("owner phone projection"))
        }
        // A foreign version is rejected, never read as this one.
        object = valid
        object["version"] = "oaath.native-projection/v1"
        XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(json(object))) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .invalidField("version"))
        }
        object = valid
        object["client"] = ["clientId": "demo-web-app"]
        XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(json(object))) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .unexpectedFields("client"))
        }
        object = valid
        object["scope"] = rawScope.merging(["extra": 1]) { _, new in new }
        XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(json(object))) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .unexpectedFields("scope"))
        }
    }

    func testRejectsNonObjectBodies() {
        XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(Data("[]".utf8))) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .notAnObject("owner phone projection"))
        }
        XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(Data("not json".utf8))) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .notAnObject("owner phone projection"))
        }
    }

    func testMatchCodeAcceptsExactlyEightBase64UrlCharacters() throws {
        XCTAssertEqual(try MatchCode("Ab1-_9Zz").value, "Ab1-_9Zz")
        for bad in ["", "Ab1-_9Z", "Ab1-_9Zz0", "Ab1-_9Z+", "Ab1-_9Z/", "Ab1 _9Zz", "Ab1-_9Z="] {
            XCTAssertThrowsError(try MatchCode(bad)) {
                XCTAssertEqual($0 as? OwnerPhoneWireError, .invalidField("displayPayload"))
            }
        }
    }

    func testMatchCodeRendersInTwoGroupsOfFour() throws {
        XCTAssertEqual(try MatchCode("Ab1-_9Zz").display, "Ab1- _9Zz")
        XCTAssertEqual(try MatchCode("AAAABBBB").display, "AAAA BBBB")
    }

    func testRejectsControlCharactersInOperationId() {
        var object = valid
        object["operationId"] = "req\u{0000}1"
        XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(json(object))) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .invalidField("operationId"))
        }
    }
}
