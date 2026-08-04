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
        try! JSONSerialization.data(withJSONObject: object)
    }

    private let rawScope: [String: Any] = [
        "kind": "raw",
        "text": #"{"permission":"erc20-transfer","chainScope":"all"}"#
    ]

    private let permissionScope: [String: Any] = [
        "kind": "permission-request",
        "chainScope": "all",
        "calls": [
            [
                "target": "0x" + String(repeating: "11", count: 20),
                "selector": "0x12345678",
                "valueLimit": "100"
            ]
        ],
        "expiresAt": 1_754_000_000,
        "perChainOperationLimit": 10
    ]

    private var valid: [String: Any] {
        [
            "version": "oaath.native-projection/v1",
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
            chainScope: "all",
            calls: [OwnerPhonePermittedCall(
                target: "0x" + String(repeating: "11", count: 20),
                selector: "0x12345678",
                valueLimit: "100"
            )],
            expiresAt: 1_754_000_000,
            perChainOperationLimit: 10
        )))
    }

    func testRejectsAnUnknownScopeKindInsteadOfRenderingPartially() {
        var object = valid
        object["scope"] = ["kind": "signature-request", "digest": "0x00"]
        XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(json(object))) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .invalidField("scope kind"))
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
                "valueLimit": "100"
            ]]]) { _, new in new },
            // short selector
            permissionScope.merging(["calls": [[
                "target": "0x" + String(repeating: "11", count: 20),
                "selector": "0x1234567",
                "valueLimit": "100"
            ]]]) { _, new in new },
            // non-canonical decimal value limit
            permissionScope.merging(["calls": [[
                "target": "0x" + String(repeating: "11", count: 20),
                "selector": "0x12345678",
                "valueLimit": "0100"
            ]]]) { _, new in new },
            // extra call field
            permissionScope.merging(["calls": [[
                "target": "0x" + String(repeating: "11", count: 20),
                "selector": "0x12345678",
                "valueLimit": "100",
                "argumentEquals": [Any]()
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
        object = valid
        object["version"] = "oaath.native-projection/v2"
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
