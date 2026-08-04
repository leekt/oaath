/**
 EXPERIMENTAL PREVIEW — closed APNs payload decode tests against the exact
 shape `packages/server/src/apns/sender.ts` serializes.

 @author taek <leekt216@gmail.com>
 */
import XCTest
@testable import OwnerPhone

final class PushPayloadTests: XCTestCase {
    private func payload(
        mutate: (inout [String: Any]) -> Void = { _ in }
    ) -> [AnyHashable: Any] {
        var payload: [String: Any] = [
            "aps": [
                "alert": [
                    "title-loc-key": "oaath_approval_title",
                    "loc-key": "oaath_approval_body",
                    "loc-args": ["Ab1-_9Zz"]
                ] as [String: Any],
                "sound": "default"
            ] as [String: Any],
            "oaath": [
                "version": "oaath.apns-payload/v1",
                "operationId": "req-1.2~x_Y",
                "expiresAt": 1_754_000_000_000
            ] as [String: Any]
        ]
        mutate(&payload)
        return payload
    }

    func testDecodesTheExactSenderPayload() throws {
        let push = try OwnerPhonePush.decode(userInfo: payload())
        XCTAssertEqual(push.operationId, "req-1.2~x_Y")
        XCTAssertEqual(push.matchCode.value, "Ab1-_9Zz")
        XCTAssertEqual(push.expiresAt, 1_754_000_000_000)
    }

    func testRejectsUnknownTopLevelField() {
        XCTAssertThrowsError(try OwnerPhonePush.decode(userInfo: payload { $0["extra"] = 1 })) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .unexpectedFields("apns payload"))
        }
    }

    func testRejectsUnknownOaathFieldEvenWhenAuthorityShaped() {
        // Nothing but {version, operationId, expiresAt} exists by design.
        for field in ["artifact", "permission", "token", "account"] {
            let mutated = payload {
                var oaath = $0["oaath"] as! [String: Any]
                oaath[field] = "x"
                $0["oaath"] = oaath
            }
            XCTAssertThrowsError(try OwnerPhonePush.decode(userInfo: mutated)) {
                XCTAssertEqual($0 as? OwnerPhoneWireError, .unexpectedFields("oaath"))
            }
        }
    }

    func testRejectsWrongVersion() {
        let mutated = payload {
            var oaath = $0["oaath"] as! [String: Any]
            oaath["version"] = "oaath.apns-payload/v2"
            $0["oaath"] = oaath
        }
        XCTAssertThrowsError(try OwnerPhonePush.decode(userInfo: mutated)) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .invalidField("version"))
        }
    }

    func testRejectsMalformedOperationIds() {
        for bad in [123 as Any, "", "not url safe!", String(repeating: "a", count: 65)] {
            let mutated = payload {
                var oaath = $0["oaath"] as! [String: Any]
                oaath["operationId"] = bad
                $0["oaath"] = oaath
            }
            XCTAssertThrowsError(try OwnerPhonePush.decode(userInfo: mutated)) {
                XCTAssertEqual($0 as? OwnerPhoneWireError, .invalidField("operationId"))
            }
        }
    }

    func testRejectsMalformedExpiry() {
        for bad in [true as Any, -1, 1.5, "1754000000000", 9_007_199_254_740_992] {
            let mutated = payload {
                var oaath = $0["oaath"] as! [String: Any]
                oaath["expiresAt"] = bad
                $0["oaath"] = oaath
            }
            XCTAssertThrowsError(try OwnerPhonePush.decode(userInfo: mutated)) {
                XCTAssertEqual($0 as? OwnerPhoneWireError, .invalidField("expiresAt"))
            }
        }
    }

    func testRejectsAlertShapeDrift() {
        // Two loc-args.
        var mutated = payload {
            var aps = $0["aps"] as! [String: Any]
            var alert = aps["alert"] as! [String: Any]
            alert["loc-args"] = ["Ab1-_9Zz", "second"]
            aps["alert"] = alert
            $0["aps"] = aps
        }
        XCTAssertThrowsError(try OwnerPhonePush.decode(userInfo: mutated)) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .invalidField("loc-args"))
        }
        // Unknown alert field.
        mutated = payload {
            var aps = $0["aps"] as! [String: Any]
            var alert = aps["alert"] as! [String: Any]
            alert["body"] = "free text"
            aps["alert"] = alert
            $0["aps"] = aps
        }
        XCTAssertThrowsError(try OwnerPhonePush.decode(userInfo: mutated)) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .unexpectedFields("alert"))
        }
        // Wrong localization key.
        mutated = payload {
            var aps = $0["aps"] as! [String: Any]
            var alert = aps["alert"] as! [String: Any]
            alert["loc-key"] = "other_body"
            aps["alert"] = alert
            $0["aps"] = aps
        }
        XCTAssertThrowsError(try OwnerPhonePush.decode(userInfo: mutated)) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .invalidField("loc-key"))
        }
        // Unknown aps field.
        mutated = payload {
            var aps = $0["aps"] as! [String: Any]
            aps["badge"] = 1
            $0["aps"] = aps
        }
        XCTAssertThrowsError(try OwnerPhonePush.decode(userInfo: mutated)) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .unexpectedFields("aps"))
        }
    }

    func testRejectsNonStringKeys() {
        var userInfo = payload()
        userInfo[1] = "x"
        XCTAssertThrowsError(try OwnerPhonePush.decode(userInfo: userInfo)) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .notAnObject("apns payload"))
        }
    }

    func testMatchesRequiresExactAgreementWithProjection() throws {
        let push = try OwnerPhonePush.decode(userInfo: payload())
        let projection = OwnerPhoneRequestProjection(
            operationId: "req-1.2~x_Y",
            matchCode: try MatchCode("Ab1-_9Zz"),
            expiresAt: 1_754_000_000_000
        )
        XCTAssertTrue(push.matches(projection))
        XCTAssertFalse(push.matches(OwnerPhoneRequestProjection(
            operationId: projection.operationId,
            matchCode: try MatchCode("AAAAAAAA"),
            expiresAt: projection.expiresAt
        )))
        XCTAssertFalse(push.matches(OwnerPhoneRequestProjection(
            operationId: "req-other",
            matchCode: projection.matchCode,
            expiresAt: projection.expiresAt
        )))
        XCTAssertFalse(push.matches(OwnerPhoneRequestProjection(
            operationId: projection.operationId,
            matchCode: projection.matchCode,
            expiresAt: projection.expiresAt + 1
        )))
    }
}
