/**
 EXPERIMENTAL PREVIEW — projection decode and match-code rendering tests
 against `packages/server/src/native/projection.ts`.

 @author taek <leekt216@gmail.com>
 */
import XCTest
@testable import OwnerPhone

final class ProjectionTests: XCTestCase {
    private func json(_ object: [String: Any]) -> Data {
        try! JSONSerialization.data(withJSONObject: object)
    }

    private var valid: [String: Any] {
        [
            "operationId": "req-1",
            "displayPayload": "Ab1-_9Zz",
            "expiresAt": 1_754_000_000_000
        ]
    }

    func testDecodesTheExactProjection() throws {
        let projection = try OwnerPhoneRequestProjection.decode(json(valid))
        XCTAssertEqual(projection.operationId, "req-1")
        XCTAssertEqual(projection.matchCode.value, "Ab1-_9Zz")
        XCTAssertEqual(projection.expiresAt, 1_754_000_000_000)
    }

    func testRejectsUnknownAndMissingFields() {
        var object = valid
        object["scope"] = "everything" // no permission detail exists by design
        XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(json(object))) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .unexpectedFields("owner phone projection"))
        }
        object = valid
        object.removeValue(forKey: "displayPayload")
        XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(json(object))) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .unexpectedFields("owner phone projection"))
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
