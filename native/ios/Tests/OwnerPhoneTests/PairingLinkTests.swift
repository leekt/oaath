/**
 EXPERIMENTAL PREVIEW — pairing-link parsing: the QR/tap/paste payload
 `oaath-demo://pair?relay=…&code=…` fills the pairing screen and nothing else.

 @author taek <leekt216@gmail.com>
 */
import XCTest
@testable import OwnerPhoneDemo

final class PairingLinkTests: XCTestCase {
    func testParsesTheExactPairingLink() {
        XCTAssertEqual(
            parsePairingLink("oaath-demo://pair?relay=http://192.168.1.20:8787&code=ABCDEFGHJK"),
            PairingLink(relayURL: "http://192.168.1.20:8787", pairingCode: "ABCDEFGHJK"))
        // Percent-encoded relay URLs decode; surrounding whitespace is pasted noise.
        XCTAssertEqual(
            parsePairingLink(
                "  oaath-demo://pair?relay=http%3A%2F%2F10.0.0.5%3A8787&code=abcd-efgh-jk \n"),
            PairingLink(relayURL: "http://10.0.0.5:8787", pairingCode: "ABCDEFGHJK"))
    }

    func testRejectsDuplicateRequiredParameters() {
        for bad in [
            "oaath-demo://pair?relay=http://10.0.0.5:8787&relay=http://10.0.0.6:8787&code=ABCDEFGHJK",
            "oaath-demo://pair?relay&relay=http://10.0.0.5:8787&code=ABCDEFGHJK",
            "oaath-demo://pair?relay=http://10.0.0.5:8787&code=ABCDEFGHJK&code=BCDEFGHJKM",
            "oaath-demo://pair?relay=http://10.0.0.5:8787&code&code=ABCDEFGHJK"
        ] {
            XCTAssertNil(parsePairingLink(bad), bad)
        }
    }

    func testRejectsEverythingElse() {
        for bad in [
            "",
            "ABCDEFGHJK",
            "https://pair?relay=http://10.0.0.5:8787&code=ABCDEFGHJK",
            "oaath-demo://decide?relay=http://10.0.0.5:8787&code=ABCDEFGHJK",
            "oaath-demo://pair?relay=http://10.0.0.5:8787",
            "oaath-demo://pair?code=ABCDEFGHJK",
            "oaath-demo://pair?relay=http://10.0.0.5:8787&code=",
            "oaath-demo://pair?relay=ftp://10.0.0.5&code=ABCDEFGHJK",
            "oaath-demo://pair?relay=http://10.0.0.5:8787&code=ABCDEFGHJK&extra=1",
            "oaath-demo:pair?relay=http://10.0.0.5:8787&code=ABCDEFGHJK",
            "oaath-demo://pair/extra?relay=http://10.0.0.5:8787&code=ABCDEFGHJK",
            "oaath-demo://pair?relay=http://10.0.0.5:8787&code=ABCDEFGHJK#ignored",
            "oaath-demo://user@pair?relay=http://10.0.0.5:8787&code=ABCDEFGHJK",
            "oaath-demo://pair:42?relay=http://10.0.0.5:8787&code=ABCDEFGHJK",
            String(repeating: " ", count: 2_049)
        ] {
            XCTAssertNil(parsePairingLink(bad), bad)
        }
    }
}
