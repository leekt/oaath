/**
 EXPERIMENTAL PREVIEW — pure demo-wiring tests: route construction, pairing
 decode, credential custody, and code delivery. No network is contacted; the
 byte mover is faked.

 @author taek <leekt216@gmail.com>
 */
import XCTest
@testable import OwnerPhone
@testable import OwnerPhoneDemo

private struct FakeHTTP: DemoHTTP {
    let status: Int
    let body: Data
    let recorder: Recorder

    final class Recorder: @unchecked Sendable {
        var requests: [URLRequest] = []
    }

    func send(_ request: URLRequest) async throws -> (Data, Int) {
        recorder.requests.append(request)
        return (body, status)
    }
}

final class DemoRelayEndpointTests: XCTestCase {
    func testBuildsTheExactPreviewRoutes() throws {
        let endpoint = try DemoRelayEndpoint(baseURLText: "http://192.168.1.20:8787/")
        XCTAssertEqual(endpoint.baseURL.absoluteString, "http://192.168.1.20:8787")

        let projection = endpoint.projectionRequest(operationId: "req-1", credential: "cred")
        XCTAssertEqual(projection.httpMethod, "GET")
        XCTAssertEqual(
            projection.url?.absoluteString, "http://192.168.1.20:8787/native/projections/req-1")
        XCTAssertEqual(projection.value(forHTTPHeaderField: "Authorization"), "Bearer cred")

        let decision = endpoint.decisionRequest(
            operationId: "req-1", body: Data("{}".utf8), credential: "cred")
        XCTAssertEqual(decision.httpMethod, "POST")
        XCTAssertEqual(
            decision.url?.absoluteString, "http://192.168.1.20:8787/native/decisions/req-1")
        XCTAssertEqual(decision.value(forHTTPHeaderField: "Content-Type"), "application/json")
        XCTAssertEqual(decision.value(forHTTPHeaderField: "Authorization"), "Bearer cred")

        let pairing = try endpoint.pairingRequest(
            pairingCode: "AAAA-BBBB", deviceToken: "ab12", publicKey: "0xbeef")
        XCTAssertEqual(pairing.url?.absoluteString, "http://192.168.1.20:8787/native/pairings")
        // The pairing code IS the authentication for this one call: no bearer.
        XCTAssertNil(pairing.value(forHTTPHeaderField: "Authorization"))
        XCTAssertEqual(
            pairing.httpBody.flatMap { String(data: $0, encoding: .utf8) },
            #"{"deviceToken":"ab12","pairingCode":"AAAA-BBBB","publicKey":"0xbeef"}"#)
    }

    func testRejectsANonHttpBaseURL() {
        for bad in ["", "ftp://relay", "relay", "http://"] {
            XCTAssertThrowsError(try DemoRelayEndpoint(baseURLText: bad)) {
                XCTAssertEqual($0 as? DemoRelayError, .invalidBaseURL)
            }
        }
    }

    func testTransportMapsCallsOntoRoutesAndReportsStatuses() async throws {
        let recorder = FakeHTTP.Recorder()
        let body = try JSONSerialization.data(withJSONObject: projectionJson(operationId: "req-1"))
        let statuses = LastStatusBox()
        let client = demoRelayClient(
            endpoint: try DemoRelayEndpoint(baseURLText: "http://127.0.0.1:8787"),
            credential: "cred",
            http: FakeHTTP(status: 200, body: body, recorder: recorder),
            onStatus: { statuses.record($0) })
        let projection = try await client.projection(operationId: "req-1")
        XCTAssertEqual(projection.operationId, "req-1")
        XCTAssertEqual(statuses.read(), 200)
        XCTAssertEqual(
            recorder.requests.map { $0.url?.absoluteString },
            ["http://127.0.0.1:8787/native/projections/req-1"])
    }

    func testTransportSurfacesARefusalAsItsStatus() async throws {
        let statuses = LastStatusBox()
        let client = demoRelayClient(
            endpoint: try DemoRelayEndpoint(baseURLText: "http://127.0.0.1:8787"),
            credential: "stale",
            http: FakeHTTP(status: 401, body: Data("{}".utf8), recorder: .init()),
            onStatus: { statuses.record($0) })
        do {
            _ = try await client.projection(operationId: "req-1")
            XCTFail("a refused credential must fail closed")
        } catch {
            XCTAssertEqual(error as? DemoRelayError, .status(401))
        }
        XCTAssertEqual(statuses.read(), 401)
    }
}

final class PairingClientTests: XCTestCase {
    func testPairsAndDecodesTheExactCredentialEnvelope() async throws {
        let recorder = FakeHTTP.Recorder()
        let account = "0x" + String(repeating: "66", count: 20)
        let device = try await pair(
            endpoint: try DemoRelayEndpoint(baseURLText: "http://127.0.0.1:8787"),
            pairingCode: "AAAA-BBBB-CC",
            deviceToken: String(repeating: "ab", count: 32),
            publicKey: "0x" + String(repeating: "cd", count: 64),
            http: FakeHTTP(
                status: 200,
                body: Data(
                    #"{"deviceCredential":"issued-token","account":"\#(account)"}"#.utf8),
                recorder: recorder))
        XCTAssertEqual(device, PairedDevice(deviceCredential: "issued-token", account: account))
        XCTAssertEqual(recorder.requests.count, 1)

        // A chainless web half derives no account; the phone shows that honestly.
        let chainless = try await pair(
            endpoint: try DemoRelayEndpoint(baseURLText: "http://127.0.0.1:8787"),
            pairingCode: "AAAA-BBBB-CC",
            deviceToken: "ab",
            publicKey: "0xcd",
            http: FakeHTTP(
                status: 200,
                body: Data(#"{"deviceCredential":"issued-token","account":null}"#.utf8),
                recorder: .init()))
        XCTAssertNil(chainless.account)
    }

    func testARefusedOrMalformedPairingFailsClosed() async throws {
        for (status, body) in [
            (401, #"{"error":{"code":"pairing_invalid"}}"#),
            (200, #"{"deviceCredential":"x","account":null,"extra":1}"#),
            (200, #"{"deviceCredential":"x"}"#),
            (200, #"{"deviceCredential":"","account":null}"#),
            (200, #"{"deviceCredential":"x","account":"0xNOT"}"#),
            (200, #"[]"#)
        ] {
            do {
                _ = try await pair(
                    endpoint: try DemoRelayEndpoint(baseURLText: "http://127.0.0.1:8787"),
                    pairingCode: "AAAA",
                    deviceToken: "ab",
                    publicKey: "0xcd",
                    http: FakeHTTP(status: status, body: Data(body.utf8), recorder: .init()))
                XCTFail("pairing must fail closed for status \(status) body \(body)")
            } catch {
                XCTAssertTrue(error is DemoPairingError)
            }
        }
    }

    func testCredentialStoreRoundTrips() {
        let store = InMemoryCredentialStore()
        XCTAssertNil(store.load())
        store.save("issued-token")
        XCTAssertEqual(store.load(), "issued-token")
        store.clear()
        XCTAssertNil(store.load())
    }
}

final class CodeDeliveryTests: XCTestCase {
    func testAppendsTheCodeToTheRedirectUri() throws {
        XCTAssertEqual(
            try codeDeliveryURL(redirectUri: "http://192.168.1.20:8788/callback", code: "one-time")
                .absoluteString,
            "http://192.168.1.20:8788/callback?code=one-time")
        // An existing query survives; the code is appended, never overwritten.
        XCTAssertEqual(
            try codeDeliveryURL(redirectUri: "https://app.example/cb?state=x", code: "c")
                .absoluteString,
            "https://app.example/cb?state=x&code=c")
    }

    func testRejectsANonHttpRedirectUri() {
        for bad in ["javascript:alert(1)", "file:///etc/passwd", "not a url", ""] {
            XCTAssertThrowsError(try codeDeliveryURL(redirectUri: bad, code: "c")) {
                XCTAssertEqual($0 as? CodeDeliveryError, .invalidRedirectUri)
            }
        }
    }

    func testDeliveryPerformsExactlyOneGet() async throws {
        let recorder = FakeHTTP.Recorder()
        let status = try await deliverCode(
            redirectUri: "http://127.0.0.1:8788/callback",
            code: "one-time",
            http: FakeHTTP(status: 200, body: Data(), recorder: recorder))
        XCTAssertEqual(status, 200)
        XCTAssertEqual(recorder.requests.map { $0.httpMethod }, ["GET"])
        XCTAssertEqual(
            recorder.requests.map { $0.url?.absoluteString },
            ["http://127.0.0.1:8788/callback?code=one-time"])
    }
}
