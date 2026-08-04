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

private actor PairingCapture {
    private var value: PersistedPairing?
    func record(_ pairing: PersistedPairing) { value = pairing }
    func read() -> PersistedPairing? { value }
}

private struct FakeOwnerSigning: DemoOwnerSigning {
    let secureEnclave = false
    func publicMaterialHex() throws -> String { "0x" + String(repeating: "11", count: 64) }
    func signDigestHex(_ digestHex: String) throws -> String {
        "0x" + String(repeating: "22", count: 64)
    }
}

private enum DeferredHTTPError: Error {
    case transport
}

private actor DeferredHTTP: DemoHTTP {
    typealias Response = (Data, Int)
    private var pending: [String: CheckedContinuation<Response, Error>] = [:]
    private var recorded: [URLRequest] = []

    func send(_ request: URLRequest) async throws -> Response {
        recorded.append(request)
        let key = Self.key(for: request)
        return try await withCheckedThrowingContinuation { continuation in
            precondition(pending[key] == nil, "duplicate deferred request key \(key)")
            pending[key] = continuation
        }
    }

    func wait(for key: String) async {
        while pending[key] == nil { await Task.yield() }
    }

    func succeed(_ key: String, body: Data, status: Int = 200) {
        precondition(pending.removeValue(forKey: key)?.resume(returning: (body, status)) != nil)
    }

    func fail(_ key: String) {
        precondition(pending.removeValue(forKey: key)?.resume(throwing: DeferredHTTPError.transport) != nil)
    }

    func requests() -> [URLRequest] { recorded }

    nonisolated static func key(for request: URLRequest) -> String {
        if request.url?.path == "/native/pairings",
           let body = request.httpBody,
           let object = try? JSONSerialization.jsonObject(with: body) as? [String: String],
           let code = object["pairingCode"] {
            return "pair:\(code)"
        }
        let bearer = request.value(forHTTPHeaderField: "Authorization") ?? "none"
        return "auth:\(bearer):\(request.url?.lastPathComponent ?? "none")"
    }
}

private func pairingResponse(_ credential: String) -> Data {
    Data(#"{"deviceCredential":"\#(credential)","account":null}"#.utf8)
}

private final class PairingIdentityHTTP: DemoHTTP, @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [URLRequest] = []
    let pairingStatus: Int
    let credential: String
    let account: String

    init(pairingStatus: Int = 200, credential: String = "credential-a") {
        self.pairingStatus = pairingStatus
        self.credential = credential
        self.account = "0x" + String(repeating: "66", count: 20)
    }

    func send(_ request: URLRequest) async throws -> (Data, Int) {
        lock.withLock { recorded.append(request) }
        if request.url?.path == "/native/pairings" {
            if pairingStatus != 200 { return (Data("{}".utf8), pairingStatus) }
            return (
                Data(#"{"deviceCredential":"\#(credential)","account":"\#(account)"}"#.utf8),
                200)
        }
        let operationId = request.url?.lastPathComponent ?? "request"
        return (
            try JSONSerialization.data(
                withJSONObject: projectionJson(operationId: operationId)),
            200)
    }

    func requests() -> [URLRequest] {
        lock.lock()
        defer { lock.unlock() }
        return recorded
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

    func testTransportMapsCallsOntoRoutesWithoutReportingSuccessAsAuthority() async throws {
        let recorder = FakeHTTP.Recorder()
        let body = try JSONSerialization.data(withJSONObject: projectionJson(operationId: "req-1"))
        let unauthorized = PairingCapture()
        let client = demoRelayClient(
            pairing: try PersistedPairing(
                endpoint: DemoRelayEndpoint(baseURLText: "http://127.0.0.1:8787"),
                credential: "cred",
                account: nil),
            http: FakeHTTP(status: 200, body: body, recorder: recorder),
            onUnauthorized: { await unauthorized.record($0) })
        let projection = try await client.projection(operationId: "req-1")
        XCTAssertEqual(projection.operationId, "req-1")
        let reportedPairing = await unauthorized.read()
        XCTAssertNil(reportedPairing)
        XCTAssertEqual(
            recorder.requests.map { $0.url?.absoluteString },
            ["http://127.0.0.1:8787/native/projections/req-1"])
    }

    func testTransportReportsTheExactPairingThatReceived401() async throws {
        let unauthorized = PairingCapture()
        let pairing = try PersistedPairing(
            endpoint: DemoRelayEndpoint(baseURLText: "http://127.0.0.1:8787"),
            credential: "stale",
            account: nil)
        let client = demoRelayClient(
            pairing: pairing,
            http: FakeHTTP(status: 401, body: Data("{}".utf8), recorder: .init()),
            onUnauthorized: { await unauthorized.record($0) })
        do {
            _ = try await client.projection(operationId: "req-1")
            XCTFail("a refused credential must fail closed")
        } catch {
            XCTAssertEqual(error as? DemoRelayError, .status(401))
        }
        let reportedPairing = await unauthorized.read()
        XCTAssertEqual(reportedPairing, pairing)
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

    func testPairingStoreRoundTripsOneExactVersionedValue() throws {
        let store = InMemoryPairingStore()
        let pairing = try PersistedPairing(
            endpoint: DemoRelayEndpoint(baseURLText: "HTTP://RELAY.EXAMPLE:8787/"),
            credential: "issued-token",
            account: nil)
        XCTAssertNil(store.load())
        try store.save(pairing)
        XCTAssertEqual(store.load(), pairing)
        XCTAssertEqual(pairing.endpoint.baseURL.absoluteString, "http://relay.example:8787")
        XCTAssertEqual(try PersistedPairing.decode(pairing.encoded()), pairing)
        store.clear()
        XCTAssertNil(store.load())
    }

    func testPairingRecordRejectsOldCredentialOnlyAndShapeDrift() throws {
        XCTAssertThrowsError(try PersistedPairing.decode(Data("issued-token".utf8)))
        let pairing = try PersistedPairing(
            endpoint: DemoRelayEndpoint(baseURLText: "http://relay-a:8787"),
            credential: "secret",
            account: nil)
        let valid = try XCTUnwrap(
            JSONSerialization.jsonObject(with: pairing.encoded()) as? [String: Any])
        for changed in [
            valid.merging(["extra": true]) { _, right in right },
            valid.merging(["version": 2]) { _, right in right },
            valid.merging(["endpoint": "http://RELAY-A:8787/"]) { _, right in right }
        ] {
            let data = try JSONSerialization.data(withJSONObject: changed)
            XCTAssertThrowsError(try PersistedPairing.decode(data))
        }
    }
}

@MainActor
final class DemoPairingIdentityTests: XCTestCase {
    func testDifferentEndpointLinkCannotRebindAndRestartUsesOnlyBoundEndpoint() async throws {
        let ownerKey = FakeOwnerSigning()
        let store = InMemoryPairingStore()
        let http = PairingIdentityHTTP()
        let model = DemoModel(pairings: store, http: http, ownerKey: ownerKey)
        model.baseURLText = "http://relay-a.example:8787/"
        model.pairingCodeText = "AAAA-BBBB"
        await model.pair()
        XCTAssertTrue(model.paired, model.statusLine)
        let bound = try XCTUnwrap(store.load())
        XCTAssertEqual(bound.endpoint.baseURL.absoluteString, "http://relay-a.example:8787")

        model.apply(link: PairingLink(
            relayURL: "http://relay-b.example:9999", pairingCode: "BBBB-CCCC"))
        XCTAssertEqual(model.baseURLText, "http://relay-a.example:8787")
        XCTAssertEqual(store.load(), bound)
        XCTAssertTrue(model.pairingCodeText.isEmpty)
        XCTAssertTrue(model.statusLine.contains("Already paired"))

        let restarted = DemoModel(pairings: store, http: http, ownerKey: ownerKey)
        XCTAssertTrue(restarted.paired)
        XCTAssertEqual(restarted.baseURLText, "http://relay-a.example:8787")
        restarted.operationIdText = "request-after-restart"
        await restarted.openManually()

        let authenticated = http.requests().filter {
            $0.value(forHTTPHeaderField: "Authorization") != nil
        }
        XCTAssertEqual(authenticated.count, 1)
        XCTAssertEqual(
            authenticated.first?.url?.absoluteString,
            "http://relay-a.example:8787/native/projections/request-after-restart")
        XCTAssertEqual(
            authenticated.first?.value(forHTTPHeaderField: "Authorization"),
            "Bearer credential-a")
        XCTAssertFalse(http.requests().contains {
            $0.url?.host == "relay-b.example" &&
                $0.value(forHTTPHeaderField: "Authorization") == "Bearer credential-a"
        })
    }

    func testFailedCandidateNeverPersistsAndSameEndpointLinkIsIgnoredWhilePaired() async throws {
        let ownerKey = FakeOwnerSigning()
        let failedStore = InMemoryPairingStore()
        let failed = DemoModel(
            pairings: failedStore,
            http: PairingIdentityHTTP(pairingStatus: 401, credential: "never-store"),
            ownerKey: ownerKey)
        failed.baseURLText = "http://relay-b.example:9999"
        failed.pairingCodeText = "BAD-CODE"
        await failed.pair()
        XCTAssertFalse(failed.paired)
        XCTAssertNil(failedStore.load())
        XCTAssertFalse(failed.statusLine.contains("never-store"))

        let store = InMemoryPairingStore()
        let http = PairingIdentityHTTP()
        let model = DemoModel(pairings: store, http: http, ownerKey: ownerKey)
        model.baseURLText = "http://relay-a.example:8787"
        model.pairingCodeText = "GOOD-CODE"
        await model.pair()
        let bound = try XCTUnwrap(store.load())
        let requestCount = http.requests().count
        model.apply(link: PairingLink(
            relayURL: "HTTP://RELAY-A.EXAMPLE:8787/", pairingCode: "NEW-CODE"))
        await model.pair()
        XCTAssertEqual(store.load(), bound)
        XCTAssertEqual(http.requests().count, requestCount)
        XCTAssertTrue(model.pairingCodeText.isEmpty)
        XCTAssertTrue(model.statusLine.contains("Already paired"))
    }

    func testLatestPairingAttemptWinsInBothResponseOrders() async throws {
        for firstResponse in ["PAIR-A", "PAIR-B"] {
            let store = InMemoryPairingStore()
            let http = DeferredHTTP()
            let model = DemoModel(pairings: store, http: http, ownerKey: FakeOwnerSigning())
            model.baseURLText = "http://relay-a.example:8787"
            model.pairingCodeText = "PAIR-A"
            let attemptA = Task { await model.pair() }
            await http.wait(for: "pair:PAIR-A")

            model.baseURLText = "http://relay-b.example:9999"
            model.pairingCodeText = "PAIR-B"
            let attemptB = Task { await model.pair() }
            await http.wait(for: "pair:PAIR-B")

            if firstResponse == "PAIR-A" {
                await http.succeed("pair:PAIR-A", body: pairingResponse("credential-a"))
                await attemptA.value
                XCTAssertNil(store.load())
                await http.succeed("pair:PAIR-B", body: pairingResponse("credential-b"))
            } else {
                await http.succeed("pair:PAIR-B", body: pairingResponse("credential-b"))
                await attemptB.value
                await http.succeed("pair:PAIR-A", body: pairingResponse("credential-a"))
            }
            await attemptA.value
            await attemptB.value

            let bound = try XCTUnwrap(store.load())
            XCTAssertEqual(bound.endpoint.baseURL.absoluteString, "http://relay-b.example:9999")
            XCTAssertEqual(bound.credential, "credential-b")
            XCTAssertTrue(model.paired)
            XCTAssertNotNil(model.approval)
        }
    }

    func testApplyingLinkWhilePairingInvalidatesTheOldAttempt() async throws {
        let store = InMemoryPairingStore()
        let http = DeferredHTTP()
        let model = DemoModel(pairings: store, http: http, ownerKey: FakeOwnerSigning())
        model.baseURLText = "http://relay-a.example:8787"
        model.pairingCodeText = "PAIR-A"
        let attempt = Task { await model.pair() }
        await http.wait(for: "pair:PAIR-A")

        model.apply(link: PairingLink(
            relayURL: "http://relay-b.example:9999", pairingCode: "PAIR-B"))
        await http.succeed("pair:PAIR-A", body: pairingResponse("credential-a"))
        await attempt.value

        XCTAssertNil(store.load())
        XCTAssertFalse(model.paired)
        XCTAssertEqual(model.baseURLText, "http://relay-b.example:9999")
        XCTAssertEqual(model.pairingCodeText, "PAIR-B")
        XCTAssertNil(model.approval)
    }

    func testDelayedA401CannotClearBAndCurrentB401ClearsOnlyB() async throws {
        let store = InMemoryPairingStore()
        let pairingA = try PersistedPairing(
            endpoint: DemoRelayEndpoint(baseURLText: "http://relay-a.example:8787"),
            credential: "credential-a",
            account: nil)
        try store.save(pairingA)
        let http = DeferredHTTP()
        let model = DemoModel(pairings: store, http: http, ownerKey: FakeOwnerSigning())
        model.operationIdText = "request-a"
        let requestA = Task { await model.openManually() }
        await http.wait(for: "auth:Bearer credential-a:request-a")

        model.unpair()
        model.baseURLText = "http://relay-b.example:9999"
        model.pairingCodeText = "PAIR-B"
        let attemptB = Task { await model.pair() }
        await http.wait(for: "pair:PAIR-B")
        await http.succeed("pair:PAIR-B", body: pairingResponse("credential-b"))
        await attemptB.value
        let pairingB = try XCTUnwrap(store.load())

        await http.succeed("auth:Bearer credential-a:request-a", body: Data("{}".utf8), status: 401)
        await requestA.value
        XCTAssertEqual(store.load(), pairingB)
        XCTAssertTrue(model.paired)

        model.operationIdText = "request-b"
        let requestB = Task { await model.openManually() }
        await http.wait(for: "auth:Bearer credential-b:request-b")
        await http.succeed("auth:Bearer credential-b:request-b", body: Data("{}".utf8), status: 401)
        await requestB.value
        XCTAssertNil(store.load())
        XCTAssertFalse(model.paired)
        XCTAssertTrue(model.statusLine.contains("refused"))
    }

    func testPrior401IsNotReusedAfterStatuslessTransportFailure() async throws {
        let store = InMemoryPairingStore()
        try store.save(PersistedPairing(
            endpoint: DemoRelayEndpoint(baseURLText: "http://relay-a.example:8787"),
            credential: "credential-a",
            account: nil))
        let http = DeferredHTTP()
        let model = DemoModel(pairings: store, http: http, ownerKey: FakeOwnerSigning())
        model.operationIdText = "refused-a"
        let refusedA = Task { await model.openManually() }
        await http.wait(for: "auth:Bearer credential-a:refused-a")
        await http.succeed("auth:Bearer credential-a:refused-a", body: Data(), status: 401)
        await refusedA.value
        XCTAssertNil(store.load())

        model.baseURLText = "http://relay-b.example:9999"
        model.pairingCodeText = "PAIR-B"
        let attemptB = Task { await model.pair() }
        await http.wait(for: "pair:PAIR-B")
        await http.succeed("pair:PAIR-B", body: pairingResponse("credential-b"))
        await attemptB.value
        let pairingB = try XCTUnwrap(store.load())

        model.operationIdText = "failed-b"
        let failedB = Task { await model.openManually() }
        await http.wait(for: "auth:Bearer credential-b:failed-b")
        await http.fail("auth:Bearer credential-b:failed-b")
        await failedB.value
        XCTAssertEqual(store.load(), pairingB)
        XCTAssertTrue(model.paired)
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
