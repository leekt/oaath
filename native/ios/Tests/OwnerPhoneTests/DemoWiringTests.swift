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
    private var pending: [String: [CheckedContinuation<Response, Error>]] = [:]
    private var recorded: [URLRequest] = []

    func send(_ request: URLRequest) async throws -> Response {
        recorded.append(request)
        let key = Self.key(for: request)
        return try await withCheckedThrowingContinuation { continuation in
            pending[key, default: []].append(continuation)
        }
    }

    func wait(for key: String, count: Int = 1) async {
        while (pending[key]?.count ?? 0) < count { await Task.yield() }
    }

    func succeed(_ key: String, body: Data, status: Int = 200, index: Int = 0) {
        guard var continuations = pending[key], continuations.indices.contains(index) else {
            preconditionFailure("missing deferred request key \(key) at index \(index)")
        }
        let continuation = continuations.remove(at: index)
        pending[key] = continuations.isEmpty ? nil : continuations
        continuation.resume(returning: (body, status))
    }

    func fail(_ key: String, index: Int = 0) {
        guard var continuations = pending[key], continuations.indices.contains(index) else {
            preconditionFailure("missing deferred request key \(key) at index \(index)")
        }
        let continuation = continuations.remove(at: index)
        pending[key] = continuations.isEmpty ? nil : continuations
        continuation.resume(throwing: DeferredHTTPError.transport)
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

private func inboxResponse(
    _ items: [(operationId: String, displayPayload: String, expiresAt: Int)]
) throws -> Data {
    try JSONSerialization.data(
        withJSONObject: [
            "requests": items.map {
                [
                    "displayPayload": $0.displayPayload,
                    "expiresAt": $0.expiresAt,
                    "operationId": $0.operationId
                ] as [String: Any]
            },
            "version": demoInboxVersion
        ],
        options: [.sortedKeys])
}

private final class InboxRecordingHTTP: DemoHTTP, @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [URLRequest] = []
    let inboxBody: Data

    init(inboxBody: Data) {
        self.inboxBody = inboxBody
    }

    func send(_ request: URLRequest) async throws -> (Data, Int) {
        lock.withLock { recorded.append(request) }
        if request.url?.path == "/demo/inbox" { return (inboxBody, 200) }
        if request.httpMethod == "GET", request.url?.path.hasPrefix("/native/projections/") == true {
            let operationId = request.url?.lastPathComponent ?? "request"
            return (try JSONSerialization.data(
                withJSONObject: projectionJson(operationId: operationId)), 200)
        }
        return (Data(), 500)
    }

    func requests() -> [URLRequest] {
        lock.withLock { recorded }
    }
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

        let inbox = endpoint.inboxRequest(credential: "cred")
        XCTAssertEqual(inbox.httpMethod, "GET")
        XCTAssertEqual(inbox.url?.absoluteString, "http://192.168.1.20:8787/demo/inbox")
        XCTAssertEqual(inbox.value(forHTTPHeaderField: "Authorization"), "Bearer cred")

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

final class DemoInboxCodecTests: XCTestCase {
    func testDecodesTheExactCanonicalBoundedInbox() throws {
        let data = try inboxResponse([
            ("request-a", "AAAA1111", 1_900_000_000_000),
            ("request-b", "BBBB2222", 1_900_000_000_001)
        ])
        let items = try decodeDemoInbox(data)
        XCTAssertNoThrow(try decodeDemoInbox(
            Data(#"{"requests":[],"version":"oaath.demo-inbox/v1"}"#.utf8)))
        XCTAssertEqual(items.map(\.operationId), ["request-a", "request-b"])
        XCTAssertEqual(items.map(\.matchCode.value), ["AAAA1111", "BBBB2222"])
        XCTAssertEqual(items.map(\.expiresAt), [1_900_000_000_000, 1_900_000_000_001])

        let tied = try inboxResponse([
            ("0", "ZERO0000", 1_900_000_000_002),
            ("A", "UPPER000", 1_900_000_000_002),
            ("_", "UNDER000", 1_900_000_000_002),
            ("a", "LOWER000", 1_900_000_000_002)
        ])
        XCTAssertEqual(try decodeDemoInbox(tied).map(\.operationId), ["0", "A", "_", "a"])
        let localeOrdered = try inboxResponse([
            ("_", "UNDER000", 1_900_000_000_002),
            ("0", "ZERO0000", 1_900_000_000_002),
            ("a", "LOWER000", 1_900_000_000_002),
            ("A", "UPPER000", 1_900_000_000_002)
        ])
        XCTAssertThrowsError(try decodeDemoInbox(localeOrdered))
    }

    func testRejectsUnknownMalformedDuplicateNoncanonicalAndOversizedInput() throws {
        let valid = try inboxResponse([("request-a", "AAAA1111", 1_900_000_000_000)])
        let validText = try XCTUnwrap(String(data: valid, encoding: .utf8))
        let malformed = [
            Data(),
            Data("[]".utf8),
            Data(#"{"extra":true,"requests":[],"version":"oaath.demo-inbox/v1"}"#.utf8),
            Data(validText.replacingOccurrences(of: "AAAA1111", with: "short").utf8),
            Data(validText.replacingOccurrences(of: "request-a", with: "bad/request").utf8),
            Data(validText.replacingOccurrences(of: "1900000000000", with: "true").utf8),
            Data("{\"requests\":[],\"version\":\"oaath.demo-inbox/v1\",\"version\":\"oaath.demo-inbox/v1\"}".utf8),
            Data(repeating: 0x20, count: 8_193)
        ]
        for (index, data) in malformed.enumerated() {
            XCTAssertThrowsError(try decodeDemoInbox(data), "malformed case \(index)") {
                XCTAssertEqual($0 as? DemoInboxError, .invalidResponse)
            }
        }

        let tooMany = try inboxResponse((0...demoInboxLimit).map {
            ("request-\($0)", "CODE\(String(format: "%04d", $0))", 1_900_000_000_000 + $0)
        })
        XCTAssertThrowsError(try decodeDemoInbox(tooMany))

        let unsorted = try inboxResponse([
            ("request-b", "BBBB2222", 1_900_000_000_001),
            ("request-a", "AAAA1111", 1_900_000_000_000)
        ])
        XCTAssertThrowsError(try decodeDemoInbox(unsorted))
    }

    func testFetchBindsEndpointAndCredentialAndReportsOnlyCaptured401() async throws {
        let pairing = try PersistedPairing(
            endpoint: DemoRelayEndpoint(baseURLText: "http://relay.example:8787"),
            credential: "device-credential",
            account: nil)
        let recorder = FakeHTTP.Recorder()
        let items = try await fetchDemoInbox(
            pairing: pairing,
            http: FakeHTTP(
                status: 200,
                body: try inboxResponse([("request-a", "AAAA1111", 1_900_000_000_000)]),
                recorder: recorder))
        XCTAssertEqual(items.map(\.operationId), ["request-a"])
        XCTAssertEqual(recorder.requests.first?.url?.absoluteString, "http://relay.example:8787/demo/inbox")
        XCTAssertEqual(
            recorder.requests.first?.value(forHTTPHeaderField: "Authorization"),
            "Bearer device-credential")

        let unauthorized = PairingCapture()
        do {
            _ = try await fetchDemoInbox(
                pairing: pairing,
                http: FakeHTTP(status: 401, body: Data(), recorder: .init()),
                onUnauthorized: { await unauthorized.record($0) })
            XCTFail("401 must fail closed")
        } catch {
            XCTAssertEqual(error as? DemoInboxError, .status(401))
        }
        let rejectedPairing = await unauthorized.read()
        XCTAssertEqual(rejectedPairing, pairing)
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
    func testInboxRefreshAndSelectionOpenExactProjectionWithoutDeciding() async throws {
        let store = InMemoryPairingStore()
        try store.save(PersistedPairing(
            endpoint: DemoRelayEndpoint(baseURLText: "http://relay.example:8787"),
            credential: "credential-a",
            account: nil))
        let http = InboxRecordingHTTP(inboxBody: try inboxResponse([
            ("request-a", "AAAA1111", 1_900_000_000_000)
        ]))
        let model = DemoModel(pairings: store, http: http, ownerKey: FakeOwnerSigning())

        await model.refreshInbox()
        XCTAssertEqual(model.inbox.map(\.operationId), ["request-a"])
        XCTAssertEqual(model.inboxStatusLine, "Pending requests refreshed.")
        await model.openInboxItem(try XCTUnwrap(model.inbox.first))

        XCTAssertEqual(
            http.requests().map { "\($0.httpMethod ?? "") \($0.url?.path ?? "")" },
            ["GET /demo/inbox", "GET /native/projections/request-a"])
        XCTAssertFalse(http.requests().contains {
            $0.httpMethod == "POST" && $0.url?.path.hasPrefix("/native/decisions/") == true
        })
        guard case let .review(review) = model.approval?.phase else {
            return XCTFail("selection did not open the existing approval model")
        }
        XCTAssertEqual(review.projection.operationId, "request-a")
        XCTAssertEqual(review.state, .pending)
    }

    func testStaleInboxRefreshCannotOverwriteAReplacementPairingOrList() async throws {
        let store = InMemoryPairingStore()
        try store.save(PersistedPairing(
            endpoint: DemoRelayEndpoint(baseURLText: "http://relay-a.example:8787"),
            credential: "credential-a",
            account: nil))
        let http = DeferredHTTP()
        let model = DemoModel(pairings: store, http: http, ownerKey: FakeOwnerSigning())
        let refreshA = Task { await model.refreshInbox() }
        await http.wait(for: "auth:Bearer credential-a:inbox")

        model.unpair()
        model.baseURLText = "http://relay-b.example:9999"
        model.pairingCodeText = "PAIR-B"
        let pairB = Task { await model.pair() }
        await http.wait(for: "pair:PAIR-B")
        await http.succeed("pair:PAIR-B", body: pairingResponse("credential-b"))
        await pairB.value

        let refreshB = Task { await model.refreshInbox() }
        await http.wait(for: "auth:Bearer credential-b:inbox")
        await http.succeed(
            "auth:Bearer credential-b:inbox",
            body: try inboxResponse([("request-b", "BBBB2222", 1_900_000_000_001)]))
        await refreshB.value
        await http.succeed(
            "auth:Bearer credential-a:inbox",
            body: try inboxResponse([("request-a", "AAAA1111", 1_900_000_000_000)]))
        await refreshA.value

        XCTAssertEqual(store.load()?.credential, "credential-b")
        XCTAssertEqual(model.inbox.map(\.operationId), ["request-b"])

        // A 401 from the current inbox request compare-clears only B.
        let refusedB = Task { await model.refreshInbox() }
        await http.wait(for: "auth:Bearer credential-b:inbox")
        await http.succeed("auth:Bearer credential-b:inbox", body: Data(), status: 401)
        await refusedB.value
        XCTAssertNil(store.load())
        XCTAssertFalse(model.paired)
        XCTAssertTrue(model.inbox.isEmpty)
    }

    func testStaleAndCancelledInbox401CannotClearTheCurrentPairing() async throws {
        let store = InMemoryPairingStore()
        let pairing = try PersistedPairing(
            endpoint: DemoRelayEndpoint(baseURLText: "http://relay.example:8787"),
            credential: "credential-a",
            account: nil)
        try store.save(pairing)
        let http = DeferredHTTP()
        let model = DemoModel(pairings: store, http: http, ownerKey: FakeOwnerSigning())
        let key = "auth:Bearer credential-a:inbox"

        let stale = Task { await model.refreshInbox() }
        await http.wait(for: key)
        let current = Task { await model.refreshInbox() }
        await http.wait(for: key, count: 2)
        await http.succeed(
            key,
            body: try inboxResponse([("request-current", "CURR0000", 1_900_000_000_001)]),
            index: 1)
        await current.value
        await http.succeed(key, body: Data(), status: 401)
        await stale.value

        XCTAssertEqual(store.load(), pairing)
        XCTAssertTrue(model.paired)
        XCTAssertEqual(model.inbox.map(\.operationId), ["request-current"])

        let cancelled = Task { await model.refreshInbox() }
        await http.wait(for: key)
        cancelled.cancel()
        await http.succeed(key, body: Data(), status: 401)
        await cancelled.value
        XCTAssertEqual(store.load(), pairing)
        XCTAssertTrue(model.paired)

        let refusedCurrent = Task { await model.refreshInbox() }
        await http.wait(for: key)
        await http.succeed(key, body: Data(), status: 401)
        await refusedCurrent.value
        XCTAssertNil(store.load())
        XCTAssertFalse(model.paired)
        XCTAssertTrue(model.inbox.isEmpty)
    }

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
