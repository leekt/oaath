/**
 EXPERIMENTAL PREVIEW — pure demo-wiring tests: route construction, pairing
 decode, credential custody, and code delivery. No network is contacted; the
 byte mover is faked.

 @author taek <leekt216@gmail.com>
 */
import Security
import XCTest
@testable import OwnerPhone
@testable import OwnerPhoneDemo

private let fakeOwnerPublicMaterialText =
    "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    + "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
private let fakeOwnerPublicMaterial = OwnerPublicMaterial(fakeOwnerPublicMaterialText)!
private let alternateOwnerPublicMaterialText =
    "0x7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
    + "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"
private let pairingCodeAInput = "AAAA-BBBB-CC"
private let pairingCodeACanonical = "AAAABBBBCC"
private let pairingCodeBInput = "DDDD-EEEE-FF"
private let pairingCodeBCanonical = "DDDDEEEEFF"
private let validDeviceToken = String(repeating: "ab", count: 32)
private let updatedDeviceToken = String(repeating: "cd", count: 32)
/// Canonical unpadded base64url encodings of 32-byte values. The final `A`
/// keeps the unused padding bits zero.
private let deviceCredentialA = String(repeating: "A", count: 43)
private let deviceCredentialB = String(repeating: "B", count: 42) + "A"
private let deviceCredentialC = String(repeating: "C", count: 42) + "A"
private let deviceCredentialD = String(repeating: "D", count: 42) + "A"

private extension PairingLoadResult {
    var storedPairingForTest: PersistedPairing? {
        guard case let .stored(pairing) = self else { return nil }
        return pairing
    }
}

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
    let publicMaterial: String

    init(publicMaterial: String = fakeOwnerPublicMaterial.hex) {
        self.publicMaterial = publicMaterial
    }

    func publicMaterialHex() throws -> String { publicMaterial }
    func signDigestHex(_ digestHex: String) throws -> String {
        "0x" + String(repeating: "22", count: 64)
    }
}

private enum VerifiableOwnerSigningError: Error {
    case keyCreationFailed
    case publicKeyUnavailable
    case signatureFailed
}

/// Real ephemeral P-256 signer for proving the injected-signer verification
/// boundary. It signs the already-computed digest, matching Secure Enclave
/// semantics, but has no keychain or device dependency.
private final class VerifiableOwnerSigning: DemoOwnerSigning, @unchecked Sendable {
    let secureEnclave = false
    private let privateKey: SecKey

    init() throws {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw VerifiableOwnerSigningError.keyCreationFailed
        }
        self.privateKey = privateKey
    }

    func publicMaterialHex() throws -> String {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw VerifiableOwnerSigningError.publicKeyUnavailable
        }
        var error: Unmanaged<CFError>?
        guard let external = SecKeyCopyExternalRepresentation(publicKey, &error) as Data?,
              external.count == 65,
              external.first == 0x04
        else { throw VerifiableOwnerSigningError.publicKeyUnavailable }
        return hexEncode(Data(external.dropFirst()))
    }

    func signDigestHex(_ digestHex: String) throws -> String {
        let digest = try decodeDigestHex(digestHex)
        var error: Unmanaged<CFError>?
        guard let der = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureDigestX962SHA256,
            digest as CFData,
            &error) as Data?
        else { throw VerifiableOwnerSigningError.signatureFailed }
        return hexEncode(try p256LowSNormalized(raw: try p256RawSignature(der: der)))
    }
}

private enum MutableOwnerSigningError: Error {
    case unavailable
}

private final class MutableOwnerSigning: DemoOwnerSigning, @unchecked Sendable {
    let secureEnclave = false
    private let lock = NSLock()
    private var available = true

    func setAvailable(_ value: Bool) {
        lock.lock()
        available = value
        lock.unlock()
    }

    func publicMaterialHex() throws -> String {
        lock.lock()
        defer { lock.unlock() }
        guard available else { throw MutableOwnerSigningError.unavailable }
        return fakeOwnerPublicMaterial.hex
    }

    func signDigestHex(_ digestHex: String) throws -> String {
        lock.lock()
        defer { lock.unlock() }
        guard available else { throw MutableOwnerSigningError.unavailable }
        return "0x" + String(repeating: "22", count: 64)
    }
}

private final class StoreMutatingOwnerSigning: DemoOwnerSigning, @unchecked Sendable {
    let secureEnclave = false
    private let lock = NSLock()
    private var didMutate = false
    private let mutate: @Sendable () -> Void

    init(mutate: @escaping @Sendable () -> Void) {
        self.mutate = mutate
    }

    func publicMaterialHex() throws -> String {
        lock.lock()
        let shouldMutate = !didMutate
        didMutate = true
        lock.unlock()
        if shouldMutate { mutate() }
        return fakeOwnerPublicMaterial.hex
    }

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

    init(pairingStatus: Int = 200, credential: String = deviceCredentialA) {
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

private final class SignatureRecordingHTTP: DemoHTTP, @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [URLRequest] = []

    func send(_ request: URLRequest) async throws -> (Data, Int) {
        lock.withLock { recorded.append(request) }
        guard request.httpMethod == "GET" else { return (Data(), 500) }
        let operationId = request.url?.lastPathComponent ?? "signature-request"
        let digest = "0x" + String(repeating: "4b", count: 32)
        return (try JSONSerialization.data(withJSONObject: [
            "version": "oaath.native-projection/v1",
            "operationId": operationId,
            "displayPayload": "Ab1-_9Zz",
            "expiresAt": 2_000_000_000_000,
            "client": [
                "clientId": "demo-web-app",
                "redirectUri": "https://app.example/callback"
            ],
            "scope": [
                "kind": "signature-request",
                "decision": "approve-or-reject",
                "digest": digest,
                "display": #"{"digest":"\#(digest)","kind":"user-operation"}"#
            ]
        ]), 200)
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
        XCTAssertEqual(
            try DemoRelayEndpoint(baseURLText: "HTTP://RELAY.EXAMPLE:80/").baseURL.absoluteString,
            "http://relay.example")
        XCTAssertEqual(
            try DemoRelayEndpoint(baseURLText: "https://relay.example:443").baseURL.absoluteString,
            "https://relay.example")

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
            pairingCode: PairingCode(pairingCodeAInput)!,
            deviceToken: PairingDeviceToken(String(repeating: "AB", count: 32))!,
            publicKey: fakeOwnerPublicMaterial)
        XCTAssertEqual(pairing.url?.absoluteString, "http://192.168.1.20:8787/native/pairings")
        // The pairing code IS the authentication for this one call: no bearer.
        XCTAssertNil(pairing.value(forHTTPHeaderField: "Authorization"))
        XCTAssertEqual(
            pairing.httpBody.flatMap { String(data: $0, encoding: .utf8) },
            #"{"deviceToken":"\#(validDeviceToken)","pairingCode":"AAAABBBBCC","publicKey":"\#(fakeOwnerPublicMaterial.hex)"}"#)
    }

    func testRejectsANonHttpBaseURL() {
        for bad in [
            "", "ftp://relay", "relay", "http://",
            "http://relay/a/..", "http://relay/a/%2e%2e",
            "http://" + String(repeating: "a", count: 506)
        ] {
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
                credential: deviceCredentialA,
                account: nil,
                ownerPublicMaterial: fakeOwnerPublicMaterial),
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
            credential: deviceCredentialC,
            account: nil,
            ownerPublicMaterial: fakeOwnerPublicMaterial)
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
            credential: deviceCredentialA,
            account: nil,
            ownerPublicMaterial: fakeOwnerPublicMaterial)
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
            "Bearer \(deviceCredentialA)")

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
            pairingCode: PairingCode(pairingCodeAInput)!,
            deviceToken: String(repeating: "ab", count: 32),
            publicKey: fakeOwnerPublicMaterial,
            pairingAttempts: InMemoryPairingAttemptStore(),
            http: FakeHTTP(
                status: 200,
                body: Data(
                    #"{"deviceCredential":"\#(deviceCredentialA)","account":"\#(account)"}"#.utf8),
                recorder: recorder))
        XCTAssertEqual(device.deviceCredential, deviceCredentialA)
        XCTAssertEqual(device.account, account)
        XCTAssertEqual(recorder.requests.count, 1)

        // A chainless web half derives no account; the phone shows that honestly.
        let chainless = try await pair(
            endpoint: try DemoRelayEndpoint(baseURLText: "http://127.0.0.1:8787"),
            pairingCode: PairingCode(pairingCodeAInput)!,
            deviceToken: validDeviceToken,
            publicKey: fakeOwnerPublicMaterial,
            pairingAttempts: InMemoryPairingAttemptStore(),
            http: FakeHTTP(
                status: 200,
                body: pairingResponse(deviceCredentialA),
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
            (200, #"{"deviceCredential":"\#(deviceCredentialA)","deviceCredential":"\#(deviceCredentialB)","account":null}"#),
            (200, #" {"deviceCredential":"\#(deviceCredentialA)","account":null}"#),
            (200, #"{"account":null,"deviceCredential":"\#(deviceCredentialA)"}"#),
            (200, #"[]"#)
        ] {
            do {
                _ = try await pair(
                    endpoint: try DemoRelayEndpoint(baseURLText: "http://127.0.0.1:8787"),
                    pairingCode: PairingCode(pairingCodeAInput)!,
                    deviceToken: validDeviceToken,
                    publicKey: fakeOwnerPublicMaterial,
                    pairingAttempts: InMemoryPairingAttemptStore(),
                    http: FakeHTTP(status: status, body: Data(body.utf8), recorder: .init()))
                XCTFail("pairing must fail closed for status \(status) body \(body)")
            } catch {
                XCTAssertTrue(error is DemoPairingError)
            }
        }
        XCTAssertThrowsError(try decodePairingResponse(Data(repeating: 0x20, count: 257))) {
            XCTAssertEqual($0 as? DemoPairingError, .invalidResponse)
        }
    }

    func testMalformedDeviceTokenCannotRetireAValidPairingCode() async throws {
        let attempts = InMemoryPairingAttemptStore()
        let recorder = FakeHTTP.Recorder()
        let endpoint = try DemoRelayEndpoint(baseURLText: "http://relay.example:8787")
        let code = try XCTUnwrap(PairingCode(pairingCodeAInput))
        let http = FakeHTTP(
            status: 200,
            body: pairingResponse(deviceCredentialA),
            recorder: recorder)

        do {
            _ = try await pair(
                endpoint: endpoint,
                pairingCode: code,
                deviceToken: "ab",
                publicKey: fakeOwnerPublicMaterial,
                pairingAttempts: attempts,
                http: http)
            XCTFail("a malformed token must fail before the durable claim")
        } catch {
            XCTAssertEqual(error as? DemoPairingError, .invalidDeviceToken)
        }
        XCTAssertTrue(recorder.requests.isEmpty)

        _ = try await pair(
            endpoint: endpoint,
            pairingCode: code,
            deviceToken: validDeviceToken.uppercased(),
            publicKey: fakeOwnerPublicMaterial,
            pairingAttempts: attempts,
            http: http)
        XCTAssertEqual(recorder.requests.count, 1)
        let body = try XCTUnwrap(recorder.requests.first?.httpBody)
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: body) as? [String: String])
        XCTAssertEqual(object["deviceToken"], validDeviceToken)
    }

    func testDeviceTokenAndCredentialShapesAreExactASCII() throws {
        XCTAssertEqual(
            PairingDeviceToken(validDeviceToken.uppercased())?.value,
            validDeviceToken)
        for invalidToken in [
            "",
            String(repeating: "a", count: 63),
            String(repeating: "a", count: 201),
            String(repeating: "g", count: 64),
            String(repeating: "é", count: 64)
        ] {
            XCTAssertNil(PairingDeviceToken(invalidToken), invalidToken)
        }

        let endpoint = try DemoRelayEndpoint(baseURLText: "http://relay.example:8787")
        for invalidCredential in [
            "",
            String(repeating: "A", count: 42),
            String(repeating: "A", count: 44),
            String(repeating: "A", count: 42) + "=",
            String(repeating: "A", count: 42) + "\n",
            String(repeating: "B", count: 43),
            String(repeating: "é", count: 43)
        ] {
            XCTAssertThrowsError(try PersistedPairing(
                endpoint: endpoint,
                credential: invalidCredential,
                account: nil,
                ownerPublicMaterial: fakeOwnerPublicMaterial))
            XCTAssertThrowsError(try decodePairingResponse(Data(
                #"{"deviceCredential":"\#(invalidCredential)","account":null}"#.utf8)))
        }
    }

    func testTheByteMovingPairEntryRetiresBeforeSending() async throws {
        let recorder = FakeHTTP.Recorder()
        let attempts = InMemoryPairingAttemptStore()
        let endpoint = try DemoRelayEndpoint(baseURLText: "http://relay.example:80")
        let code = try XCTUnwrap(PairingCode(pairingCodeAInput))
        let http = FakeHTTP(
            status: 200,
            body: pairingResponse(deviceCredentialA),
            recorder: recorder)

        _ = try await pair(
            endpoint: endpoint,
            pairingCode: code,
            deviceToken: validDeviceToken,
            publicKey: fakeOwnerPublicMaterial,
            pairingAttempts: attempts,
            http: http)
        do {
            _ = try await pair(
                endpoint: try DemoRelayEndpoint(baseURLText: "https://other.example/base"),
                pairingCode: code,
                deviceToken: validDeviceToken,
                publicKey: fakeOwnerPublicMaterial,
                pairingAttempts: attempts,
                http: http)
            XCTFail("retired pairing code must fail before transport")
        } catch {
            XCTAssertEqual(error as? PairingAttemptStoreError, .alreadyAttempted)
        }
        XCTAssertEqual(recorder.requests.count, 1)
    }

    func testPairingStoreRoundTripsOneExactVersionedValue() throws {
        let store = InMemoryPairingStore()
        let pairing = try PersistedPairing(
            endpoint: DemoRelayEndpoint(baseURLText: "HTTP://RELAY.EXAMPLE:8787/"),
            credential: deviceCredentialA,
            account: nil,
            ownerPublicMaterial: fakeOwnerPublicMaterial)
        XCTAssertEqual(store.load(), .absent)
        XCTAssertTrue(try store.installIfAbsent(pairing))
        XCTAssertEqual(store.load(), .stored(pairing))
        XCTAssertEqual(pairing.endpoint.baseURL.absoluteString, "http://relay.example:8787")
        XCTAssertEqual(try PersistedPairing.decode(pairing.encoded()), pairing)
        XCTAssertTrue(store.clear())
        XCTAssertEqual(store.load(), .absent)
    }

    func testPairingRecordRejectsOldCredentialOnlyAndShapeDrift() throws {
        XCTAssertThrowsError(try PersistedPairing.decode(Data("issued-token".utf8)))
        let pairing = try PersistedPairing(
            endpoint: DemoRelayEndpoint(baseURLText: "http://relay-a:8787"),
            credential: deviceCredentialA,
            account: nil,
            ownerPublicMaterial: fakeOwnerPublicMaterial)
        let valid = try XCTUnwrap(
            JSONSerialization.jsonObject(with: pairing.encoded()) as? [String: Any])
        for changed in [
            valid.merging(["extra": true]) { _, right in right },
            valid.merging(["version": 1]) { _, right in right },
            valid.merging(["ownerPublicMaterial": "0x00"]) { _, right in right },
            valid.merging(["endpoint": "http://RELAY-A:8787/"]) { _, right in right }
        ] {
            let data = try JSONSerialization.data(withJSONObject: changed)
            XCTAssertThrowsError(try PersistedPairing.decode(data))
        }

        let canonical = try pairing.encoded()
        let canonicalText = try XCTUnwrap(String(data: canonical, encoding: .utf8))
        let credentialField = #""credential":"\#(deviceCredentialA)""#
        let duplicateCredential = canonicalText.replacingOccurrences(
            of: credentialField,
            with: credentialField + ",\"credential\":\"\(deviceCredentialB)\"")
        XCTAssertNotEqual(duplicateCredential, canonicalText)
        for malformed in [
            Data((" " + canonicalText).utf8),
            Data(duplicateCredential.utf8),
            Data(repeating: 0x20, count: 2_049)
        ] {
            XCTAssertThrowsError(try PersistedPairing.decode(malformed)) {
                XCTAssertEqual($0 as? PairingStoreError, .invalidRecord)
            }
        }
    }

    func testPairingCodeCanonicalizesExactlyLikeTheRelay() {
        XCTAssertEqual(PairingCode(" abcd-efgh-jk \n")?.value, "ABCDEFGHJK")
        for invalid in ["AB-CD", "ABCDEFGHIJ", "ABCDEFGH1K", "ABCDEFGHJKM"] {
            XCTAssertNil(PairingCode(invalid), invalid)
        }
    }

    func testOwnerPublicMaterialRequiresARealP256Point() {
        XCTAssertEqual(OwnerPublicMaterial(fakeOwnerPublicMaterial.hex), fakeOwnerPublicMaterial)
        XCTAssertNil(OwnerPublicMaterial("0x" + String(repeating: "11", count: 64)))
        XCTAssertNil(OwnerPublicMaterial(fakeOwnerPublicMaterial.hex.uppercased()))
        XCTAssertNil(OwnerPublicMaterial("0x00"))
    }

    func testPairingStoreInstallIsAtomicAndPreservesContradictoryEvidence() throws {
        let pairingA = try PersistedPairing(
            endpoint: DemoRelayEndpoint(baseURLText: "http://relay-a.example:8787"),
            credential: deviceCredentialA,
            account: nil,
            ownerPublicMaterial: fakeOwnerPublicMaterial)
        let pairingB = try PersistedPairing(
            endpoint: DemoRelayEndpoint(baseURLText: "http://relay-b.example:8787"),
            credential: deviceCredentialB,
            account: nil,
            ownerPublicMaterial: fakeOwnerPublicMaterial)

        let occupied = InMemoryPairingStore(result: .stored(pairingA))
        XCTAssertFalse(try occupied.installIfAbsent(pairingB))
        XCTAssertEqual(occupied.load(), .stored(pairingA))

        let unreadable = InMemoryPairingStore(result: .unreadable)
        XCTAssertFalse(try unreadable.installIfAbsent(pairingB))
        XCTAssertEqual(unreadable.load(), .unreadable)
    }

    func testPairingAttemptLedgerRoundTripsOnlyCanonicalHashedEvidence() throws {
        let codeA = try XCTUnwrap(PairingCode(pairingCodeAInput))
        let codeB = try XCTUnwrap(PairingCode(pairingCodeBInput))
        let attemptA = PairingAttemptIdentity(code: codeA)
        let attemptB = PairingAttemptIdentity(code: codeB)
        let store = InMemoryPairingAttemptStore()

        XCTAssertTrue(try store.claimIfNew(attemptB))
        XCTAssertTrue(try store.claimIfNew(attemptA))
        XCTAssertFalse(try store.claimIfNew(attemptA))
        let bytes = try store.persistedData()
        let text = try XCTUnwrap(String(data: bytes, encoding: .utf8))
        XCTAssertFalse(text.contains(pairingCodeACanonical))
        XCTAssertFalse(text.contains(pairingCodeBCanonical))

        let reloaded = try InMemoryPairingAttemptStore(persistedData: bytes)
        XCTAssertFalse(try reloaded.claimIfNew(attemptA))
        XCTAssertFalse(try reloaded.claimIfNew(attemptB))

        let hashText = attemptA.codeHash.base64EncodedString()
        for malformed in [
            Data("{}".utf8),
            Data(#"{"attempts":[],"version":2}"#.utf8),
            Data(#"{"attempts":[{"codeHash":"AA=="}],"version":1}"#.utf8),
            Data(#"{"attempts":[],"attempts":[],"version":1}"#.utf8),
            Data(
                #"{"attempts":[{"codeHash":"\#(hashText)","codeHash":"\#(hashText)"}],"version":1}"#.utf8),
            Data((" " + text).utf8),
            Data(repeating: 0x20, count: 8_193)
        ] {
            XCTAssertThrowsError(try InMemoryPairingAttemptStore(persistedData: malformed)) {
                XCTAssertEqual($0 as? PairingAttemptStoreError, .unreadable)
            }
        }
    }

    func testPairingAttemptLedgerCapacityFailsClosedWithoutEviction() throws {
        let alphabet = Array("ABCDEFGHJKMNPQRSTUVWXYZ23456789")
        func attempt(_ index: Int) -> PairingAttemptIdentity {
            let text = "AAAAAAAA"
                + String(alphabet[index / alphabet.count])
                + String(alphabet[index % alphabet.count])
            return PairingAttemptIdentity(code: PairingCode(text)!)
        }
        let store = InMemoryPairingAttemptStore()
        for index in 0..<64 {
            XCTAssertTrue(try store.claimIfNew(attempt(index)))
        }
        XCTAssertFalse(try store.claimIfNew(attempt(0)))
        XCTAssertThrowsError(try store.claimIfNew(attempt(64))) {
            XCTAssertEqual($0 as? PairingAttemptStoreError, .capacityReached)
        }
    }
}

@MainActor
final class DemoPairingIdentityTests: XCTestCase {
    func testDeviceTokenUpdatesCaptureOnlyTheExactNormalizedShape() {
        let model = DemoModel(pairings: InMemoryPairingStore(), ownerKey: FakeOwnerSigning())
        let original = model.deviceToken
        XCTAssertFalse(model.updateDeviceToken("not-an-apns-token"))
        XCTAssertEqual(model.deviceToken, original)
        XCTAssertTrue(model.updateDeviceToken(updatedDeviceToken.uppercased()))
        XCTAssertEqual(model.deviceToken, updatedDeviceToken)
    }

    func testReloadRequiresTheExactPersistedOwnerKeyAcrossInstances() throws {
        let pairing = try PersistedPairing(
            endpoint: DemoRelayEndpoint(baseURLText: "http://relay.example:8787"),
            credential: deviceCredentialA,
            account: nil,
            ownerPublicMaterial: fakeOwnerPublicMaterial)
        let store = InMemoryPairingStore(result: .stored(pairing))

        let accepted = DemoModel(pairings: store, ownerKey: FakeOwnerSigning())
        XCTAssertTrue(accepted.paired)
        XCTAssertNotNil(accepted.approval)

        let changedMaterial = alternateOwnerPublicMaterialText
        let restarted = DemoModel(
            pairings: store,
            ownerKey: FakeOwnerSigning(publicMaterial: changedMaterial))
        XCTAssertFalse(restarted.paired)
        XCTAssertNil(restarted.approval)
        XCTAssertTrue(restarted.storedPairingBlocked)
        XCTAssertEqual(store.load(), .stored(pairing))

        let missing = DemoModel(pairings: store, ownerKey: nil)
        XCTAssertFalse(missing.paired)
        XCTAssertNil(missing.approval)
        XCTAssertTrue(missing.storedPairingBlocked)
        XCTAssertEqual(store.load(), .stored(pairing))
    }

    func testUnreadablePairingNeverAuthorizesReplacement() async {
        let store = InMemoryPairingStore(result: .unreadable)
        let recorder = FakeHTTP.Recorder()
        let model = DemoModel(
            pairings: store,
            http: FakeHTTP(status: 200, body: Data(), recorder: recorder),
            ownerKey: FakeOwnerSigning())

        XCTAssertFalse(model.paired)
        XCTAssertNil(model.approval)
        XCTAssertTrue(model.storedPairingBlocked)
        model.baseURLText = "http://relay.example:8787"
        model.pairingCodeText = pairingCodeAInput
        await model.pair()
        XCTAssertEqual(store.load(), .unreadable)
        XCTAssertTrue(recorder.requests.isEmpty)
    }

    func testInvalidOrOffCurveOwnerMaterialSpendsNoPairingCode() async {
        let store = InMemoryPairingStore()
        let recorder = FakeHTTP.Recorder()
        let model = DemoModel(
            pairings: store,
            http: FakeHTTP(
                status: 200,
                body: pairingResponse(deviceCredentialC),
                recorder: recorder),
            ownerKey: FakeOwnerSigning(
                publicMaterial: "0x" + String(repeating: "11", count: 64)))
        model.baseURLText = "http://relay.example:8787"
        model.pairingCodeText = pairingCodeAInput

        await model.pair()

        XCTAssertTrue(recorder.requests.isEmpty)
        XCTAssertEqual(store.load(), .absent)
        XCTAssertFalse(model.paired)
        XCTAssertTrue(model.statusLine.contains("public material"))
    }

    func testKnownOccupiedStoreBlocksBeforeThePairingEffect() async throws {
        let store = InMemoryPairingStore()
        let recorder = FakeHTTP.Recorder()
        let model = DemoModel(
            pairings: store,
            http: FakeHTTP(
                status: 200,
                body: pairingResponse(deviceCredentialC),
                recorder: recorder),
            ownerKey: FakeOwnerSigning())
        let intervening = try PersistedPairing(
            endpoint: DemoRelayEndpoint(baseURLText: "http://other.example:8787"),
            credential: deviceCredentialD,
            account: nil,
            ownerPublicMaterial: fakeOwnerPublicMaterial)
        XCTAssertTrue(try store.installIfAbsent(intervening))
        model.baseURLText = "http://relay.example:8787"
        model.pairingCodeText = pairingCodeAInput

        await model.pair()

        XCTAssertTrue(recorder.requests.isEmpty)
        XCTAssertEqual(store.load(), .stored(intervening))
        XCTAssertTrue(model.storedPairingBlocked)
    }

    func testInterveningPairingCannotBeOverwrittenAfterTheRequest() async throws {
        let store = InMemoryPairingStore()
        let http = DeferredHTTP()
        let model = DemoModel(pairings: store, http: http, ownerKey: FakeOwnerSigning())
        model.baseURLText = "http://relay.example:8787"
        model.pairingCodeText = pairingCodeAInput
        let attempt = Task { await model.pair() }
        await http.wait(for: "pair:\(pairingCodeACanonical)")

        let intervening = try PersistedPairing(
            endpoint: DemoRelayEndpoint(baseURLText: "http://other.example:8787"),
            credential: deviceCredentialD,
            account: nil,
            ownerPublicMaterial: fakeOwnerPublicMaterial)
        XCTAssertTrue(try store.installIfAbsent(intervening))
        await http.succeed(
            "pair:\(pairingCodeACanonical)", body: pairingResponse(deviceCredentialC))
        await attempt.value

        XCTAssertEqual(store.load(), .stored(intervening))
        XCTAssertFalse(model.paired)
        XCTAssertTrue(model.storedPairingBlocked)
    }

    func testSameOneShotCodeHasOnlyOneRequestDespiteTokenChanges() async {
        let store = InMemoryPairingStore()
        let http = DeferredHTTP()
        let model = DemoModel(pairings: store, http: http, ownerKey: FakeOwnerSigning())
        model.baseURLText = "http://relay.example:8787"
        model.pairingCodeText = "aaaa bbbb cc"
        let first = Task { await model.pair() }
        await http.wait(for: "pair:\(pairingCodeACanonical)")

        XCTAssertTrue(model.updateDeviceToken(updatedDeviceToken.uppercased()))
        XCTAssertEqual(model.deviceToken, updatedDeviceToken)
        await model.pair()
        let requestsAfterSecondTap = await http.requests()
        XCTAssertEqual(requestsAfterSecondTap.count, 1)

        await http.succeed(
            "pair:\(pairingCodeACanonical)", body: pairingResponse(deviceCredentialA))
        await first.value
        XCTAssertTrue(model.paired)
        XCTAssertEqual(store.load().storedPairingForTest?.credential, deviceCredentialA)
    }

    func testStaleCompletionRetiresEveryFormattingVariantOfTheCode() async {
        let store = InMemoryPairingStore()
        let http = DeferredHTTP()
        let model = DemoModel(pairings: store, http: http, ownerKey: FakeOwnerSigning())
        model.baseURLText = "http://relay.example:8787"
        model.pairingCodeText = pairingCodeAInput
        let first = Task { await model.pair() }
        await http.wait(for: "pair:\(pairingCodeACanonical)")

        // Editing invalidates A's UI completion owner but cannot undo its HTTP
        // effect or authorize a canonical-equivalent second request.
        model.pairingCodeText = "aaaa bbbb cc"
        await model.pair()
        let requestsWhileFirstIsPending = await http.requests()
        XCTAssertEqual(requestsWhileFirstIsPending.count, 1)
        await http.succeed(
            "pair:\(pairingCodeACanonical)", body: pairingResponse(deviceCredentialA))
        await first.value
        XCTAssertFalse(model.paired)
        XCTAssertEqual(store.load(), .absent)

        await model.pair()
        let requestsAfterStaleCompletion = await http.requests()
        XCTAssertEqual(requestsAfterStaleCompletion.count, 1)
        XCTAssertTrue(model.statusLine.contains("already attempted"))
    }

    func testFailedClearPreservesPairedAndBlockedStateForRetry() throws {
        let pairing = try PersistedPairing(
            endpoint: DemoRelayEndpoint(baseURLText: "http://relay.example:8787"),
            credential: deviceCredentialA,
            account: nil,
            ownerPublicMaterial: fakeOwnerPublicMaterial)
        let pairedStore = InMemoryPairingStore(
            result: .stored(pairing), mutationsSucceed: false)
        let pairedModel = DemoModel(pairings: pairedStore, ownerKey: FakeOwnerSigning())
        XCTAssertTrue(pairedModel.paired)

        pairedModel.unpair()

        XCTAssertTrue(pairedModel.paired)
        XCTAssertEqual(pairedStore.load(), .stored(pairing))
        XCTAssertTrue(pairedModel.statusLine.contains("could not be cleared"))

        let blockedStore = InMemoryPairingStore(
            result: .unreadable, mutationsSucceed: false)
        let blockedModel = DemoModel(pairings: blockedStore, ownerKey: FakeOwnerSigning())
        blockedModel.unpair()
        XCTAssertTrue(blockedModel.storedPairingBlocked)
        XCTAssertEqual(blockedStore.load(), .unreadable)
    }

    func testRebuildRejectsAStoreChangedByTheInjectedSigner() throws {
        let pairingA = try PersistedPairing(
            endpoint: DemoRelayEndpoint(baseURLText: "http://relay-a.example:8787"),
            credential: deviceCredentialA,
            account: nil,
            ownerPublicMaterial: fakeOwnerPublicMaterial)
        let pairingB = try PersistedPairing(
            endpoint: DemoRelayEndpoint(baseURLText: "http://relay-b.example:8787"),
            credential: deviceCredentialB,
            account: nil,
            ownerPublicMaterial: fakeOwnerPublicMaterial)
        let store = InMemoryPairingStore(result: .stored(pairingA))
        let signer = StoreMutatingOwnerSigning {
            _ = store.clear()
            _ = try? store.installIfAbsent(pairingB)
        }

        let model = DemoModel(pairings: store, ownerKey: signer)

        XCTAssertFalse(model.paired)
        XCTAssertNil(model.approval)
        XCTAssertTrue(model.storedPairingBlocked)
        XCTAssertEqual(store.load(), .stored(pairingB))
    }

    func testUnavailableBoundKeyCannotFallThroughToAPlaceholderSignature() async throws {
        let pairing = try PersistedPairing(
            endpoint: DemoRelayEndpoint(baseURLText: "http://relay.example:8787"),
            credential: deviceCredentialA,
            account: nil,
            ownerPublicMaterial: fakeOwnerPublicMaterial)
        let store = InMemoryPairingStore(result: .stored(pairing))
        let signer = MutableOwnerSigning()
        let http = SignatureRecordingHTTP()
        let model = DemoModel(pairings: store, http: http, ownerKey: signer)
        model.operationIdText = "signature-request"
        await model.openManually()
        let approval = try XCTUnwrap(model.approval)
        guard case .review = approval.phase else {
            return XCTFail("signature projection did not open")
        }

        signer.setAvailable(false)
        await approval.approve()

        XCTAssertEqual(
            http.requests().map { $0.httpMethod ?? "" },
            ["GET"],
            "key loss must fail before any decision submission")
        guard case let .review(review) = approval.phase else {
            return XCTFail("failed signing must leave the review pending")
        }
        XCTAssertEqual(review.state, .pending)
    }

    func testInvalidSignatureFromTheBoundSignerNeverReachesSubmission() async throws {
        let pairing = try PersistedPairing(
            endpoint: DemoRelayEndpoint(baseURLText: "http://relay.example:8787"),
            credential: deviceCredentialA,
            account: nil,
            ownerPublicMaterial: fakeOwnerPublicMaterial)
        let http = SignatureRecordingHTTP()
        let model = DemoModel(
            pairings: InMemoryPairingStore(result: .stored(pairing)),
            http: http,
            ownerKey: FakeOwnerSigning())
        model.operationIdText = "signature-request"
        await model.openManually()
        let approval = try XCTUnwrap(model.approval)

        await approval.approve()

        XCTAssertEqual(
            http.requests().map { $0.httpMethod ?? "" },
            ["GET"],
            "a signature that does not verify under the persisted key must not be submitted")
        guard case let .review(review) = approval.phase else {
            return XCTFail("invalid signing output must leave the review pending")
        }
        XCTAssertEqual(review.state, .pending)
    }

    func testValidSignatureFromTheExactBoundKeyReachesSubmission() async throws {
        let signer = try VerifiableOwnerSigning()
        let publicMaterial = try XCTUnwrap(OwnerPublicMaterial(signer.publicMaterialHex()))
        let pairing = try PersistedPairing(
            endpoint: DemoRelayEndpoint(baseURLText: "http://relay.example:8787"),
            credential: deviceCredentialA,
            account: nil,
            ownerPublicMaterial: publicMaterial)
        let http = SignatureRecordingHTTP()
        let model = DemoModel(
            pairings: InMemoryPairingStore(result: .stored(pairing)),
            http: http,
            ownerKey: signer)
        model.operationIdText = "signature-request"
        await model.openManually()
        let approval = try XCTUnwrap(model.approval)

        await approval.approve()

        XCTAssertEqual(http.requests().map { $0.httpMethod ?? "" }, ["GET", "POST"])
    }

    func testPairingAttemptSurvivesFullStateRecreationAndBlocksResubmission() async throws {
        let persistedAttemptBytes: Data
        do {
            let attempts = InMemoryPairingAttemptStore()
            let http = DeferredHTTP()
            let model = DemoModel(
                pairings: InMemoryPairingStore(),
                http: http,
                ownerKey: FakeOwnerSigning(),
                pairingAttempts: attempts)
            model.baseURLText = "http://relay.example"
            model.pairingCodeText = pairingCodeAInput
            let request = Task { await model.pair() }
            await http.wait(for: "pair:\(pairingCodeACanonical)")
            await http.fail("pair:\(pairingCodeACanonical)")
            await request.value
            let firstProcessRequests = await http.requests()
            XCTAssertEqual(firstProcessRequests.count, 1)
            persistedAttemptBytes = try attempts.persistedData()
        }

        // Recreate every mutable owner from bytes: model, authority store,
        // signer, transport, and retry ledger share no in-memory state.
        let recorder = FakeHTTP.Recorder()
        let restarted = DemoModel(
            pairings: InMemoryPairingStore(),
            http: FakeHTTP(
                status: 200,
                body: pairingResponse(deviceCredentialC),
                recorder: recorder),
            ownerKey: FakeOwnerSigning(),
            pairingAttempts: try InMemoryPairingAttemptStore(
                persistedData: persistedAttemptBytes))
        restarted.baseURLText = "https://other.example/base"
        restarted.pairingCodeText = "aaaa bbbb cc"

        await restarted.pair()

        XCTAssertTrue(recorder.requests.isEmpty)
        XCTAssertFalse(restarted.paired)
        XCTAssertTrue(restarted.statusLine.contains("already attempted"))
    }

    func testUnavailableAttemptLedgerBlocksBeforeAnyPairingEffect() async {
        let recorder = FakeHTTP.Recorder()
        let model = DemoModel(
            pairings: InMemoryPairingStore(),
            http: FakeHTTP(
                status: 200,
                body: pairingResponse(deviceCredentialC),
                recorder: recorder),
            ownerKey: FakeOwnerSigning(),
            pairingAttempts: InMemoryPairingAttemptStore(mutationsSucceed: false))
        model.baseURLText = "http://relay.example:8787"
        model.pairingCodeText = pairingCodeAInput

        await model.pair()

        XCTAssertTrue(recorder.requests.isEmpty)
        XCTAssertTrue(model.statusLine.contains("history is unavailable"))
    }

    func testScannedPairingQRCanOnlyFillValidatedCandidates() {
        let store = InMemoryPairingStore()
        let recorder = FakeHTTP.Recorder()
        let model = DemoModel(
            pairings: store,
            http: FakeHTTP(status: 500, body: Data(), recorder: recorder),
            ownerKey: FakeOwnerSigning())

        XCTAssertTrue(model.applyScannedPairingPayload(
            "oaath-demo://pair?relay=HTTP%3A%2F%2FRELAY.EXAMPLE%3A8787%2F&code=abcd-efgh-jk"))
        XCTAssertEqual(model.baseURLText, "http://relay.example:8787")
        XCTAssertEqual(model.pairingCodeText, "ABCDEFGHJK")
        XCTAssertFalse(model.paired)
        XCTAssertEqual(store.load(), .absent)
        XCTAssertTrue(recorder.requests.isEmpty)

        XCTAssertFalse(model.applyScannedPairingPayload("https://attacker.example/not-pairing"))
        XCTAssertEqual(model.baseURLText, "http://relay.example:8787")
        XCTAssertEqual(model.pairingCodeText, "ABCDEFGHJK")
        XCTAssertFalse(model.paired)
        XCTAssertEqual(store.load(), .absent)
        XCTAssertTrue(recorder.requests.isEmpty)
    }

    func testInboxRefreshAndSelectionOpenExactProjectionWithoutDeciding() async throws {
        let store = InMemoryPairingStore()
        try store.installIfAbsent(PersistedPairing(
            endpoint: DemoRelayEndpoint(baseURLText: "http://relay.example:8787"),
            credential: deviceCredentialA,
            account: nil,
            ownerPublicMaterial: fakeOwnerPublicMaterial))
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
        try store.installIfAbsent(PersistedPairing(
            endpoint: DemoRelayEndpoint(baseURLText: "http://relay-a.example:8787"),
            credential: deviceCredentialA,
            account: nil,
            ownerPublicMaterial: fakeOwnerPublicMaterial))
        let http = DeferredHTTP()
        let model = DemoModel(pairings: store, http: http, ownerKey: FakeOwnerSigning())
        let refreshA = Task { await model.refreshInbox() }
        await http.wait(for: "auth:Bearer \(deviceCredentialA):inbox")

        model.unpair()
        model.baseURLText = "http://relay-b.example:9999"
        model.pairingCodeText = pairingCodeBInput
        let pairB = Task { await model.pair() }
        await http.wait(for: "pair:\(pairingCodeBCanonical)")
        await http.succeed(
            "pair:\(pairingCodeBCanonical)", body: pairingResponse(deviceCredentialB))
        await pairB.value

        let refreshB = Task { await model.refreshInbox() }
        await http.wait(for: "auth:Bearer \(deviceCredentialB):inbox")
        await http.succeed(
            "auth:Bearer \(deviceCredentialB):inbox",
            body: try inboxResponse([("request-b", "BBBB2222", 1_900_000_000_001)]))
        await refreshB.value
        await http.succeed(
            "auth:Bearer \(deviceCredentialA):inbox",
            body: try inboxResponse([("request-a", "AAAA1111", 1_900_000_000_000)]))
        await refreshA.value

        XCTAssertEqual(store.load().storedPairingForTest?.credential, deviceCredentialB)
        XCTAssertEqual(model.inbox.map(\.operationId), ["request-b"])

        // A 401 from the current inbox request compare-clears only B.
        let refusedB = Task { await model.refreshInbox() }
        await http.wait(for: "auth:Bearer \(deviceCredentialB):inbox")
        await http.succeed(
            "auth:Bearer \(deviceCredentialB):inbox", body: Data(), status: 401)
        await refusedB.value
        XCTAssertEqual(store.load(), .absent)
        XCTAssertFalse(model.paired)
        XCTAssertTrue(model.inbox.isEmpty)
    }

    func testStaleAndCancelledInbox401CannotClearTheCurrentPairing() async throws {
        let store = InMemoryPairingStore()
        let pairing = try PersistedPairing(
            endpoint: DemoRelayEndpoint(baseURLText: "http://relay.example:8787"),
            credential: deviceCredentialA,
            account: nil,
            ownerPublicMaterial: fakeOwnerPublicMaterial)
        try store.installIfAbsent(pairing)
        let http = DeferredHTTP()
        let model = DemoModel(pairings: store, http: http, ownerKey: FakeOwnerSigning())
        let key = "auth:Bearer \(deviceCredentialA):inbox"

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

        XCTAssertEqual(store.load(), .stored(pairing))
        XCTAssertTrue(model.paired)
        XCTAssertEqual(model.inbox.map(\.operationId), ["request-current"])

        let cancelled = Task { await model.refreshInbox() }
        await http.wait(for: key)
        cancelled.cancel()
        await http.succeed(key, body: Data(), status: 401)
        await cancelled.value
        XCTAssertEqual(store.load(), .stored(pairing))
        XCTAssertTrue(model.paired)

        let refusedCurrent = Task { await model.refreshInbox() }
        await http.wait(for: key)
        await http.succeed(key, body: Data(), status: 401)
        await refusedCurrent.value
        XCTAssertEqual(store.load(), .absent)
        XCTAssertFalse(model.paired)
        XCTAssertTrue(model.inbox.isEmpty)
    }

    func testDifferentEndpointLinkCannotRebindAndRestartUsesOnlyBoundEndpoint() async throws {
        let ownerKey = FakeOwnerSigning()
        let store = InMemoryPairingStore()
        let http = PairingIdentityHTTP()
        let model = DemoModel(pairings: store, http: http, ownerKey: ownerKey)
        model.baseURLText = "http://relay-a.example:8787/"
        model.pairingCodeText = pairingCodeAInput
        await model.pair()
        XCTAssertTrue(model.paired, model.statusLine)
        let bound = try XCTUnwrap(store.load().storedPairingForTest)
        XCTAssertEqual(bound.endpoint.baseURL.absoluteString, "http://relay-a.example:8787")

        model.apply(link: PairingLink(
            relayURL: "http://relay-b.example:9999", pairingCode: "BBBB-CCCC"))
        XCTAssertEqual(model.baseURLText, "http://relay-a.example:8787")
        XCTAssertEqual(store.load(), .stored(bound))
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
            "Bearer \(deviceCredentialA)")
        XCTAssertFalse(http.requests().contains {
            $0.url?.host == "relay-b.example" &&
                $0.value(forHTTPHeaderField: "Authorization")
                    == "Bearer \(deviceCredentialA)"
        })
    }

    func testFailedCandidateNeverPersistsAndSameEndpointLinkIsIgnoredWhilePaired() async throws {
        let ownerKey = FakeOwnerSigning()
        let failedStore = InMemoryPairingStore()
        let failed = DemoModel(
            pairings: failedStore,
            http: PairingIdentityHTTP(pairingStatus: 401, credential: deviceCredentialC),
            ownerKey: ownerKey)
        failed.baseURLText = "http://relay-b.example:9999"
        failed.pairingCodeText = pairingCodeAInput
        await failed.pair()
        XCTAssertFalse(failed.paired)
        XCTAssertEqual(failedStore.load(), .absent)
        XCTAssertFalse(failed.statusLine.contains("never-store"))

        let store = InMemoryPairingStore()
        let http = PairingIdentityHTTP()
        let model = DemoModel(pairings: store, http: http, ownerKey: ownerKey)
        model.baseURLText = "http://relay-a.example:8787"
        model.pairingCodeText = pairingCodeBInput
        await model.pair()
        let bound = try XCTUnwrap(store.load().storedPairingForTest)
        let requestCount = http.requests().count
        model.apply(link: PairingLink(
            relayURL: "HTTP://RELAY-A.EXAMPLE:8787/", pairingCode: "NEW-CODE"))
        await model.pair()
        XCTAssertEqual(store.load(), .stored(bound))
        XCTAssertEqual(http.requests().count, requestCount)
        XCTAssertTrue(model.pairingCodeText.isEmpty)
        XCTAssertTrue(model.statusLine.contains("Already paired"))
    }

    func testLatestPairingAttemptWinsInBothResponseOrders() async throws {
        for firstResponse in ["A", "B"] {
            let store = InMemoryPairingStore()
            let http = DeferredHTTP()
            let model = DemoModel(pairings: store, http: http, ownerKey: FakeOwnerSigning())
            model.baseURLText = "http://relay-a.example:8787"
            model.pairingCodeText = pairingCodeAInput
            let attemptA = Task { await model.pair() }
            await http.wait(for: "pair:\(pairingCodeACanonical)")

            model.baseURLText = "http://relay-b.example:9999"
            model.pairingCodeText = pairingCodeBInput
            let attemptB = Task { await model.pair() }
            await http.wait(for: "pair:\(pairingCodeBCanonical)")

            if firstResponse == "A" {
                await http.succeed(
                    "pair:\(pairingCodeACanonical)", body: pairingResponse(deviceCredentialA))
                await attemptA.value
                XCTAssertEqual(store.load(), .absent)
                await http.succeed(
                    "pair:\(pairingCodeBCanonical)", body: pairingResponse(deviceCredentialB))
            } else {
                await http.succeed(
                    "pair:\(pairingCodeBCanonical)", body: pairingResponse(deviceCredentialB))
                await attemptB.value
                await http.succeed(
                    "pair:\(pairingCodeACanonical)", body: pairingResponse(deviceCredentialA))
            }
            await attemptA.value
            await attemptB.value

            let bound = try XCTUnwrap(store.load().storedPairingForTest)
            XCTAssertEqual(bound.endpoint.baseURL.absoluteString, "http://relay-b.example:9999")
            XCTAssertEqual(bound.credential, deviceCredentialB)
            XCTAssertTrue(model.paired)
            XCTAssertNotNil(model.approval)
        }
    }

    func testApplyingLinkWhilePairingInvalidatesTheOldAttempt() async throws {
        let store = InMemoryPairingStore()
        let http = DeferredHTTP()
        let model = DemoModel(pairings: store, http: http, ownerKey: FakeOwnerSigning())
        model.baseURLText = "http://relay-a.example:8787"
        model.pairingCodeText = pairingCodeAInput
        let attempt = Task { await model.pair() }
        await http.wait(for: "pair:\(pairingCodeACanonical)")

        model.apply(link: PairingLink(
            relayURL: "http://relay-b.example:9999", pairingCode: "PAIR-B"))
        await http.succeed(
            "pair:\(pairingCodeACanonical)", body: pairingResponse(deviceCredentialA))
        await attempt.value

        XCTAssertEqual(store.load(), .absent)
        XCTAssertFalse(model.paired)
        XCTAssertEqual(model.baseURLText, "http://relay-b.example:9999")
        XCTAssertEqual(model.pairingCodeText, "PAIR-B")
        XCTAssertNil(model.approval)
    }

    func testDelayedA401CannotClearBAndCurrentB401ClearsOnlyB() async throws {
        let store = InMemoryPairingStore()
        let pairingA = try PersistedPairing(
            endpoint: DemoRelayEndpoint(baseURLText: "http://relay-a.example:8787"),
            credential: deviceCredentialA,
            account: nil,
            ownerPublicMaterial: fakeOwnerPublicMaterial)
        try store.installIfAbsent(pairingA)
        let http = DeferredHTTP()
        let model = DemoModel(pairings: store, http: http, ownerKey: FakeOwnerSigning())
        model.operationIdText = "request-a"
        let requestA = Task { await model.openManually() }
        await http.wait(for: "auth:Bearer \(deviceCredentialA):request-a")

        model.unpair()
        model.baseURLText = "http://relay-b.example:9999"
        model.pairingCodeText = pairingCodeBInput
        let attemptB = Task { await model.pair() }
        await http.wait(for: "pair:\(pairingCodeBCanonical)")
        await http.succeed(
            "pair:\(pairingCodeBCanonical)", body: pairingResponse(deviceCredentialB))
        await attemptB.value
        let pairingB = try XCTUnwrap(store.load().storedPairingForTest)

        await http.succeed(
            "auth:Bearer \(deviceCredentialA):request-a",
            body: Data("{}".utf8),
            status: 401)
        await requestA.value
        XCTAssertEqual(store.load(), .stored(pairingB))
        XCTAssertTrue(model.paired)

        model.operationIdText = "request-b"
        let requestB = Task { await model.openManually() }
        await http.wait(for: "auth:Bearer \(deviceCredentialB):request-b")
        await http.succeed(
            "auth:Bearer \(deviceCredentialB):request-b",
            body: Data("{}".utf8),
            status: 401)
        await requestB.value
        XCTAssertEqual(store.load(), .absent)
        XCTAssertFalse(model.paired)
        XCTAssertTrue(model.statusLine.contains("refused"))
    }

    func testPrior401IsNotReusedAfterStatuslessTransportFailure() async throws {
        let store = InMemoryPairingStore()
        try store.installIfAbsent(PersistedPairing(
            endpoint: DemoRelayEndpoint(baseURLText: "http://relay-a.example:8787"),
            credential: deviceCredentialA,
            account: nil,
            ownerPublicMaterial: fakeOwnerPublicMaterial))
        let http = DeferredHTTP()
        let model = DemoModel(pairings: store, http: http, ownerKey: FakeOwnerSigning())
        model.operationIdText = "refused-a"
        let refusedA = Task { await model.openManually() }
        await http.wait(for: "auth:Bearer \(deviceCredentialA):refused-a")
        await http.succeed(
            "auth:Bearer \(deviceCredentialA):refused-a", body: Data(), status: 401)
        await refusedA.value
        XCTAssertEqual(store.load(), .absent)

        model.baseURLText = "http://relay-b.example:9999"
        model.pairingCodeText = pairingCodeBInput
        let attemptB = Task { await model.pair() }
        await http.wait(for: "pair:\(pairingCodeBCanonical)")
        await http.succeed(
            "pair:\(pairingCodeBCanonical)", body: pairingResponse(deviceCredentialB))
        await attemptB.value
        let pairingB = try XCTUnwrap(store.load().storedPairingForTest)

        model.operationIdText = "failed-b"
        let failedB = Task { await model.openManually() }
        await http.wait(for: "auth:Bearer \(deviceCredentialB):failed-b")
        await http.fail("auth:Bearer \(deviceCredentialB):failed-b")
        await failedB.value
        XCTAssertEqual(store.load(), .stored(pairingB))
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
