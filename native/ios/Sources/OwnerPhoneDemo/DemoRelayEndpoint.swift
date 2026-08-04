/**
 EXPERIMENTAL PREVIEW — demo wiring of the relay's preview routes.

 This module is the demo half the library deliberately does not own: base URL
 handling, the route map, and request construction. Wire truth for the routes:
 `packages/server/src/relay/handler.ts` (projection/decision) and
 `examples/phone/run.mjs` (pairing — an example-owned route, not a relay one).

 @author taek <leekt216@gmail.com>
 */
import Foundation
import OwnerPhone

public enum DemoRelayError: Error, Equatable, Sendable {
    case invalidBaseURL
    case invalidResponse
    /// Structured HTTP refusal; 401 sends the app back to pairing.
    case status(Int)
}

/// One relay deployment, addressed by base URL. Pure request construction —
/// nothing here moves bytes or holds state.
public struct DemoRelayEndpoint: Equatable, Sendable {
    public let baseURL: URL

    /// Accepts `http`/`https` with a host, e.g. `http://192.168.1.20:8787`.
    /// Plain http is tolerated because this is a LAN demo; see the Demo README
    /// for the dev-only ATS exception it requires.
    public init(baseURLText: String) throws {
        let trimmed = baseURLText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard var components = URLComponents(string: trimmed),
              let scheme = components.scheme?.lowercased(),
              scheme == "http" || scheme == "https",
              let host = components.host,
              !host.isEmpty,
              components.user == nil,
              components.password == nil,
              components.query == nil,
              components.fragment == nil
        else {
            throw DemoRelayError.invalidBaseURL
        }
        components.scheme = scheme
        components.host = host.lowercased()
        while components.path.hasSuffix("/") { components.path.removeLast() }
        guard let url = components.url else { throw DemoRelayError.invalidBaseURL }
        self.baseURL = url
    }

    /// `GET /native/projections/{operationId}`, owner-authenticated.
    func projectionRequest(operationId: String, credential: String) -> URLRequest {
        var request = URLRequest(
            url: baseURL.appendingPathComponent("native/projections/\(operationId)"))
        request.httpMethod = "GET"
        request.setValue("Bearer \(credential)", forHTTPHeaderField: "Authorization")
        return request
    }

    /// `POST /native/decisions/{operationId}`, owner-authenticated.
    func decisionRequest(operationId: String, body: Data, credential: String) -> URLRequest {
        var request = URLRequest(
            url: baseURL.appendingPathComponent("native/decisions/\(operationId)"))
        request.httpMethod = "POST"
        request.setValue("Bearer \(credential)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = body
        return request
    }

    /// `POST /native/pairings` — the pairing code IS the authentication for
    /// this one call, so no bearer is attached. The body registers the APNs
    /// device token and the owner key's public material together.
    public func pairingRequest(
        pairingCode: String,
        deviceToken: String,
        publicKey: String
    ) throws -> URLRequest {
        var request = URLRequest(url: baseURL.appendingPathComponent("native/pairings"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(
            withJSONObject: [
                "pairingCode": pairingCode,
                "deviceToken": deviceToken,
                "publicKey": publicKey
            ],
            options: [.sortedKeys])
        return request
    }
}

/// Minimal byte mover so tests can fake HTTP; `URLSession` satisfies it.
public protocol DemoHTTP: Sendable {
    func send(_ request: URLRequest) async throws -> (Data, Int)
}

extension URLSession: DemoHTTP {
    public func send(_ request: URLRequest) async throws -> (Data, Int) {
        let (data, response) = try await data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw DemoRelayError.invalidResponse
        }
        return (data, http.statusCode)
    }
}

/// Maps the library's transport-injected relay client onto the preview routes.
/// The library validates and decodes everything; this closure only moves bytes.
/// Each client captures the exact pairing that authorized its requests. A 401
/// reports only that captured identity, never process-global transport status.
public func demoRelayClient(
    pairing: PersistedPairing,
    http: any DemoHTTP,
    onUnauthorized: (@Sendable (PersistedPairing) async -> Void)? = nil
) -> TransportRelayClient {
    TransportRelayClient { call in
        let request: URLRequest
        switch call.kind {
        case .fetchProjection:
            request = pairing.endpoint.projectionRequest(
                operationId: call.operationId, credential: pairing.credential)
        case .submitDecision:
            request = pairing.endpoint.decisionRequest(
                operationId: call.operationId,
                body: call.body ?? Data(),
                credential: pairing.credential)
        }
        let (data, status) = try await http.send(request)
        if status == 401 { await onUnauthorized?(pairing) }
        guard status == 200 else { throw DemoRelayError.status(status) }
        return data
    }
}
