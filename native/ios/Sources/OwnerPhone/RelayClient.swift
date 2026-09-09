/**
 EXPERIMENTAL PREVIEW — thin client for the relay's native preview surface.

 The relay serves the preview routes `GET /native/projections/{operationId}`,
 `GET /native/permission-signing/{operationId}`, and `POST /native/decisions/{operationId}` (see
 `packages/server/src/relay/handler.ts`). This client is defined against the
 documented projection/decision shapes, and the transport — base URL,
 authentication, TLS — stays deployment-wired: a deployment injects one
 closure that moves bytes and carries the authenticated owner credential.
 Revocation uses a separate decision domain and versioned acknowledgement;
 its transport contract does not imply a deployed service queue or HTTP handler.
 Nothing here reads configuration or holds credentials.

 @author taek <leekt216@gmail.com>
 */
import Foundation

/// One relay call, already validated and encoded. The deployment-wired
/// transport maps it onto whatever route it stands up.
public struct OwnerPhoneRelayCall: Equatable, Sendable {
    public enum Kind: Equatable, Sendable {
        case fetchProjection
        case fetchPermissionSigningProjection
        case submitDecision
        case submitRevocationDecision
    }

    public let kind: Kind
    public let operationId: String
    /// Strict JSON command body for either decision domain; nil for fetches.
    public let body: Data?
}

public protocol OwnerPhoneRelayClient: Sendable {
    func projection(operationId: String) async throws -> OwnerPhoneRequestProjection
    func permissionSigningProjection(operationId: String) async throws -> OwnerPhoneRequestProjection
    func submit(
        operationId: String,
        command: OwnerPhoneDecisionCommand,
        domain: OwnerPhoneDecisionDomain
    ) async throws -> OwnerPhoneDecision
}

/// Strict client over one injected byte transport.
public struct TransportRelayClient: OwnerPhoneRelayClient {
    public typealias Transport = @Sendable (OwnerPhoneRelayCall) async throws -> Data

    private let transport: Transport

    public init(transport: @escaping Transport) {
        self.transport = transport
    }

    public func projection(operationId: String) async throws -> OwnerPhoneRequestProjection {
        try await fetchProjection(operationId: operationId, kind: .fetchProjection)
    }

    public func permissionSigningProjection(operationId: String) async throws -> OwnerPhoneRequestProjection {
        try await fetchProjection(operationId: operationId, kind: .fetchPermissionSigningProjection)
    }

    private func fetchProjection(
        operationId: String, kind: OwnerPhoneRelayCall.Kind
    ) async throws -> OwnerPhoneRequestProjection {
        let id = try Wire.identifier(operationId, maximum: WireLimits.operationId, label: "operationId")
        let data = try await transport(
            OwnerPhoneRelayCall(kind: kind, operationId: id, body: nil))
        let projection = try OwnerPhoneRequestProjection.decode(data)
        guard projection.operationId == id else {
            throw OwnerPhoneWireError.invalidField("operationId")
        }
        return projection
    }

    public func submit(
        operationId: String,
        command: OwnerPhoneDecisionCommand,
        domain: OwnerPhoneDecisionDomain
    ) async throws -> OwnerPhoneDecision {
        let id = try Wire.identifier(operationId, maximum: WireLimits.operationId, label: "operationId")
        let body = try command.encode()
        let data = try await transport(
            OwnerPhoneRelayCall(kind: domain == .authorization ? .submitDecision : .submitRevocationDecision,
                                operationId: id, body: body))
        let decision = try domain == .authorization
            ? OwnerPhoneDecision.decode(data) : OwnerPhoneDecision.decodeRevocation(data)
        guard decision.operationId == id else {
            throw OwnerPhoneWireError.invalidField("operationId")
        }
        return decision
    }
}
