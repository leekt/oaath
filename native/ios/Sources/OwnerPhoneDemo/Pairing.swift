/**
 EXPERIMENTAL PREVIEW — pairing client and device-credential custody.

 Pairing is registration: the phone posts the one-shot pairing code it was
 shown together with its APNs device token, and receives a device-scoped owner
 credential. The pairing code printed to a terminal on a trusted LAN is the
 demo's trust root; a production deployment owns pairing UX (QR, attestation)
 through its authentication port.

 @author taek <leekt216@gmail.com>
 */
import Foundation

public enum DemoPairingError: Error, Equatable, Sendable {
    case refused
    case invalidResponse
}

/// Strict decode of `{deviceCredential}` — exactly one key, bounded text.
public func decodePairingResponse(_ data: Data) throws -> String {
    guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          Set(object.keys) == ["deviceCredential"],
          let credential = object["deviceCredential"] as? String,
          !credential.isEmpty,
          credential.count <= 256
    else {
        throw DemoPairingError.invalidResponse
    }
    return credential
}

/// One pairing call. A refused code (unknown, consumed, or expired — the relay
/// deliberately does not distinguish) surfaces as `.refused`.
public func pair(
    endpoint: DemoRelayEndpoint,
    pairingCode: String,
    deviceToken: String,
    http: any DemoHTTP
) async throws -> String {
    let request = try endpoint.pairingRequest(pairingCode: pairingCode, deviceToken: deviceToken)
    let (data, status) = try await http.send(request)
    guard status == 200 else { throw DemoPairingError.refused }
    return try decodePairingResponse(data)
}

/// Custody of the device-scoped owner credential, beside the key custody stub.
public protocol DeviceCredentialStore: Sendable {
    func load() -> String?
    func save(_ credential: String)
    func clear()
}

/// Test double and simulator fallback.
public final class InMemoryCredentialStore: DeviceCredentialStore, @unchecked Sendable {
    private var credential: String?
    public init() {}
    public func load() -> String? { credential }
    public func save(_ credential: String) { self.credential = credential }
    public func clear() { credential = nil }
}

#if canImport(Security)
import Security

/// Keychain-backed store following the `KeychainKeyCustodyStub` pattern: one
/// non-synchronizable generic-password item. Not production-qualified.
public struct KeychainCredentialStore: DeviceCredentialStore {
    public let service: String

    public init(service: String = "org.oaath.owner-phone.device-credential") {
        self.service = service
    }

    public func load() -> String? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data
        else { return nil }
        return String(data: data, encoding: .utf8)
    }

    public func save(_ credential: String) {
        clear()
        let attributes: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData: Data(credential.utf8)
        ]
        SecItemAdd(attributes as CFDictionary, nil)
    }

    public func clear() {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service
        ]
        SecItemDelete(query as CFDictionary)
    }
}
#endif
