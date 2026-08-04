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

/// One paired device: the device-scoped owner credential, plus the smart
/// account address the relay derived server-side from the registered public
/// key (`null` when the web half has no chain to derive it against). The phone
/// displays what the relay derived — the derivation honestly lives with the
/// web half, which is the side that proves the chain evidence.
public struct PairedDevice: Equatable, Sendable {
    public let deviceCredential: String
    public let account: String?

    public init(deviceCredential: String, account: String?) {
        self.deviceCredential = deviceCredential
        self.account = account
    }
}

/// Strict decode of `{deviceCredential, account}` — exactly two keys; the
/// account is a lowercase 20-byte hex address or null.
public func decodePairingResponse(_ data: Data) throws -> PairedDevice {
    guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          Set(object.keys) == ["deviceCredential", "account"],
          let credential = object["deviceCredential"] as? String,
          !credential.isEmpty,
          credential.count <= 256
    else {
        throw DemoPairingError.invalidResponse
    }
    if object["account"] is NSNull {
        return PairedDevice(deviceCredential: credential, account: nil)
    }
    guard let account = object["account"] as? String, isLowercaseAddress(account) else {
        throw DemoPairingError.invalidResponse
    }
    return PairedDevice(deviceCredential: credential, account: account)
}

/// Lowercase `0x`-prefixed 20-byte hex, the projection's address shape.
private func isLowercaseAddress(_ text: String) -> Bool {
    guard text.count == 42, text.hasPrefix("0x") else { return false }
    for scalar in text.unicodeScalars.dropFirst(2) {
        switch scalar {
        case "0"..."9", "a"..."f": continue
        default: return false
        }
    }
    return true
}

/// One pairing call. The body registers the APNs device token AND the owner
/// key's public material (`0x` + 64-byte x‖y) beside the one-shot pairing
/// code. A refused code (unknown, consumed, or expired — the relay
/// deliberately does not distinguish) surfaces as `.refused`.
public func pair(
    endpoint: DemoRelayEndpoint,
    pairingCode: String,
    deviceToken: String,
    publicKey: String,
    http: any DemoHTTP
) async throws -> PairedDevice {
    let request = try endpoint.pairingRequest(
        pairingCode: pairingCode, deviceToken: deviceToken, publicKey: publicKey)
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
