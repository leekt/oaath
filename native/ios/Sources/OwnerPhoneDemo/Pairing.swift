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

public enum PairingStoreError: Error, Equatable, Sendable {
    case invalidRecord
    case storageFailed
}

/// The one authoritative persisted pairing identity. Endpoint and bearer are
/// encoded in the same exact versioned value and can never be loaded apart.
public struct PersistedPairing: Equatable, Sendable {
    public static let version = 1
    public let endpoint: DemoRelayEndpoint
    public let credential: String
    public let account: String?

    public init(endpoint: DemoRelayEndpoint, credential: String, account: String?) throws {
        guard !credential.isEmpty, credential.count <= 256 else {
            throw PairingStoreError.invalidRecord
        }
        if let account, !isLowercaseAddress(account) { throw PairingStoreError.invalidRecord }
        self.endpoint = endpoint
        self.credential = credential
        self.account = account
    }

    public func encoded() throws -> Data {
        let encodedAccount: Any = account.map { $0 as Any } ?? NSNull()
        return try JSONSerialization.data(
            withJSONObject: [
                "version": Self.version,
                "endpoint": endpoint.baseURL.absoluteString,
                "credential": credential,
                "account": encodedAccount
            ],
            options: [.sortedKeys])
    }

    public static func decode(_ data: Data) throws -> PersistedPairing {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == ["version", "endpoint", "credential", "account"],
              let version = object["version"] as? NSNumber,
              CFGetTypeID(version) != CFBooleanGetTypeID(),
              version.doubleValue == Double(Self.version),
              let endpointText = object["endpoint"] as? String,
              let credential = object["credential"] as? String
        else { throw PairingStoreError.invalidRecord }
        let account: String?
        if object["account"] is NSNull { account = nil }
        else if let value = object["account"] as? String { account = value }
        else { throw PairingStoreError.invalidRecord }
        do {
            let endpoint = try DemoRelayEndpoint(baseURLText: endpointText)
            guard endpoint.baseURL.absoluteString == endpointText else {
                throw PairingStoreError.invalidRecord
            }
            return try PersistedPairing(
                endpoint: endpoint, credential: credential, account: account)
        } catch {
            throw PairingStoreError.invalidRecord
        }
    }
}

/// Atomic custody of the complete persisted pairing value. Authenticated
/// requests capture this exact value; a refusal may clear it only while it is
/// still current, so a delayed response cannot revoke a replacement pairing.
public protocol DevicePairingStore: Sendable {
    func load() -> PersistedPairing?
    func save(_ pairing: PersistedPairing) throws
    func clear()
    @discardableResult func clear(ifCurrent pairing: PersistedPairing) -> Bool
}

/// Test double and simulator fallback.
public final class InMemoryPairingStore: DevicePairingStore, @unchecked Sendable {
    private let lock = NSLock()
    private var pairing: PersistedPairing?
    public init() {}
    public func load() -> PersistedPairing? {
        lock.lock()
        defer { lock.unlock() }
        return pairing
    }
    public func save(_ pairing: PersistedPairing) throws {
        lock.lock()
        self.pairing = pairing
        lock.unlock()
    }
    public func clear() {
        lock.lock()
        pairing = nil
        lock.unlock()
    }
    @discardableResult public func clear(ifCurrent expected: PersistedPairing) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard pairing == expected else { return false }
        pairing = nil
        return true
    }
}

#if canImport(Security)
import Security

/// Keychain-backed store: endpoint, bearer, and account occupy one exact,
/// non-synchronizable generic-password value. Old raw credential values are
/// rejected rather than combined with another endpoint.
public struct KeychainPairingStore: DevicePairingStore {
    private static let lock = NSLock()
    public let service: String

    public init(service: String = "org.oaath.owner-phone.pairing-v1") {
        self.service = service
    }

    public func load() -> PersistedPairing? {
        Self.lock.withLock { loadUnlocked() }
    }

    public func save(_ pairing: PersistedPairing) throws {
        try Self.lock.withLock {
            let query: [CFString: Any] = [
                kSecClass: kSecClassGenericPassword,
                kSecAttrService: service
            ]
            let data = try pairing.encoded()
            let update: [CFString: Any] = [kSecValueData: data]
            let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
            if status == errSecSuccess { return }
            guard status == errSecItemNotFound else { throw PairingStoreError.storageFailed }
            let attributes: [CFString: Any] = [
                kSecClass: kSecClassGenericPassword,
                kSecAttrService: service,
                kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                kSecValueData: data
            ]
            guard SecItemAdd(attributes as CFDictionary, nil) == errSecSuccess else {
                throw PairingStoreError.storageFailed
            }
        }
    }

    public func clear() {
        Self.lock.withLock { deleteUnlocked() }
    }

    @discardableResult public func clear(ifCurrent expected: PersistedPairing) -> Bool {
        Self.lock.withLock {
            guard loadUnlocked() == expected else { return false }
            deleteUnlocked()
            return true
        }
    }

    private func loadUnlocked() -> PersistedPairing? {
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
        return try? PersistedPairing.decode(data)
    }

    private func deleteUnlocked() {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service
        ]
        SecItemDelete(query as CFDictionary)
    }
}
#endif
