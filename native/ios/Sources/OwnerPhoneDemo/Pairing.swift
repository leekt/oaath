/**
 EXPERIMENTAL PREVIEW — pairing client and device-credential custody.

 Pairing is registration: the phone posts the one-shot pairing code it was
 shown together with its APNs device token, and receives a device-scoped owner
 credential. The pairing code printed to a terminal on a trusted LAN is the
 demo's trust root; a production deployment owns pairing UX (QR, attestation)
 through its authentication port.

 @author taek <leekt216@gmail.com>
 */
import CryptoKit
import Foundation

public enum DemoPairingError: Error, Equatable, Sendable {
    case refused
    case invalidDeviceToken
    case invalidResponse
}

/// Canonical form of the relay's ten-character one-shot code. Human spacing,
/// hyphens, and lowercase are accepted exactly as the relay accepts them, then
/// collapsed before identity comparison or transmission.
public struct PairingCode: Equatable, Sendable {
    public let value: String

    public init?(_ text: String) {
        let allowed = Array("ABCDEFGHJKMNPQRSTUVWXYZ23456789".utf8)
        var bytes: [UInt8] = []
        bytes.reserveCapacity(10)
        for scalar in text.unicodeScalars {
            if scalar == "-" || CharacterSet.whitespacesAndNewlines.contains(scalar) {
                continue
            }
            var value = scalar.value
            if (97...122).contains(value) { value -= 32 }
            guard value <= UInt8.max,
                  allowed.contains(UInt8(value))
            else { return nil }
            bytes.append(UInt8(value))
        }
        guard bytes.count == 10,
              let value = String(bytes: bytes, encoding: .ascii)
        else { return nil }
        self.value = value
    }

    var identityHash: Data {
        Data(SHA256.hash(data: Data(value.utf8)))
    }
}

/// Exact APNs token accepted by the example relay. Capture and normalization
/// happen before the durable one-shot claim, so malformed caller input cannot
/// retire a valid pairing code.
struct PairingDeviceToken: Equatable, Sendable {
    let value: String

    init?(_ text: String) {
        let bytes = Array(text.utf8)
        guard (64...200).contains(bytes.count) else { return nil }
        var normalized: [UInt8] = []
        normalized.reserveCapacity(bytes.count)
        for byte in bytes {
            switch byte {
            case 48...57, 97...102:
                normalized.append(byte)
            case 65...70:
                normalized.append(byte + 32)
            default:
                return nil
            }
        }
        self.value = String(decoding: normalized, as: UTF8.self)
    }
}

/// Exact 32-byte base64url credential emitted by `examples/phone`. Checking
/// the canonical re-encoding also rejects non-zero padding bits.
private struct PairingDeviceCredential: Equatable, Sendable {
    let value: String

    init?(_ text: String) {
        let bytes = Array(text.utf8)
        guard bytes.count == 43,
              bytes.allSatisfy({ byte in
                  (48...57).contains(byte)
                      || (65...90).contains(byte)
                      || (97...122).contains(byte)
                      || byte == 45
                      || byte == 95
              })
        else { return nil }
        let padded = text
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/") + "="
        guard let decoded = Data(base64Encoded: padded), decoded.count == 32 else {
            return nil
        }
        let canonical = decoded.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        guard canonical == text else { return nil }
        self.value = text
    }
}

/// Exact public material registered for the owner P-256 key: lowercase
/// `0x` followed by 64-byte x‖y. Caller-injected signing capabilities cross
/// this boundary once before any pairing request can consume a one-shot code.
public struct OwnerPublicMaterial: Equatable, Sendable {
    public let hex: String
    let x963Representation: Data

    public init?(_ hex: String) {
        guard hex.count == 130, hex.hasPrefix("0x") else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(64)
        var highNibble: UInt8?
        for scalar in hex.unicodeScalars.dropFirst(2) {
            let nibble: UInt8
            switch scalar {
            case "0"..."9": nibble = UInt8(scalar.value - 48)
            case "a"..."f": nibble = UInt8(scalar.value - 87)
            default: return nil
            }
            if let high = highNibble {
                bytes.append((high << 4) | nibble)
                highNibble = nil
            } else {
                highNibble = nibble
            }
        }
        var x963 = Data([0x04])
        x963.append(contentsOf: bytes)
        guard (try? P256.Signing.PublicKey(x963Representation: x963)) != nil else {
            return nil
        }
        self.hex = hex
        self.x963Representation = x963
    }
}

/// One paired device: the device-scoped owner credential, plus the smart
/// account address the relay derived server-side from the registered public
/// key (`null` when the web half has no chain to derive it against). The phone
/// displays what the relay derived — the derivation honestly lives with the
/// web half, which is the side that proves the chain evidence.
public struct PairedDevice: Equatable, Sendable {
    public let deviceCredential: String
    public let account: String?

    fileprivate init(deviceCredential: PairingDeviceCredential, account: String?) {
        self.deviceCredential = deviceCredential.value
        self.account = account
    }
}

/// Strict decode of `{deviceCredential, account}` — exactly two keys; the
/// credential is canonical 32-byte base64url, and the account is a lowercase
/// 20-byte hex address or null. The example owns one compact byte encoding;
/// re-encoding rejects duplicate keys and representation drift.
public func decodePairingResponse(_ data: Data) throws -> PairedDevice {
    guard !data.isEmpty,
          data.count <= 256,
          let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          Set(object.keys) == ["deviceCredential", "account"],
          let credentialText = object["deviceCredential"] as? String,
          let credential = PairingDeviceCredential(credentialText)
    else {
        throw DemoPairingError.invalidResponse
    }
    let device: PairedDevice
    let canonical: Data
    if object["account"] is NSNull {
        device = PairedDevice(deviceCredential: credential, account: nil)
        canonical = Data(
            #"{"deviceCredential":"\#(credential.value)","account":null}"#.utf8)
    } else {
        guard let account = object["account"] as? String, isLowercaseAddress(account) else {
            throw DemoPairingError.invalidResponse
        }
        device = PairedDevice(deviceCredential: credential, account: account)
        canonical = Data(
            #"{"deviceCredential":"\#(credential.value)","account":"\#(account)"}"#.utf8)
    }
    guard data == canonical else { throw DemoPairingError.invalidResponse }
    return device
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
func pair(
    endpoint: DemoRelayEndpoint,
    pairingCode: PairingCode,
    deviceToken: String,
    publicKey: OwnerPublicMaterial,
    pairingAttempts: any PairingAttemptStore,
    http: any DemoHTTP
) async throws -> PairedDevice {
    guard let deviceToken = PairingDeviceToken(deviceToken) else {
        throw DemoPairingError.invalidDeviceToken
    }
    let attempt = PairingAttemptIdentity(code: pairingCode)
    guard try pairingAttempts.claimIfNew(attempt) else {
        throw PairingAttemptStoreError.alreadyAttempted
    }
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
    /// Version 2 rejects pairings registered with the retired physical-device
    /// software fallback. Re-pairing binds the credential to the v2 key tags.
    public static let version = 2
    private static let maxEncodedBytes = 2_048
    public let endpoint: DemoRelayEndpoint
    public let credential: String
    public let account: String?
    /// Exact owner key registered when this credential was issued.
    public let ownerPublicMaterial: OwnerPublicMaterial

    public init(
        endpoint: DemoRelayEndpoint,
        credential: String,
        account: String?,
        ownerPublicMaterial: OwnerPublicMaterial
    ) throws {
        guard PairingDeviceCredential(credential) != nil else {
            throw PairingStoreError.invalidRecord
        }
        if let account, !isLowercaseAddress(account) { throw PairingStoreError.invalidRecord }
        self.endpoint = endpoint
        self.credential = credential
        self.account = account
        self.ownerPublicMaterial = ownerPublicMaterial
    }

    public func encoded() throws -> Data {
        let encodedAccount: Any = account.map { $0 as Any } ?? NSNull()
        return try JSONSerialization.data(
            withJSONObject: [
                "version": Self.version,
                "endpoint": endpoint.baseURL.absoluteString,
                "credential": credential,
                "account": encodedAccount,
                "ownerPublicMaterial": ownerPublicMaterial.hex
            ],
            options: [.sortedKeys])
    }

    public static func decode(_ data: Data) throws -> PersistedPairing {
        guard !data.isEmpty,
              data.count <= Self.maxEncodedBytes,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys)
                == ["version", "endpoint", "credential", "account", "ownerPublicMaterial"],
              let version = object["version"] as? NSNumber,
              CFGetTypeID(version) != CFBooleanGetTypeID(),
              version.doubleValue == Double(Self.version),
              let endpointText = object["endpoint"] as? String,
              let credential = object["credential"] as? String,
              let ownerPublicMaterialText = object["ownerPublicMaterial"] as? String,
              let ownerPublicMaterial = OwnerPublicMaterial(ownerPublicMaterialText)
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
            let pairing = try PersistedPairing(
                endpoint: endpoint,
                credential: credential,
                account: account,
                ownerPublicMaterial: ownerPublicMaterial)
            guard try pairing.encoded() == data else {
                throw PairingStoreError.invalidRecord
            }
            return pairing
        } catch {
            throw PairingStoreError.invalidRecord
        }
    }
}

/// Durable authority is tri-state: malformed or inaccessible evidence is not
/// interchangeable with a record that was proven absent.
public enum PairingLoadResult: Equatable, Sendable {
    case absent
    case stored(PersistedPairing)
    case unreadable
}

/// Atomic custody of the complete persisted pairing value. Authenticated
/// requests capture this exact value; a refusal may clear it only while it is
/// still current, so a delayed response cannot revoke a replacement pairing.
public protocol DevicePairingStore: Sendable {
    func load() -> PairingLoadResult
    /// Atomically installs only into proven absence. Existing or unreadable
    /// evidence is preserved and returns false.
    @discardableResult func installIfAbsent(_ pairing: PersistedPairing) throws -> Bool
    /// Explicit local forget. False leaves model authority blocked/retryable.
    @discardableResult func clear() -> Bool
    @discardableResult func clear(ifCurrent pairing: PersistedPairing) -> Bool
}

/// Thread-safe in-memory test double.
public final class InMemoryPairingStore: DevicePairingStore, @unchecked Sendable {
    private let lock = NSLock()
    private var result: PairingLoadResult
    private let mutationsSucceed: Bool
    public init(
        result: PairingLoadResult = .absent,
        mutationsSucceed: Bool = true
    ) {
        self.result = result
        self.mutationsSucceed = mutationsSucceed
    }
    public func load() -> PairingLoadResult {
        lock.lock()
        defer { lock.unlock() }
        return result
    }
    @discardableResult public func installIfAbsent(
        _ pairing: PersistedPairing
    ) throws -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard mutationsSucceed else { throw PairingStoreError.storageFailed }
        guard result == .absent else { return false }
        result = .stored(pairing)
        return true
    }
    @discardableResult public func clear() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard mutationsSucceed else { return false }
        result = .absent
        return true
    }
    @discardableResult public func clear(ifCurrent expected: PersistedPairing) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard mutationsSucceed, result == .stored(expected) else { return false }
        result = .absent
        return true
    }
}

/// Non-secret durable evidence that a canonical one-shot code was dispatched
/// (or retired just before dispatch). It is global so changing relay aliases
/// cannot authorize disclosure or resubmission. Raw codes are never stored.
struct PairingAttemptIdentity: Hashable, Sendable {
    let codeHash: Data

    init(code: PairingCode) {
        self.codeHash = code.identityHash
    }

    fileprivate init(codeHash: Data) {
        self.codeHash = codeHash
    }
}

enum PairingAttemptStoreError: Error, Equatable, Sendable {
    case alreadyAttempted
    case unreadable
    case storageFailed
    /// The ledger never evicts retry evidence. Exhaustion fails closed.
    case capacityReached
}

/// Owns the durable never-resubmit transition. `claimIfNew` must complete
/// before request bytes may move; false means the same code was already
/// retired by this or an earlier process.
protocol PairingAttemptStore: Sendable {
    @discardableResult
    func claimIfNew(_ attempt: PairingAttemptIdentity) throws -> Bool
}

final class InMemoryPairingAttemptStore: PairingAttemptStore, @unchecked Sendable {
    private let lock = NSLock()
    private var attempts: Set<PairingAttemptIdentity>
    private let mutationsSucceed: Bool

    init(
        attempts: Set<PairingAttemptIdentity> = [],
        mutationsSucceed: Bool = true
    ) {
        self.attempts = attempts
        self.mutationsSucceed = mutationsSucceed
    }

    /// Test-only durable-byte seam: reload tests recreate the store rather
    /// than sharing its in-memory set.
    convenience init(
        persistedData: Data,
        mutationsSucceed: Bool = true
    ) throws {
        self.init(
            attempts: try PersistedPairingAttempts.decode(persistedData).attempts,
            mutationsSucceed: mutationsSucceed)
    }

    func persistedData() throws -> Data {
        lock.lock()
        defer { lock.unlock() }
        return try PersistedPairingAttempts(attempts: attempts).encoded()
    }

    @discardableResult
    func claimIfNew(_ attempt: PairingAttemptIdentity) throws -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard mutationsSucceed else { throw PairingAttemptStoreError.storageFailed }
        guard !attempts.contains(attempt) else { return false }
        guard attempts.count < PersistedPairingAttempts.limit else {
            throw PairingAttemptStoreError.capacityReached
        }
        attempts.insert(attempt)
        return true
    }
}

/// One exact bounded security-artifact schema. Entries remain forever rather
/// than guessing that wall-clock time proves a server-side one-shot expired.
private struct PersistedPairingAttempts {
    static let version = 1
    static let limit = 64
    static let maxEncodedBytes = 8_192
    let attempts: Set<PairingAttemptIdentity>

    func encoded() throws -> Data {
        let ordered = Self.ordered(attempts)
        return try JSONSerialization.data(
            withJSONObject: [
                "version": Self.version,
                "attempts": ordered.map {
                    ["codeHash": $0.codeHash.base64EncodedString()]
                }
            ],
            options: [.sortedKeys])
    }

    static func decode(_ data: Data) throws -> Self {
        guard !data.isEmpty,
              data.count <= Self.maxEncodedBytes,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == ["version", "attempts"],
              let version = object["version"] as? NSNumber,
              CFGetTypeID(version) != CFBooleanGetTypeID(),
              version.doubleValue == Double(Self.version),
              let values = object["attempts"] as? [Any],
              values.count <= Self.limit
        else { throw PairingAttemptStoreError.unreadable }
        var decoded: [PairingAttemptIdentity] = []
        decoded.reserveCapacity(values.count)
        for value in values {
            guard let entry = value as? [String: Any],
                  Set(entry.keys) == ["codeHash"],
                  let hashText = entry["codeHash"] as? String,
                  let hash = Data(base64Encoded: hashText),
                  hash.count == 32,
                  hash.base64EncodedString() == hashText
            else { throw PairingAttemptStoreError.unreadable }
            decoded.append(PairingAttemptIdentity(codeHash: hash))
        }
        let attempts = Set(decoded)
        guard attempts.count == decoded.count,
              decoded == ordered(attempts)
        else { throw PairingAttemptStoreError.unreadable }
        let ledger = Self(attempts: attempts)
        guard (try? ledger.encoded()) == data else {
            throw PairingAttemptStoreError.unreadable
        }
        return ledger
    }

    private static func ordered(
        _ attempts: Set<PairingAttemptIdentity>
    ) -> [PairingAttemptIdentity] {
        attempts.sorted { $0.codeHash.lexicographicallyPrecedes($1.codeHash) }
    }
}

#if canImport(Security)
import Security

/// Keychain-backed store: endpoint, bearer, and account occupy one exact,
/// non-synchronizable generic-password value. Old raw credential values are
/// rejected rather than combined with another endpoint.
public struct KeychainPairingStore: DevicePairingStore {
    private static let lock = NSLock()
    private static let account = "pairing"
    public let service: String

    public init(service: String = "org.oaath.owner-phone.pairing-v2") {
        self.service = service
    }

    public func load() -> PairingLoadResult {
        Self.lock.withLock { loadUnlocked() }
    }

    @discardableResult public func installIfAbsent(
        _ pairing: PersistedPairing
    ) throws -> Bool {
        try Self.lock.withLock {
            let data = try pairing.encoded()
            let attributes: [CFString: Any] = [
                kSecClass: kSecClassGenericPassword,
                kSecAttrService: service,
                kSecAttrAccount: Self.account,
                kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                kSecValueData: data
            ]
            let status = SecItemAdd(attributes as CFDictionary, nil)
            if status == errSecSuccess { return true }
            if status == errSecDuplicateItem { return false }
            throw PairingStoreError.storageFailed
        }
    }

    @discardableResult public func clear() -> Bool {
        Self.lock.withLock { deleteUnlocked() }
    }

    @discardableResult public func clear(ifCurrent expected: PersistedPairing) -> Bool {
        Self.lock.withLock {
            guard loadUnlocked() == .stored(expected) else { return false }
            return deleteUnlocked()
        }
    }

    private func baseQuery() -> [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: Self.account
        ]
    }

    private func loadUnlocked() -> PairingLoadResult {
        var query = baseQuery()
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return .absent }
        guard status == errSecSuccess,
              let data = item as? Data,
              let pairing = try? PersistedPairing.decode(data)
        else { return .unreadable }
        return .stored(pairing)
    }

    private func deleteUnlocked() -> Bool {
        let status = SecItemDelete(baseQuery() as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}

/// Device-only durable pairing-attempt ledger. It is intentionally separate
/// from the installed pairing identity: retry evidence survives unpairing and
/// process recreation and is never interpreted as authority.
struct KeychainPairingAttemptStore: PairingAttemptStore {
    private enum LoadResult {
        case absent
        case stored(PersistedPairingAttempts)
        case unreadable
    }

    private static let lock = NSLock()
    private static let account = "attempt-ledger"
    let service: String

    init(service: String = "org.oaath.owner-phone.pairing-attempts-v1") {
        self.service = service
    }

    @discardableResult
    func claimIfNew(_ attempt: PairingAttemptIdentity) throws -> Bool {
        try Self.lock.withLock {
            let load = loadUnlocked()
            let existing: Set<PairingAttemptIdentity>
            switch load {
            case .absent:
                existing = []
            case .stored(let ledger):
                existing = ledger.attempts
            case .unreadable:
                throw PairingAttemptStoreError.unreadable
            }
            guard !existing.contains(attempt) else { return false }
            guard existing.count < PersistedPairingAttempts.limit else {
                throw PairingAttemptStoreError.capacityReached
            }
            var updated = existing
            updated.insert(attempt)
            let data = try PersistedPairingAttempts(attempts: updated).encoded()
            switch load {
            case .absent:
                let attributes = baseQuery().merging([
                    kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                    kSecValueData: data
                ]) { _, right in right }
                guard SecItemAdd(attributes as CFDictionary, nil) == errSecSuccess else {
                    throw PairingAttemptStoreError.storageFailed
                }
            case .stored:
                let update: [CFString: Any] = [kSecValueData: data]
                guard SecItemUpdate(
                    baseQuery() as CFDictionary,
                    update as CFDictionary) == errSecSuccess
                else { throw PairingAttemptStoreError.storageFailed }
            case .unreadable:
                preconditionFailure("unreadable handled above")
            }
            return true
        }
    }

    private func baseQuery() -> [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: Self.account
        ]
    }

    private func loadUnlocked() -> LoadResult {
        var query = baseQuery()
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return .absent }
        guard status == errSecSuccess,
              let data = item as? Data,
              let ledger = try? PersistedPairingAttempts.decode(data)
        else { return .unreadable }
        return .stored(ledger)
    }
}
#endif
