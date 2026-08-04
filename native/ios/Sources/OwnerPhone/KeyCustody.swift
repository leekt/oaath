/**
 EXPERIMENTAL PREVIEW — owner key custody scaffold. No physical-device proof.

 This is the interface a future owner-credential composition will consume, plus
 one keychain-backed stub. Honest limits, per the program's deferral of
 production qualification:

 - No physical Secure Enclave behavior is proven anywhere in this repository.
   `useSecureEnclave` defaults to `false`; flipping it on requires a
   provisioned physical device — simulators and macOS test hosts prove nothing.
   The demo app probes it at first launch and falls back honestly
   (`OwnerPhoneDemo/DemoOwnerKey.swift`).
 - Signatures are returned in the platform's DER form. ECDSA normalization
   (raw r‖s, low-S) is owned by `Signing.swift`, mirroring the SDK's
   `kernel/key/p256.ts` rule; the demo key applies it before any byte leaves
   the device.
 - Nothing here composes an operation, account, or chain; the custody boundary
   signs only a caller-supplied, already-domain-separated 32-byte digest.

 @author taek <leekt216@gmail.com>
 */
import Foundation
#if canImport(Security)
import Security
#endif

public enum OwnerPhoneKeyCustodyError: Error, Equatable, Sendable {
    case invalidDigest
    case keyCreationFailed
    case keyUnavailable
    case signatureFailed
}

/// Custody of the owner's P-256 credential: create-once, non-exportable,
/// sign-a-digest. WebAuthn-style user verification wraps this boundary later.
public protocol OwnerPhoneKeyCustody: Sendable {
    /// X9.63 uncompressed public key (65 bytes, leading 0x04).
    func publicKey() throws -> Data
    /// Signs one already-domain-separated 32-byte digest; returns DER ECDSA.
    func signDigest(_ digest: Data) throws -> Data
}

#if canImport(Security)
/// Keychain-backed stub. On a provisioned physical iOS device with
/// `useSecureEnclave: true` the private key is created inside the Secure
/// Enclave; everywhere else it is a non-extractable, non-synchronizable
/// keychain key available only while this device is unlocked. The demo
/// intentionally requires no biometry or user-presence prompt: its explicit
/// Approve tap is the consent gate. Neither mode is production-qualified.
public struct KeychainKeyCustodyStub: OwnerPhoneKeyCustody {
    public let applicationTag: Data
    public let useSecureEnclave: Bool

    public init(
        applicationTag: String = "org.oaath.owner-phone.p256",
        useSecureEnclave: Bool = false
    ) {
        self.applicationTag = Data(applicationTag.utf8)
        self.useSecureEnclave = useSecureEnclave
    }

    public func publicKey() throws -> Data {
        let privateKey = try ensureKey()
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw OwnerPhoneKeyCustodyError.keyUnavailable
        }
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(publicKey, &error) as Data?,
              data.count == 65,
              data.first == 0x04
        else {
            throw OwnerPhoneKeyCustodyError.keyUnavailable
        }
        return data
    }

    public func signDigest(_ digest: Data) throws -> Data {
        // Validated before any keychain access, so a malformed digest never
        // triggers a user-presence prompt.
        guard digest.count == 32 else {
            throw OwnerPhoneKeyCustodyError.invalidDigest
        }
        let privateKey = try ensureKey()
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureDigestX962SHA256,
            digest as CFData,
            &error
        ) as Data? else {
            throw OwnerPhoneKeyCustodyError.signatureFailed
        }
        return signature
    }

    static func softwarePrivateKeyAttributes(applicationTag: Data) -> [CFString: Any] {
        [
            kSecAttrIsPermanent: true,
            kSecAttrApplicationTag: applicationTag,
            kSecAttrIsExtractable: false,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
    }

    private func ensureKey() throws -> SecKey {
        if let existing = try loadKey() {
            return existing
        }
        var privateKeyAttributes = Self.softwarePrivateKeyAttributes(
            applicationTag: applicationTag)
        var attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256
        ]
        if useSecureEnclave {
            var accessError: Unmanaged<CFError>?
            // `.privateKeyUsage` only, no biometry/user-presence requirement:
            // the demo's explicit Approve tap is the consent gate, and a
            // presence prompt on top of it would double-ask. A production
            // deployment adds `.userPresence`/biometry policy here.
            guard let access = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage],
                &accessError
            ) else {
                throw OwnerPhoneKeyCustodyError.keyCreationFailed
            }
            attributes[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave
            // Access control owns accessibility for Enclave items; software
            // fallback keeps the direct kSecAttrAccessible attribute above.
            privateKeyAttributes.removeValue(forKey: kSecAttrAccessible)
            privateKeyAttributes[kSecAttrAccessControl] = access
        }
        attributes[kSecPrivateKeyAttrs] = privateKeyAttributes
        var error: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(attributes as CFDictionary, &error) != nil else {
            throw OwnerPhoneKeyCustodyError.keyCreationFailed
        }
        // Re-read through the same attribute checks used on every later load.
        // A backend that ignored either custody attribute fails closed.
        guard let established = try loadKey() else {
            throw OwnerPhoneKeyCustodyError.keyCreationFailed
        }
        return established
    }

    private func loadKey() throws -> SecKey? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag: applicationTag,
            kSecReturnRef: true,
            kSecMatchLimit: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let item else {
            throw OwnerPhoneKeyCustodyError.keyUnavailable
        }
        // swiftlint:disable:next force_cast
        let key = item as! SecKey
        guard let attributes = SecKeyCopyAttributes(key) as? [CFString: Any],
              attributes[kSecAttrIsExtractable] as? Bool == false
        else {
            throw OwnerPhoneKeyCustodyError.keyUnavailable
        }
        // Query the keychain item's accessibility separately: SecKey attributes
        // do not consistently expose it on every supported host.
        let accessQuery: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag: applicationTag,
            kSecReturnAttributes: true,
            kSecMatchLimit: kSecMatchLimitOne
        ]
        var accessItem: CFTypeRef?
        guard SecItemCopyMatching(accessQuery as CFDictionary, &accessItem) == errSecSuccess,
              let stored = accessItem as? [CFString: Any],
              stored[kSecAttrAccessible] as? String == kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String
        else {
            throw OwnerPhoneKeyCustodyError.keyUnavailable
        }
        return key
    }
}
#endif
