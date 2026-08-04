/**
 EXPERIMENTAL PREVIEW — owner key custody scaffold. No physical-device proof.

 This is the interface a future owner-credential composition will consume, plus
 one keychain-backed stub. Honest limits, per the program's deferral of
 production qualification:

 - No physical Secure Enclave behavior is proven anywhere in this repository.
   `useSecureEnclave` defaults to `false`; flipping it on requires a
   provisioned physical device — simulators and macOS test hosts prove nothing.
 - Signatures are returned in the platform's DER form. ECDSA normalization
   (P1363 r||s, low-S) belongs to the composition that consumes the signature
   and is deliberately absent: no oaath consumer for it exists yet.
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
/// Enclave and protected by user presence; everywhere else it is an ordinary
/// non-synchronizable keychain key. Neither mode is production-qualified.
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

    private func ensureKey() throws -> SecKey {
        if let existing = try loadKey() {
            return existing
        }
        var privateKeyAttributes: [CFString: Any] = [
            kSecAttrIsPermanent: true,
            kSecAttrApplicationTag: applicationTag
        ]
        var attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256
        ]
        if useSecureEnclave {
            var accessError: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage, .userPresence],
                &accessError
            ) else {
                throw OwnerPhoneKeyCustodyError.keyCreationFailed
            }
            attributes[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave
            privateKeyAttributes[kSecAttrAccessControl] = access
        }
        attributes[kSecPrivateKeyAttrs] = privateKeyAttributes
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw OwnerPhoneKeyCustodyError.keyCreationFailed
        }
        return key
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
        return (item as! SecKey)
    }
}
#endif
