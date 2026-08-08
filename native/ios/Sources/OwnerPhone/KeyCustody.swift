/**
 EXPERIMENTAL PREVIEW — owner key custody scaffold. No physical-device proof.

 This is the interface a future owner-credential composition will consume, plus
 one keychain-backed stub. Honest limits, per the program's deferral of
 production qualification:

 - No physical Secure Enclave behavior is proven anywhere in this repository.
   `useSecureEnclave` defaults to `false`; flipping it on requires a
   provisioned physical device — simulators and macOS test hosts prove nothing.
   The demo app selects it exclusively on physical iOS and fails closed if it
   cannot be created or loaded; only simulator and host builds select software
   custody (`OwnerPhoneDemo/DemoOwnerKey.swift`).
 - Secure Enclave signing requires the platform's user-presence policy in
   addition to private-key usage. The physical prompt itself still requires
   device evidence; host tests can pin only the creation policy.
 - Signatures are returned in the platform's DER form. ECDSA normalization
   (raw r‖s, low-S) is owned by `Signing.swift`, mirroring the SDK's
   `kernel/key/p256.ts` rule.
 - Nothing here composes an operation, account, or chain. This low-level
   scaffold is not reachable from the native network-request approval path;
   custody accepts only the device-derived verified-signable type, while the
   live v3 projection remains reject-only.

 @author taek <leekt216@gmail.com>
 */
import Foundation
#if canImport(Security)
import Security
#endif

public enum OwnerPhoneKeyCustodyError: Error, Equatable, Sendable {
    case keyCreationFailed
    case keyUnavailable
    case signatureFailed
}

/// Custody of the owner's persistent platform P-256 credential. Secure Enclave
/// instances are non-exportable; the simulator/host key is only a device-local
/// keychain development fallback. This low-level primitive is not authority to
/// sign a network-supplied digest; the app has no such approval path.
public protocol OwnerPhoneKeyCustody: Sendable {
    /// X9.63 uncompressed public key (65 bytes, leading 0x04).
    func publicKey() throws -> Data
    /// Signs only an exact request refined by `OwnerPhone`; returns DER ECDSA.
    func sign(_ digest: VerifiedSignableDigest) throws -> Data
}

#if canImport(Security)
/// Keychain-backed stub. On a provisioned physical iOS device with
/// `useSecureEnclave: true` the private key is created inside the Secure
/// Enclave; simulator and host builds use a non-synchronizable keychain key
/// available only while this device is unlocked. The demo
/// requires the platform user-presence policy before each signing effect.
/// Neither mode is production-qualified.
public struct KeychainKeyCustodyStub: OwnerPhoneKeyCustody {
    public let applicationTag: Data
    public let useSecureEnclave: Bool
    /// Provisioning may create once; every returned signing handle is
    /// load-only so missing durable custody can never be silently replaced.
    public let createIfMissing: Bool

    public init(
        applicationTag: String = "org.oaath.owner-phone.p256",
        useSecureEnclave: Bool = false,
        createIfMissing: Bool = true
    ) {
        self.applicationTag = Data(applicationTag.utf8)
        self.useSecureEnclave = useSecureEnclave
        self.createIfMissing = createIfMissing
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

    public func sign(_ digest: VerifiedSignableDigest) throws -> Data {
        let privateKey = try ensureKey()
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureDigestX962SHA256,
            digest.platformSigningBytes as CFData,
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
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
    }

    /// Exact physical-key consent policy. Kept as one owned value so host
    /// evidence can prove the creation flags without claiming a device prompt.
    static let secureEnclaveAccessControlFlags: SecAccessControlCreateFlags = [
        .privateKeyUsage,
        .userPresence
    ]

    /// Host-testable claim check used on creation and every reload. These are
    /// the identity and capability attributes documented for
    /// `SecKeyCopyAttributes`; the exact Secure Enclave token is the physical
    /// key's non-exportability proof. Accessibility is fixed by the access
    /// control used at creation, but is not a documented returned key
    /// attribute and therefore is not used as a reload gate.
    static func keyAttributesMatchClaim(
        _ attributes: [CFString: Any],
        useSecureEnclave: Bool
    ) -> Bool {
        guard attributes[kSecAttrKeyType] as? String
                == kSecAttrKeyTypeECSECPrimeRandom as String,
              attributes[kSecAttrKeyClass] as? String
                == kSecAttrKeyClassPrivate as String,
              let keySize = attributes[kSecAttrKeySizeInBits] as? NSNumber,
              keySize.intValue == 256,
              let canSign = attributes[kSecAttrCanSign] as? NSNumber,
              canSign.boolValue
        else {
            return false
        }
        let tokenValue = attributes[kSecAttrTokenID]
        let token = tokenValue as? String
        if useSecureEnclave {
            return token == kSecAttrTokenIDSecureEnclave as String
        }
        if tokenValue == nil { return true }
        guard let token else { return false }
        return token != kSecAttrTokenIDSecureEnclave as String
    }

    static func privateKeyQuery(applicationTag: Data) -> [CFString: Any] {
        [
            kSecClass: kSecClassKey,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag: applicationTag,
            // Absence authorizes creation, so inventory every candidate and
            // reject ambiguity instead of selecting an arbitrary key.
            kSecMatchLimit: kSecMatchLimitAll
        ]
    }

    private func ensureKey() throws -> SecKey {
        if let existing = try loadKey() {
            return existing
        }
        guard createIfMissing else {
            throw OwnerPhoneKeyCustodyError.keyUnavailable
        }
        let privateKeyAttributes: [CFString: Any]
        var attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256
        ]
        if useSecureEnclave {
            var accessError: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                Self.secureEnclaveAccessControlFlags,
                &accessError
            ) else {
                throw OwnerPhoneKeyCustodyError.keyCreationFailed
            }
            attributes[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave
            // This is Apple's supported iOS Secure Enclave shape. In
            // particular, do not add macOS-only `kSecAttrIsExtractable`.
            privateKeyAttributes = [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: applicationTag,
                kSecAttrAccessControl: access
            ]
        } else {
            privateKeyAttributes = Self.softwarePrivateKeyAttributes(
                applicationTag: applicationTag)
        }
        attributes[kSecPrivateKeyAttrs] = privateKeyAttributes
        var error: Unmanaged<CFError>?
        guard let created = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
              let createdAttributes = SecKeyCopyAttributes(created) as? [CFString: Any],
              Self.keyAttributesMatchClaim(
                createdAttributes,
                useSecureEnclave: useSecureEnclave),
              SecKeyIsAlgorithmSupported(
                created,
                .sign,
                .ecdsaSignatureDigestX962SHA256)
        else {
            throw OwnerPhoneKeyCustodyError.keyCreationFailed
        }
        // `kSecAttrIsPermanent` in the creation dictionary owns persistence.
        // Returning Apple's already-validated handle avoids turning successful
        // creation into a failure through an unnecessary second query.
        return created
    }

    private func loadKey() throws -> SecKey? {
        // The application tag is the stable keychain identity. Token identity
        // is verified on the returned key rather than used as a search filter,
        // matching Apple's documented retrieval shape and recovering keys that
        // were successfully created before a stricter reload rejected them.
        var query = Self.privateKeyQuery(applicationTag: applicationTag)
        query[kSecReturnRef] = true
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess,
              let keys = item as? [SecKey],
              keys.count == 1
        else {
            throw OwnerPhoneKeyCustodyError.keyUnavailable
        }
        let key = keys[0]
        guard let keyAttributes = SecKeyCopyAttributes(key) as? [CFString: Any],
              Self.keyAttributesMatchClaim(
                keyAttributes,
                useSecureEnclave: useSecureEnclave),
              SecKeyIsAlgorithmSupported(
                key,
                .sign,
                .ecdsaSignatureDigestX962SHA256)
        else {
            throw OwnerPhoneKeyCustodyError.keyUnavailable
        }
        return key
    }
}
#endif
