/**
 EXPERIMENTAL PREVIEW — the demo's owner P-256 key: real custody, real bytes.

 First use creates the key once and keeps it; the private key never leaves its
 store. On a physical iPhone the key is created INSIDE the Secure Enclave
 (`kSecAttrTokenIDSecureEnclave`, `.privateKeyUsage`, no biometry requirement
 for the demo — the explicit Approve tap is the consent gate). Where the
 Enclave is unavailable (simulator, macOS test host) the same code falls back
 to an ordinary non-synchronizable keychain P-256 key and says so honestly:
 `secureEnclave` drives the app's banner, never a silent downgrade.

 The public key is exposed as the SDK's `publicMaterial` encoding —
 `abi.encode(x, y)`, 64 bytes — which is exactly what the relay registers at
 pairing and what the pinned Kernel P-256 validator installs. Signatures are
 DER from the platform, converted to raw r‖s and low-S-normalized
 (`OwnerPhone/Signing.swift`) before leaving the device, for BOTH consent
 flows: the Kernel replayable enable digest and a UserOperation hash.

 @author taek <leekt216@gmail.com>
 */
import Foundation
import OwnerPhone

#if canImport(Security)
public protocol DemoOwnerSigning: Sendable {
    var secureEnclave: Bool { get }
    func publicMaterialHex() throws -> String
    func signDigestHex(_ digestHex: String) throws -> String
}

public struct DemoOwnerKey: DemoOwnerSigning, Sendable {
    let custody: KeychainKeyCustodyStub
    /// True when the private key lives inside the Secure Enclave; false is the
    /// honest simulator/host fallback the UI must banner.
    public let secureEnclave: Bool

    init(custody: KeychainKeyCustodyStub, secureEnclave: Bool) {
        self.custody = custody
        self.secureEnclave = secureEnclave
    }

    /// The SDK's `publicMaterial` for a raw P-256 owner: `0x` + x ‖ y, 64
    /// bytes, dropping the X9.63 `0x04` prefix.
    public func publicMaterialHex() throws -> String {
        hexEncode(try custody.publicKey().dropFirst())
    }

    /// Signs one lowercase `0x`-prefixed 32-byte digest and returns the
    /// normalized raw low-S signature as `0x` + 128 hex characters.
    public func signDigestHex(_ digestHex: String) throws -> String {
        let der = try custody.signDigest(try decodeDigestHex(digestHex))
        return hexEncode(try p256LowSNormalized(raw: try p256RawSignature(der: der)))
    }
}

/// Resolves the demo owner key once per launch: try the Secure Enclave first,
/// fall back to a plain keychain key under a distinct tag. The probe is a real
/// key load/creation, so "enclave" is evidence, not a capability guess.
public func resolveDemoOwnerKey() -> DemoOwnerKey? {
    let enclave = KeychainKeyCustodyStub(
        applicationTag: "org.oaath.owner-phone.p256",
        useSecureEnclave: true)
    if (try? enclave.publicKey()) != nil {
        return DemoOwnerKey(custody: enclave, secureEnclave: true)
    }
    let fallback = KeychainKeyCustodyStub(
        applicationTag: "org.oaath.owner-phone.p256.fallback",
        useSecureEnclave: false)
    if (try? fallback.publicKey()) != nil {
        return DemoOwnerKey(custody: fallback, secureEnclave: false)
    }
    return nil
}
#endif
