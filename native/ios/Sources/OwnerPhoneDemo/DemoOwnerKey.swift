/**
 EXPERIMENTAL PREVIEW — the demo's owner P-256 key: real custody, real bytes.

 First use creates the key once and keeps it. On a physical iPhone the key is
 created INSIDE the Secure Enclave
 (`kSecAttrTokenIDSecureEnclave`, `.privateKeyUsage`, no biometry requirement
 for the demo — the explicit Approve tap is the consent gate). Where the
 simulator and macOS host builds use an ordinary, separately tagged keychain
 P-256 key and say so honestly:
 `secureEnclave` drives the app's banner, never a silent downgrade.

 The public key is exposed as the SDK's `publicMaterial` encoding —
 `abi.encode(x, y)`, 64 bytes — which is exactly what the relay registers at
 pairing and what the pinned Kernel P-256 validator installs. The demo app
 exposes no raw-digest signing API: legacy network digest projections are
 reject-only until a device-derived verified-signable type exists.

 @author taek <leekt216@gmail.com>
 */
import Foundation
import OwnerPhone
import Security

#if canImport(Security)
public protocol DemoOwnerSigning: Sendable {
    var secureEnclave: Bool { get }
    func publicMaterialHex() throws -> String
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

}

enum DemoOwnerKeyEnvironment: Equatable {
    case physicalIOS
    case simulatorOrHost

    static var current: Self {
        #if os(iOS) && !targetEnvironment(simulator)
        return .physicalIOS
        #else
        return .simulatorOrHost
        #endif
    }
}

enum DemoOwnerKeyStorage: Equatable {
    case secureEnclave
    case softwareFallback
}

/// Pure policy seam: physical iOS has no transition from an Enclave failure
/// to software custody. Simulator/macOS use the explicitly separate fallback.
func resolveDemoOwnerKey<Value>(
    environment: DemoOwnerKeyEnvironment,
    createIfMissing: Bool,
    load: (DemoOwnerKeyStorage, Bool) -> Value?
) -> Value? {
    switch environment {
    case .physicalIOS:
        return load(.secureEnclave, createIfMissing)
    case .simulatorOrHost:
        return load(.softwareFallback, createIfMissing)
    }
}

/// Resolves the one platform-authorized owner key once per launch. Each
/// persisted security artifact has a versioned, custody-specific tag.
public func resolveDemoOwnerKey(createIfMissing: Bool = true) -> DemoOwnerKey? {
    resolveDemoOwnerKey(
        environment: .current,
        createIfMissing: createIfMissing
    ) { storage, mayCreate in
        let applicationTag: String
        let useSecureEnclave: Bool
        let secureEnclave: Bool
        switch storage {
        case .secureEnclave:
            applicationTag = "org.oaath.owner-phone.p256.v2.enclave"
            useSecureEnclave = true
            secureEnclave = true
        case .softwareFallback:
            applicationTag = "org.oaath.owner-phone.p256.v2.software"
            useSecureEnclave = false
            secureEnclave = false
        }
        let probe = KeychainKeyCustodyStub(
            applicationTag: applicationTag,
            useSecureEnclave: useSecureEnclave,
            createIfMissing: mayCreate)
        guard (try? probe.publicKey()) != nil else { return nil }
        // Once resolved, every later public-key read and signature is
        // load-only. Deletion or unreadability fails instead of rotating keys.
        let loadOnly = KeychainKeyCustodyStub(
            applicationTag: applicationTag,
            useSecureEnclave: useSecureEnclave,
            createIfMissing: false)
        return DemoOwnerKey(custody: loadOnly, secureEnclave: secureEnclave)
    }
}
#endif
