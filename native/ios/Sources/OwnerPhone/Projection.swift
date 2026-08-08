/**
 EXPERIMENTAL PREVIEW — the owner-phone consent projection, exactly as the
 relay serves it on `GET /native/projections/{operationId}`.

 Wire truth: `packages/server/src/native/projection.ts`. Two surfaces exist and
 only one of them is opaque:

 - The **push** payload transits Apple and stays opaque: match code, operation
   id, expiry, nothing else (`PushPayload.swift`).
 - This projection travels only the authenticated relay → owner channel, so it
   is the consent surface: it carries the requesting client identity and the
   requested scope. The owner sees exactly the authority they grant before
   deciding. An unstructured scope arrives as an explicitly labeled raw string
   and must be rendered as such — never silently.

 The match code is not a secret and not authority: it lets the owner check by
 eye that the code on the phone is the code the browser shows. Holding it
 authorizes nothing.

 @author taek <leekt216@gmail.com>
 */
import CryptoKit
import Foundation

/// `NATIVE_DISPLAY_PAYLOAD_LENGTH` in `native/projection.ts`.
public let ownerPhoneMatchCodeLength = 8

/// `OAATH_NATIVE_PROJECTION_VERSION` in `native/projection.ts`.
public let ownerPhoneProjectionVersion = "oaath.native-projection/v4"

/// Current protocol versions embedded in the v4 owner-signing projection.
public let ownerPhoneSigningRequestVersion = "oaath.owner-signing-request/v1"
public let ownerPhoneOwnerCredentialVersion = "oaath.owner-credential-profile/v1"

/// The bounded 8-character base64url match code the phone renders.
public struct MatchCode: Equatable, Sendable {
    public let value: String

    public init(_ value: String) throws {
        guard value.count == ownerPhoneMatchCodeLength else {
            throw OwnerPhoneWireError.invalidField("displayPayload")
        }
        for scalar in value.unicodeScalars {
            switch scalar {
            case "A"..."Z", "a"..."z", "0"..."9", "-", "_":
                continue
            default:
                throw OwnerPhoneWireError.invalidField("displayPayload")
            }
        }
        self.value = value
    }

    /// Rendered in two groups of four for comparison by eye: `"ABCD EFGH"`.
    /// The browser shows the same eight characters unspaced.
    public var display: String {
        let middle = value.index(value.startIndex, offsetBy: 4)
        return "\(value[..<middle]) \(value[middle...])"
    }
}

/// The requesting client, exactly as the stored request binds it.
public struct OwnerPhoneClientIdentity: Equatable, Sendable {
    public let clientId: String
    /// Where the released one-time code is delivered after an approval.
    public let redirectUri: String

    public init(clientId: String, redirectUri: String) {
        self.clientId = clientId
        self.redirectUri = redirectUri
    }
}

/// One equality rule on a fixed 32-byte ABI argument word.
public struct OwnerPhoneArgumentEquality: Equatable, Sendable {
    /// Zero-based 32-byte word after the selector.
    public let index: Int
    public let value: String

    public init(index: Int, value: String) {
        self.index = index
        self.value = value
    }
}

/// One permitted call of a structured permission scope: target contract,
/// 4-byte selector, the per-call value limit (canonical decimal uint256), and
/// every supported argument constraint.
public struct OwnerPhonePermittedCall: Equatable, Sendable {
    public let target: String
    public let selector: String
    public let valueLimit: String
    public let argumentEquals: [OwnerPhoneArgumentEquality]

    public init(
        target: String,
        selector: String,
        valueLimit: String,
        argumentEquals: [OwnerPhoneArgumentEquality]
    ) {
        self.target = target
        self.selector = selector
        self.valueLimit = valueLimit
        self.argumentEquals = argumentEquals
    }
}

/// One credential identity as the owner reviews it: public material only.
public enum OwnerPhoneCredential: Equatable, Sendable {
    case ecdsa(address: String)
    case p256(publicKey: String)
    case webauthn(publicKey: String, authenticatorIdHash: String)
}

/// The application identity the signed permission request binds, verbatim.
public struct OwnerPhoneApplicationIdentity: Equatable, Sendable {
    public let applicationId: String
    public let clientId: String
    public let origin: String
    /// Opaque device identity, fingerprinted server-side.
    public let deviceFingerprint: String

    public init(applicationId: String, clientId: String, origin: String, deviceFingerprint: String) {
        self.applicationId = applicationId
        self.clientId = clientId
        self.origin = origin
        self.deviceFingerprint = deviceFingerprint
    }
}

/// The logical account the requested authority acts for.
public struct OwnerPhoneAccountIdentity: Equatable, Sendable {
    public let accountIndex: String
    public let kernelVersion: String
    public let factoryRoute: String
    public let entryPointVersion: String
    public let ownerCredential: OwnerPhoneCredential

    public init(
        accountIndex: String,
        kernelVersion: String,
        factoryRoute: String,
        entryPointVersion: String,
        ownerCredential: OwnerPhoneCredential
    ) {
        self.accountIndex = accountIndex
        self.kernelVersion = kernelVersion
        self.factoryRoute = factoryRoute
        self.entryPointVersion = entryPointVersion
        self.ownerCredential = ownerCredential
    }
}

/// Where the session key lives when it is not the page's own: the remote
/// trust model the owner is asked to approve. The request hash binds it, so
/// approving this display approves exactly this custody.
public struct OwnerPhoneSessionSigner: Equatable, Sendable {
    /// `application_backend` or `oaath_hosted`.
    public let mode: String
    public let providerId: String

    public init(mode: String, providerId: String) {
        self.mode = mode
        self.providerId = providerId
    }
}

/// The consent facts of an `@oaath/protocol` permission request: every fact
/// that determines who receives authority, over which account, and under what
/// limits.
public struct OwnerPhonePermissionScope: Equatable, Sendable {
    public let application: OwnerPhoneApplicationIdentity
    public let account: OwnerPhoneAccountIdentity
    /// The session credential that receives the scoped authority.
    public let operatorCredential: OwnerPhoneCredential
    /// Remote session-key custody, or nil for frontend custody.
    public let sessionSigner: OwnerPhoneSessionSigner?
    /// Pinned `"all"` — the only chain scope the protocol issues in 0.1.0.
    public let chainScope: String
    public let calls: [OwnerPhonePermittedCall]
    public let requestedAt: Int
    /// The permission request's own expiry, as the requesting client stated it.
    public let expiresAt: Int
    /// The policy's on-chain validity window; `policyValidUntil` may be null.
    public let policyValidAfter: Int
    public let policyValidUntil: Int?
    public let perChainOperationLimit: Int

    public init(
        application: OwnerPhoneApplicationIdentity,
        account: OwnerPhoneAccountIdentity,
        operatorCredential: OwnerPhoneCredential,
        sessionSigner: OwnerPhoneSessionSigner?,
        chainScope: String,
        calls: [OwnerPhonePermittedCall],
        requestedAt: Int,
        expiresAt: Int,
        policyValidAfter: Int,
        policyValidUntil: Int?,
        perChainOperationLimit: Int
    ) {
        self.application = application
        self.account = account
        self.operatorCredential = operatorCredential
        self.sessionSigner = sessionSigner
        self.chainScope = chainScope
        self.calls = calls
        self.requestedAt = requestedAt
        self.expiresAt = expiresAt
        self.policyValidAfter = policyValidAfter
        self.policyValidUntil = policyValidUntil
        self.perChainOperationLimit = perChainOperationLimit
    }
}

/// The protocol-versioned owner credential bound into an owner-signing
/// request. The nested credential is public material only.
public struct OwnerPhoneSigningCredential: Equatable, Sendable {
    public let version: String
    public let credential: OwnerPhoneCredential

    init(version: String, credential: OwnerPhoneCredential) {
        self.version = version
        self.credential = credential
    }
}

public enum OwnerPhoneSigningPurpose: String, Equatable, Sendable {
    case permit
    case permit2
    case application
    case kernelEnable = "kernel-enable"
}

public struct OwnerPhoneSigningSigner: Equatable, Sendable {
    public let account: String
    public let ownerCredential: OwnerPhoneSigningCredential

    init(account: String, ownerCredential: OwnerPhoneSigningCredential) {
        self.account = account
        self.ownerCredential = ownerCredential
    }
}

public struct OwnerPhoneSigningReplayFacts: Equatable, Sendable {
    public let nonce: String?
    public let deadline: String?

    init(nonce: String?, deadline: String?) {
        self.nonce = nonce
        self.deadline = deadline
    }
}

/// A fully captured semantic EIP-712 request. `digestComparison` is neutral
/// evidence derived by this device; it grants no signing or approval authority.
public struct OwnerPhoneEIP712SigningRequest: Equatable, Sendable {
    public let version: String
    public let purpose: OwnerPhoneSigningPurpose
    public let signer: OwnerPhoneSigningSigner
    let typedData: CanonicalEIP712TypedData
    public let expectedDigest: String
    let digestComparison: EIP712DigestComparison
    public let replay: OwnerPhoneSigningReplayFacts

    init(
        version: String,
        purpose: OwnerPhoneSigningPurpose,
        signer: OwnerPhoneSigningSigner,
        typedData: CanonicalEIP712TypedData,
        expectedDigest: String,
        digestComparison: EIP712DigestComparison,
        replay: OwnerPhoneSigningReplayFacts
    ) {
        self.version = version
        self.purpose = purpose
        self.signer = signer
        self.typedData = typedData
        self.expectedDigest = expectedDigest
        self.digestComparison = digestComparison
        self.replay = replay
    }
}

/// A protocol raw digest stays readable solely to explain why it must be
/// rejected. It is never converted into device-derived digest evidence.
public struct OwnerPhoneRawDigestSigningRequest: Equatable, Sendable {
    public let version: String
    public let digest: String
    public let reason: String

    init(version: String, digest: String, reason: String) {
        self.version = version
        self.digest = digest
        self.reason = reason
    }
}

public enum OwnerPhoneSigningRequest: Equatable, Sendable {
    case eip712(OwnerPhoneEIP712SigningRequest)
    case rawDigest(OwnerPhoneRawDigestSigningRequest)
}

/// The one closed discriminator used by both the consent surface and the
/// approval action. Kernel owner signing is available only when authenticated
/// wire semantics and the separately injected local binding both agree.
enum OwnerPhoneApprovalAvailability: Equatable, Sendable {
    case permission
    case kernelP256OwnerSigning
    case rejectOnly
}

/// Authenticated wire semantics only. The decoder grants `.approveOrReject`
/// solely after the exact Kernel/P-256 request has passed local semantic
/// refinement; this never embeds custody capability in wire evidence.
enum OwnerPhoneSigningDecisionCapability: Equatable, Sendable {
    case rejectOnly
    case approveOrReject
}

/// The server/protocol request commitment plus its exact captured request.
/// `requestHash` is authenticated projection evidence; this device does not
/// independently reproduce `hashOwnerSigningRequest` in this child.
public struct OwnerPhoneSigningRequestScope: Equatable, Sendable {
    public let requestHash: String
    public let request: OwnerPhoneSigningRequest
    let decisionCapability: OwnerPhoneSigningDecisionCapability

    init(
        requestHash: String,
        request: OwnerPhoneSigningRequest,
        decisionCapability: OwnerPhoneSigningDecisionCapability = .rejectOnly
    ) {
        self.requestHash = requestHash
        self.request = request
        self.decisionCapability = decisionCapability
    }
}

/// Closed scope union mirroring `OwnerPhoneScopeProjection`. A scope that is
/// not a protocol permission request or an owner-signing request arrives as `.raw`
/// and the UI must show it as an explicit "unstructured scope" state — an
/// unknown `kind` fails closed.
public enum OwnerPhoneScope: Equatable, Sendable {
    case permissionRequest(OwnerPhonePermissionScope)
    case ownerSigningRequest(OwnerPhoneSigningRequestScope)
    case raw(String)
}

/// Mirrors `OwnerPhoneRequestProjection` in `native/projection.ts`.
public struct OwnerPhoneRequestProjection: Equatable, Sendable {
    /// Stable across every projection of the same request, and the key the
    /// approve/reject saga is keyed by.
    public let operationId: String
    /// Wire field `displayPayload`.
    public let matchCode: MatchCode
    /// The stored request's expiry, in epoch milliseconds.
    public let expiresAt: Int
    public let client: OwnerPhoneClientIdentity
    public let scope: OwnerPhoneScope

    public init(
        operationId: String,
        matchCode: MatchCode,
        expiresAt: Int,
        client: OwnerPhoneClientIdentity,
        scope: OwnerPhoneScope
    ) {
        self.operationId = operationId
        self.matchCode = matchCode
        self.expiresAt = expiresAt
        self.client = client
        self.scope = scope
    }

    /// Strict decode of the relay's JSON consent projection: exactly
    /// `{version, operationId, displayPayload, expiresAt, client, scope}`.
    public static func decode(_ data: Data) throws -> OwnerPhoneRequestProjection {
        let object = try Wire.object(data, label: "owner phone projection")
        try Wire.exactKeys(
            object,
            ["version", "operationId", "displayPayload", "expiresAt", "client", "scope"],
            label: "owner phone projection")
        guard object["version"] as? String == ownerPhoneProjectionVersion else {
            throw OwnerPhoneWireError.invalidField("version")
        }
        return OwnerPhoneRequestProjection(
            operationId: try Wire.identifier(
                object["operationId"], maximum: WireLimits.operationId, label: "operationId"),
            matchCode: try MatchCode(try Wire.text(
                object["displayPayload"], maximum: ownerPhoneMatchCodeLength, label: "displayPayload")),
            expiresAt: try Wire.timestamp(object["expiresAt"], label: "expiresAt"),
            client: try decodeClient(object["client"]),
            scope: try decodeScope(object["scope"])
        )
    }

    private static func decodeClient(_ value: Any?) throws -> OwnerPhoneClientIdentity {
        let object = try Wire.object(value, label: "client")
        try Wire.exactKeys(object, ["clientId", "redirectUri"], label: "client")
        return OwnerPhoneClientIdentity(
            clientId: try Wire.identifier(object["clientId"], label: "clientId"),
            redirectUri: try Wire.text(
                object["redirectUri"], maximum: WireLimits.redirectUri, label: "redirectUri")
        )
    }

    private static func decodeSessionSigner(_ value: Any?) throws -> OwnerPhoneSessionSigner? {
        if value is NSNull { return nil }
        let object = try Wire.object(value, label: "sessionSigner")
        try Wire.exactKeys(object, ["mode", "providerId"], label: "sessionSigner")
        guard let mode = object["mode"] as? String,
            mode == "application_backend" || mode == "oaath_hosted"
        else {
            throw OwnerPhoneWireError.invalidField("sessionSigner mode")
        }
        return OwnerPhoneSessionSigner(
            mode: mode,
            providerId: try Wire.text(
                object["providerId"], maximum: WireLimits.identifier, label: "sessionSigner providerId"))
    }

    private static func decodeScope(_ value: Any?) throws -> OwnerPhoneScope {
        let object = try Wire.object(value, label: "scope")
        switch object["kind"] as? String {
        case "permission-request":
            try Wire.exactKeys(
                object,
                [
                    "kind", "decision", "application", "account", "operatorCredential",
                    "sessionSigner", "chainScope", "calls", "requestedAt", "expiresAt",
                    "policyValidAfter", "policyValidUntil", "perChainOperationLimit",
                ],
                label: "scope")
            guard object["decision"] as? String == "approve-or-reject" else {
                throw OwnerPhoneWireError.invalidField("scope decision")
            }
            guard object["chainScope"] as? String == "all" else {
                throw OwnerPhoneWireError.invalidField("chainScope")
            }
            guard let entries = object["calls"] as? [Any], !entries.isEmpty else {
                throw OwnerPhoneWireError.invalidField("calls")
            }
            let policyValidUntil: Int?
            if object["policyValidUntil"] is NSNull {
                policyValidUntil = nil
            } else {
                policyValidUntil = try Wire.timestamp(
                    object["policyValidUntil"], label: "policyValidUntil")
            }
            return .permissionRequest(OwnerPhonePermissionScope(
                application: try decodeApplication(object["application"]),
                account: try decodeAccount(object["account"]),
                operatorCredential: try decodeCredential(
                    object["operatorCredential"], label: "operatorCredential"),
                sessionSigner: try decodeSessionSigner(object["sessionSigner"]),
                chainScope: "all",
                calls: try entries.map(decodeCall),
                requestedAt: try Wire.timestamp(object["requestedAt"], label: "requestedAt"),
                expiresAt: try Wire.timestamp(object["expiresAt"], label: "scope expiresAt"),
                policyValidAfter: try Wire.timestamp(
                    object["policyValidAfter"], label: "policyValidAfter"),
                policyValidUntil: policyValidUntil,
                perChainOperationLimit: try Wire.timestamp(
                    object["perChainOperationLimit"], label: "perChainOperationLimit")
            ))
        case "owner-signing-request":
            try Wire.exactKeys(
                object,
                ["kind", "decision", "requestHash", "request"],
                label: "scope")
            guard let decision = object["decision"] as? String,
                  decision == "reject-only" || decision == "approve-or-reject"
            else {
                throw OwnerPhoneWireError.invalidField("scope decision")
            }
            let captured = OwnerPhoneSigningRequestScope(
                requestHash: try Wire.lowercaseHex(
                    object["requestHash"], byteLength: 32, label: "requestHash"),
                request: try decodeSigningRequest(object["request"]),
                decisionCapability: .rejectOnly
            )
            if decision == "reject-only" {
                return .ownerSigningRequest(captured)
            }
            do {
                _ = try refineKernelEnableSigningScope(captured)
            } catch {
                throw OwnerPhoneWireError.invalidField("scope decision")
            }
            return .ownerSigningRequest(OwnerPhoneSigningRequestScope(
                requestHash: captured.requestHash,
                request: captured.request,
                decisionCapability: .approveOrReject
            ))
        case "raw":
            try Wire.exactKeys(object, ["kind", "decision", "text"], label: "scope")
            guard object["decision"] as? String == "reject-only" else {
                throw OwnerPhoneWireError.invalidField("scope decision")
            }
            return .raw(try Wire.text(
                object["text"], maximum: WireLimits.requestedScope, label: "scope text"))
        default:
            // A scope kind this build does not know is contradictory evidence,
            // never something to render partially.
            throw OwnerPhoneWireError.invalidField("scope kind")
        }
    }

    private static func decodeApplication(_ value: Any?) throws -> OwnerPhoneApplicationIdentity {
        let object = try Wire.object(value, label: "scope application")
        try Wire.exactKeys(
            object,
            ["applicationId", "clientId", "origin", "deviceFingerprint"],
            label: "scope application")
        return OwnerPhoneApplicationIdentity(
            applicationId: try Wire.identifier(object["applicationId"], label: "applicationId"),
            clientId: try Wire.identifier(object["clientId"], label: "scope clientId"),
            origin: try Wire.text(
                object["origin"], maximum: WireLimits.redirectUri, label: "origin"),
            deviceFingerprint: try Wire.text(
                object["deviceFingerprint"],
                maximum: ownerPhoneMatchCodeLength,
                label: "deviceFingerprint")
        )
    }

    private static func decodeAccount(_ value: Any?) throws -> OwnerPhoneAccountIdentity {
        let object = try Wire.object(value, label: "scope account")
        try Wire.exactKeys(
            object,
            ["accountIndex", "kernelVersion", "factoryRoute", "entryPointVersion", "ownerCredential"],
            label: "scope account")
        guard object["kernelVersion"] as? String == "0.4.0" else {
            throw OwnerPhoneWireError.invalidField("kernelVersion")
        }
        let factoryRoute = object["factoryRoute"] as? String
        guard factoryRoute == "kernel_factory" || factoryRoute == "meta_factory" else {
            throw OwnerPhoneWireError.invalidField("factoryRoute")
        }
        guard object["entryPointVersion"] as? String == "0.7" else {
            throw OwnerPhoneWireError.invalidField("entryPointVersion")
        }
        return OwnerPhoneAccountIdentity(
            accountIndex: try Wire.decimalUint(object["accountIndex"], label: "accountIndex"),
            kernelVersion: "0.4.0",
            factoryRoute: factoryRoute ?? "kernel_factory",
            entryPointVersion: "0.7",
            ownerCredential: try decodeCredential(
                object["ownerCredential"], label: "ownerCredential")
        )
    }

    private static func decodeCredential(
        _ value: Any?, label: String
    ) throws -> OwnerPhoneCredential {
        let object = try Wire.object(value, label: label)
        switch object["kind"] as? String {
        case "ecdsa":
            try Wire.exactKeys(object, ["kind", "address"], label: label)
            return .ecdsa(address: try Wire.lowercaseHex(
                object["address"], byteLength: 20, label: "\(label) address"))
        case "p256":
            try Wire.exactKeys(object, ["kind", "publicKey"], label: label)
            return .p256(publicKey: try Wire.lowercaseHex(
                object["publicKey"], byteLength: 65, label: "\(label) publicKey"))
        case "webauthn":
            try Wire.exactKeys(object, ["kind", "publicKey", "authenticatorIdHash"], label: label)
            return .webauthn(
                publicKey: try Wire.lowercaseHex(
                    object["publicKey"], byteLength: 65, label: "\(label) publicKey"),
                authenticatorIdHash: try Wire.lowercaseHex(
                    object["authenticatorIdHash"], byteLength: 32,
                    label: "\(label) authenticatorIdHash"))
        default:
            throw OwnerPhoneWireError.invalidField("\(label) kind")
        }
    }

    private static func decodeSigningRequest(_ value: Any?) throws -> OwnerPhoneSigningRequest {
        let object = try Wire.object(value, label: "owner signing request")
        switch object["kind"] as? String {
        case "eip712":
            try Wire.exactKeys(
                object,
                ["version", "kind", "purpose", "signer", "typedData", "expectedDigest", "replay"],
                label: "owner signing request")
            guard object["version"] as? String == ownerPhoneSigningRequestVersion,
                  let purposeText = object["purpose"] as? String,
                  let purpose = OwnerPhoneSigningPurpose(rawValue: purposeText)
            else {
                throw OwnerPhoneWireError.invalidField("owner signing request version or purpose")
            }
            let expectedDigest = try Wire.lowercaseHex(
                object["expectedDigest"], byteLength: 32, label: "expectedDigest")
            let typedData: CanonicalEIP712TypedData
            let derived: DerivedEIP712Digest
            do {
                guard let semanticValue = object["typedData"] else {
                    throw OwnerPhoneWireError.invalidField("typedData")
                }
                typedData = try captureCanonicalEIP712TypedData(jsonValue: semanticValue)
                derived = try deriveEIP712Digest(from: typedData)
            } catch {
                throw OwnerPhoneWireError.invalidField("typedData")
            }
            let comparison: EIP712DigestComparison = derived.canonicalHex == expectedDigest
                ? .matches(derived)
                : .mismatch(expectedCanonicalHex: expectedDigest, derived: derived)
            return .eip712(OwnerPhoneEIP712SigningRequest(
                version: ownerPhoneSigningRequestVersion,
                purpose: purpose,
                signer: try decodeSigningSigner(object["signer"]),
                typedData: typedData,
                expectedDigest: expectedDigest,
                digestComparison: comparison,
                replay: try decodeSigningReplay(object["replay"])
            ))
        case "raw-digest":
            try Wire.exactKeys(
                object,
                ["version", "kind", "digest", "reason", "decision"],
                label: "owner signing request")
            guard object["version"] as? String == ownerPhoneSigningRequestVersion,
                  object["decision"] as? String == "reject-only"
            else {
                throw OwnerPhoneWireError.invalidField("owner signing request version or decision")
            }
            return .rawDigest(OwnerPhoneRawDigestSigningRequest(
                version: ownerPhoneSigningRequestVersion,
                digest: try Wire.lowercaseHex(
                    object["digest"], byteLength: 32, label: "raw digest"),
                reason: try Wire.text(
                    object["reason"], maximum: 256, label: "raw digest reason")
            ))
        default:
            throw OwnerPhoneWireError.invalidField("owner signing request kind")
        }
    }

    private static func decodeSigningSigner(_ value: Any?) throws -> OwnerPhoneSigningSigner {
        let object = try Wire.object(value, label: "owner signing signer")
        try Wire.exactKeys(
            object, ["account", "ownerCredential"], label: "owner signing signer")
        let account = try Wire.lowercaseHex(
            object["account"], byteLength: 20, label: "owner signing account")
        guard account != "0x" + String(repeating: "00", count: 20) else {
            throw OwnerPhoneWireError.invalidField("owner signing account")
        }
        return OwnerPhoneSigningSigner(
            account: account,
            ownerCredential: try decodeSigningCredential(object["ownerCredential"])
        )
    }

    private static func decodeSigningCredential(_ value: Any?) throws -> OwnerPhoneSigningCredential {
        let object = try Wire.object(value, label: "owner signing credential")
        guard object["version"] as? String == ownerPhoneOwnerCredentialVersion else {
            throw OwnerPhoneWireError.invalidField("owner signing credential version")
        }
        let credential: OwnerPhoneCredential
        switch object["kind"] as? String {
        case "ecdsa":
            try Wire.exactKeys(
                object, ["version", "kind", "address"], label: "owner signing credential")
            let address = try Wire.lowercaseHex(
                object["address"], byteLength: 20, label: "owner signing credential address")
            guard address != "0x" + String(repeating: "00", count: 20) else {
                throw OwnerPhoneWireError.invalidField("owner signing credential address")
            }
            credential = .ecdsa(address: address)
        case "p256":
            try Wire.exactKeys(
                object, ["version", "kind", "publicKey"], label: "owner signing credential")
            credential = .p256(publicKey: try signingP256PublicKey(object["publicKey"]))
        case "webauthn":
            try Wire.exactKeys(
                object,
                ["version", "kind", "publicKey", "authenticatorIdHash"],
                label: "owner signing credential")
            credential = .webauthn(
                publicKey: try signingP256PublicKey(object["publicKey"]),
                authenticatorIdHash: try Wire.lowercaseHex(
                    object["authenticatorIdHash"],
                    byteLength: 32,
                    label: "owner signing credential authenticatorIdHash"))
        default:
            throw OwnerPhoneWireError.invalidField("owner signing credential kind")
        }
        return OwnerPhoneSigningCredential(
            version: ownerPhoneOwnerCredentialVersion,
            credential: credential)
    }

    private static func signingP256PublicKey(_ value: Any?) throws -> String {
        let publicKey = try Wire.lowercaseHex(
            value, byteLength: 65, label: "owner signing credential publicKey")
        guard publicKey.hasPrefix("0x04"),
              let bytes = signingHexBytes(publicKey),
              (try? P256.Signing.PublicKey(x963Representation: Data(bytes))) != nil
        else {
            throw OwnerPhoneWireError.invalidField("owner signing credential publicKey")
        }
        return publicKey
    }

    private static func signingHexBytes(_ value: String) -> [UInt8]? {
        let source = Array(value.utf8.dropFirst(2))
        guard source.count.isMultiple(of: 2) else { return nil }
        var result = [UInt8]()
        result.reserveCapacity(source.count / 2)
        var index = 0
        while index < source.count {
            func nibble(_ byte: UInt8) -> UInt8? {
                if (48...57).contains(byte) { return byte - 48 }
                if (97...102).contains(byte) { return byte - 87 }
                return nil
            }
            guard let high = nibble(source[index]), let low = nibble(source[index + 1]) else {
                return nil
            }
            result.append(high << 4 | low)
            index += 2
        }
        return result
    }

    private static func decodeSigningReplay(_ value: Any?) throws -> OwnerPhoneSigningReplayFacts {
        let object = try Wire.object(value, label: "owner signing replay")
        try Wire.exactKeys(object, ["nonce", "deadline"], label: "owner signing replay")
        return OwnerPhoneSigningReplayFacts(
            nonce: try signingDecimalOrNil(object["nonce"], label: "replay nonce"),
            deadline: try signingDecimalOrNil(object["deadline"], label: "replay deadline")
        )
    }

    private static func signingDecimalOrNil(_ value: Any?, label: String) throws -> String? {
        if value is NSNull { return nil }
        let text = try Wire.decimalUint(value, label: label)
        let maximum = "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        guard text.count < maximum.count || (text.count == maximum.count && text <= maximum) else {
            throw OwnerPhoneWireError.invalidField(label)
        }
        return text
    }

    private static func decodeCall(_ value: Any) throws -> OwnerPhonePermittedCall {
        let object = try Wire.object(value, label: "scope call")
        try Wire.exactKeys(
            object, ["target", "selector", "valueLimit", "argumentEquals"], label: "scope call")
        guard let rules = object["argumentEquals"] as? [Any] else {
            throw OwnerPhoneWireError.invalidField("argumentEquals")
        }
        return OwnerPhonePermittedCall(
            target: try Wire.lowercaseHex(object["target"], byteLength: 20, label: "target"),
            selector: try Wire.lowercaseHex(object["selector"], byteLength: 4, label: "selector"),
            valueLimit: try Wire.decimalUint(object["valueLimit"], label: "valueLimit"),
            argumentEquals: try rules.map(decodeArgumentEquality)
        )
    }

    private static func decodeArgumentEquality(_ value: Any) throws -> OwnerPhoneArgumentEquality {
        let object = try Wire.object(value, label: "argument rule")
        try Wire.exactKeys(object, ["index", "value"], label: "argument rule")
        return OwnerPhoneArgumentEquality(
            index: try Wire.timestamp(object["index"], label: "argument rule index"),
            value: try Wire.lowercaseHex(object["value"], byteLength: 32, label: "argument rule value")
        )
    }
}
