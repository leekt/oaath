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
import Foundation

/// `NATIVE_DISPLAY_PAYLOAD_LENGTH` in `native/projection.ts`.
public let ownerPhoneMatchCodeLength = 8

/// `OAATH_NATIVE_PROJECTION_VERSION` in `native/projection.ts`.
public let ownerPhoneProjectionVersion = "oaath.native-projection/v2"

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

/// The consent facts of an `@oaath/protocol` permission request: every fact
/// that determines who receives authority, over which account, and under what
/// limits.
public struct OwnerPhonePermissionScope: Equatable, Sendable {
    public let application: OwnerPhoneApplicationIdentity
    public let account: OwnerPhoneAccountIdentity
    /// The session credential that receives the scoped authority.
    public let operatorCredential: OwnerPhoneCredential
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
        self.chainScope = chainScope
        self.calls = calls
        self.requestedAt = requestedAt
        self.expiresAt = expiresAt
        self.policyValidAfter = policyValidAfter
        self.policyValidUntil = policyValidUntil
        self.perChainOperationLimit = perChainOperationLimit
    }
}

/// One signature request: the relay asks this device's owner key to sign one
/// 32-byte digest. `display` is the server-validated canonical display JSON;
/// the UI renders its exact authenticated bytes before the owner decides. Approving
/// returns the signature as the decision artifact — the artifact IS the
/// signature, released to the client through the one-shot code/artifact flow.
public struct OwnerPhoneSignatureRequestScope: Equatable, Sendable {
    /// Lowercase `0x`-prefixed 32-byte digest the owner key signs on approval.
    public let digest: String
    /// The full display JSON, exactly as the requesting client stored it.
    public let display: String

    public init(digest: String, display: String) {
        self.digest = digest
        self.display = display
    }
}

/// Closed scope union mirroring `OwnerPhoneScopeProjection`. A scope that is
/// not a protocol permission request or a signature request arrives as `.raw`
/// and the UI must show it as an explicit "unstructured scope" state — an
/// unknown `kind` fails closed.
public enum OwnerPhoneScope: Equatable, Sendable {
    case permissionRequest(OwnerPhonePermissionScope)
    case signatureRequest(OwnerPhoneSignatureRequestScope)
    case raw(String)

    /// Whether this scope may be approved at all. A raw scope is reject-only:
    /// the UI never renders an Approve control for authority it could not
    /// read, and the relay refuses such an approval independently.
    public var approvable: Bool {
        switch self {
        case .permissionRequest, .signatureRequest:
            return true
        case .raw:
            return false
        }
    }
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

    private static func decodeScope(_ value: Any?) throws -> OwnerPhoneScope {
        let object = try Wire.object(value, label: "scope")
        switch object["kind"] as? String {
        case "permission-request":
            try Wire.exactKeys(
                object,
                [
                    "kind", "decision", "application", "account", "operatorCredential",
                    "chainScope", "calls", "requestedAt", "expiresAt", "policyValidAfter",
                    "policyValidUntil", "perChainOperationLimit",
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
        case "signature-request":
            try Wire.exactKeys(object, ["kind", "decision", "digest", "display"], label: "scope")
            guard object["decision"] as? String == "approve-or-reject" else {
                throw OwnerPhoneWireError.invalidField("scope decision")
            }
            let digest = try Wire.lowercaseHex(
                object["digest"], byteLength: 32, label: "digest")
            let display = try Wire.text(
                object["display"], maximum: WireLimits.requestedScope, label: "display")
            try validateCanonicalDisplay(display, digest: digest)
            return .signatureRequest(OwnerPhoneSignatureRequestScope(
                digest: digest,
                display: display
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

    /// The server accepts only recursively sorted, compact JSON display bytes.
    /// Re-encoding with the same closed codec rejects duplicate-key collapse,
    /// whitespace/escape drift, and a display that omits or changes the digest.
    private static func validateCanonicalDisplay(_ display: String, digest: String) throws {
        let bytes = Data(display.utf8)
        guard let value = try? JSONSerialization.jsonObject(with: bytes),
              let object = value as? [String: Any],
              object["digest"] as? String == digest,
              let canonical = try? JSONSerialization.data(
                  withJSONObject: object, options: [.sortedKeys]),
              canonical == bytes
        else {
            throw OwnerPhoneWireError.invalidField("display")
        }
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
