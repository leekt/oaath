/**
 EXPERIMENTAL PREVIEW — the owner-phone request projection, exactly as the
 relay sends it.

 Wire truth: `packages/server/src/native/projection.ts`. The projection is
 deliberately opaque — a stable `operationId`, an 8-character derived match
 code, and the request's own expiry. No permission, scope, client, chain, or
 account detail exists in it by design, so none is modeled here.

 The match code is not a secret and not authority: it lets the owner check by
 eye that the code on the phone is the code the browser shows. Holding it
 authorizes nothing.

 @author taek <leekt216@gmail.com>
 */
import Foundation

/// `NATIVE_DISPLAY_PAYLOAD_LENGTH` in `native/projection.ts`.
public let ownerPhoneMatchCodeLength = 8

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

/// Mirrors `OwnerPhoneRequestProjection` in `native/projection.ts`.
public struct OwnerPhoneRequestProjection: Equatable, Sendable {
    /// Stable across every projection of the same request, and the key the
    /// approve/reject saga is keyed by.
    public let operationId: String
    /// Wire field `displayPayload`.
    public let matchCode: MatchCode
    /// The stored request's expiry, in epoch milliseconds.
    public let expiresAt: Int

    public init(operationId: String, matchCode: MatchCode, expiresAt: Int) {
        self.operationId = operationId
        self.matchCode = matchCode
        self.expiresAt = expiresAt
    }

    /// Strict decode of the relay's JSON projection: exactly
    /// `{operationId, displayPayload, expiresAt}`, nothing else.
    public static func decode(_ data: Data) throws -> OwnerPhoneRequestProjection {
        let object = try Wire.object(data, label: "owner phone projection")
        try Wire.exactKeys(object, ["operationId", "displayPayload", "expiresAt"], label: "owner phone projection")
        return OwnerPhoneRequestProjection(
            operationId: try Wire.identifier(
                object["operationId"], maximum: WireLimits.operationId, label: "operationId"),
            matchCode: try MatchCode(try Wire.text(
                object["displayPayload"], maximum: ownerPhoneMatchCodeLength, label: "displayPayload")),
            expiresAt: try Wire.timestamp(object["expiresAt"], label: "expiresAt")
        )
    }
}
