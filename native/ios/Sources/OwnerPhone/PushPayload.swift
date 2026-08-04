/**
 EXPERIMENTAL PREVIEW — closed decode of the OAAth APNs payload.

 Wire truth: `packages/server/src/apns/sender.ts`. The payload transits Apple,
 so by design it carries only the localization keys, the 8-character match
 code as the single `loc-args` element, and `{version, operationId, expiresAt}`
 under `oaath`. Nothing else exists in the payload, and nothing else is
 accepted: any unknown field at any level fails closed, so authority material
 can never ride a notification into this app.

 A push is never authorization. It only tells the app which operation id to
 fetch over its own authenticated channel.

 @author taek <leekt216@gmail.com>
 */
import Foundation

public struct OwnerPhonePush: Equatable, Sendable {
    /// `OAATH_APNS_PAYLOAD_VERSION` in `apns/sender.ts`.
    public static let payloadVersion = "oaath.apns-payload/v1"
    /// `APNS_TITLE_LOC_KEY` / `APNS_BODY_LOC_KEY`: the phone owns every word
    /// the owner reads; the payload carries only these keys.
    public static let titleLocKey = "oaath_approval_title"
    public static let bodyLocKey = "oaath_approval_body"

    public let operationId: String
    public let matchCode: MatchCode
    public let expiresAt: Int

    /// Strict decode of a delivered notification's `userInfo`, exactly the
    /// shape `createApnsSender().notification()` serializes.
    public static func decode(userInfo: [AnyHashable: Any]) throws -> OwnerPhonePush {
        let payload = try Wire.object(userInfo, label: "apns payload")
        try Wire.exactKeys(payload, ["aps", "oaath"], label: "apns payload")

        let aps = try Wire.object(payload["aps"], label: "aps")
        try Wire.exactKeys(aps, ["alert", "sound"], label: "aps")
        guard aps["sound"] as? String == "default" else {
            throw OwnerPhoneWireError.invalidField("sound")
        }

        let alert = try Wire.object(aps["alert"], label: "alert")
        try Wire.exactKeys(alert, ["title-loc-key", "loc-key", "loc-args"], label: "alert")
        guard alert["title-loc-key"] as? String == titleLocKey,
              alert["loc-key"] as? String == bodyLocKey
        else {
            throw OwnerPhoneWireError.invalidField("loc-key")
        }
        guard let locArgs = alert["loc-args"] as? [Any], locArgs.count == 1 else {
            throw OwnerPhoneWireError.invalidField("loc-args")
        }
        let matchCode = try MatchCode(try Wire.text(
            locArgs[0], maximum: ownerPhoneMatchCodeLength, label: "displayPayload"))

        let oaath = try Wire.object(payload["oaath"], label: "oaath")
        try Wire.exactKeys(oaath, ["version", "operationId", "expiresAt"], label: "oaath")
        guard oaath["version"] as? String == payloadVersion else {
            throw OwnerPhoneWireError.invalidField("version")
        }

        return OwnerPhonePush(
            operationId: try Wire.identifier(
                oaath["operationId"], maximum: WireLimits.operationId, label: "operationId"),
            matchCode: matchCode,
            expiresAt: try Wire.timestamp(oaath["expiresAt"], label: "expiresAt")
        )
    }

    /// A push and the authenticated projection must agree exactly; a mismatch
    /// is contradictory evidence and the review fails closed.
    public func matches(_ projection: OwnerPhoneRequestProjection) -> Bool {
        operationId == projection.operationId
            && matchCode == projection.matchCode
            && expiresAt == projection.expiresAt
    }
}
