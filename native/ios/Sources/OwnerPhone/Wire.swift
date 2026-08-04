/**
 EXPERIMENTAL PREVIEW — strict wire capture for the owner-phone previews.

 Every relay and APNs input is hostile until captured exactly once: closed
 objects, exact key sets, bounded control-character-free text, URL-safe
 identifiers, and safe-integer timestamps mirroring
 `packages/server/src/store/records.ts`. Unknown fields fail closed.

 Machine decisions use the structured `OwnerPhoneWireError` discriminants,
 never message text.

 @author taek <leekt216@gmail.com>
 */
import Foundation

public enum OwnerPhoneWireError: Error, Equatable, Sendable {
    /// The value is not a string-keyed JSON object.
    case notAnObject(String)
    /// The object's key set is not exactly the closed contract's key set.
    case unexpectedFields(String)
    /// A field is missing, mistyped, out of bounds, or malformed.
    case invalidField(String)
}

/// Mirrors `RELAY_LIMITS` in `packages/server/src/store/records.ts`.
enum WireLimits {
    static let identifier = 256
    /// `apns-collapse-id` is limited to 64 bytes (`apns/sender.ts`).
    static let operationId = 64
    static let redirectUri = 2048
    static let requestedScope = 8192
    static let artifactPlaintext = 32_768
    /// A canonical decimal uint256 is at most 78 digits.
    static let decimalUint = 78
}

enum Wire {
    static func object(_ value: Any?, label: String) throws -> [String: Any] {
        if let object = value as? [String: Any] {
            return object
        }
        // `userInfo` dictionaries arrive as `[AnyHashable: Any]`.
        if let hashable = value as? [AnyHashable: Any] {
            var object: [String: Any] = [:]
            for (key, item) in hashable {
                guard let key = key as? String else {
                    throw OwnerPhoneWireError.notAnObject(label)
                }
                object[key] = item
            }
            return object
        }
        throw OwnerPhoneWireError.notAnObject(label)
    }

    static func object(_ data: Data, label: String) throws -> [String: Any] {
        guard let value = try? JSONSerialization.jsonObject(with: data) else {
            throw OwnerPhoneWireError.notAnObject(label)
        }
        return try object(value, label: label)
    }

    static func exactKeys(_ object: [String: Any], _ expected: Set<String>, label: String) throws {
        guard Set(object.keys) == expected else {
            throw OwnerPhoneWireError.unexpectedFields(label)
        }
    }

    /// Bounded non-empty text with no control characters.
    ///
    /// Knowingly laxer than the TS source in two safe directions: `text.count`
    /// counts grapheme clusters where TS `length` counts UTF-16 units
    /// (graphemes <= units, so nothing TS accepts is rejected here), and the
    /// timestamp check admits `-0` where TS rejects it (JSON encoders emit
    /// `-0` as `0`, so the server can never send it). Do not "fix" either
    /// into a stricter check — it would start rejecting valid server output.
    static func text(_ value: Any?, maximum: Int, label: String) throws -> String {
        guard let text = value as? String, !text.isEmpty, text.count <= maximum else {
            throw OwnerPhoneWireError.invalidField(label)
        }
        for scalar in text.unicodeScalars where scalar.value < 0x20 || scalar.value == 0x7f {
            throw OwnerPhoneWireError.invalidField(label)
        }
        return text
    }

    /// URL-safe identifier: `^[A-Za-z0-9._~-]+$`, bounded.
    static func identifier(_ value: Any?, maximum: Int = WireLimits.identifier, label: String) throws -> String {
        let text = try self.text(value, maximum: maximum, label: label)
        for scalar in text.unicodeScalars {
            switch scalar {
            case "A"..."Z", "a"..."z", "0"..."9", ".", "_", "~", "-":
                continue
            default:
                throw OwnerPhoneWireError.invalidField(label)
            }
        }
        return text
    }

    /// Lowercase `0x`-prefixed hex of exactly `byteLength` bytes, mirroring the
    /// protocol's address (20) and selector (4) shapes.
    static func lowercaseHex(_ value: Any?, byteLength: Int, label: String) throws -> String {
        let text = try self.text(value, maximum: 2 + byteLength * 2, label: label)
        guard text.count == 2 + byteLength * 2, text.hasPrefix("0x") else {
            throw OwnerPhoneWireError.invalidField(label)
        }
        for scalar in text.unicodeScalars.dropFirst(2) {
            switch scalar {
            case "0"..."9", "a"..."f":
                continue
            default:
                throw OwnerPhoneWireError.invalidField(label)
            }
        }
        return text
    }

    /// Canonical decimal uint256 string: `^(0|[1-9][0-9]*)$`, at most 78 digits.
    static func decimalUint(_ value: Any?, label: String) throws -> String {
        let text = try self.text(value, maximum: WireLimits.decimalUint, label: label)
        for scalar in text.unicodeScalars {
            switch scalar {
            case "0"..."9":
                continue
            default:
                throw OwnerPhoneWireError.invalidField(label)
            }
        }
        guard text == "0" || !text.hasPrefix("0") else {
            throw OwnerPhoneWireError.invalidField(label)
        }
        return text
    }

    /// Non-negative safe integer in epoch milliseconds, mirroring `timestamp()`
    /// in `store/records.ts`. Booleans and fractional numbers fail closed.
    static func timestamp(_ value: Any?, label: String) throws -> Int {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID()
        else {
            throw OwnerPhoneWireError.invalidField(label)
        }
        let double = number.doubleValue
        guard double.isFinite,
              double >= 0,
              double <= 9_007_199_254_740_991,
              double.rounded(.towardZero) == double
        else {
            throw OwnerPhoneWireError.invalidField(label)
        }
        return Int(double)
    }
}
