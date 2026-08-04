/**
 EXPERIMENTAL PREVIEW — strict pull-inbox wiring for the example app.

 The inbox is an opaque chooser, not a consent or authority surface. It carries
 only an operation id, match code, and expiry. Selecting an item fetches the
 full authenticated OwnerPhone projection before any decision is possible.

 @author taek <leekt216@gmail.com>
 */
import Foundation
import OwnerPhone

public let demoInboxVersion = "oaath.demo-inbox/v1"
public let demoInboxLimit = 20
private let demoInboxMaximumBytes = 8_192

public enum DemoInboxError: Error, Equatable, Sendable {
    case invalidResponse
    case status(Int)
}

public struct DemoInboxItem: Equatable, Sendable, Identifiable {
    public var id: String { operationId }
    public let operationId: String
    public let matchCode: MatchCode
    public let expiresAt: Int

    public init(operationId: String, matchCode: MatchCode, expiresAt: Int) {
        self.operationId = operationId
        self.matchCode = matchCode
        self.expiresAt = expiresAt
    }
}

/// Closed decode of `{requests, version}`. Foundation normally collapses
/// duplicate JSON keys, so a lexical pass rejects them at every object depth
/// before the exact typed capture runs.
public func decodeDemoInbox(_ data: Data) throws -> [DemoInboxItem] {
    guard !data.isEmpty, data.count <= demoInboxMaximumBytes,
          !containsDuplicateJSONKeys(data),
          let value = try? JSONSerialization.jsonObject(with: data),
          let object = value as? [String: Any],
          Set(object.keys) == ["requests", "version"],
          object["version"] as? String == demoInboxVersion,
          let entries = object["requests"] as? [Any],
          entries.count <= demoInboxLimit
    else { throw DemoInboxError.invalidResponse }

    var operationIds = Set<String>()
    var items: [DemoInboxItem] = []
    for entry in entries {
        guard let item = entry as? [String: Any],
              Set(item.keys) == ["displayPayload", "expiresAt", "operationId"],
              let operationId = item["operationId"] as? String,
              isCanonicalOperationId(operationId),
              operationIds.insert(operationId).inserted,
              let displayPayload = item["displayPayload"] as? String,
              let matchCode = try? MatchCode(displayPayload),
              let expiresAt = exactTimestamp(item["expiresAt"])
        else { throw DemoInboxError.invalidResponse }
        items.append(DemoInboxItem(
            operationId: operationId, matchCode: matchCode, expiresAt: expiresAt))
    }
    guard items == items.sorted(by: {
        $0.expiresAt != $1.expiresAt
            ? $0.expiresAt < $1.expiresAt
            : $0.operationId < $1.operationId
    }) else { throw DemoInboxError.invalidResponse }
    return items
}

private func containsDuplicateJSONKeys(_ data: Data) -> Bool {
    guard var scanner = JSONKeyScanner(data), scanner.scanValue() else { return true }
    scanner.skipWhitespace()
    return scanner.hasDuplicate || !scanner.isAtEnd
}

private struct JSONKeyScanner {
    private let bytes: [UInt8]
    private var index = 0
    var hasDuplicate = false
    var isAtEnd: Bool { index == bytes.count }

    init?(_ data: Data) {
        self.bytes = Array(data)
        guard String(data: data, encoding: .utf8) != nil else { return nil }
    }

    mutating func skipWhitespace() {
        while index < bytes.count, [0x20, 0x09, 0x0a, 0x0d].contains(bytes[index]) {
            index += 1
        }
    }

    mutating func scanValue() -> Bool {
        skipWhitespace()
        guard index < bytes.count else { return false }
        switch bytes[index] {
        case 0x7b: return scanObject()
        case 0x5b: return scanArray()
        case 0x22: return scanString() != nil
        default:
            let start = index
            while index < bytes.count,
                  ![0x20, 0x09, 0x0a, 0x0d, 0x2c, 0x5d, 0x7d].contains(bytes[index]) {
                index += 1
            }
            return index > start
        }
    }

    private mutating func scanObject() -> Bool {
        index += 1
        skipWhitespace()
        if take(0x7d) { return true }
        var keys = Set<String>()
        while true {
            skipWhitespace()
            guard let token = scanString(), let key = decodeString(token) else { return false }
            if !keys.insert(key).inserted { hasDuplicate = true }
            skipWhitespace()
            guard take(0x3a), scanValue() else { return false }
            skipWhitespace()
            if take(0x7d) { return true }
            guard take(0x2c) else { return false }
        }
    }

    private mutating func scanArray() -> Bool {
        index += 1
        skipWhitespace()
        if take(0x5d) { return true }
        while true {
            guard scanValue() else { return false }
            skipWhitespace()
            if take(0x5d) { return true }
            guard take(0x2c) else { return false }
        }
    }

    private mutating func scanString() -> ArraySlice<UInt8>? {
        guard take(0x22) else { return nil }
        let start = index - 1
        while index < bytes.count {
            if bytes[index] == 0x5c {
                index += 2
                continue
            }
            if bytes[index] == 0x22 {
                index += 1
                return bytes[start..<index]
            }
            index += 1
        }
        return nil
    }

    private mutating func take(_ byte: UInt8) -> Bool {
        guard index < bytes.count, bytes[index] == byte else { return false }
        index += 1
        return true
    }

    private func decodeString(_ token: ArraySlice<UInt8>) -> String? {
        let wrapped = Data([0x5b] + token + [0x5d])
        return (try? JSONSerialization.jsonObject(with: wrapped) as? [String])?.first
    }
}

private func isCanonicalOperationId(_ value: String) -> Bool {
    guard !value.isEmpty, value.utf8.count <= 64, value.utf16.count == value.utf8.count else {
        return false
    }
    for scalar in value.unicodeScalars {
        switch scalar {
        case "A"..."Z", "a"..."z", "0"..."9", ".", "_", "~", "-": continue
        default: return false
        }
    }
    return true
}

private func exactTimestamp(_ value: Any?) -> Int? {
    guard let number = value as? NSNumber,
          CFGetTypeID(number) != CFBooleanGetTypeID()
    else { return nil }
    let double = number.doubleValue
    guard double.isFinite, double >= 0, double <= 9_007_199_254_740_991,
          double.rounded(.towardZero) == double
    else { return nil }
    return Int(double)
}

/// One authenticated read using the immutable endpoint + credential pairing.
public func fetchDemoInbox(
    pairing: PersistedPairing,
    http: any DemoHTTP,
    onUnauthorized: (@Sendable (PersistedPairing) async -> Void)? = nil
) async throws -> [DemoInboxItem] {
    let request = pairing.endpoint.inboxRequest(credential: pairing.credential)
    let (data, status) = try await http.send(request)
    if status == 401 { await onUnauthorized?(pairing) }
    guard status == 200 else { throw DemoInboxError.status(status) }
    return try decodeDemoInbox(data)
}
