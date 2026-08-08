/**
 Package-internal, reject-only EIP-712 capture and digest derivation.

 The relay's already-parsed canonical typed-data JSON value is still hostile at
 the native boundary. This file captures it once into immutable Swift values, mirrors the protocol's
 supported EIP-712 subset and bounds, and derives comparison evidence with
 Ethereum Keccak-256. It does not authorize a request or expose digest bytes to
 key custody.

 @author taek <leekt216@gmail.com>
 */
import CryptoSwift
import Foundation

enum EIP712DerivationError: Error, Equatable, Sendable {
    case notAnObject(String)
    case unexpectedFields(String)
    case invalidField(String)
    case limitExceeded(String)
    case aliasedContainer(String)
    case encodingFailure
    case invalidExpectedDigest
}

struct CanonicalEIP712Field: Equatable, Sendable {
    let name: String
    let type: String
}

indirect enum CanonicalEIP712Value: Equatable, Sendable {
    case string(String)
    case boolean(Bool)
    case array([CanonicalEIP712Value])
    case object([String: CanonicalEIP712Value])
}

struct CanonicalEIP712TypedData: Equatable, Sendable {
    let types: [String: [CanonicalEIP712Field]]
    let primaryType: String
    let domain: [String: CanonicalEIP712Value]
    let message: [String: CanonicalEIP712Value]
}

/// Device-derived comparison evidence. The immutable bytes stay package-
/// internal so the verified-signable refinement can consume the exact digest
/// without decoding presentation text.
struct DerivedEIP712Digest: Equatable, Sendable {
    let canonicalHex: String
    let bytes: Data

    fileprivate init(bytes: [UInt8]) {
        self.bytes = Data(bytes)
        canonicalHex = "0x" + bytes.map { String(format: "%02x", $0) }.joined()
    }
}

enum EIP712DigestComparison: Equatable, Sendable {
    case matches(DerivedEIP712Digest)
    case mismatch(expectedCanonicalHex: String, derived: DerivedEIP712Digest)
}

private enum EIP712Limits {
    static let types = 64
    static let fields = 64
    static let identifierUTF16 = 64
    static let depth = 16
    static let array = 256
    static let scalarBytes = 16 * 1024
    static let totalBytes = 64 * 1024
    static let totalValues = 4_096
}

private struct EIP712TypeReference: Equatable, Sendable {
    let base: String
    /// Array suffixes from innermost to outermost. `nil` is dynamic.
    let dimensions: [Int?]
}

private struct EIP712CaptureBudget {
    var values = 0
    var bytes = 0

    mutating func consumeValue(label: String) throws {
        values += 1
        guard values <= EIP712Limits.totalValues else {
            throw EIP712DerivationError.limitExceeded(label)
        }
    }

    mutating func consumeBytes(
        _ text: String,
        label: String,
        maximum: Int = EIP712Limits.scalarBytes
    ) throws {
        let count = text.utf8.count
        guard count <= maximum, bytes <= EIP712Limits.totalBytes - count else {
            throw EIP712DerivationError.limitExceeded(label)
        }
        bytes += count
    }
}

/// Tracks every container for the whole capture, matching the protocol's
/// reject-on-alias rule as well as rejecting cycles.
private struct EIP712CaptureContext {
    var containers = Set<ObjectIdentifier>()

    mutating func record(_ value: Any, label: String) throws -> NSDictionary {
        guard let object = value as? NSDictionary, !(value is NSArray) else {
            throw EIP712DerivationError.notAnObject(label)
        }
        try insert(object, label: label)
        for key in object.allKeys where !(key is String) && !(key is NSString) {
            throw EIP712DerivationError.invalidField(label)
        }
        return object
    }

    mutating func array(_ value: Any, label: String) throws -> NSArray {
        guard let array = value as? NSArray else {
            throw EIP712DerivationError.invalidField(label)
        }
        try insert(array, label: label)
        return array
    }

    private mutating func insert(_ object: AnyObject, label: String) throws {
        // Foundation interns empty immutable JSON containers. Two independent
        // `[]` or `{}` values can therefore have the same object identity after
        // JSONSerialization, even though neither can carry an alias or cycle.
        // Mutable empty containers still participate in identity tracking.
        if let array = object as? NSArray,
           array.count == 0,
           !(object is NSMutableArray)
        {
            return
        }
        if let dictionary = object as? NSDictionary,
           dictionary.count == 0,
           !(object is NSMutableDictionary)
        {
            return
        }
        guard containers.insert(ObjectIdentifier(object)).inserted else {
            throw EIP712DerivationError.aliasedContainer(label)
        }
    }
}

private let reservedEIP712Keys: Set<String> = ["__proto__", "constructor", "prototype"]

private func dictionaryKeys(_ object: NSDictionary, label: String) throws -> Set<String> {
    var keys = Set<String>()
    for rawKey in object.allKeys {
        guard let key = rawKey as? String, keys.insert(key).inserted else {
            throw EIP712DerivationError.invalidField(label)
        }
    }
    return keys
}

private func exactKeys(_ object: NSDictionary, _ expected: Set<String>, label: String) throws {
    guard try dictionaryKeys(object, label: label) == expected else {
        throw EIP712DerivationError.unexpectedFields(label)
    }
}

private func requiredValue(_ object: NSDictionary, key: String, label: String) throws -> Any {
    guard let value = object.object(forKey: key) else {
        throw EIP712DerivationError.unexpectedFields(label)
    }
    return value
}

private func eip712Identifier(_ value: Any, label: String) throws -> String {
    guard let text = value as? String,
          !text.isEmpty,
          text.utf16.count <= EIP712Limits.identifierUTF16,
          !reservedEIP712Keys.contains(text)
    else {
        throw EIP712DerivationError.invalidField(label)
    }
    let bytes = Array(text.utf8)
    for (index, byte) in bytes.enumerated() {
        let alpha = (65...90).contains(byte) || (97...122).contains(byte)
        let allowed = alpha || byte == 95 || (index > 0 && (48...57).contains(byte))
        if !allowed {
            throw EIP712DerivationError.invalidField(label)
        }
    }
    return text
}

private func canonicalDecimal(_ bytes: [UInt8], allowNegative: Bool) -> Bool {
    guard !bytes.isEmpty else { return false }
    var digits = ArraySlice(bytes)
    if allowNegative, digits.first == 45 {
        digits = digits.dropFirst()
        guard !digits.isEmpty, digits.first != 48 else { return false }
    }
    guard digits.allSatisfy({ (48...57).contains($0) }) else { return false }
    return digits.count == 1 || digits.first != 48
}

private func parseEIP712Type(_ value: Any, label: String) throws -> EIP712TypeReference {
    guard let text = value as? String,
          text.utf8.count <= EIP712Limits.identifierUTF16 * 2
    else {
        throw EIP712DerivationError.invalidField(label)
    }
    let bytes = Array(text.utf8)
    let bracket = bytes.firstIndex(of: 91) ?? bytes.count
    let baseBytes = Array(bytes[..<bracket])
    let base = String(decoding: baseBytes, as: UTF8.self)
    _ = try eip712Identifier(base, label: label)

    var dimensions = [Int?]()
    var index = bracket
    while index < bytes.count {
        guard bytes[index] == 91 else {
            throw EIP712DerivationError.invalidField(label)
        }
        index += 1
        let start = index
        while index < bytes.count, bytes[index] != 93 {
            guard (48...57).contains(bytes[index]) else {
                throw EIP712DerivationError.invalidField(label)
            }
            index += 1
        }
        guard index < bytes.count, bytes[index] == 93 else {
            throw EIP712DerivationError.invalidField(label)
        }
        let lengthBytes = bytes[start..<index]
        if lengthBytes.isEmpty {
            dimensions.append(nil)
        } else {
            guard canonicalDecimal(Array(lengthBytes), allowNegative: false), lengthBytes.first != 48 else {
                throw EIP712DerivationError.invalidField(label)
            }
            var length = 0
            for byte in lengthBytes {
                length = length * 10 + Int(byte - 48)
                guard length <= EIP712Limits.array else {
                    throw EIP712DerivationError.limitExceeded(label)
                }
            }
            dimensions.append(length)
        }
        index += 1
    }

    if base == "uint" || base == "int" {
        throw EIP712DerivationError.invalidField(label)
    }
    if base.hasPrefix("uint") || base.hasPrefix("int") {
        let prefix = base.hasPrefix("uint") ? "uint" : "int"
        let suffix = base.dropFirst(prefix.count)
        guard canonicalDecimal(Array(suffix.utf8), allowNegative: false),
              let width = Int(suffix),
              (8...256).contains(width), width.isMultiple(of: 8)
        else {
            throw EIP712DerivationError.invalidField(label)
        }
    } else if base.hasPrefix("bytes"), base != "bytes" {
        let suffix = base.dropFirst(5)
        guard canonicalDecimal(Array(suffix.utf8), allowNegative: false),
              let width = Int(suffix), (1...32).contains(width)
        else {
            throw EIP712DerivationError.invalidField(label)
        }
    }
    return EIP712TypeReference(base: base, dimensions: dimensions)
}

private func integerDetails(_ base: String) -> (signed: Bool, width: Int)? {
    if base.hasPrefix("uint") {
        let suffix = base.dropFirst(4)
        guard canonicalDecimal(Array(suffix.utf8), allowNegative: false),
              let width = Int(suffix),
              (8...256).contains(width),
              width.isMultiple(of: 8)
        else {
            return nil
        }
        return (false, width)
    }
    if base.hasPrefix("int") {
        let suffix = base.dropFirst(3)
        guard canonicalDecimal(Array(suffix.utf8), allowNegative: false),
              let width = Int(suffix),
              (8...256).contains(width),
              width.isMultiple(of: 8)
        else {
            return nil
        }
        return (true, width)
    }
    return nil
}

private func fixedBytesWidth(_ base: String) -> Int? {
    guard base.hasPrefix("bytes"), base != "bytes" else { return nil }
    let suffix = base.dropFirst(5)
    guard canonicalDecimal(Array(suffix.utf8), allowNegative: false),
          let width = Int(suffix),
          (1...32).contains(width)
    else {
        return nil
    }
    return width
}

private func isEIP712Builtin(_ base: String) -> Bool {
    if base == "address" || base == "bool" || base == "string" || base == "bytes" {
        return true
    }
    if fixedBytesWidth(base) != nil { return true }
    if integerDetails(base) != nil { return true }
    return false
}

private func captureEIP712Types(
    _ value: Any,
    context: inout EIP712CaptureContext,
    budget: inout EIP712CaptureBudget
) throws -> [String: [CanonicalEIP712Field]] {
    let object = try context.record(value, label: "EIP-712 types")
    let names = try dictionaryKeys(object, label: "EIP-712 types").sorted()
    guard (2...EIP712Limits.types).contains(names.count), names.contains("EIP712Domain") else {
        throw EIP712DerivationError.limitExceeded("EIP-712 types")
    }

    var result = [String: [CanonicalEIP712Field]]()
    for name in names {
        _ = try eip712Identifier(name, label: "EIP-712 type name")
        try budget.consumeBytes(name, label: "EIP-712 type name")
        guard !isEIP712Builtin(name) else {
            throw EIP712DerivationError.invalidField("EIP-712 type name")
        }
        let entries = try context.array(
            try requiredValue(object, key: name, label: "EIP-712 types"),
            label: "EIP-712 \(name) fields"
        )
        guard entries.count <= EIP712Limits.fields else {
            throw EIP712DerivationError.limitExceeded("EIP-712 \(name) fields")
        }
        var fieldNames = Set<String>()
        var fields = [CanonicalEIP712Field]()
        fields.reserveCapacity(entries.count)
        for index in 0..<entries.count {
            let label = "EIP-712 \(name) field \(index)"
            let field = try context.record(entries.object(at: index), label: label)
            try exactKeys(field, ["name", "type"], label: label)
            let fieldName = try eip712Identifier(
                try requiredValue(field, key: "name", label: label),
                label: "EIP-712 \(name) field name"
            )
            guard fieldNames.insert(fieldName).inserted else {
                throw EIP712DerivationError.invalidField("EIP-712 \(name) field name")
            }
            let typeValue = try requiredValue(field, key: "type", label: label)
            guard let type = typeValue as? String else {
                throw EIP712DerivationError.invalidField("EIP-712 \(name).\(fieldName) type")
            }
            _ = try parseEIP712Type(type, label: "EIP-712 \(name).\(fieldName) type")
            try budget.consumeBytes(fieldName, label: "EIP-712 field name")
            try budget.consumeBytes(type, label: "EIP-712 field type")
            fields.append(CanonicalEIP712Field(name: fieldName, type: type))
        }
        result[name] = fields
    }

    let domainFields = result["EIP712Domain"] ?? []
    let domainOrder = ["name", "version", "chainId", "verifyingContract", "salt"]
    let domainTypes = [
        "name": "string",
        "version": "string",
        "chainId": "uint256",
        "verifyingContract": "address",
        "salt": "bytes32"
    ]
    guard !domainFields.isEmpty else {
        throw EIP712DerivationError.invalidField("EIP712Domain fields")
    }
    var previous = -1
    for field in domainFields {
        guard let position = domainOrder.firstIndex(of: field.name),
              domainTypes[field.name] == field.type,
              position > previous
        else {
            throw EIP712DerivationError.invalidField("EIP712Domain fields")
        }
        previous = position
    }

    for (name, fields) in result {
        for field in fields {
            let parsed = try parseEIP712Type(
                field.type,
                label: "EIP-712 \(name).\(field.name) type"
            )
            guard isEIP712Builtin(parsed.base) || result[parsed.base] != nil else {
                throw EIP712DerivationError.invalidField("EIP-712 \(name).\(field.name) type")
            }
        }
    }
    return result
}

private func captureEIP712Scalar(
    _ value: Any,
    base: String,
    label: String,
    budget: inout EIP712CaptureBudget
) throws -> CanonicalEIP712Value {
    try budget.consumeValue(label: label)
    if base == "bool" {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) == CFBooleanGetTypeID()
        else {
            throw EIP712DerivationError.invalidField(label)
        }
        return .boolean(number.boolValue)
    }
    guard let text = value as? String else {
        // In particular, JSON numbers are never accepted for EIP-712 integers.
        throw EIP712DerivationError.invalidField(label)
    }
    if base == "address" {
        guard decodeLowercaseEIP712Hex(text, exactBytes: 20) != nil else {
            throw EIP712DerivationError.invalidField(label)
        }
        try budget.consumeBytes(text, label: label)
        return .string(text)
    }
    if base == "string" {
        try budget.consumeBytes(text, label: label)
        return .string(text)
    }
    if base == "bytes" || fixedBytesWidth(base) != nil {
        guard let bytes = decodeLowercaseEIP712Hex(text),
              bytes.count <= EIP712Limits.scalarBytes,
              fixedBytesWidth(base).map({ $0 == bytes.count }) ?? true
        else {
            throw EIP712DerivationError.invalidField(label)
        }
        try budget.consumeBytes(
            text,
            label: label,
            maximum: 2 + EIP712Limits.scalarBytes * 2
        )
        return .string(text)
    }
    if let integer = integerDetails(base) {
        let raw = Array(text.utf8)
        guard raw.count <= 79,
              canonicalDecimal(raw, allowNegative: integer.signed),
              decimalWord(text, signed: integer.signed, width: integer.width) != nil
        else {
            throw EIP712DerivationError.invalidField(label)
        }
        try budget.consumeBytes(text, label: label)
        return .string(text)
    }
    throw EIP712DerivationError.invalidField(label)
}

private func captureEIP712Value(
    _ value: Any,
    type: EIP712TypeReference,
    types: [String: [CanonicalEIP712Field]],
    label: String,
    depth: Int,
    context: inout EIP712CaptureContext,
    budget: inout EIP712CaptureBudget
) throws -> CanonicalEIP712Value {
    guard depth <= EIP712Limits.depth else {
        throw EIP712DerivationError.limitExceeded(label)
    }
    if let expected = type.dimensions.last {
        try budget.consumeValue(label: label)
        let entries = try context.array(value, label: label)
        guard entries.count <= EIP712Limits.array,
              expected == nil || entries.count == expected
        else {
            throw EIP712DerivationError.invalidField(label)
        }
        let nested = EIP712TypeReference(base: type.base, dimensions: type.dimensions.dropLast())
        var captured = [CanonicalEIP712Value]()
        captured.reserveCapacity(entries.count)
        for index in 0..<entries.count {
            captured.append(try captureEIP712Value(
                entries.object(at: index),
                type: nested,
                types: types,
                label: "\(label)[\(index)]",
                depth: depth + 1,
                context: &context,
                budget: &budget
            ))
        }
        return .array(captured)
    }
    guard let fields = types[type.base] else {
        return try captureEIP712Scalar(value, base: type.base, label: label, budget: &budget)
    }
    try budget.consumeValue(label: label)
    let object = try context.record(value, label: label)
    try exactKeys(object, Set(fields.map(\.name)), label: label)
    var captured = [String: CanonicalEIP712Value]()
    for field in fields {
        captured[field.name] = try captureEIP712Value(
            try requiredValue(object, key: field.name, label: label),
            type: try parseEIP712Type(field.type, label: "\(label).\(field.name) type"),
            types: types,
            label: "\(label).\(field.name)",
            depth: depth + 1,
            context: &context,
            budget: &budget
        )
    }
    return .object(captured)
}

/// The caller owns JSON byte parsing. This boundary accepts only the parsed
/// canonical value so it cannot silently claim duplicate-key handling that
/// Foundation's JSON parser does not provide.
func captureCanonicalEIP712TypedData(jsonValue value: Any) throws -> CanonicalEIP712TypedData {
    var context = EIP712CaptureContext()
    var budget = EIP712CaptureBudget()
    let root = try context.record(value, label: "canonical EIP-712 typed data")
    try exactKeys(root, ["types", "primaryType", "domain", "message"], label: "canonical EIP-712 typed data")
    let types = try captureEIP712Types(
        try requiredValue(root, key: "types", label: "canonical EIP-712 typed data"),
        context: &context,
        budget: &budget
    )
    let primaryType = try eip712Identifier(
        try requiredValue(root, key: "primaryType", label: "canonical EIP-712 typed data"),
        label: "EIP-712 primaryType"
    )
    guard primaryType != "EIP712Domain", types[primaryType] != nil else {
        throw EIP712DerivationError.invalidField("EIP-712 primaryType")
    }

    var reachable: Set<String> = ["EIP712Domain"]
    var pending = [primaryType]
    while let name = pending.popLast() {
        if reachable.contains(name) { continue }
        reachable.insert(name)
        for field in types[name] ?? [] {
            let dependency = try parseEIP712Type(
                field.type,
                label: "EIP-712 \(name).\(field.name) type"
            ).base
            if !isEIP712Builtin(dependency), !reachable.contains(dependency) {
                pending.append(dependency)
            }
        }
    }
    guard reachable.count == types.count else {
        throw EIP712DerivationError.invalidField("EIP-712 types")
    }

    let domainValue = try captureEIP712Value(
        try requiredValue(root, key: "domain", label: "canonical EIP-712 typed data"),
        type: EIP712TypeReference(base: "EIP712Domain", dimensions: []),
        types: types,
        label: "EIP-712 domain",
        depth: 0,
        context: &context,
        budget: &budget
    )
    let messageValue = try captureEIP712Value(
        try requiredValue(root, key: "message", label: "canonical EIP-712 typed data"),
        type: EIP712TypeReference(base: primaryType, dimensions: []),
        types: types,
        label: "EIP-712 message",
        depth: 0,
        context: &context,
        budget: &budget
    )
    guard case let .object(domain) = domainValue, case let .object(message) = messageValue else {
        throw EIP712DerivationError.encodingFailure
    }
    return CanonicalEIP712TypedData(
        types: types,
        primaryType: primaryType,
        domain: domain,
        message: message
    )
}

private func renderEIP712Struct(
    _ name: String,
    types: [String: [CanonicalEIP712Field]]
) throws -> String {
    guard let fields = types[name] else { throw EIP712DerivationError.encodingFailure }
    return name + "(" + fields.map { "\($0.type) \($0.name)" }.joined(separator: ",") + ")"
}

private func encodeEIP712Type(
    _ primary: String,
    types: [String: [CanonicalEIP712Field]]
) throws -> [UInt8] {
    var dependencies = Set<String>()
    var pending = [primary]
    var visited = Set<String>()
    while let name = pending.popLast() {
        if !visited.insert(name).inserted { continue }
        guard let fields = types[name] else { throw EIP712DerivationError.encodingFailure }
        for field in fields {
            let dependency = try parseEIP712Type(field.type, label: "EIP-712 field type").base
            guard !isEIP712Builtin(dependency) else { continue }
            if dependency != primary { dependencies.insert(dependency) }
            if !visited.contains(dependency) { pending.append(dependency) }
        }
    }
    var encoded = try renderEIP712Struct(primary, types: types)
    for dependency in dependencies.sorted() {
        encoded += try renderEIP712Struct(dependency, types: types)
    }
    return Array(encoded.utf8)
}

private func keccak256(_ bytes: [UInt8]) throws -> [UInt8] {
    let digest = SHA3(variant: .keccak256).calculate(for: bytes)
    guard digest.count == 32 else { throw EIP712DerivationError.encodingFailure }
    return digest
}

private func hashEIP712Struct(
    _ name: String,
    value: CanonicalEIP712Value,
    typedData: CanonicalEIP712TypedData
) throws -> [UInt8] {
    guard case let .object(object) = value,
          let fields = typedData.types[name]
    else {
        throw EIP712DerivationError.encodingFailure
    }
    var encoded = try keccak256(encodeEIP712Type(name, types: typedData.types))
    for field in fields {
        guard let fieldValue = object[field.name] else {
            throw EIP712DerivationError.encodingFailure
        }
        encoded += try encodeEIP712Value(
            fieldValue,
            type: parseEIP712Type(field.type, label: "EIP-712 field type"),
            typedData: typedData
        )
    }
    return try keccak256(encoded)
}

private func encodeEIP712Value(
    _ value: CanonicalEIP712Value,
    type: EIP712TypeReference,
    typedData: CanonicalEIP712TypedData
) throws -> [UInt8] {
    if type.dimensions.last != nil {
        guard case let .array(values) = value else {
            throw EIP712DerivationError.encodingFailure
        }
        let nested = EIP712TypeReference(base: type.base, dimensions: type.dimensions.dropLast())
        var encoded = [UInt8]()
        encoded.reserveCapacity(values.count * 32)
        for item in values {
            encoded += try encodeEIP712Value(item, type: nested, typedData: typedData)
        }
        return try keccak256(encoded)
    }
    if typedData.types[type.base] != nil {
        return try hashEIP712Struct(type.base, value: value, typedData: typedData)
    }
    switch (type.base, value) {
    case ("bool", let .boolean(flag)):
        return [UInt8](repeating: 0, count: 31) + [flag ? 1 : 0]
    case ("address", let .string(text)):
        guard let bytes = decodeLowercaseEIP712Hex(text, exactBytes: 20) else {
            throw EIP712DerivationError.encodingFailure
        }
        return [UInt8](repeating: 0, count: 12) + bytes
    case ("string", let .string(text)):
        return try keccak256(Array(text.utf8))
    case ("bytes", let .string(text)):
        guard let bytes = decodeLowercaseEIP712Hex(text) else {
            throw EIP712DerivationError.encodingFailure
        }
        return try keccak256(bytes)
    case (_, let .string(text)) where fixedBytesWidth(type.base) != nil:
        guard let bytes = decodeLowercaseEIP712Hex(text), bytes.count <= 32 else {
            throw EIP712DerivationError.encodingFailure
        }
        return bytes + [UInt8](repeating: 0, count: 32 - bytes.count)
    case (_, let .string(text)) where integerDetails(type.base) != nil:
        guard let details = integerDetails(type.base),
              let word = decimalWord(text, signed: details.signed, width: details.width)
        else {
            throw EIP712DerivationError.encodingFailure
        }
        return word
    default:
        throw EIP712DerivationError.encodingFailure
    }
}

private func compareBigEndian(_ left: [UInt8], _ right: [UInt8]) -> Int {
    for index in 0..<left.count where left[index] != right[index] {
        return left[index] < right[index] ? -1 : 1
    }
    return 0
}

private func decimalMagnitude(_ text: String) -> [UInt8]? {
    let digits = text.utf8.first == 45 ? text.utf8.dropFirst() : text.utf8[...]
    var word = [UInt8](repeating: 0, count: 32)
    for digit in digits {
        var carry = Int(digit - 48)
        for index in stride(from: 31, through: 0, by: -1) {
            let value = Int(word[index]) * 10 + carry
            word[index] = UInt8(value & 0xff)
            carry = value >> 8
        }
        if carry != 0 { return nil }
    }
    return word
}

private func decimalWord(_ text: String, signed: Bool, width: Int) -> [UInt8]? {
    guard let magnitude = decimalMagnitude(text) else { return nil }
    let byteWidth = width / 8
    var maximum = [UInt8](repeating: 0, count: 32)
    if signed {
        maximum[32 - byteWidth] = text.hasPrefix("-") ? 0x80 : 0x7f
        if !text.hasPrefix("-") {
            for index in (33 - byteWidth)..<32 { maximum[index] = 0xff }
        }
    } else {
        for index in (32 - byteWidth)..<32 { maximum[index] = 0xff }
    }
    guard compareBigEndian(magnitude, maximum) <= 0 else { return nil }
    guard signed, text.hasPrefix("-") else { return magnitude }
    var complement = magnitude.map { ~$0 }
    var carry: UInt16 = 1
    for index in stride(from: 31, through: 0, by: -1) {
        let value = UInt16(complement[index]) + carry
        complement[index] = UInt8(value & 0xff)
        carry = value >> 8
    }
    return complement
}

private func decodeLowercaseEIP712Hex(_ text: String, exactBytes: Int? = nil) -> [UInt8]? {
    let source = Array(text.utf8)
    guard source.count >= 2, source[0] == 48, source[1] == 120,
          (source.count - 2).isMultiple(of: 2)
    else {
        return nil
    }
    let count = (source.count - 2) / 2
    if let exactBytes, count != exactBytes { return nil }
    var bytes = [UInt8]()
    bytes.reserveCapacity(count)
    var index = 2
    while index < source.count {
        guard let high = lowercaseHexNibble(source[index]),
              let low = lowercaseHexNibble(source[index + 1])
        else {
            return nil
        }
        bytes.append(high << 4 | low)
        index += 2
    }
    return bytes
}

private func lowercaseHexNibble(_ byte: UInt8) -> UInt8? {
    if (48...57).contains(byte) { return byte - 48 }
    if (97...102).contains(byte) { return byte - 87 }
    return nil
}

func deriveEIP712Digest(from typedData: CanonicalEIP712TypedData) throws -> DerivedEIP712Digest {
    let domain = try hashEIP712Struct(
        "EIP712Domain",
        value: .object(typedData.domain),
        typedData: typedData
    )
    let message = try hashEIP712Struct(
        typedData.primaryType,
        value: .object(typedData.message),
        typedData: typedData
    )
    return try DerivedEIP712Digest(bytes: keccak256([0x19, 0x01] + domain + message))
}

func deriveEIP712Digest(jsonValue: Any) throws -> DerivedEIP712Digest {
    try deriveEIP712Digest(from: captureCanonicalEIP712TypedData(jsonValue: jsonValue))
}

func compareEIP712Digest(
    jsonValue: Any,
    expectedDigest: String
) throws -> EIP712DigestComparison {
    guard decodeLowercaseEIP712Hex(expectedDigest, exactBytes: 32) != nil else {
        throw EIP712DerivationError.invalidExpectedDigest
    }
    let derived = try deriveEIP712Digest(jsonValue: jsonValue)
    if derived.canonicalHex == expectedDigest {
        return .matches(derived)
    }
    return .mismatch(expectedCanonicalHex: expectedDigest, derived: derived)
}
