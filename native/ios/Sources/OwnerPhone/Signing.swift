/**
 EXPERIMENTAL PREVIEW — P-256 signature normalization for the owner key.

 The SDK's rule (`packages/sdk/src/kernel/key/p256.ts`): a Kernel-native P-256
 signature is the raw 64-byte `r ‖ s` with `s` in the low half of the curve
 order, over an already-domain-separated 32-byte digest. The platform's
 `SecKeyCreateSignature` returns DER, so the phone converts DER → raw via
 CryptoKit and low-S-normalizes with P-256 order arithmetic before anything
 leaves the device. The same normalized bytes serve both consent flows: the
 Kernel replayable enable digest (step 5) and a UserOperation hash (step 7).

 Pure and dependency-free beyond CryptoKit, so `swift test` proves it on any
 host — no Secure Enclave, keychain, or network involved.

 @author taek <leekt216@gmail.com>
 */
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

public enum OwnerPhoneSigningError: Error, Equatable, Sendable {
    case malformedDerSignature
    case malformedRawSignature
    /// `r` or `s` outside `(0, n)` — contradictory signature material.
    case componentOutOfRange
    case malformedDigest
}

/// P-256 (secp256r1) group order `n`, big-endian.
let p256Order: [UInt8] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
]

/// `n / 2`, big-endian: the low-S boundary.
let p256HalfOrder: [UInt8] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00,
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42,
    0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8
]

/// Big-endian comparison of two equal-length words.
private func compare(_ left: [UInt8], _ right: [UInt8]) -> Int {
    for index in 0..<left.count where left[index] != right[index] {
        return left[index] < right[index] ? -1 : 1
    }
    return 0
}

/// Big-endian subtraction `left - right`; the caller guarantees `left >= right`.
private func subtract(_ left: [UInt8], _ right: [UInt8]) -> [UInt8] {
    var result = [UInt8](repeating: 0, count: left.count)
    var borrow = 0
    for index in stride(from: left.count - 1, through: 0, by: -1) {
        var value = Int(left[index]) - Int(right[index]) - borrow
        borrow = value < 0 ? 1 : 0
        if value < 0 { value += 256 }
        result[index] = UInt8(value)
    }
    return result
}

#if canImport(CryptoKit)
/// DER ECDSA → raw 64-byte `r ‖ s`, each component left-padded to 32 bytes.
/// CryptoKit owns the DER parse; a payload it cannot read fails closed.
public func p256RawSignature(der: Data) throws -> Data {
    guard let signature = try? P256.Signing.ECDSASignature(derRepresentation: der) else {
        throw OwnerPhoneSigningError.malformedDerSignature
    }
    let raw = signature.rawRepresentation
    guard raw.count == 64 else {
        throw OwnerPhoneSigningError.malformedDerSignature
    }
    return raw
}
#endif

/// Low-S normalization of a raw 64-byte `r ‖ s` signature: `s > n/2` becomes
/// `n - s` (an equally valid signature for the same digest, and the only form
/// the SDK and the on-chain verifier accept as canonical). `r` and `s` must
/// each lie in `(0, n)`; anything else is contradictory material, never fixed.
public func p256LowSNormalized(raw: Data) throws -> Data {
    guard raw.count == 64 else {
        throw OwnerPhoneSigningError.malformedRawSignature
    }
    let r = [UInt8](raw.prefix(32))
    var s = [UInt8](raw.suffix(32))
    let zero = [UInt8](repeating: 0, count: 32)
    guard compare(r, zero) > 0, compare(r, p256Order) < 0,
          compare(s, zero) > 0, compare(s, p256Order) < 0
    else {
        throw OwnerPhoneSigningError.componentOutOfRange
    }
    if compare(s, p256HalfOrder) > 0 {
        s = subtract(p256Order, s)
    }
    return Data(r + s)
}

/// Lowercase `0x`-prefixed hex of `data`.
public func hexEncode(_ data: Data) -> String {
    "0x" + data.map { String(format: "%02x", $0) }.joined()
}

/// Strict decode of a lowercase `0x`-prefixed 32-byte digest.
public func decodeDigestHex(_ text: String) throws -> Data {
    guard let data = decodeLowercaseHex(text, byteCount: 32) else {
        throw OwnerPhoneSigningError.malformedDigest
    }
    return data
}

/// Strict decode of the SDK/on-chain raw low-S signature envelope. Component
/// range and low-S canonicality remain owned by `p256LowSNormalized`.
public func decodeP256RawSignatureHex(_ text: String) throws -> Data {
    guard let data = decodeLowercaseHex(text, byteCount: 64) else {
        throw OwnerPhoneSigningError.malformedRawSignature
    }
    return data
}

private func decodeLowercaseHex(_ text: String, byteCount: Int) -> Data? {
    guard text.count == 2 + byteCount * 2, text.hasPrefix("0x") else { return nil }
    var bytes = [UInt8]()
    bytes.reserveCapacity(byteCount)
    var iterator = text.dropFirst(2).makeIterator()
    while let high = iterator.next() {
        guard let low = iterator.next(),
              let highValue = high.hexDigitValue, let lowValue = low.hexDigitValue,
              !high.isUppercase, !low.isUppercase
        else {
            return nil
        }
        bytes.append(UInt8(highValue << 4 | lowValue))
    }
    return Data(bytes)
}
