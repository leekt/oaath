/**
 EXPERIMENTAL PREVIEW — pure signing-normalization proofs: DER → raw r‖s
 conversion vectors, low-S normalization against P-256 order vectors, hex
 codecs, and a real-CryptoKit round trip proving a normalized signature still
 verifies. No keychain, Secure Enclave, or network — `swift test` on any host.

 @author taek <leekt216@gmail.com>
 */
import CryptoKit
import XCTest
@testable import OwnerPhone

private func word(_ leading: [UInt8]) -> [UInt8] {
    leading + [UInt8](repeating: 0, count: 32 - leading.count)
}

private func trailing(_ value: UInt8) -> [UInt8] {
    [UInt8](repeating: 0, count: 31) + [value]
}

final class SigningTests: XCTestCase {
    func testDerToRawConversionVectors() throws {
        // Minimal DER: SEQUENCE { INTEGER 1, INTEGER 2 }.
        let minimal = Data([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02])
        XCTAssertEqual(
            try p256RawSignature(der: minimal),
            Data(trailing(1) + trailing(2)))

        // A component with the high bit set carries DER's 0x00 prefix byte;
        // the raw form left-pads to exactly 32 bytes without it.
        var highBit = Data([0x30, 0x26, 0x02, 0x21, 0x00])
        highBit.append(contentsOf: word([0x80]))
        highBit.append(contentsOf: [0x02, 0x01, 0x01])
        XCTAssertEqual(
            try p256RawSignature(der: highBit),
            Data(word([0x80]) + trailing(1)))
    }

    func testMalformedDerFailsClosed() {
        for bad in [Data(), Data([0x30, 0x00]), Data([0x02, 0x01, 0x01]), Data("junk".utf8)] {
            XCTAssertThrowsError(try p256RawSignature(der: bad)) {
                XCTAssertEqual($0 as? OwnerPhoneSigningError, .malformedDerSignature)
            }
        }
    }

    func testLowSNormalizationVectors() throws {
        let r = trailing(1)

        // s = n - 1 (maximal high-S) normalizes to n - s = 1.
        var nMinusOne = p256Order
        nMinusOne[31] = p256Order[31] - 1
        XCTAssertEqual(
            try p256LowSNormalized(raw: Data(r + nMinusOne)),
            Data(r + trailing(1)))

        // s = n/2 + 1 (the first high-S value) normalizes to exactly n/2,
        // because n = 2 * (n/2) + 1.
        var halfPlusOne = p256HalfOrder
        halfPlusOne[31] = p256HalfOrder[31] + 1
        XCTAssertEqual(
            try p256LowSNormalized(raw: Data(r + halfPlusOne)),
            Data(r + p256HalfOrder))

        // s = n/2 and s = 1 are already low and pass through unchanged.
        XCTAssertEqual(
            try p256LowSNormalized(raw: Data(r + p256HalfOrder)),
            Data(r + p256HalfOrder))
        XCTAssertEqual(
            try p256LowSNormalized(raw: Data(r + trailing(1))),
            Data(r + trailing(1)))
    }

    func testOutOfRangeComponentsFailClosedInsteadOfBeingFixed() {
        let zero = [UInt8](repeating: 0, count: 32)
        let one = trailing(1)
        for (r, s) in [(zero, one), (one, zero), (p256Order, one), (one, p256Order)] {
            XCTAssertThrowsError(try p256LowSNormalized(raw: Data(r + s))) {
                XCTAssertEqual($0 as? OwnerPhoneSigningError, .componentOutOfRange)
            }
        }
        XCTAssertThrowsError(try p256LowSNormalized(raw: Data(one))) {
            XCTAssertEqual($0 as? OwnerPhoneSigningError, .malformedRawSignature)
        }
    }

    func testNormalizedSignatureStillVerifiesWithRealCryptoKit() throws {
        // The whole phone-side pipeline over a real key: DER → raw → low-S,
        // then verify the exact normalized bytes against the public key.
        let key = P256.Signing.PrivateKey()
        let digest = SHA256.hash(data: Data("oaath signing pipeline".utf8))
        for _ in 0..<16 {
            let der = try key.signature(for: digest).derRepresentation
            let normalized = try p256LowSNormalized(raw: try p256RawSignature(der: der))
            let signature = try P256.Signing.ECDSASignature(rawRepresentation: normalized)
            XCTAssertTrue(key.publicKey.isValidSignature(signature, for: digest))
            // And the low-S bound actually holds on the emitted bytes.
            let s = [UInt8](normalized.suffix(32))
            XCTAssertNotEqual(try p256LowSNormalized(raw: normalized), Data())
            XCTAssertLessThanOrEqual(compareForTest(s, p256HalfOrder), 0)
        }
    }

    func testDigestHexCodecIsStrict() throws {
        let digest = "0x" + String(repeating: "4b", count: 32)
        XCTAssertEqual(hexEncode(try decodeDigestHex(digest)), digest)
        for bad in [
            "",
            "4b4b",
            "0x" + String(repeating: "4b", count: 31),
            "0x" + String(repeating: "4B", count: 32),
            "0x" + String(repeating: "zz", count: 32)
        ] {
            XCTAssertThrowsError(try decodeDigestHex(bad)) {
                XCTAssertEqual($0 as? OwnerPhoneSigningError, .malformedDigest)
            }
        }
    }

    func testRawSignatureHexCodecIsStrict() throws {
        let signature = "0x" + String(repeating: "2a", count: 64)
        XCTAssertEqual(hexEncode(try decodeP256RawSignatureHex(signature)), signature)
        for bad in [
            "",
            String(repeating: "2a", count: 64),
            "0x" + String(repeating: "2a", count: 63),
            "0x" + String(repeating: "2A", count: 64),
            "0x" + String(repeating: "zz", count: 64)
        ] {
            XCTAssertThrowsError(try decodeP256RawSignatureHex(bad)) {
                XCTAssertEqual($0 as? OwnerPhoneSigningError, .malformedRawSignature)
            }
        }
    }
}

/// Big-endian compare, duplicated here so the test does not trust the code
/// under test for its own assertion.
private func compareForTest(_ left: [UInt8], _ right: [UInt8]) -> Int {
    for index in 0..<left.count where left[index] != right[index] {
        return left[index] < right[index] ? -1 : 1
    }
    return 0
}
