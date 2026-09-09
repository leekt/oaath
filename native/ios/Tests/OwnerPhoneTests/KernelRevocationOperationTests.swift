/**
 The same unsigned operations are checked by the protocol parser and Swift.
 Forbidden calls have independently correct viem hashes: rejecting them must
 prove call meaning, not merely a stale expected digest. No keys or signatures.
 */
import Foundation
import XCTest
@testable import OwnerPhone

final class KernelRevocationOperationTests: XCTestCase {
    private func fixture() throws -> [String: Any] {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent()
        return try Wire.object(Data(contentsOf: root.appendingPathComponent(
            "packages/protocol/test/fixtures/kernel-revocation-operation.json")), label: "fixture")
    }

    private func install(_ fixture: [String: Any]) throws -> OwnerPhoneSigningRequestScope {
        let data = try JSONSerialization.data(withJSONObject: XCTUnwrap(fixture["installProjection"]))
        let projection = try OwnerPhoneRequestProjection.decode(data)
        guard case let .ownerSigningRequest(scope) = projection.scope else {
            throw OwnerPhoneWireError.invalidField("fixture install")
        }
        return scope
    }

    private func entries(_ fixture: [String: Any], _ key: String) throws -> [[String: Any]] {
        try XCTUnwrap(fixture[key] as? [[String: Any]])
    }

    private func derive(
        _ entry: [String: Any], install: OwnerPhoneSigningRequestScope
    ) throws -> DerivedKernelRevocationOperation {
        try deriveKernelRevocationOperation(
            install: install,
            effect: XCTUnwrap(entry["effect"] as? String),
            chainId: XCTUnwrap(entry["chainId"] as? Int),
            entryPoint: XCTUnwrap(entry["entryPoint"] as? String),
            operation: XCTUnwrap(entry["operation"]),
            expectedDigest: XCTUnwrap(entry["expectedDigest"] as? String))
    }

    func testRejectsForbiddenCallsEvenWithCorrectOperationHashes() throws {
        let fixture = try fixture()
        let install = try install(fixture)
        for entry in try entries(fixture, "forbiddenCalls") {
            XCTAssertThrowsError(try derive(entry, install: install)) {
                XCTAssertTrue($0 as? KernelRevocationOperationError == .callMismatch)
            }
        }
    }

    func testRejectsChangedChainEntryPointNonceAndGasWithTheOriginalDigest() throws {
        let fixture = try fixture()
        let install = try install(fixture)
        let original = try XCTUnwrap(entries(fixture, "valid").first)
        var chain = original
        chain["chainId"] = 421614
        var entryPoint = original
        entryPoint["entryPoint"] = "0x" + String(repeating: "11", count: 20)
        var changed = [chain, entryPoint]
        for (key, value) in [
            ("nonce", "0"), ("preVerificationGas", "1"),
            ("gasFees", "0x" + String(repeating: "11", count: 32)),
            ("accountGasLimits", "0x" + String(repeating: "22", count: 32)),
            ("initCode", "0x" + String(repeating: "55", count: 20))
        ] {
            var entry = original
            var op = try XCTUnwrap(entry["operation"] as? [String: Any])
            op[key] = value
            entry["operation"] = op
            changed.append(entry)
        }
        for entry in changed {
            XCTAssertThrowsError(try derive(entry, install: install)) {
                XCTAssertTrue($0 as? KernelRevocationOperationError == .digestMismatch)
            }
        }
    }

    func testRefusesNonRootNonceOtherAccountSponsorshipAndUnsupportedFactory() throws {
        let fixture = try fixture()
        let install = try install(fixture)
        let original = try XCTUnwrap(entries(fixture, "valid").first)
        for (key, value) in [
            ("nonce", "1208925819614629174706176"), // 2^80: outside root namespace.
            ("sender", "0x" + String(repeating: "11", count: 20)),
            ("paymasterAndData", "0x12"),
            ("initCode", "0x1234"),
            ("initCode", "0x7702" + String(repeating: "00", count: 18))
        ] {
            var entry = original
            var op = try XCTUnwrap(entry["operation"] as? [String: Any])
            op[key] = value
            entry["operation"] = op
            XCTAssertThrowsError(try derive(entry, install: install)) {
                XCTAssertTrue($0 as? KernelRevocationOperationError == .invalidOperation)
            }
        }
    }

    func testCapturesExactPackedFieldsAndIntegerWidths() throws {
        let fixture = try fixture()
        let install = try install(fixture)
        let original = try XCTUnwrap(entries(fixture, "valid").first)
        for (key, value) in [
            ("signature", "0x"), ("nonce", "01"), ("nonce", "-1"),
            ("nonce", String(repeating: "9", count: 78)),
            ("preVerificationGas", "1329227995784915872903807060280344576"), // 2^120.
            ("gasFees", "0x12"), ("accountGasLimits", "0x" + String(repeating: "AA", count: 32)),
            ("callData", "0x1"), ("initCode", "0x" + String(repeating: "00", count: 65_537))
        ] {
            var entry = original
            var op = try XCTUnwrap(entry["operation"] as? [String: Any])
            op[key] = value
            entry["operation"] = op
            XCTAssertThrowsError(try derive(entry, install: install))
        }
    }

    func testRejectsUnknownEffectInvalidChainAndZeroEntryPoint() throws {
        let fixture = try fixture()
        let install = try install(fixture)
        let original = try XCTUnwrap(entries(fixture, "valid").first)
        for (key, value): (String, Any) in [
            ("effect", "execute"), ("chainId", 0), ("chainId", -1),
            ("chainId", 9_007_199_254_740_992),
            ("entryPoint", "0x" + String(repeating: "00", count: 20)),
            ("expectedDigest", "0x12")
        ] {
            var entry = original
            entry[key] = value
            XCTAssertThrowsError(try derive(entry, install: install))
        }
    }

    func testAcceptsBothEffectsAndCounterfactualDataWithViemDigestParity() throws {
        let fixture = try fixture()
        let install = try install(fixture)
        let entries = try entries(fixture, "valid")
        XCTAssertTrue(entries.count == 3)
        for entry in entries {
            let first = try derive(entry, install: install)
            let recreated = try derive(entry, install: install)
            XCTAssertTrue(first == recreated)
            XCTAssertTrue(first.canonicalHex == entry["expectedDigest"] as? String)
            XCTAssertTrue(first.chainId == entry["chainId"] as? Int)
            XCTAssertTrue(first.entryPoint == entry["entryPoint"] as? String)
            XCTAssertTrue(first.effect.rawValue == entry["effect"] as? String)
        }
    }

    func testExhaustedInstallSequenceCannotWrapToZero() throws {
        var fixture = try fixture()
        var projection = try XCTUnwrap(fixture["installProjection"] as? [String: Any])
        var scope = try XCTUnwrap(projection["scope"] as? [String: Any])
        var request = try XCTUnwrap(scope["request"] as? [String: Any])
        var typedData = try XCTUnwrap(request["typedData"] as? [String: Any])
        var message = try XCTUnwrap(typedData["message"] as? [String: Any])
        let nonce = "18446744073709551615" // Exhausted uint64 install sequence.
        message["nonce"] = nonce
        typedData["message"] = message
        request["typedData"] = typedData
        request["replay"] = ["nonce": nonce, "deadline": NSNull()]
        request["expectedDigest"] = try deriveEIP712Digest(jsonValue: typedData).canonicalHex
        scope["request"] = request
        projection["scope"] = scope
        fixture["installProjection"] = projection
        let install = try install(fixture)
        let entry = try XCTUnwrap(entries(fixture, "valid").first)
        XCTAssertThrowsError(try derive(entry, install: install)) {
            XCTAssertTrue($0 as? KernelRevocationOperationError == .invalidInstall)
        }
    }

    func testGenericRawDigestCannotStandInForAnInstallScope() throws {
        let fixture = try fixture()
        let entry = try XCTUnwrap(entries(fixture, "valid").first)
        guard case let .ownerSigningRequest(scope) = OwnerPhoneScope.rawDigestSigningFixture() else {
            return XCTFail("missing raw digest fixture")
        }
        XCTAssertThrowsError(try derive(entry, install: scope)) {
            XCTAssertTrue($0 as? KernelEnableSigningError == .requestNotKernelEnable)
        }
    }
}
