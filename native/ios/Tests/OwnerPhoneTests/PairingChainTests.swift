import CryptoKit
import Foundation
import XCTest
@testable import OwnerPhone
@testable import OwnerPhoneDemo

final class PairingChainTests: XCTestCase {
    private let account = "0x" + String(repeating: "66", count: 20)
    private let entryPoint = "0x0000000071727de22e5e9d8baf0edac6f37da032"

    private func response(_ chains: String, account: String? = nil) -> Data {
        let account = account ?? self.account
        return Data(("{\"version\":\"oaath.phone-pairing/v1\",\"deviceCredential\":\"" +
            String(repeating: "A", count: 43) + "\",\"account\":\"\(account)\",\"chains\":\(chains)}").utf8)
    }

    func testPairingRefusesMissingEmptyDuplicateAndMalformedChainConfiguration() throws {
        for chains in [
            "null", "[]",
            "[{\"chainId\":31337,\"entryPoint\":\"\(entryPoint)\"},{\"chainId\":31337,\"entryPoint\":\"\(entryPoint)\"}]",
            "[{\"chainId\":true,\"entryPoint\":\"\(entryPoint)\"}]",
            "[{\"chainId\":0,\"entryPoint\":\"\(entryPoint)\"}]",
            "[{\"chainId\":31337.5,\"entryPoint\":\"\(entryPoint)\"}]",
            "[{\"chainId\":31337,\"entryPoint\":\"0x12\"}]",
            "[{\"chainId\":31337,\"entryPoint\":\"\(entryPoint)\",\"extra\":1}]"
        ] {
            XCTAssertThrowsError(try decodePairingResponse(response(chains))) {
                XCTAssertTrue($0 as? DemoPairingError == .invalidResponse)
            }
        }
        let chain = "[{\"chainId\":31337,\"entryPoint\":\"\(entryPoint)\"}]"
        let valid = response(chain)
        let validText = try XCTUnwrap(String(data: valid, encoding: .utf8))
        for text in [
            validText.replacingOccurrences(of: ",\"chains\":\(chain)", with: ""),
            validText.replacingOccurrences(of: "\"\(account)\"", with: "null"),
            validText.replacingOccurrences(of: "oaath.phone-pairing/v1", with: "oaath.phone-pairing/v0")
        ] { XCTAssertThrowsError(try decodePairingResponse(Data(text.utf8))) }
    }

    func testTypedConfigurationRejectsUnknownAndContradictoryBindings() throws {
        for entries in [
            [:], [0: entryPoint], [-1: entryPoint],
            [9_007_199_254_740_992: entryPoint],
            [31337: "0x" + String(repeating: "00", count: 20)],
            [31337: entryPoint.uppercased()]
        ] {
            XCTAssertThrowsError(try OwnerPhoneKernelChains(entryPoints: entries))
        }
        let chains = try OwnerPhoneKernelChains(entryPoints: [31337: entryPoint, 421614: entryPoint])
        XCTAssertTrue(chains.contains(chainId: 31337, entryPoint: entryPoint))
        XCTAssertFalse(chains.contains(chainId: 1, entryPoint: entryPoint))
        XCTAssertFalse(chains.contains(chainId: 31337, entryPoint: account))
    }

    func testPairingRecreationRetainsEveryChainAndEntryPoint() throws {
        let wire = response("[{\"chainId\":31337,\"entryPoint\":\"\(entryPoint)\"},{\"chainId\":421614,\"entryPoint\":\"\(account)\"}]")
        let device = try decodePairingResponse(wire)
        let key = P256.Signing.PrivateKey()
        let material = try XCTUnwrap(OwnerPublicMaterial(hexEncode(Data(key.publicKey.x963Representation.dropFirst()))))
        let original = try PersistedPairing(
            endpoint: DemoRelayEndpoint(baseURLText: "http://relay.example:8787"),
            credential: device.deviceCredential, account: device.account,
            chains: device.chains, ownerPublicMaterial: material)
        let restored = try PersistedPairing.decode(original.encoded())
        XCTAssertTrue(PersistedPairing.version == 4)
        XCTAssertTrue(restored == original)
        XCTAssertTrue(restored.chains.entryPoints == [31337: entryPoint, 421614: account])
        let binding = try OwnerPhoneKernelP256ApprovalBinding(
            account: restored.account, p256PublicMaterial: material.hex,
            chains: restored.chains, pairingIsCurrent: { true },
            sign: { _ in throw KernelEnableSigningError.signerFailed })
        XCTAssertTrue(binding.chains == restored.chains)

        var record = try XCTUnwrap(JSONSerialization.jsonObject(with: original.encoded()) as? [String: Any])
        record.removeValue(forKey: "chains")
        XCTAssertThrowsError(try PersistedPairing.decode(JSONSerialization.data(withJSONObject: record, options: .sortedKeys)))
        record["version"] = 3
        XCTAssertThrowsError(try PersistedPairing.decode(JSONSerialization.data(withJSONObject: record, options: .sortedKeys)))
    }

    func testChangedChainConfigurationInvalidatesTheCapturedPairing() throws {
        let key = P256.Signing.PrivateKey()
        let material = try XCTUnwrap(OwnerPublicMaterial(hexEncode(Data(key.publicKey.x963Representation.dropFirst()))))
        func pairing(_ chains: OwnerPhoneKernelChains) throws -> PersistedPairing {
            try PersistedPairing(
                endpoint: DemoRelayEndpoint(baseURLText: "http://relay.example:8787"),
                credential: String(repeating: "A", count: 43), account: account,
                chains: chains, ownerPublicMaterial: material)
        }
        let original = try pairing(OwnerPhoneKernelChains(entryPoints: [31337: entryPoint]))
        let replacement = try pairing(OwnerPhoneKernelChains(entryPoints: [421614: entryPoint]))
        let store = InMemoryPairingStore(result: .stored(original))
        let binding = try OwnerPhoneKernelP256ApprovalBinding(
            account: original.account, p256PublicMaterial: material.hex, chains: original.chains,
            pairingIsCurrent: { store.load() == .stored(original) },
            sign: { _ in throw KernelEnableSigningError.signerFailed })
        XCTAssertTrue(binding.pairingIsCurrent())
        XCTAssertTrue(store.clear())
        XCTAssertTrue(try store.installIfAbsent(replacement))
        XCTAssertFalse(binding.pairingIsCurrent())
        XCTAssertTrue(store.load() == .stored(replacement))
    }
}
