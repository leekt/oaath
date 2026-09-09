import CryptoKit
import Foundation
import XCTest
@testable import OwnerPhone

private final class RevocationSignerProbe: @unchecked Sendable {
    let key = P256.Signing.PrivateKey()
    private let lock = NSLock()
    private var calls = 0
    func sign(_ digest: VerifiedSignableDigest) throws -> Data {
        lock.lock()
        calls += 1
        lock.unlock()
        return try key.signature(for: digest.cryptoKitDigest).derRepresentation
    }
    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return calls
    }
}

private struct TestRevocationDigest: Digest {
    static let byteCount = 32
    let storage: Data
    func withUnsafeBytes<Result>(_ body: (UnsafeRawBufferPointer) throws -> Result) rethrows -> Result {
        try storage.withUnsafeBytes(body)
    }
    func hash(into hasher: inout Hasher) { hasher.combine(storage) }
}

private actor RevocationTransportProbe {
    let projection: Data
    private var bodies = [Data]()
    init(projection: Data) { self.projection = projection }
    func send(_ call: OwnerPhoneRelayCall) throws -> Data {
        switch call.kind {
        case .fetchProjection: return projection
        case .submitRevocationDecision:
            bodies.append(try XCTUnwrap(call.body))
            if bodies.count == 1 { throw OwnerPhoneWireError.invalidField("decision") }
            return Data(#"{"version":"oaath.native-revocation-decision/v1","operationId":"revoke-0","outcome":"approved","decidedAt":1800000000001,"settlement":"replayed"}"#.utf8)
        default: throw OwnerPhoneWireError.invalidField("wrong decision domain")
        }
    }
    var retriedExactly: Bool { bodies.count == 2 && bodies[0] == bodies[1] }
}

final class NativeRevocationConsentTests: XCTestCase {
    private let now = 1_800_000_000_000
    private let account = "0x" + String(repeating: "66", count: 20)

    private func wire(_ index: Int = 0, key: P256.Signing.PrivateKey? = nil) throws -> Data {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent()
        let data = try Data(contentsOf: root.appendingPathComponent(
            "packages/server/test/fixtures/phone-revocation-golden.json"))
        var projection = try XCTUnwrap((JSONSerialization.jsonObject(with: data) as? [[String: Any]])?[index])
        guard let key else { return try JSONSerialization.data(withJSONObject: projection) }
        var scope = try XCTUnwrap(projection["scope"] as? [String: Any])
        var install = try XCTUnwrap(scope["install"] as? [String: Any])
        var request = try XCTUnwrap(install["request"] as? [String: Any])
        var signer = try XCTUnwrap(request["signer"] as? [String: Any])
        let publicKey = hexEncode(key.publicKey.x963Representation)
        signer["ownerCredential"] = ["version": ownerPhoneOwnerCredentialVersion,
                                      "kind": "p256", "publicKey": publicKey]
        request["signer"] = signer
        install["request"] = request
        scope["install"] = install
        var permission = try XCTUnwrap(scope["permission"] as? [String: Any])
        var account = try XCTUnwrap(permission["account"] as? [String: Any])
        account["ownerCredential"] = ["kind": "p256", "publicKey": publicKey]
        permission["account"] = account
        scope["permission"] = permission
        projection["scope"] = scope
        // The fixture server commitment stays authenticated metadata, as it is
        // for enable consent. This unit substitutes an ephemeral owner key to
        // prove native signing; it does not claim a full request-hash derivation.
        return try JSONSerialization.data(withJSONObject: projection)
    }

    private func binding(_ probe: RevocationSignerProbe, chains: OwnerPhoneKernelChains = configuredTestChains,
                         account: String? = nil) throws -> OwnerPhoneKernelP256ApprovalBinding {
        try OwnerPhoneKernelP256ApprovalBinding(
            account: account ?? self.account,
            p256PublicMaterial: hexEncode(Data(probe.key.publicKey.x963Representation.dropFirst())),
            chains: chains, pairingIsCurrent: { true }, sign: { try probe.sign($0) })
    }

    func testWrongChainEntryPointAccountOrExpiredReviewCannotInvokeCustody() throws {
        let probe = RevocationSignerProbe()
        let projection = try OwnerPhoneRequestProjection.decode(wire(key: probe.key))
        for chains in [
            try OwnerPhoneKernelChains(entryPoints: [1: "0x0000000071727de22e5e9d8baf0edac6f37da032"]),
            try OwnerPhoneKernelChains(entryPoints: [31337: account])
        ] {
            XCTAssertThrowsError(try binding(probe, chains: chains).makeArtifact(
                OwnerPhoneReview(projection: projection), now: now))
        }
        XCTAssertThrowsError(try binding(probe, account: "0x" + String(repeating: "11", count: 20)).makeArtifact(
            OwnerPhoneReview(projection: projection), now: now))
        XCTAssertThrowsError(try binding(probe).makeArtifact(
            OwnerPhoneReview(projection: projection), now: projection.expiresAt))
        let otherProbe = RevocationSignerProbe()
        XCTAssertThrowsError(try binding(otherProbe).makeArtifact(
            OwnerPhoneReview(projection: projection), now: now))
        var authorizing = OwnerPhoneReview(projection: projection)
        try authorizing.beginAuthorization(availability: .kernelP256OwnerSigning, now: now)
        XCTAssertThrowsError(try binding(probe).makeArtifact(authorizing, now: now))
        XCTAssertTrue(otherProbe.count == 0)
        XCTAssertTrue(probe.count == 0)
    }

    func testBothRevocationEffectsProduceVerifiedP256Artifacts() throws {
        for index in [0, 2] {
            let probe = RevocationSignerProbe()
            let projection = try OwnerPhoneRequestProjection.decode(wire(index, key: probe.key))
            guard case let .kernelRevocation(scope) = projection.scope else {
                return XCTFail("expected revocation consent")
            }
            let artifact = try binding(probe).makeArtifact(OwnerPhoneReview(projection: projection), now: now)
            let object = try Wire.object(Data(artifact.utf8), label: "test artifact")
            XCTAssertTrue(object["requestHash"] as? String == scope.requestHash)
            XCTAssertTrue(object["kind"] as? String == "p256")
            let signatureHex = try XCTUnwrap(object["signature"] as? String)
            let bytes = try XCTUnwrap(decodeLowercaseEIP712Hex(signatureHex, exactBytes: 64))
            let signature = try P256.Signing.ECDSASignature(rawRepresentation: Data(bytes))
            XCTAssertTrue(probe.key.publicKey.isValidSignature(signature, for: TestRevocationDigest(storage: scope.operation.digest)))
            XCTAssertTrue(probe.count == 1)
            XCTAssertNil(projection.client.redirectUri)
        }
    }

    func testConsentRendersExactHighWidthOperationFactsAndBothEffects() throws {
        for index in 0...2 {
            let projection = try OwnerPhoneRequestProjection.decode(wire(index))
            guard case let .kernelRevocation(scope) = projection.scope else {
                return XCTFail("expected revocation consent")
            }
            let facts = KernelRevocationConsentPresentation(scope: scope).sections.flatMap(\.facts)
            let values = Dictionary(uniqueKeysWithValues: facts.map { ($0.label, $0.value) })
            XCTAssertEqual(values["Workspace"], scope.permission.context.workspaceId)
            XCTAssertEqual(values["Chain"], "31337")
            XCTAssertEqual(values["Effect"], index == 2
                           ? "Remove the installed permission" : "Prevent this approval from installing")
            XCTAssertEqual(values["Account deployment"], index == 1 ? "Included in this operation" : "Not requested")
            XCTAssertEqual(values["Operation nonce"], index == 1 ? "0" : "1208925819614629174706175")
            XCTAssertEqual(values["Verification gas limit"], "94522879700260683142460330790866415")
            XCTAssertEqual(values["Pre-verification gas"], "1329227995784915872903807060280344575")
            XCTAssertEqual(values["Call gas limit"], "900000")
            XCTAssertEqual(values["Maximum fee per gas (wei)"], "2000000000")
            XCTAssertEqual(values["Maximum priority fee per gas (wei)"], "1000000000")
            XCTAssertEqual(values["Locally derived operation hash"], scope.operation.canonicalHex)
        }
    }

    func testRevocationRejectsCodeDeliveryOrContradictoryClientMetadata() throws {
        let original = try Wire.object(wire(), label: "test")
        for client in [
            ["clientId": "phone-demo", "redirectUri": "https://app.example/callback"],
            ["clientId": "different-client", "redirectUri": NSNull()]
        ] as [[String: Any]] {
            var changed = original
            changed["client"] = client
            XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(JSONSerialization.data(withJSONObject: changed)))
        }
    }

    func testRevocationCannotSettleWithAnOAuthRelease() throws {
        let projection = try OwnerPhoneRequestProjection.decode(wire(key: P256.Signing.PrivateKey()))
        var review = OwnerPhoneReview(projection: projection)
        try review.beginSubmission(.rejected, now: now)
        XCTAssertThrowsError(try review.settle(OwnerPhoneDecision(
            operationId: projection.operationId, outcome: .rejected, decidedAt: now,
            settlement: .decided, release: .rejected))) {
            XCTAssertEqual($0 as? OwnerPhoneReview.TransitionError, .contradictoryEvidence)
        }
        XCTAssertEqual(review.state, .submitting(.rejected))
    }

    @MainActor
    func testBackgroundOrReplacedPairingCannotStartRevocationSigning() async throws {
        for foreground in [false, true] {
            let probe = RevocationSignerProbe()
            let transport = RevocationTransportProbe(projection: try wire(key: probe.key))
            let binding = try OwnerPhoneKernelP256ApprovalBinding(
                account: account,
                p256PublicMaterial: hexEncode(Data(probe.key.publicKey.x963Representation.dropFirst())),
                chains: configuredTestChains, pairingIsCurrent: { !foreground }, sign: { try probe.sign($0) })
            let model = ApprovalModel(relay: TransportRelayClient { try await transport.send($0) },
                                      kernelP256ApprovalBinding: binding, now: { 1_800_000_000_000 })
            model.setForeground(foreground)
            await model.open(operationId: "revoke-0")
            await model.approve()
            XCTAssertTrue(probe.count == 0)
            guard case let .review(review) = model.phase else { return XCTFail("review lost") }
            XCTAssertEqual(review.state, .pending)
        }
    }

    @MainActor
    func testAmbiguousRevocationDecisionRetriesTheExactArtifactWithoutSigningAgain() async throws {
        let probe = RevocationSignerProbe()
        let transport = RevocationTransportProbe(projection: try wire(key: probe.key))
        let model = ApprovalModel(
            relay: TransportRelayClient { try await transport.send($0) },
            kernelP256ApprovalBinding: try binding(probe), now: { 1_800_000_000_000 })
        model.setForeground(true)
        await model.open(operationId: "revoke-0")
        await model.approve()
        XCTAssertTrue(model.unresolvedNotice)
        await model.approve()
        guard case let .review(review) = model.phase,
              case let .settled(decision) = review.state else {
            return XCTFail("revocation decision did not settle")
        }
        XCTAssertTrue(decision.outcome == .approved)
        XCTAssertNil(decision.release)
        XCTAssertTrue(probe.count == 1)
        let retriedExactly = await transport.retriedExactly
        XCTAssertTrue(retriedExactly)
    }
}
