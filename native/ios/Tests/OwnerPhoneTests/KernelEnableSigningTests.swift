/**
 Package-internal proofs for the disconnected Kernel-enable signing refinement.

 Keys and signatures are test-scoped; the one temporary keychain key is
 deleted at test exit. Assertions expose booleans and artifact shape/order,
 never secret or signature material.

 @author taek <leekt216@gmail.com>
 */
import CryptoKit
import Foundation
import XCTest
@testable import OwnerPhone
#if canImport(Security)
import Security
#endif

private let signingTestNow = 1_800_000_000_000
private let signingTestAccount = "0x" + String(repeating: "66", count: 20)

private struct KernelSigningHarness {
    let key: P256.Signing.PrivateKey
    let pairedIdentity: KernelEnablePairedIdentity
    let review: OwnerPhoneReview
    let requestHash: String
}

struct KernelReviewHarness {
    let pairedIdentity: KernelEnablePairedIdentity
    let review: OwnerPhoneReview
    let requestHash: String
}

private enum InjectedSignerFailure: Error {
    case refused
}

private final class SigningInvocationProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var calls = 0

    func record() {
        lock.lock()
        calls += 1
        lock.unlock()
    }

    func count() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return calls
    }
}

final class KernelEnableSigningTests: XCTestCase {
    func testSemanticCapabilityAndPairingCheckDoNotInvokeTheSigner() throws {
        let key = P256.Signing.PrivateKey()
        let harness = try makeReviewHarness(
            publicKeyX963: key.publicKey.x963Representation)
        let signer = SigningInvocationProbe()
        let binding = try OwnerPhoneKernelP256ApprovalBinding(
            account: signingTestAccount,
            p256PublicMaterial: hexEncode(Data(key.publicKey.x963Representation.dropFirst())),
            pairingIsCurrent: { true },
            sign: { _ in
                signer.record()
                throw InjectedSignerFailure.refused
            })
        guard case let .ownerSigningRequest(scope) = harness.review.projection.scope else {
            return XCTFail("expected a Kernel owner-signing request")
        }

        let refined = try refineKernelEnableSigningScope(scope)
        XCTAssertTrue(refined.requestHash == harness.requestHash)
        XCTAssertTrue(refined.account == signingTestAccount)
        XCTAssertTrue(refined.digest.canonicalHex.count == 66)
        XCTAssertTrue(binding.semanticallyMatches(harness.review.projection))
        XCTAssertTrue(signer.count() == 0)
    }

    func testApprovalBindingAcceptsOnlyExactAccountAndOnCurvePublicMaterial() throws {
        let key = P256.Signing.PrivateKey()
        let validMaterial = hexEncode(Data(key.publicKey.x963Representation.dropFirst()))
        XCTAssertNoThrow(try OwnerPhoneKernelP256ApprovalBinding(
            account: signingTestAccount,
            p256PublicMaterial: validMaterial,
            pairingIsCurrent: { true },
            sign: { _ in throw InjectedSignerFailure.refused }))

        let invalidBindings = [
            (signingTestAccount.uppercased(), validMaterial),
            ("0x" + String(repeating: "00", count: 20), validMaterial),
            (signingTestAccount, "0x12"),
            (signingTestAccount, "0xA" + String(validMaterial.dropFirst(3))),
            (signingTestAccount, "0x" + String(repeating: "00", count: 64)),
        ]
        for (account, material) in invalidBindings {
            XCTAssertThrowsError(try OwnerPhoneKernelP256ApprovalBinding(
                account: account,
                p256PublicMaterial: material,
                pairingIsCurrent: { true },
                sign: { _ in throw InjectedSignerFailure.refused }
            )) {
                XCTAssertTrue(
                    $0 as? KernelEnableSigningError == .pairedIdentityInvalid)
            }
        }
    }

#if canImport(Security)
    func testLoadOnlyKeychainCustodyConsumesOnlyTheVerifiedDigest() throws {
        let tag = "org.oaath.tests.verified-signing.\(UUID().uuidString)"
        let applicationTag = Data(tag.utf8)
        defer {
            let query: [CFString: Any] = [
                kSecClass: kSecClassKey,
                kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeyClass: kSecAttrKeyClassPrivate,
                kSecAttrApplicationTag: applicationTag
            ]
            SecItemDelete(query as CFDictionary)
        }

        let provisioned = KeychainKeyCustodyStub(applicationTag: tag)
        let publicKey = try provisioned.publicKey()
        let loadOnly = KeychainKeyCustodyStub(
            applicationTag: tag,
            createIfMissing: false)
        XCTAssertTrue(try loadOnly.publicKey() == publicKey)
        let harness = try makeReviewHarness(publicKeyX963: publicKey)
        var custodyCalls = 0

        let artifact = try makeKernelEnableOwnerSigningArtifact(
            review: harness.review,
            now: signingTestNow,
            pairedIdentity: harness.pairedIdentity
        ) { digest in
            custodyCalls += 1
            return try loadOnly.sign(digest)
        }

        XCTAssertTrue(custodyCalls == 1)
        XCTAssertTrue(artifact.hasPrefix(
            "{\"version\":\"oaath.owner-signing-artifact/v1\",\"kind\":\"p256\","))
        XCTAssertTrue(artifact.hasSuffix("}"))
    }

    func testMissingLoadOnlyCustodyCreatesNeitherKeyNorArtifact() throws {
        let tag = "org.oaath.tests.missing-verified-signing.\(UUID().uuidString)"
        let applicationTag = Data(tag.utf8)
        defer {
            let query: [CFString: Any] = [
                kSecClass: kSecClassKey,
                kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeyClass: kSecAttrKeyClassPrivate,
                kSecAttrApplicationTag: applicationTag
            ]
            SecItemDelete(query as CFDictionary)
        }
        let missing = KeychainKeyCustodyStub(
            applicationTag: tag,
            createIfMissing: false)
        let requestKey = P256.Signing.PrivateKey()
        let harness = try makeReviewHarness(
            publicKeyX963: requestKey.publicKey.x963Representation)
        var custodyCalls = 0
        var producedArtifact = false
        var structuredError: KernelEnableSigningError?

        do {
            _ = try makeKernelEnableOwnerSigningArtifact(
                review: harness.review,
                now: signingTestNow,
                pairedIdentity: harness.pairedIdentity
            ) { digest in
                custodyCalls += 1
                return try missing.sign(digest)
            }
            producedArtifact = true
        } catch {
            structuredError = error as? KernelEnableSigningError
        }

        XCTAssertTrue(custodyCalls == 1)
        XCTAssertTrue(!producedArtifact)
        XCTAssertTrue(structuredError == .signerFailed)
        XCTAssertThrowsError(try missing.publicKey()) {
            XCTAssertTrue($0 as? OwnerPhoneKeyCustodyError == .keyUnavailable)
        }
    }
#endif

    func testExactPendingKernelRequestSignsOnceAndEmitsCanonicalVerifiedArtifact() throws {
        let harness = try makeHarness()
        var signerCalls = 0
        var signedDigest: VerifiedSignableDigest?

        let artifact = try makeKernelEnableOwnerSigningArtifact(
            review: harness.review,
            now: signingTestNow,
            pairedIdentity: harness.pairedIdentity
        ) { digest in
            signerCalls += 1
            signedDigest = digest
            return try harness.key.signature(for: digest.cryptoKitDigest).derRepresentation
        }

        XCTAssertTrue(signerCalls == 1)
        XCTAssertTrue(artifact.hasPrefix(
            "{\"version\":\"oaath.owner-signing-artifact/v1\",\"kind\":\"p256\","))
        XCTAssertTrue(artifact.hasSuffix("}"))

        guard let version = artifact.range(of: "\"version\":"),
              let kind = artifact.range(of: "\"kind\":"),
              let requestHash = artifact.range(of: "\"requestHash\":"),
              let signature = artifact.range(of: "\"signature\":"),
              version.lowerBound < kind.lowerBound,
              kind.lowerBound < requestHash.lowerBound,
              requestHash.lowerBound < signature.lowerBound,
              let object = try JSONSerialization.jsonObject(
                with: Data(artifact.utf8)) as? [String: Any],
              let signatureHex = object["signature"] as? String,
              let digest = signedDigest
        else {
            return XCTFail("canonical artifact shape or field order was not preserved")
        }

        XCTAssertTrue(Set(object.keys) == ["version", "kind", "requestHash", "signature"])
        XCTAssertTrue(object["version"] as? String == ownerPhoneSigningArtifactVersion)
        XCTAssertTrue(object["kind"] as? String == "p256")
        XCTAssertTrue(object["requestHash"] as? String == harness.requestHash)
        XCTAssertTrue(isCanonicalSignatureHex(signatureHex))
        let exactArtifact =
            "{\"version\":\"\(ownerPhoneSigningArtifactVersion)\",\"kind\":\"p256\"," +
            "\"requestHash\":\"\(harness.requestHash)\",\"signature\":\"\(signatureHex)\"}"
        XCTAssertTrue(artifact == exactArtifact)

        let raw = try decodeP256RawSignatureHex(signatureHex)
        let normalized = try p256LowSNormalized(raw: raw)
        let parsed = try P256.Signing.ECDSASignature(rawRepresentation: raw)
        XCTAssertTrue(normalized == raw)
        XCTAssertTrue(harness.key.publicKey.isValidSignature(
            parsed,
            for: digest.cryptoKitDigest))
    }

    func testEveryContradictoryReviewFailsBeforeSignerAndArtifact() throws {
        let harness = try makeHarness()
        let request = try kernelRequest(harness.review)

        assertPreSignRejection(
            review: replacingScope(harness.review, with: .rawDigestSigningFixture()),
            pairedIdentity: harness.pairedIdentity,
            key: harness.key,
            expected: .requestNotKernelEnable)

        assertPreSignRejection(
            review: replacingRequest(
                harness.review,
                with: cloneRequest(request, purpose: .application)),
            pairedIdentity: harness.pairedIdentity,
            key: harness.key,
            expected: .requestNotKernelEnable)

        let applicationTypedData = CanonicalEIP712TypedData(
            types: [
                "EIP712Domain": kernelDomainTypeFields(),
                "Application": [CanonicalEIP712Field(name: "value", type: "bytes32")]
            ],
            primaryType: "Application",
            domain: request.typedData.domain,
            message: ["value": .string("0x" + String(repeating: "ab", count: 32))])
        let applicationDigest = try deriveEIP712Digest(from: applicationTypedData)
        assertPreSignRejection(
            review: replacingRequest(
                harness.review,
                with: cloneRequest(
                    request,
                    typedData: applicationTypedData,
                    expectedDigest: applicationDigest.canonicalHex)),
            pairedIdentity: harness.pairedIdentity,
            key: harness.key,
            expected: .typedDataInvalid)

        let ecdsaSigner = OwnerPhoneSigningSigner(
            account: request.signer.account,
            ownerCredential: OwnerPhoneSigningCredential(
                version: ownerPhoneOwnerCredentialVersion,
                credential: .ecdsa(address: "0x" + String(repeating: "33", count: 20))))
        assertPreSignRejection(
            review: replacingRequest(
                harness.review,
                with: cloneRequest(request, signer: ecdsaSigner)),
            pairedIdentity: harness.pairedIdentity,
            key: harness.key,
            expected: .credentialMismatch)

        let wrongAccountSigner = OwnerPhoneSigningSigner(
            account: "0x" + String(repeating: "77", count: 20),
            ownerCredential: request.signer.ownerCredential)
        assertPreSignRejection(
            review: replacingRequest(
                harness.review,
                with: cloneRequest(request, signer: wrongAccountSigner)),
            pairedIdentity: harness.pairedIdentity,
            key: harness.key,
            expected: .accountMismatch)

        let otherKey = P256.Signing.PrivateKey()
        let wrongKeySigner = OwnerPhoneSigningSigner(
            account: request.signer.account,
            ownerCredential: OwnerPhoneSigningCredential(
                version: ownerPhoneOwnerCredentialVersion,
                credential: .p256(publicKey: hexEncode(otherKey.publicKey.x963Representation))))
        assertPreSignRejection(
            review: replacingRequest(
                harness.review,
                with: cloneRequest(request, signer: wrongKeySigner)),
            pairedIdentity: harness.pairedIdentity,
            key: harness.key,
            expected: .credentialMismatch)

        var wrongDomain = request.typedData.domain
        wrongDomain["name"] = .string("Not Kernel")
        assertPreSignRejection(
            review: replacingRequest(
                harness.review,
                with: cloneRequest(
                    request,
                    typedData: cloneTypedData(request.typedData, domain: wrongDomain))),
            pairedIdentity: harness.pairedIdentity,
            key: harness.key,
            expected: .typedDataInvalid)

        var wrongVerifyingContract = request.typedData.domain
        wrongVerifyingContract["verifyingContract"] =
            .string("0x" + String(repeating: "88", count: 20))
        assertPreSignRejection(
            review: replacingRequest(
                harness.review,
                with: cloneRequest(
                    request,
                    typedData: cloneTypedData(
                        request.typedData,
                        domain: wrongVerifyingContract))),
            pairedIdentity: harness.pairedIdentity,
            key: harness.key,
            expected: .typedDataInvalid)

        var extraTypes = request.typedData.types
        extraTypes["Extra"] = []
        assertPreSignRejection(
            review: replacingRequest(
                harness.review,
                with: cloneRequest(
                    request,
                    typedData: cloneTypedData(request.typedData, types: extraTypes))),
            pairedIdentity: harness.pairedIdentity,
            key: harness.key,
            expected: .typedDataInvalid)

        var reorderedTypes = request.typedData.types
        reorderedTypes["Install"] = Array(reorderedTypes["Install"]?.reversed() ?? [])
        assertPreSignRejection(
            review: replacingRequest(
                harness.review,
                with: cloneRequest(
                    request,
                    typedData: cloneTypedData(request.typedData, types: reorderedTypes))),
            pairedIdentity: harness.pairedIdentity,
            key: harness.key,
            expected: .typedDataInvalid)

        assertPreSignRejection(
            review: replacingRequest(
                harness.review,
                with: cloneRequest(
                    request,
                    replay: OwnerPhoneSigningReplayFacts(nonce: "1", deadline: nil))),
            pairedIdentity: harness.pairedIdentity,
            key: harness.key,
            expected: .replayInvalid)

        assertPreSignRejection(
            review: replacingRequest(
                harness.review,
                with: cloneRequest(
                    request,
                    replay: OwnerPhoneSigningReplayFacts(nonce: "0", deadline: "1"))),
            pairedIdentity: harness.pairedIdentity,
            key: harness.key,
            expected: .replayInvalid)

        assertPreSignRejection(
            review: replacingRequest(
                harness.review,
                with: cloneRequest(
                    request,
                    expectedDigest: "0x" + String(repeating: "00", count: 32))),
            pairedIdentity: harness.pairedIdentity,
            key: harness.key,
            expected: .digestMismatch)

        for typedData in invalidPackageTypedData(request.typedData) {
            assertPreSignRejection(
                review: replacingRequest(
                    harness.review,
                    with: cloneRequest(request, typedData: typedData)),
                pairedIdentity: harness.pairedIdentity,
                key: harness.key,
                expected: .typedDataInvalid)
        }

        let expired = replacingExpiry(harness.review, with: signingTestNow)
        assertPreSignRejection(
            review: expired,
            pairedIdentity: harness.pairedIdentity,
            key: harness.key,
            expected: .expired)

        var nonpending = harness.review
        try nonpending.beginSubmission(.rejected, now: signingTestNow)
        assertPreSignRejection(
            review: nonpending,
            pairedIdentity: harness.pairedIdentity,
            key: harness.key,
            expected: .reviewNotPending)

        assertPreSignRejection(
            review: harness.review,
            pairedIdentity: KernelEnablePairedIdentity(account: nil, p256XY: nil),
            key: harness.key,
            expected: .pairedIdentityInvalid)
    }

    func testReturnedDerMustNormalizeAndVerifyAgainstTheExactPairedKey() throws {
        let harness = try makeHarness()
        let wrongKey = P256.Signing.PrivateKey()
        var wrongKeyCalls = 0
        var wrongKeyProducedArtifact = false
        var wrongKeyError: KernelEnableSigningError?
        do {
            _ = try makeKernelEnableOwnerSigningArtifact(
                review: harness.review,
                now: signingTestNow,
                pairedIdentity: harness.pairedIdentity
            ) { digest in
                wrongKeyCalls += 1
                return try wrongKey.signature(for: digest.cryptoKitDigest).derRepresentation
            }
            wrongKeyProducedArtifact = true
        } catch {
            wrongKeyError = error as? KernelEnableSigningError
        }
        XCTAssertTrue(wrongKeyCalls == 1)
        XCTAssertTrue(!wrongKeyProducedArtifact)
        XCTAssertTrue(wrongKeyError == .signatureVerificationFailed)

        var malformedCalls = 0
        var malformedProducedArtifact = false
        var malformedError: KernelEnableSigningError?
        do {
            _ = try makeKernelEnableOwnerSigningArtifact(
                review: harness.review,
                now: signingTestNow,
                pairedIdentity: harness.pairedIdentity
            ) { _ in
                malformedCalls += 1
                return Data("not DER".utf8)
            }
            malformedProducedArtifact = true
        } catch {
            malformedError = error as? KernelEnableSigningError
        }
        XCTAssertTrue(malformedCalls == 1)
        XCTAssertTrue(!malformedProducedArtifact)
        XCTAssertTrue(malformedError == .signatureInvalid)

        var failureCalls = 0
        var failureProducedArtifact = false
        var failureError: KernelEnableSigningError?
        do {
            _ = try makeKernelEnableOwnerSigningArtifact(
                review: harness.review,
                now: signingTestNow,
                pairedIdentity: harness.pairedIdentity
            ) { _ in
                failureCalls += 1
                throw InjectedSignerFailure.refused
            }
            failureProducedArtifact = true
        } catch {
            failureError = error as? KernelEnableSigningError
        }
        XCTAssertTrue(failureCalls == 1)
        XCTAssertTrue(!failureProducedArtifact)
        XCTAssertTrue(failureError == .signerFailed)
    }

    private func assertPreSignRejection(
        review: OwnerPhoneReview,
        pairedIdentity: KernelEnablePairedIdentity,
        key: P256.Signing.PrivateKey,
        expected: KernelEnableSigningError,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        var calls = 0
        var producedArtifact = false
        var structuredError: KernelEnableSigningError?
        do {
            _ = try makeKernelEnableOwnerSigningArtifact(
                review: review,
                now: signingTestNow,
                pairedIdentity: pairedIdentity
            ) { digest in
                calls += 1
                return try key.signature(for: digest.cryptoKitDigest).derRepresentation
            }
            producedArtifact = true
        } catch {
            structuredError = error as? KernelEnableSigningError
        }
        XCTAssertTrue(!producedArtifact, file: file, line: line)
        XCTAssertTrue(calls == 0, file: file, line: line)
        XCTAssertTrue(structuredError == expected, file: file, line: line)
    }
}

private func makeHarness() throws -> KernelSigningHarness {
    let key = P256.Signing.PrivateKey()
    let x963 = key.publicKey.x963Representation
    let reviewHarness = try makeReviewHarness(publicKeyX963: x963)
    return KernelSigningHarness(
        key: key,
        pairedIdentity: reviewHarness.pairedIdentity,
        review: reviewHarness.review,
        requestHash: reviewHarness.requestHash)
}

func makeReviewHarness(publicKeyX963 x963: Data) throws -> KernelReviewHarness {
    let typedData = validKernelTypedData()
    let digest = try deriveEIP712Digest(from: typedData)
    let request = OwnerPhoneEIP712SigningRequest(
        version: ownerPhoneSigningRequestVersion,
        purpose: .kernelEnable,
        signer: OwnerPhoneSigningSigner(
            account: signingTestAccount,
            ownerCredential: OwnerPhoneSigningCredential(
                version: ownerPhoneOwnerCredentialVersion,
                credential: .p256(publicKey: hexEncode(x963)))),
        typedData: typedData,
        expectedDigest: digest.canonicalHex,
        digestComparison: .matches(digest),
        replay: OwnerPhoneSigningReplayFacts(nonce: "0", deadline: nil))
    let requestHash = hexEncode(Data(SHA256.hash(data: Data(UUID().uuidString.utf8))))
    let scope = OwnerPhoneSigningRequestScope(
        requestHash: requestHash,
        request: .eip712(request))
    let projection = OwnerPhoneRequestProjection(
        operationId: UUID().uuidString,
        matchCode: try MatchCode("Ab1-_9Zz"),
        expiresAt: signingTestNow + 60_000,
        client: OwnerPhoneClientIdentity(
            clientId: "kernel-signing-test",
            redirectUri: "https://app.example/callback"),
        scope: .ownerSigningRequest(scope))
    return KernelReviewHarness(
        pairedIdentity: KernelEnablePairedIdentity(
            account: signingTestAccount,
            p256XY: Data(x963.dropFirst())),
        review: OwnerPhoneReview(projection: projection),
        requestHash: requestHash)
}

private func validKernelTypedData() -> CanonicalEIP712TypedData {
    CanonicalEIP712TypedData(
        types: [
            "EIP712Domain": kernelDomainTypeFields(),
            "InstallPackages": [
                CanonicalEIP712Field(name: "nonce", type: "uint256"),
                CanonicalEIP712Field(name: "packages", type: "Install[]")
            ],
            "Install": [
                CanonicalEIP712Field(name: "moduleType", type: "uint256"),
                CanonicalEIP712Field(name: "module", type: "address"),
                CanonicalEIP712Field(name: "moduleData", type: "bytes"),
                CanonicalEIP712Field(name: "internalData", type: "bytes")
            ]
        ],
        primaryType: "InstallPackages",
        domain: [
            "name": .string("Kernel"),
            "version": .string("0.4.0"),
            "verifyingContract": .string(signingTestAccount)
        ],
        message: [
            "nonce": .string("0"),
            "packages": .array([
                .object([
                    "moduleType": .string("5"),
                    "module": .string("0x" + String(repeating: "11", count: 20)),
                    "moduleData": .string("0x"),
                    "internalData": .string("0x12345678")
                ]),
                .object([
                    "moduleType": .string("6"),
                    "module": .string("0x" + String(repeating: "22", count: 20)),
                    "moduleData": .string("0x"),
                    "internalData": .string("0x12345678")
                ])
            ])
        ])
}

private func kernelDomainTypeFields() -> [CanonicalEIP712Field] {
    [
        CanonicalEIP712Field(name: "name", type: "string"),
        CanonicalEIP712Field(name: "version", type: "string"),
        CanonicalEIP712Field(name: "verifyingContract", type: "address")
    ]
}

private func kernelRequest(_ review: OwnerPhoneReview) throws -> OwnerPhoneEIP712SigningRequest {
    guard case let .ownerSigningRequest(scope) = review.projection.scope,
          case let .eip712(request) = scope.request
    else {
        throw KernelEnableSigningError.requestNotKernelEnable
    }
    return request
}

private func cloneRequest(
    _ request: OwnerPhoneEIP712SigningRequest,
    purpose: OwnerPhoneSigningPurpose? = nil,
    signer: OwnerPhoneSigningSigner? = nil,
    typedData: CanonicalEIP712TypedData? = nil,
    expectedDigest: String? = nil,
    replay: OwnerPhoneSigningReplayFacts? = nil
) -> OwnerPhoneEIP712SigningRequest {
    let selectedTypedData = typedData ?? request.typedData
    let selectedDigest = expectedDigest ?? request.expectedDigest
    let comparison: EIP712DigestComparison
    if let derived = try? deriveEIP712Digest(from: selectedTypedData) {
        comparison = derived.canonicalHex == selectedDigest
            ? .matches(derived)
            : .mismatch(expectedCanonicalHex: selectedDigest, derived: derived)
    } else {
        comparison = request.digestComparison
    }
    return OwnerPhoneEIP712SigningRequest(
        version: request.version,
        purpose: purpose ?? request.purpose,
        signer: signer ?? request.signer,
        typedData: selectedTypedData,
        expectedDigest: selectedDigest,
        digestComparison: comparison,
        replay: replay ?? request.replay)
}

private func cloneTypedData(
    _ typedData: CanonicalEIP712TypedData,
    types: [String: [CanonicalEIP712Field]]? = nil,
    domain: [String: CanonicalEIP712Value]? = nil,
    message: [String: CanonicalEIP712Value]? = nil
) -> CanonicalEIP712TypedData {
    CanonicalEIP712TypedData(
        types: types ?? typedData.types,
        primaryType: typedData.primaryType,
        domain: domain ?? typedData.domain,
        message: message ?? typedData.message)
}

private func replacingRequest(
    _ review: OwnerPhoneReview,
    with request: OwnerPhoneEIP712SigningRequest
) -> OwnerPhoneReview {
    guard case let .ownerSigningRequest(scope) = review.projection.scope else {
        preconditionFailure("test review is not an owner-signing request")
    }
    return replacingScope(
        review,
        with: .ownerSigningRequest(OwnerPhoneSigningRequestScope(
            requestHash: scope.requestHash,
            request: .eip712(request))))
}

private func replacingScope(
    _ review: OwnerPhoneReview,
    with scope: OwnerPhoneScope
) -> OwnerPhoneReview {
    let projection = review.projection
    return OwnerPhoneReview(projection: OwnerPhoneRequestProjection(
        operationId: projection.operationId,
        matchCode: projection.matchCode,
        expiresAt: projection.expiresAt,
        client: projection.client,
        scope: scope))
}

private func replacingExpiry(_ review: OwnerPhoneReview, with expiresAt: Int) -> OwnerPhoneReview {
    let projection = review.projection
    return OwnerPhoneReview(projection: OwnerPhoneRequestProjection(
        operationId: projection.operationId,
        matchCode: projection.matchCode,
        expiresAt: expiresAt,
        client: projection.client,
        scope: projection.scope))
}

private func invalidPackageTypedData(
    _ typedData: CanonicalEIP712TypedData
) -> [CanonicalEIP712TypedData] {
    guard case let .array(original)? = typedData.message["packages"], original.count == 2,
          case let .object(firstOriginal) = original[0]
    else {
        preconditionFailure("test packages are missing")
    }
    func replacing(_ packages: [CanonicalEIP712Value]) -> CanonicalEIP712TypedData {
        var message = typedData.message
        message["packages"] = .array(packages)
        return cloneTypedData(typedData, message: message)
    }
    func firstPackage(
        _ change: (inout [String: CanonicalEIP712Value]) -> Void
    ) -> CanonicalEIP712TypedData {
        var packages = original
        var first = firstOriginal
        change(&first)
        packages[0] = .object(first)
        return replacing(packages)
    }

    return [
        replacing([]),
        replacing(Array(repeating: original[0], count: 257)),
        firstPackage { $0["moduleType"] = .string("7") },
        firstPackage { $0["module"] = .string("0x" + String(repeating: "00", count: 20)) },
        firstPackage { $0["moduleData"] = .string("0xAB") },
        replacing([original[1], original[0]])
    ]
}

private func isCanonicalSignatureHex(_ text: String) -> Bool {
    let bytes = Array(text.utf8)
    guard bytes.count == 130, bytes[0] == 48, bytes[1] == 120 else { return false }
    return bytes.dropFirst(2).allSatisfy {
        (48...57).contains($0) || (97...102).contains($0)
    }
}
