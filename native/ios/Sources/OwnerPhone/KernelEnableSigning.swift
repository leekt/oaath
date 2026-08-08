/**
 Package-internal Kernel 0.4.0 replayable-install signing refinement.

 This is deliberately disconnected from the live v3 approval surface. It
 accepts only an already-captured pending review, proves the exact Kernel
 profile and paired P-256 identity before invoking one injected signer, then
 normalizes and verifies that result before emitting the current canonical
 owner-signing artifact JSON. No network, keychain, or persistence effect
 lives here.

 @author taek <leekt216@gmail.com>
 */
import CryptoKit
import Foundation

let ownerPhoneSigningArtifactVersion = "oaath.owner-signing-artifact/v1"

enum KernelEnableSigningError: Error, Equatable, Sendable {
    case reviewNotPending
    case expired
    case requestNotKernelEnable
    case pairedIdentityInvalid
    case accountMismatch
    case credentialMismatch
    case typedDataInvalid
    case replayInvalid
    case digestMismatch
    case signerFailed
    case signatureInvalid
    case signatureVerificationFailed
}

/// The two public facts loaded together from the pairing owner. P-256 material
/// is the SDK's exact 64-byte x‖y representation, without the X9.63 `0x04`.
struct KernelEnablePairedIdentity: Equatable, Sendable {
    let account: String?
    let p256XY: Data?
}

/// A sealed future approval capability. Construction captures one exact,
/// already-validated account/P-256 pairing and only a verified-digest signer;
/// no raw digest or raw signer escapes this owner.
public struct OwnerPhoneKernelP256ApprovalBinding: Sendable {
    private let pairedIdentity: KernelEnablePairedIdentity
    private let pairingIsCurrentClosure: @Sendable () -> Bool
    private let signClosure: @Sendable (VerifiedSignableDigest) throws -> Data

    /// `p256PublicMaterial` is the exact lowercase `0x`-prefixed 64-byte x‖y
    /// representation registered by pairing. Construction rejects a zero or
    /// non-canonical account and material that is malformed or off-curve.
    public init(
        account: String,
        p256PublicMaterial: String,
        pairingIsCurrent: @escaping @Sendable () -> Bool,
        sign: @escaping @Sendable (VerifiedSignableDigest) throws -> Data
    ) throws {
        guard let p256XY = decodeKernelP256PublicMaterial(p256PublicMaterial) else {
            throw KernelEnableSigningError.pairedIdentityInvalid
        }
        let pairedIdentity = KernelEnablePairedIdentity(
            account: account,
            p256XY: p256XY)
        _ = try kernelEnablePublicKey(for: pairedIdentity)
        self.pairedIdentity = pairedIdentity
        pairingIsCurrentClosure = pairingIsCurrent
        signClosure = sign
    }

    func pairingIsCurrent() -> Bool {
        pairingIsCurrentClosure()
    }

    func validates(_ review: OwnerPhoneReview, now: Int) -> Bool {
        (try? verifyKernelEnableReview(
            review,
            now: now,
            pairedIdentity: pairedIdentity)) != nil
    }

    func semanticallyMatches(_ projection: OwnerPhoneRequestProjection) -> Bool {
        (try? verifyKernelEnableProjection(
            projection,
            pairedIdentity: pairedIdentity)) != nil
    }

    func makeArtifact(_ review: OwnerPhoneReview, now: Int) throws -> String {
        try makeKernelEnableOwnerSigningArtifact(
            review: review,
            now: now,
            pairedIdentity: pairedIdentity,
            signer: signClosure)
    }
}

/// The only digest type accepted by owner-key custody. The type crosses the
/// package boundary so demo custody can consume it, but construction and raw
/// bytes remain owned by this module: arbitrary network bytes cannot be
/// promoted to signing authority by another caller.
public struct VerifiedSignableDigest: Sendable {
    static let byteCount = 32

    private let storage: Data

    fileprivate init(derived: DerivedEIP712Digest) {
        precondition(derived.bytes.count == Self.byteCount)
        storage = derived.bytes
    }

    /// Package-only views for the two exact cryptographic consumers. Neither
    /// is public API, so adopters can carry this authority but cannot inspect
    /// or forge its digest bytes.
    var platformSigningBytes: Data { storage }
    var cryptoKitDigest: VerifiedCryptoKitDigest {
        VerifiedCryptoKitDigest(storage: storage)
    }
}

struct VerifiedCryptoKitDigest: Digest {
    static let byteCount = VerifiedSignableDigest.byteCount
    private let storage: Data

    fileprivate init(storage: Data) {
        precondition(storage.count == VerifiedSignableDigest.byteCount)
        self.storage = storage
    }

    func withUnsafeBytes<Result>(
        _ body: (UnsafeRawBufferPointer) throws -> Result
    ) rethrows -> Result {
        try storage.withUnsafeBytes { buffer in
            try body(buffer)
        }
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(storage)
    }
}

private let kernelDomainFields = [
    CanonicalEIP712Field(name: "name", type: "string"),
    CanonicalEIP712Field(name: "version", type: "string"),
    CanonicalEIP712Field(name: "verifyingContract", type: "address")
]

private let kernelInstallPackagesFields = [
    CanonicalEIP712Field(name: "nonce", type: "uint256"),
    CanonicalEIP712Field(name: "packages", type: "Install[]")
]

private let kernelInstallFields = [
    CanonicalEIP712Field(name: "moduleType", type: "uint256"),
    CanonicalEIP712Field(name: "module", type: "address"),
    CanonicalEIP712Field(name: "moduleData", type: "bytes"),
    CanonicalEIP712Field(name: "internalData", type: "bytes")
]

private struct VerifiedKernelEnableRequest {
    let requestHash: String
    let digest: VerifiedSignableDigest
    let publicKey: P256.Signing.PublicKey
}

/**
 Produces the fixed-order canonical `oaath.owner-signing-artifact/v1` JSON.

 Every request, review, replay, digest, account, and credential check completes
 before `signer` is invoked. The signer is invoked exactly once, and its DER
 result must normalize to a compact low-S signature that verifies over the
 exact paired/requested P-256 public key and the device-derived digest.
 */
func makeKernelEnableOwnerSigningArtifact(
    review: OwnerPhoneReview,
    now: Int,
    pairedIdentity: KernelEnablePairedIdentity,
    signer: (VerifiedSignableDigest) throws -> Data
) throws -> String {
    let verified = try verifyKernelEnableReview(
        review,
        now: now,
        pairedIdentity: pairedIdentity)

    let der: Data
    do {
        der = try signer(verified.digest)
    } catch {
        throw KernelEnableSigningError.signerFailed
    }

    let raw: Data
    let signature: P256.Signing.ECDSASignature
    do {
        raw = try p256LowSNormalized(raw: p256RawSignature(der: der))
        signature = try P256.Signing.ECDSASignature(rawRepresentation: raw)
    } catch {
        throw KernelEnableSigningError.signatureInvalid
    }
    guard verified.publicKey.isValidSignature(
        signature,
        for: verified.digest.cryptoKitDigest)
    else {
        throw KernelEnableSigningError.signatureVerificationFailed
    }

    return "{\"version\":\"\(ownerPhoneSigningArtifactVersion)\",\"kind\":\"p256\"," +
        "\"requestHash\":\"\(verified.requestHash)\",\"signature\":\"\(hexEncode(raw))\"}"
}

private func verifyKernelEnableReview(
    _ review: OwnerPhoneReview,
    now: Int,
    pairedIdentity: KernelEnablePairedIdentity
) throws -> VerifiedKernelEnableRequest {
    guard case .pending = review.state else {
        throw KernelEnableSigningError.reviewNotPending
    }
    guard now < review.projection.expiresAt else {
        throw KernelEnableSigningError.expired
    }
    return try verifyKernelEnableProjection(
        review.projection,
        pairedIdentity: pairedIdentity)
}

private func verifyKernelEnableProjection(
    _ projection: OwnerPhoneRequestProjection,
    pairedIdentity: KernelEnablePairedIdentity
) throws -> VerifiedKernelEnableRequest {
    guard case let .ownerSigningRequest(scope) = projection.scope,
          case let .eip712(request) = scope.request,
          request.version == ownerPhoneSigningRequestVersion,
          request.purpose == .kernelEnable
    else {
        throw KernelEnableSigningError.requestNotKernelEnable
    }

    guard isLowercaseHex(scope.requestHash, byteCount: 32) else {
        throw KernelEnableSigningError.pairedIdentityInvalid
    }
    let publicKey = try kernelEnablePublicKey(for: pairedIdentity)
    guard let pairedAccount = pairedIdentity.account else {
        throw KernelEnableSigningError.pairedIdentityInvalid
    }

    guard request.signer.account == pairedAccount else {
        throw KernelEnableSigningError.accountMismatch
    }
    guard request.signer.ownerCredential.version == ownerPhoneOwnerCredentialVersion,
          case let .p256(requestedPublicKey) = request.signer.ownerCredential.credential,
          requestedPublicKey == hexEncode(publicKey.x963Representation)
    else {
        throw KernelEnableSigningError.credentialMismatch
    }

    let typedData = request.typedData
    guard typedData.primaryType == "InstallPackages",
          Set(typedData.types.keys) == ["EIP712Domain", "InstallPackages", "Install"],
          typedData.types["EIP712Domain"] == kernelDomainFields,
          typedData.types["InstallPackages"] == kernelInstallPackagesFields,
          typedData.types["Install"] == kernelInstallFields,
          Set(typedData.domain.keys) == ["name", "version", "verifyingContract"],
          typedData.domain["name"] == .string("Kernel"),
          typedData.domain["version"] == .string("0.4.0"),
          typedData.domain["verifyingContract"] == .string(pairedAccount),
          Set(typedData.message.keys) == ["nonce", "packages"],
          case let .string(messageNonce)? = typedData.message["nonce"],
          case let .array(packages)? = typedData.message["packages"],
          validateKernelPackages(packages)
    else {
        throw KernelEnableSigningError.typedDataInvalid
    }

    guard request.replay.nonce == messageNonce, request.replay.deadline == nil else {
        throw KernelEnableSigningError.replayInvalid
    }

    let derived: DerivedEIP712Digest
    do {
        derived = try deriveEIP712Digest(from: typedData)
    } catch {
        throw KernelEnableSigningError.typedDataInvalid
    }
    guard derived.canonicalHex == request.expectedDigest else {
        throw KernelEnableSigningError.digestMismatch
    }

    return VerifiedKernelEnableRequest(
        requestHash: scope.requestHash,
        digest: VerifiedSignableDigest(derived: derived),
        publicKey: publicKey)
}

private func kernelEnablePublicKey(
    for pairedIdentity: KernelEnablePairedIdentity
) throws -> P256.Signing.PublicKey {
    guard let account = pairedIdentity.account,
          isNonzeroAddress(account),
          let pairedXY = pairedIdentity.p256XY,
          pairedXY.count == 64
    else {
        throw KernelEnableSigningError.pairedIdentityInvalid
    }
    var x963 = Data([0x04])
    x963.append(pairedXY)
    do {
        return try P256.Signing.PublicKey(x963Representation: x963)
    } catch {
        throw KernelEnableSigningError.pairedIdentityInvalid
    }
}

private func decodeKernelP256PublicMaterial(_ text: String) -> Data? {
    let characters = Array(text.utf8)
    guard characters.count == 130,
          characters[0] == 48,
          characters[1] == 120
    else { return nil }
    var result = Data()
    result.reserveCapacity(64)
    for index in stride(from: 2, to: characters.count, by: 2) {
        guard let high = lowercaseHexValue(characters[index]),
              let low = lowercaseHexValue(characters[index + 1])
        else { return nil }
        result.append(high << 4 | low)
    }
    return result
}

private func lowercaseHexValue(_ byte: UInt8) -> UInt8? {
    switch byte {
    case 48...57: return byte - 48
    case 97...102: return byte - 87
    default: return nil
    }
}

private func validateKernelPackages(_ values: [CanonicalEIP712Value]) -> Bool {
    guard (1...256).contains(values.count) else { return false }
    var pendingPermission: String?

    for value in values {
        guard case let .object(package) = value,
              Set(package.keys) == ["moduleType", "module", "moduleData", "internalData"],
              case let .string(moduleType)? = package["moduleType"],
              ["1", "2", "3", "4", "5", "6"].contains(moduleType),
              case let .string(module)? = package["module"],
              isNonzeroAddress(module),
              case let .string(moduleData)? = package["moduleData"],
              isCanonicalBytes(moduleData),
              case let .string(internalData)? = package["internalData"],
              isCanonicalBytes(internalData)
        else {
            return false
        }

        guard moduleType == "5" || moduleType == "6" else { continue }
        guard internalData.count >= 10 else { return false }
        let permission = String(internalData.prefix(10))
        if let pendingPermission, pendingPermission != permission { return false }
        if moduleType == "6" {
            guard pendingPermission != nil else { return false }
            pendingPermission = nil
        } else {
            pendingPermission = permission
        }
    }

    return pendingPermission == nil
}

private func isNonzeroAddress(_ text: String) -> Bool {
    isLowercaseHex(text, byteCount: 20) && text != "0x" + String(repeating: "00", count: 20)
}

private func isCanonicalBytes(_ text: String) -> Bool {
    let bytes = Array(text.utf8)
    guard bytes.count >= 2,
          bytes[0] == 48,
          bytes[1] == 120,
          (bytes.count - 2).isMultiple(of: 2)
    else {
        return false
    }
    return bytes.dropFirst(2).allSatisfy(isLowercaseHexDigit)
}

private func isLowercaseHex(_ text: String, byteCount: Int) -> Bool {
    let bytes = Array(text.utf8)
    return bytes.count == 2 + byteCount * 2 &&
        bytes[0] == 48 && bytes[1] == 120 &&
        bytes.dropFirst(2).allSatisfy(isLowercaseHexDigit)
}

private func isLowercaseHexDigit(_ byte: UInt8) -> Bool {
    (48...57).contains(byte) || (97...102).contains(byte)
}
