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

/// The only digest type accepted by the injected Kernel-enable signer.
/// Construction and raw storage are private to this file: arbitrary network
/// bytes cannot be promoted to signing authority by another caller.
struct VerifiedSignableDigest: Digest {
    static let byteCount = 32

    private let storage: Data

    fileprivate init(derived: DerivedEIP712Digest) {
        precondition(derived.bytes.count == Self.byteCount)
        storage = derived.bytes
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
    guard verified.publicKey.isValidSignature(signature, for: verified.digest) else {
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
    guard case let .ownerSigningRequest(scope) = review.projection.scope,
          case let .eip712(request) = scope.request,
          request.version == ownerPhoneSigningRequestVersion,
          request.purpose == .kernelEnable
    else {
        throw KernelEnableSigningError.requestNotKernelEnable
    }

    guard isLowercaseHex(scope.requestHash, byteCount: 32),
          let pairedAccount = pairedIdentity.account,
          isNonzeroAddress(pairedAccount),
          let pairedXY = pairedIdentity.p256XY,
          pairedXY.count == 64
    else {
        throw KernelEnableSigningError.pairedIdentityInvalid
    }

    var x963 = Data([0x04])
    x963.append(pairedXY)
    guard let publicKey = try? P256.Signing.PublicKey(x963Representation: x963) else {
        throw KernelEnableSigningError.pairedIdentityInvalid
    }

    guard request.signer.account == pairedAccount else {
        throw KernelEnableSigningError.accountMismatch
    }
    guard request.signer.ownerCredential.version == ownerPhoneOwnerCredentialVersion,
          case let .p256(requestedPublicKey) = request.signer.ownerCredential.credential,
          requestedPublicKey == hexEncode(x963)
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
