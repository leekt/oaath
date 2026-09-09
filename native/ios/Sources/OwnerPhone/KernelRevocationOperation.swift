/**
 Pure Kernel 0.4.0 / EntryPoint 0.7 revocation operation derivation.

 Reuses the captured replayable-install scope, reconstructs its one exact
 removal effect, and hashes the packed operation locally. This is semantic
 evidence only: no pairing, permission-request commitment, review, configured
 chain decision, custody capability, submission, or finality lives here.
 */
import CryptoSwift
import Foundation

enum KernelRevocationOperationError: Error, Equatable, Sendable {
    case invalidOperation
    case invalidInstall
    case unsupportedEffect
    case callMismatch
    case digestMismatch
}

enum KernelRevocationEffect: String, Equatable, Sendable {
    case invalidateInstall = "invalidate-install"
    case uninstallPermission = "uninstall-permission"
}

/// Cannot be constructed outside the derivation owner and cannot be passed to
/// owner-key custody. Consent and paired-identity refinement are separate work.
struct DerivedKernelRevocationOperation: Equatable, Sendable {
    let account: String
    let chainId: Int
    let entryPoint: String
    let effect: KernelRevocationEffect
    let digest: Data
    var canonicalHex: String { hexEncode(digest) }

    fileprivate init(
        account: String, chainId: Int, entryPoint: String,
        effect: KernelRevocationEffect, digest: [UInt8]
    ) {
        self.account = account
        self.chainId = chainId
        self.entryPoint = entryPoint
        self.effect = effect
        self.digest = Data(digest)
    }
}

/// The enclosing request decoder supplies its captured install scope and wire
/// operation. Captures the operation once, then consumes owned bytes throughout.
func deriveKernelRevocationOperation(
    install: OwnerPhoneSigningRequestScope,
    effect: String,
    chainId: Int,
    entryPoint: String,
    operation: Any,
    expectedDigest: String
) throws -> DerivedKernelRevocationOperation {
    guard let effect = KernelRevocationEffect(rawValue: effect) else {
        throw KernelRevocationOperationError.unsupportedEffect
    }
    guard (1...9_007_199_254_740_991).contains(chainId) else {
        throw KernelRevocationOperationError.invalidOperation
    }
    let refinedInstall = try refineKernelEnableSigningScope(install)
    guard case let .eip712(request) = install.request else {
        throw KernelRevocationOperationError.invalidInstall
    }
    let op = try Wire.object(operation, label: "Kernel revocation operation")
    try Wire.exactKeys(op, [
        "sender", "nonce", "initCode", "callData", "accountGasLimits",
        "preVerificationGas", "gasFees", "paymasterAndData"
    ], label: "Kernel revocation operation")

    let sender = try revocationAddress(op["sender"])
    let nonce = try revocationUint(op["nonce"], width: 256)
    let initCode = try revocationBytes(op["initCode"])
    let callData = try revocationBytes(op["callData"])
    let accountGasLimits = try revocationBytes(op["accountGasLimits"], count: 32)
    let preVerificationGas = try revocationUint(op["preVerificationGas"], width: 120)
    let gasFees = try revocationBytes(op["gasFees"], count: 32)
    let entryPointBytes = try revocationAddress(entryPoint)
    let expectedBytes = try revocationBytes(expectedDigest, count: 32)
    guard op["paymasterAndData"] as? String == "0x",
          op["sender"] as? String == refinedInstall.account,
          nonce.prefix(22).allSatisfy({ $0 == 0 }), // root + uint16 namespace + uint64 sequence
          initCode.isEmpty || (initCode.count >= 20 &&
              Array(initCode.prefix(20)) != [0x77, 0x02] + [UInt8](repeating: 0, count: 18))
    else {
        throw KernelRevocationOperationError.invalidOperation
    }

    let expectedCallData = try revocationCallData(
        request: request, account: sender, effect: effect)
    guard callData == expectedCallData else {
        throw KernelRevocationOperationError.callMismatch
    }
    // EntryPoint 0.7 hashes the eight packed fields without a signature, then
    // binds that hash to its address and the chain. No EIP-712 prefix or typehash.
    let packed = revocationAddressWord(sender) + nonce + revocationHash(initCode) +
        revocationHash(callData) + accountGasLimits + preVerificationGas + gasFees +
        revocationHash([])
    let digest = revocationHash(
        revocationHash(packed) + revocationAddressWord(entryPointBytes) + revocationWord(chainId))
    guard digest == expectedBytes else {
        throw KernelRevocationOperationError.digestMismatch
    }
    return DerivedKernelRevocationOperation(
        account: refinedInstall.account, chainId: chainId, entryPoint: entryPoint,
        effect: effect, digest: digest)
}

private func revocationCallData(
    request: OwnerPhoneEIP712SigningRequest,
    account: [UInt8],
    effect: KernelRevocationEffect
) throws -> [UInt8] {
    let calls: [[UInt8]]
    switch effect {
    case .invalidateInstall:
        let nonce = try revocationUint(request.replay.nonce, width: 256)
        let key = [UInt8](repeating: 0, count: 8) + nonce.prefix(24)
        var nextSequence = [UInt8](repeating: 0, count: 24) + nonce.suffix(8)
        var carry: UInt16 = 1
        for index in stride(from: 31, through: 24, by: -1) {
            let sum = UInt16(nextSequence[index]) + carry
            nextSequence[index] = UInt8(sum & 0xff)
            carry = sum >> 8
        }
        guard carry == 0 else { throw KernelRevocationOperationError.invalidInstall }
        calls = [revocationSelector("setNonce(uint192,uint64)") + key + nextSequence]
    case .uninstallPermission:
        guard case let .array(packages)? = request.typedData.message["packages"] else {
            throw KernelRevocationOperationError.invalidInstall
        }
        var policies = [[UInt8]]()
        var signers = [[UInt8]]()
        for value in packages {
            guard case let .object(package) = value,
                  case let .string(moduleType)? = package["moduleType"],
                  moduleType == "5" || moduleType == "6",
                  case let .string(module)? = package["module"],
                  case let .string(moduleData)? = package["moduleData"],
                  case let .string(internalData)? = package["internalData"]
            else { throw KernelRevocationOperationError.invalidInstall }
            let installData = try revocationBytes(moduleData)
            guard installData.count >= 32 else {
                throw KernelRevocationOperationError.invalidInstall
            }
            let prefix = revocationDynamicBytes(Array(installData.prefix(32)))
            let internalBytes = try revocationBytes(internalData)
            let initData = revocationWord(64) + revocationWord(64 + prefix.count) +
                prefix + revocationDynamicBytes(internalBytes)
            let call = try revocationSelector("uninstallModule(uint256,address,bytes)") +
                revocationWord(moduleType == "5" ? 5 : 6) +
                revocationAddressWord(revocationAddress(module)) + revocationWord(96) +
                revocationDynamicBytes(initData)
            if moduleType == "5" { policies.append(call) } else { signers.append(call) }
        }
        guard signers.count == 1 else { throw KernelRevocationOperationError.invalidInstall }
        calls = policies.reversed() + signers
    }

    let executionData: [UInt8]
    let mode: [UInt8]
    if calls.count == 1 {
        mode = revocationWord(0)
        executionData = account + revocationWord(0) + calls[0]
    } else {
        mode = [1] + [UInt8](repeating: 0, count: 31)
        let tuples = calls.map { call in
            revocationAddressWord(account) + revocationWord(0) + revocationWord(96) +
                revocationDynamicBytes(call)
        }
        var heads = [UInt8]()
        var tails = [UInt8]()
        let headSize = tuples.count * 32
        for tuple in tuples {
            heads += revocationWord(headSize + tails.count)
            tails += tuple
        }
        // abi.encode(Execution[]): outer offset, array length, tuple offsets/data.
        executionData = revocationWord(32) + revocationWord(tuples.count) + heads + tails
    }
    return revocationSelector("execute(bytes32,bytes)") + mode + revocationWord(64) +
        revocationDynamicBytes(executionData)
}

private func revocationBytes(_ value: Any?, count: Int? = nil) throws -> [UInt8] {
    guard let text = value as? String, text.utf8.count <= 131_074,
          let bytes = decodeLowercaseEIP712Hex(text, exactBytes: count)
    else { throw KernelRevocationOperationError.invalidOperation }
    return bytes
}

private func revocationAddress(_ value: Any?) throws -> [UInt8] {
    let bytes = try revocationBytes(value, count: 20)
    guard bytes.contains(where: { $0 != 0 }) else {
        throw KernelRevocationOperationError.invalidOperation
    }
    return bytes
}

private func revocationUint(_ value: Any?, width: Int) throws -> [UInt8] {
    let text = try Wire.decimalUint(value, label: "Kernel revocation integer")
    guard let word = decimalWord(text, signed: false, width: width) else {
        throw KernelRevocationOperationError.invalidOperation
    }
    return word
}

private func revocationWord(_ value: Int) -> [UInt8] {
    var remaining = UInt64(value)
    var word = [UInt8](repeating: 0, count: 32)
    for index in stride(from: 31, through: 24, by: -1) {
        word[index] = UInt8(remaining & 0xff)
        remaining >>= 8
    }
    return word
}

private func revocationAddressWord(_ address: [UInt8]) -> [UInt8] {
    [UInt8](repeating: 0, count: 12) + address
}

private func revocationDynamicBytes(_ bytes: [UInt8]) -> [UInt8] {
    revocationWord(bytes.count) + bytes +
        [UInt8](repeating: 0, count: (32 - bytes.count % 32) % 32)
}

private func revocationHash(_ bytes: [UInt8]) -> [UInt8] {
    SHA3(variant: .keccak256).calculate(for: bytes)
}

private func revocationSelector(_ signature: String) -> [UInt8] {
    Array(revocationHash(Array(signature.utf8)).prefix(4))
}
