/** Closed revocation consent. Service metadata identifies the permission; the device derives its operation. */
import Foundation

public struct OwnerPhoneKernelRevocationScope: Equatable, Sendable {
    public let requestHash: String
    public let permission: OwnerPhonePermissionScope
    let install: OwnerPhoneSigningRequestScope
    let ownerPublicKey: Data
    let operation: DerivedKernelRevocationOperation

    fileprivate init(requestHash: String, permission: OwnerPhonePermissionScope,
                     install: OwnerPhoneSigningRequestScope, ownerPublicKey: Data,
                     operation: DerivedKernelRevocationOperation) {
        self.requestHash = requestHash
        self.permission = permission
        self.install = install
        self.ownerPublicKey = ownerPublicKey
        self.operation = operation
    }
}

func decodeKernelRevocationScope(_ object: [String: Any]) throws -> OwnerPhoneKernelRevocationScope {
    try Wire.exactKeys(object, ["kind", "decision", "requestHash", "permission", "install",
                               "effect", "chainId", "entryPoint", "operation", "expectedDigest"], label: "revocation")
    let permissionObject = try Wire.object(object["permission"], label: "revocation permission")
    let installObject = try Wire.object(object["install"], label: "revocation install")
    guard object["decision"] as? String == "approve-or-reject",
          permissionObject["kind"] as? String == "permission-request",
          installObject["kind"] as? String == "owner-signing-request",
          case let .permissionRequest(permission) = try OwnerPhoneRequestProjection.decodeScope(permissionObject),
          case let .ownerSigningRequest(install) = try OwnerPhoneRequestProjection.decodeScope(installObject),
          install.decisionCapability == .approveOrReject,
          case let .eip712(request) = install.request,
          case let .p256(publicKey) = request.signer.ownerCredential.credential,
          permission.account.ownerCredential == request.signer.ownerCredential.credential,
          permission.account.kernelVersion == "0.4.0",
          permission.account.factoryRoute == "kernel_factory",
          permission.account.entryPointVersion == "0.7",
          let keyBytes = decodeLowercaseEIP712Hex(publicKey, exactBytes: 65),
          let operation = object["operation"]
    else { throw OwnerPhoneWireError.invalidField("revocation binding") }
    let derived = try deriveKernelRevocationOperation(
        install: install,
        effect: Wire.text(object["effect"], maximum: 32, label: "revocation effect"),
        chainId: Wire.timestamp(object["chainId"], label: "revocation chain"),
        entryPoint: Wire.lowercaseHex(object["entryPoint"], byteLength: 20, label: "revocation EntryPoint"),
        operation: operation,
        expectedDigest: Wire.lowercaseHex(object["expectedDigest"], byteLength: 32, label: "revocation digest"))
    return OwnerPhoneKernelRevocationScope(
        requestHash: try Wire.lowercaseHex(object["requestHash"], byteLength: 32, label: "revocation requestHash"),
        permission: permission, install: install, ownerPublicKey: Data(keyBytes), operation: derived)
}

struct KernelRevocationConsentPresentation {
    let sections: [OwnerSigningConsentSection]

    init(scope: OwnerPhoneKernelRevocationScope) {
        let op = scope.operation
        func section(_ id: String, _ title: String, _ values: [(String, String)]) -> OwnerSigningConsentSection {
            .init(id: id, title: title, facts: values.enumerated().map {
                .init(id: "\(id).\($0.offset)", label: $0.element.0, value: $0.element.1)
            })
        }
        sections = [
            section("permission", "Permission identified by the service", [
                ("Workspace", scope.permission.context.workspaceId),
                ("Workspace kind", scope.permission.context.workspaceKind.rawValue),
                ("Account ID", scope.permission.context.accountId),
                ("Application", scope.permission.application.applicationId),
                ("Origin", scope.permission.application.origin),
                ("Service request commitment", scope.requestHash)
            ]),
            section("effect", "Operation verified by this phone", [
                ("Effect", op.effect == .invalidateInstall ? "Prevent this approval from installing" : "Remove the installed permission"),
                ("Chain", String(op.chainId)), ("Account", op.account), ("EntryPoint 0.7", op.entryPoint),
                ("Account deployment", op.deploymentRequired ? "Included in this operation" : "Not requested"),
                ("Operation nonce", op.nonce), ("Locally derived operation hash", op.canonicalHex)
            ]),
            section("gas", "Self-funded operation gas bounds", [
                ("Verification gas limit", op.verificationGasLimit), ("Call gas limit", op.callGasLimit),
                ("Pre-verification gas", op.preVerificationGas),
                ("Maximum fee per gas (wei)", op.maxFeePerGas),
                ("Maximum priority fee per gas (wei)", op.maxPriorityFeePerGas)
            ])
        ]
    }
}
