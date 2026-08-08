/**
 EXPERIMENTAL PREVIEW — exact presentation coverage for the existing
 permission-request consent projection.

 @author taek <leekt216@gmail.com>
 */
#if canImport(SwiftUI)
import XCTest
@testable import OwnerPhone

final class PermissionConsentPresentationTests: XCTestCase {
    private let ownerPublicKey = "0x" + String(repeating: "11", count: 65)
    private let authenticatorIdHash = "0x" + String(repeating: "22", count: 32)
    private let operatorPublicKey = "0x" + String(repeating: "33", count: 65)
    private let firstTarget = "0x" + String(repeating: "44", count: 20)
    private let secondTarget = "0x" + String(repeating: "55", count: 20)
    private let firstArgument = "0x" + String(repeating: "66", count: 32)
    private let secondArgument = "0x" + String(repeating: "77", count: 32)

    private func scope(
        owner: OwnerPhoneCredential,
        operatorCredential: OwnerPhoneCredential,
        sessionSigner: OwnerPhoneSessionSigner?,
        policyValidUntil: Int? = 1_753_003_600
    ) -> OwnerPhonePermissionScope {
        OwnerPhonePermissionScope(
            application: OwnerPhoneApplicationIdentity(
                applicationId: "app-a",
                clientId: "permission-client",
                origin: "https://app.example",
                deviceFingerprint: "8sWHndmh"),
            account: OwnerPhoneAccountIdentity(
                accountIndex: "7",
                kernelVersion: "0.4.0",
                factoryRoute: "meta_factory",
                entryPointVersion: "0.7",
                ownerCredential: owner),
            operatorCredential: operatorCredential,
            sessionSigner: sessionSigner,
            chainScope: "all",
            calls: [
                OwnerPhonePermittedCall(
                    target: firstTarget,
                    selector: "0x12345678",
                    valueLimit: "100",
                    argumentEquals: [
                        OwnerPhoneArgumentEquality(index: 0, value: firstArgument),
                        OwnerPhoneArgumentEquality(index: 3, value: secondArgument),
                    ]),
                OwnerPhonePermittedCall(
                    target: secondTarget,
                    selector: "0x90abcdef",
                    valueLimit: "0",
                    argumentEquals: []),
            ],
            requestedAt: 1_753_000_000,
            expiresAt: 1_753_000_600,
            policyValidAfter: 1_753_000_100,
            policyValidUntil: policyValidUntil,
            perChainOperationLimit: 10)
    }

    private func facts(
        _ presentation: PermissionConsentPresentation
    ) -> [String: PermissionConsentFact.Value] {
        Dictionary(uniqueKeysWithValues: presentation.sections.flatMap { section in
            section.facts.map { ($0.id, $0.value) }
        })
    }

    private func evidence(
        _ presentation: PermissionConsentPresentation
    ) -> [String: PermissionConsentEvidence] {
        Dictionary(uniqueKeysWithValues: presentation.sections.flatMap { section in
            section.facts.map { ($0.id, $0.evidence) }
        })
    }

    func testPresentsEveryAuthorityDefiningPermissionFact() {
        let presentation = PermissionConsentPresentation(
            client: OwnerPhoneClientIdentity(
                clientId: "authenticated-client",
                redirectUri: "https://app.example/callback"),
            scope: scope(
                owner: .webauthn(
                    publicKey: ownerPublicKey,
                    authenticatorIdHash: authenticatorIdHash),
                operatorCredential: .p256(publicKey: operatorPublicKey),
                sessionSigner: OwnerPhoneSessionSigner(
                    mode: "oaath_hosted",
                    providerId: "kms-primary")))

        XCTAssertEqual(
            presentation.sections.map(\.id),
            ["application", "account", "authority", "call.0", "call.1", "validity"])
        XCTAssertTrue(presentation.sections.allSatisfy { !$0.title.isEmpty })
        XCTAssertTrue(presentation.sections.flatMap(\.facts).allSatisfy { !$0.label.isEmpty })
        let values = facts(presentation)
        let evidenceByFact = evidence(presentation)
        XCTAssertEqual(values.count, 33)
        XCTAssertEqual(evidenceByFact.count, values.count)

        XCTAssertEqual(values["application.applicationId"], .text("app-a"))
        XCTAssertEqual(values["application.permissionClientId"], .text("permission-client"))
        XCTAssertEqual(values["application.authenticatedClientId"], .text("authenticated-client"))
        XCTAssertEqual(values["application.origin"], .text("https://app.example"))
        XCTAssertEqual(values["application.redirectUri"], .text("https://app.example/callback"))
        XCTAssertEqual(values["application.deviceFingerprint"], .text("8sWHndmh"))

        XCTAssertEqual(values["account.accountIndex"], .text("7"))
        XCTAssertEqual(values["account.kernelVersion"], .text("0.4.0"))
        XCTAssertEqual(values["account.factoryRoute"], .text("meta_factory"))
        XCTAssertEqual(values["account.entryPointVersion"], .text("0.7"))
        XCTAssertEqual(values["account.ownerCredential.kind"], .text("WebAuthn"))
        XCTAssertEqual(values["account.ownerCredential.publicKey"], .text(ownerPublicKey))
        XCTAssertEqual(
            values["account.ownerCredential.authenticatorIdHash"],
            .text(authenticatorIdHash))

        XCTAssertEqual(values["authority.operatorCredential.kind"], .text("P-256"))
        XCTAssertEqual(
            values["authority.operatorCredential.publicKey"],
            .text(operatorPublicKey))
        XCTAssertEqual(values["authority.custody"], .text("oaath_hosted"))
        XCTAssertEqual(values["authority.providerId"], .text("kms-primary"))
        XCTAssertEqual(values["authority.chainScope"], .text("all"))

        XCTAssertEqual(values["call.0.target"], .text(firstTarget))
        XCTAssertEqual(values["call.0.selector"], .text("0x12345678"))
        XCTAssertEqual(values["call.0.valueLimit"], .text("100"))
        XCTAssertEqual(values["call.0.argument.0.index"], .text("0"))
        XCTAssertEqual(values["call.0.argument.0.value"], .text(firstArgument))
        XCTAssertEqual(values["call.0.argument.1.index"], .text("3"))
        XCTAssertEqual(values["call.0.argument.1.value"], .text(secondArgument))
        XCTAssertEqual(values["call.1.target"], .text(secondTarget))
        XCTAssertEqual(values["call.1.selector"], .text("0x90abcdef"))
        XCTAssertEqual(values["call.1.valueLimit"], .text("0"))

        XCTAssertEqual(values["validity.requestedAt"], .unixSeconds(1_753_000_000))
        XCTAssertEqual(values["validity.expiresAt"], .unixSeconds(1_753_000_600))
        XCTAssertEqual(values["validity.policyValidAfter"], .unixSeconds(1_753_000_100))
        XCTAssertEqual(values["validity.policyValidUntil"], .unixSeconds(1_753_003_600))
        XCTAssertEqual(values["validity.perChainOperationLimit"], .text("10"))

        XCTAssertEqual(
            Set(evidenceByFact.compactMap { $0.value == .relayBound ? $0.key : nil }),
            Set([
                "application.authenticatedClientId",
                "application.redirectUri",
            ]))
        XCTAssertEqual(
            Set(evidenceByFact.compactMap { $0.value == .requestedConstraint ? $0.key : nil }),
            Set([
                "authority.chainScope",
                "call.0.target",
                "call.0.selector",
                "call.0.valueLimit",
                "call.0.argument.0.index",
                "call.0.argument.0.value",
                "call.0.argument.1.index",
                "call.0.argument.1.value",
                "call.1.target",
                "call.1.selector",
                "call.1.valueLimit",
                "validity.policyValidAfter",
                "validity.policyValidUntil",
                "validity.perChainOperationLimit",
            ]))
        XCTAssertEqual(
            evidenceByFact.values.filter { $0 == .requestedScope }.count,
            values.count - 16)
        XCTAssertEqual(PermissionConsentEvidence.relayBound.display, "Relay-bound")
        XCTAssertEqual(PermissionConsentEvidence.requestedScope.display, "Requested scope")
        XCTAssertEqual(
            PermissionConsentEvidence.requestedConstraint.display,
            "Requested constraint · enforcement unproven")
        XCTAssertTrue(PermissionConsentPresentation.evidenceNotice.contains("not guaranteed"))
        XCTAssertFalse(evidenceByFact.values.contains { evidence in
            let label = evidence.display.lowercased()
            return label.contains("guaranteed") || label.contains("onchain-enforced")
        })
    }

    func testKeepsFrontendCustodyAndUnboundedPolicyExplicit() {
        let address = "0x" + String(repeating: "88", count: 20)
        let presentation = PermissionConsentPresentation(
            client: OwnerPhoneClientIdentity(
                clientId: "authenticated-client",
                redirectUri: "https://app.example/callback"),
            scope: scope(
                owner: .ecdsa(address: address),
                operatorCredential: .ecdsa(address: address),
                sessionSigner: nil,
                policyValidUntil: nil))
        let values = facts(presentation)

        XCTAssertEqual(values["account.ownerCredential.kind"], .text("ECDSA"))
        XCTAssertEqual(values["account.ownerCredential.address"], .text(address))
        XCTAssertEqual(values["authority.operatorCredential.kind"], .text("ECDSA"))
        XCTAssertEqual(values["authority.operatorCredential.address"], .text(address))
        XCTAssertEqual(values["authority.custody"], .text("frontend"))
        XCTAssertEqual(values["authority.providerId"], .text("none"))
        XCTAssertEqual(values["validity.policyValidUntil"], .text("no upper bound"))
    }
}
#endif
