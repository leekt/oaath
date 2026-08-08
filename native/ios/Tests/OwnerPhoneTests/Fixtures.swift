/**
 EXPERIMENTAL PREVIEW — shared projection fixtures for the unit target.

 @author taek <leekt216@gmail.com>
 */
import Foundation
@testable import OwnerPhone

extension OwnerPhoneRequestProjection {
    /// A structurally valid consent projection for tests that exercise other
    /// owners (push matching, the review machine); wire decoding is pinned by
    /// `ProjectionTests` against raw JSON, never by this convenience.
    static func fixture(
        operationId: String = "req-1",
        matchCode: String = "Ab1-_9Zz",
        expiresAt: Int = 1_754_000_000_000,
        scope: OwnerPhoneScope? = nil
    ) -> OwnerPhoneRequestProjection {
        OwnerPhoneRequestProjection(
            operationId: operationId,
            matchCode: try! MatchCode(matchCode),
            expiresAt: expiresAt,
            client: OwnerPhoneClientIdentity(
                clientId: "demo-web-app",
                redirectUri: "http://192.168.1.20:8788/callback"
            ),
            scope: scope ?? .permissionRequest(OwnerPhonePermissionScope(
                application: OwnerPhoneApplicationIdentity(
                    applicationId: "app-a",
                    clientId: "demo-web-app",
                    origin: "https://app.example",
                    deviceFingerprint: "8sWHndmh"
                ),
                account: OwnerPhoneAccountIdentity(
                    accountIndex: "7",
                    kernelVersion: "0.4.0",
                    factoryRoute: "meta_factory",
                    entryPointVersion: "0.7",
                    ownerCredential: .ecdsa(
                        address: "0x" + String(repeating: "33", count: 20))
                ),
                operatorCredential: .ecdsa(
                    address: "0x" + String(repeating: "44", count: 20)),
                sessionSigner: nil,
                chainScope: "all",
                calls: [OwnerPhonePermittedCall(
                    target: "0x" + String(repeating: "11", count: 20),
                    selector: "0x12345678",
                    valueLimit: "100",
                    argumentEquals: []
                )],
                requestedAt: 1_753_000_000,
                expiresAt: 1_754_000_000,
                policyValidAfter: 1_753_000_000,
                policyValidUntil: nil,
                perChainOperationLimit: 10
            ))
        )
    }
}

extension OwnerPhoneScope {
    static func rawDigestSigningFixture(
        digest: String = "0x" + String(repeating: "44", count: 32)
    ) -> OwnerPhoneScope {
        .ownerSigningRequest(OwnerPhoneSigningRequestScope(
            requestHash: "0x" + String(repeating: "55", count: 32),
            request: .rawDigest(OwnerPhoneRawDigestSigningRequest(
                version: ownerPhoneSigningRequestVersion,
                digest: digest,
                reason: "No device-side derivation is available"
            ))
        ))
    }
}
