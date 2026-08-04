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
        expiresAt: Int = 1_754_000_000_000
    ) -> OwnerPhoneRequestProjection {
        OwnerPhoneRequestProjection(
            operationId: operationId,
            matchCode: try! MatchCode(matchCode),
            expiresAt: expiresAt,
            client: OwnerPhoneClientIdentity(
                clientId: "demo-web-app",
                redirectUri: "http://192.168.1.20:8788/callback"
            ),
            scope: .raw(#"{"chainScope":"all"}"#)
        )
    }
}
