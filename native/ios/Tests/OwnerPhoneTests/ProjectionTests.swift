/**
 EXPERIMENTAL PREVIEW — consent projection decode and match-code rendering
 tests against `packages/server/src/native/projection.ts`. The JSON fixtures
 here mirror the relay's golden route tests
 (`packages/server/test/native.test.ts`) byte-shape for byte-shape.

 @author taek <leekt216@gmail.com>
 */
import XCTest
@testable import OwnerPhone

final class ProjectionTests: XCTestCase {
    private func json(_ object: [String: Any]) -> Data {
        (try? JSONSerialization.data(withJSONObject: object)) ?? Data()
    }

    private let rawScope: [String: Any] = [
        "kind": "raw",
        "decision": "reject-only",
        "text": #"{"permission":"erc20-transfer","chainScope":"all"}"#
    ]

    private let permissionScope: [String: Any] = [
        "kind": "permission-request",
        "decision": "approve-or-reject",
        "application": [
            "applicationId": "app-a",
            "clientId": "demo-web-app",
            "origin": "https://app.example",
            "deviceFingerprint": "8sWHndmh"
        ],
        "account": [
            "accountIndex": "7",
            "kernelVersion": "0.4.0",
            "factoryRoute": "meta_factory",
            "entryPointVersion": "0.7",
            "ownerCredential": [
                "kind": "ecdsa",
                "address": "0x" + String(repeating: "33", count: 20)
            ]
        ],
        "operatorCredential": [
            "kind": "ecdsa",
            "address": "0x" + String(repeating: "44", count: 20)
        ],
        "sessionSigner": NSNull(),
        "chainScope": "all",
        "calls": [
            [
                "target": "0x" + String(repeating: "11", count: 20),
                "selector": "0x12345678",
                "valueLimit": "100",
                "argumentEquals": [["index": 0, "value": "0x" + String(repeating: "22", count: 32)]]
            ]
        ],
        "requestedAt": 1_753_000_000,
        "expiresAt": 1_754_000_000,
        "policyValidAfter": 1_753_000_000,
        "policyValidUntil": NSNull(),
        "perChainOperationLimit": 10
    ]

    private let mailDigest =
        "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
    private let p256PublicKey =
        "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"

    private var signingCredential: [String: Any] {
        [
            "version": ownerPhoneOwnerCredentialVersion,
            "kind": "p256",
            "publicKey": p256PublicKey
        ]
    }

    private var mailTypedData: [String: Any] {
        [
            "types": [
                "EIP712Domain": [
                    ["name": "name", "type": "string"],
                    ["name": "version", "type": "string"],
                    ["name": "chainId", "type": "uint256"],
                    ["name": "verifyingContract", "type": "address"],
                ],
                "Person": [
                    ["name": "name", "type": "string"],
                    ["name": "wallet", "type": "address"],
                ],
                "Mail": [
                    ["name": "from", "type": "Person"],
                    ["name": "to", "type": "Person"],
                    ["name": "contents", "type": "string"],
                ],
            ],
            "primaryType": "Mail",
            "domain": [
                "name": "Ether Mail",
                "version": "1",
                "chainId": "1",
                "verifyingContract": "0xcccccccccccccccccccccccccccccccccccccccc",
            ],
            "message": [
                "from": [
                    "name": "Cow",
                    "wallet": "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826",
                ],
                "to": [
                    "name": "Bob",
                    "wallet": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ],
                "contents": "Hello, Bob!",
            ],
        ]
    }

    private func eip712Request(expectedDigest: String? = nil) -> [String: Any] {
        [
            "version": ownerPhoneSigningRequestVersion,
            "kind": "eip712",
            "purpose": "application",
            "signer": [
                "account": "0x" + String(repeating: "11", count: 20),
                "ownerCredential": signingCredential,
            ],
            "typedData": mailTypedData,
            "expectedDigest": expectedDigest ?? mailDigest,
            "replay": ["nonce": "0", "deadline": NSNull()],
        ]
    }

    private func ownerSigningScope(request: [String: Any]) -> [String: Any] {
        [
            "kind": "owner-signing-request",
            "decision": "reject-only",
            "requestHash":
                "0x1588b0d137ab76a1f63adc58befd1137642312ea71cdca34659851e4796488ba",
            "request": request,
        ]
    }

    private var valid: [String: Any] {
        [
            "version": "oaath.native-projection/v3",
            "operationId": "req-1",
            "displayPayload": "Ab1-_9Zz",
            "expiresAt": 1_754_000_000_000,
            "client": ["clientId": "demo-web-app", "redirectUri": "http://192.168.1.20:8788/callback"],
            "scope": rawScope
        ]
    }

    func testDecodesTheExactConsentProjection() throws {
        let projection = try OwnerPhoneRequestProjection.decode(json(valid))
        XCTAssertEqual(projection.operationId, "req-1")
        XCTAssertEqual(projection.matchCode.value, "Ab1-_9Zz")
        XCTAssertEqual(projection.expiresAt, 1_754_000_000_000)
        XCTAssertEqual(projection.client.clientId, "demo-web-app")
        XCTAssertEqual(projection.client.redirectUri, "http://192.168.1.20:8788/callback")
        XCTAssertEqual(
            projection.scope,
            .raw(#"{"permission":"erc20-transfer","chainScope":"all"}"#))
    }

    func testDecodesAStructuredPermissionScope() throws {
        var object = valid
        object["scope"] = permissionScope
        let projection = try OwnerPhoneRequestProjection.decode(json(object))
        XCTAssertEqual(projection.scope, .permissionRequest(OwnerPhonePermissionScope(
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
                ownerCredential: .ecdsa(address: "0x" + String(repeating: "33", count: 20))
            ),
            operatorCredential: .ecdsa(address: "0x" + String(repeating: "44", count: 20)),
            sessionSigner: nil,
            chainScope: "all",
            calls: [OwnerPhonePermittedCall(
                target: "0x" + String(repeating: "11", count: 20),
                selector: "0x12345678",
                valueLimit: "100",
                argumentEquals: [OwnerPhoneArgumentEquality(
                    index: 0,
                    value: "0x" + String(repeating: "22", count: 32)
                )]
            )],
            requestedAt: 1_753_000_000,
            expiresAt: 1_754_000_000,
            policyValidAfter: 1_753_000_000,
            policyValidUntil: nil,
            perChainOperationLimit: 10
        )))
    }

    func testDecodesRemoteSessionCustodyAndRejectsUnknownModes() throws {
        // Remote custody is a consent fact: it decodes, displays, and stays
        // approvable — the request hash the decision commits to binds it.
        var custody = permissionScope
        custody["sessionSigner"] = ["mode": "oaath_hosted", "providerId": "kms-primary"]
        var object = valid
        object["scope"] = custody
        let projection = try OwnerPhoneRequestProjection.decode(json(object))
        guard case .permissionRequest(let scope) = projection.scope else {
            return XCTFail("expected a permission-request scope")
        }
        XCTAssertEqual(
            scope.sessionSigner,
            OwnerPhoneSessionSigner(mode: "oaath_hosted", providerId: "kms-primary"))

        // A custody model this decoder cannot name is never rendered partially.
        for hostile: Any in [
            ["mode": "owner_hosted", "providerId": "kms-primary"],
            ["mode": "frontend", "providerId": NSNull()],
            ["mode": "oaath_hosted"],
            ["mode": "oaath_hosted", "providerId": "kms-primary", "extra": 1],
            "oaath_hosted",
        ] {
            custody["sessionSigner"] = hostile
            object["scope"] = custody
            XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(json(object)))
        }
    }

    func testARawScopeIsRejectOnly() throws {
        let projection = try OwnerPhoneRequestProjection.decode(json(valid))
        guard case .raw = projection.scope else {
            return XCTFail("expected a raw scope")
        }
    }

    func testRejectsAnUnknownScopeKindInsteadOfRenderingPartially() {
        var object = valid
        object["scope"] = ["kind": "delegation-request", "detail": "everything"]
        XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(json(object))) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .invalidField("scope kind"))
        }
    }

    func testDecodesTheFullEIP712RequestAndDerivesAMatchingDigest() throws {
        var object = valid
        object["scope"] = ownerSigningScope(request: eip712Request())
        let projection = try OwnerPhoneRequestProjection.decode(json(object))
        guard case let .ownerSigningRequest(scope) = projection.scope,
              case let .eip712(request) = scope.request
        else {
            return XCTFail("expected a structured owner-signing request")
        }
        XCTAssertEqual(
            scope.requestHash,
            "0x1588b0d137ab76a1f63adc58befd1137642312ea71cdca34659851e4796488ba")
        XCTAssertEqual(request.version, ownerPhoneSigningRequestVersion)
        XCTAssertEqual(request.purpose, .application)
        XCTAssertEqual(request.signer.account, "0x" + String(repeating: "11", count: 20))
        XCTAssertEqual(request.signer.ownerCredential.version, ownerPhoneOwnerCredentialVersion)
        guard case let .p256(publicKey) = request.signer.ownerCredential.credential else {
            return XCTFail("expected the exact P-256 owner credential")
        }
        XCTAssertEqual(publicKey, p256PublicKey)
        XCTAssertEqual(request.typedData.primaryType, "Mail")
        XCTAssertEqual(request.typedData.message["contents"], .string("Hello, Bob!"))
        XCTAssertEqual(request.expectedDigest, mailDigest)
        guard case let .matches(derived) = request.digestComparison else {
            return XCTFail("expected a locally matching digest")
        }
        XCTAssertEqual(derived.canonicalHex, mailDigest)
        XCTAssertEqual(request.replay, OwnerPhoneSigningReplayFacts(nonce: "0", deadline: nil))
        XCTAssertEqual(scope.decisionCapability, .rejectOnly)
    }

    func testDigestSubstitutionRemainsDecodableButMismatchedAndRejectOnly() throws {
        let substituted = "0x" + String(repeating: "55", count: 32)
        var object = valid
        object["scope"] = ownerSigningScope(request: eip712Request(expectedDigest: substituted))
        let projection = try OwnerPhoneRequestProjection.decode(json(object))
        guard case let .ownerSigningRequest(scope) = projection.scope,
              case let .eip712(request) = scope.request
        else {
            return XCTFail("expected a structured owner-signing request")
        }
        guard case let .mismatch(expected, derived) = request.digestComparison else {
            return XCTFail("expected a locally mismatched digest")
        }
        XCTAssertEqual(expected, substituted)
        XCTAssertEqual(derived.canonicalHex, mailDigest)
        XCTAssertEqual(scope.decisionCapability, .rejectOnly)
    }

    func testTwoEmptyArraysDecodeAfterJSONParsing() throws {
        var request = eip712Request(expectedDigest: mailDigest)
        request["typedData"] = emptyArraysAndFieldCountTypedData()
        var object = valid
        object["scope"] = ownerSigningScope(request: request)

        let projection = try OwnerPhoneRequestProjection.decode(json(object))
        guard case let .ownerSigningRequest(scope) = projection.scope,
              case let .eip712(signingRequest) = scope.request
        else {
            return XCTFail("expected a structured owner-signing request")
        }
        XCTAssertEqual(signingRequest.typedData.message["left"], .array([]))
        XCTAssertEqual(signingRequest.typedData.message["right"], .array([]))
        XCTAssertEqual(scope.decisionCapability, .rejectOnly)
    }

    func testRawDigestRequestIsReadableAndRejectOnly() throws {
        let digest = "0x" + String(repeating: "44", count: 32)
        var object = valid
        object["scope"] = ownerSigningScope(request: [
            "version": ownerPhoneSigningRequestVersion,
            "kind": "raw-digest",
            "digest": digest,
            "reason": "No device-side derivation is available",
            "decision": "reject-only"
        ])
        let projection = try OwnerPhoneRequestProjection.decode(json(object))
        guard case let .ownerSigningRequest(scope) = projection.scope,
              case let .rawDigest(request) = scope.request
        else {
            return XCTFail("expected a raw-digest owner-signing request")
        }
        XCTAssertEqual(request.version, ownerPhoneSigningRequestVersion)
        XCTAssertEqual(request.digest, digest)
        XCTAssertEqual(request.reason, "No device-side derivation is available")
        XCTAssertEqual(scope.decisionCapability, .rejectOnly)
    }

    func testRejectsMalformedMissingAndUnknownOwnerSigningFields() {
        let zeroAddress = "0x" + String(repeating: "00", count: 20)
        let malformedRequests: [[String: Any]] = [
            eip712Request().merging(["version": "oaath.owner-signing-request/v2"]) { _, new in new },
            eip712Request().merging(["kind": "personal-sign"]) { _, new in new },
            eip712Request().merging(["purpose": "generic"]) { _, new in new },
            eip712Request().merging(["expectedDigest": mailDigest.uppercased()]) { _, new in new },
            eip712Request().merging(["expectedDigest": "0x12"]) { _, new in new },
            eip712Request().merging(["signer": [
                "account": zeroAddress,
                "ownerCredential": signingCredential
            ]]) { _, new in new },
            eip712Request().merging(["signer": [
                "account": "0x" + String(repeating: "11", count: 20),
                "ownerCredential": [
                    "version": ownerPhoneOwnerCredentialVersion,
                    "kind": "p256",
                    "publicKey": "0x04" + String(repeating: "00", count: 64)
                ]
            ]]) { _, new in new },
            eip712Request().merging(["replay": ["nonce": "01", "deadline": NSNull()]]) { _, new in new },
            eip712Request().merging(["typedData": ["primaryType": "Mail"]]) { _, new in new },
            eip712Request().merging(["extra": true]) { _, new in new },
            [
                "version": ownerPhoneSigningRequestVersion,
                "kind": "raw-digest",
                "digest": "0x" + String(repeating: "44", count: 32),
                "reason": "unsupported authority",
                "decision": "approve-or-reject"
            ],
            [
                "version": ownerPhoneSigningRequestVersion,
                "kind": "raw-digest",
                "digest": "0x" + String(repeating: "44", count: 32),
                "decision": "reject-only"
            ],
        ]
        for request in malformedRequests {
            var object = valid
            object["scope"] = ownerSigningScope(request: request)
            XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(json(object)))
        }

        let malformedScopes: [[String: Any]] = [
            ownerSigningScope(request: eip712Request()).merging(["decision": "approve-or-reject"]) { _, new in new },
            ownerSigningScope(request: eip712Request()).merging(["requestHash": "0x12"]) { _, new in new },
            ["kind": "owner-signing-request", "decision": "reject-only"],
            ownerSigningScope(request: eip712Request()).merging(["extra": true]) { _, new in new },
            ["kind": "signature-request", "decision": "reject-only"],
        ]
        for scope in malformedScopes {
            var object = valid
            object["scope"] = scope
            XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(json(object)))
        }
    }

    func testRejectsMalformedStructuredScopeFields() {
        let malformed: [[String: Any]] = [
            // chainScope other than the pinned "all"
            permissionScope.merging(["chainScope": "one"]) { _, new in new },
            // empty calls: the protocol never issues an empty policy
            permissionScope.merging(["calls": [Any]()]) { _, new in new },
            // uppercase hex target
            permissionScope.merging(["calls": [[
                "target": "0x" + String(repeating: "AA", count: 20),
                "selector": "0x12345678",
                "valueLimit": "100",
                "argumentEquals": [Any]()
            ]]]) { _, new in new },
            // short selector
            permissionScope.merging(["calls": [[
                "target": "0x" + String(repeating: "11", count: 20),
                "selector": "0x1234567",
                "valueLimit": "100",
                "argumentEquals": [Any]()
            ]]]) { _, new in new },
            // non-canonical decimal value limit
            permissionScope.merging(["calls": [[
                "target": "0x" + String(repeating: "11", count: 20),
                "selector": "0x12345678",
                "valueLimit": "0100",
                "argumentEquals": [Any]()
            ]]]) { _, new in new },
            // a raw decision on an approvable kind is contradictory evidence
            permissionScope.merging(["decision": "reject-only"]) { _, new in new },
            // an unknown owner credential kind never renders partially
            permissionScope.merging(["account": [
                "accountIndex": "7",
                "kernelVersion": "0.4.0",
                "factoryRoute": "meta_factory",
                "entryPointVersion": "0.7",
                "ownerCredential": ["kind": "quantum", "address": "0x"]
            ]]) { _, new in new },
            // extra call field
            permissionScope.merging(["calls": [[
                "target": "0x" + String(repeating: "11", count: 20),
                "selector": "0x12345678",
                "valueLimit": "100",
                "argumentEquals": [Any](),
                "extra": 1
            ]]]) { _, new in new }
        ]
        for scope in malformed {
            var object = valid
            object["scope"] = scope
            XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(json(object)))
        }
    }

    func testRejectsUnknownAndMissingFields() {
        var object = valid
        object["permissionDetail"] = "everything"
        XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(json(object))) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .unexpectedFields("owner phone projection"))
        }
        object = valid
        object.removeValue(forKey: "displayPayload")
        XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(json(object))) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .unexpectedFields("owner phone projection"))
        }
        // A foreign version is rejected, never read as this one.
        object = valid
        object["version"] = "oaath.native-projection/v1"
        XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(json(object))) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .invalidField("version"))
        }
        object = valid
        object["client"] = ["clientId": "demo-web-app"]
        XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(json(object))) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .unexpectedFields("client"))
        }
        object = valid
        object["scope"] = rawScope.merging(["extra": 1]) { _, new in new }
        XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(json(object))) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .unexpectedFields("scope"))
        }
    }

    func testRejectsNonObjectBodies() {
        XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(Data("[]".utf8))) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .notAnObject("owner phone projection"))
        }
        XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(Data("not json".utf8))) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .notAnObject("owner phone projection"))
        }
    }

    func testMatchCodeAcceptsExactlyEightBase64UrlCharacters() throws {
        XCTAssertEqual(try MatchCode("Ab1-_9Zz").value, "Ab1-_9Zz")
        for bad in ["", "Ab1-_9Z", "Ab1-_9Zz0", "Ab1-_9Z+", "Ab1-_9Z/", "Ab1 _9Zz", "Ab1-_9Z="] {
            XCTAssertThrowsError(try MatchCode(bad)) {
                XCTAssertEqual($0 as? OwnerPhoneWireError, .invalidField("displayPayload"))
            }
        }
    }

    func testMatchCodeRendersInTwoGroupsOfFour() throws {
        XCTAssertEqual(try MatchCode("Ab1-_9Zz").display, "Ab1- _9Zz")
        XCTAssertEqual(try MatchCode("AAAABBBB").display, "AAAA BBBB")
    }

    func testRejectsControlCharactersInOperationId() {
        var object = valid
        object["operationId"] = "req\u{0000}1"
        XCTAssertThrowsError(try OwnerPhoneRequestProjection.decode(json(object))) {
            XCTAssertEqual($0 as? OwnerPhoneWireError, .invalidField("operationId"))
        }
    }
}

#if canImport(SwiftUI)
final class OwnerSigningConsentPresentationTests: XCTestCase {
    private func fixture() throws -> [String: Any] {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("packages/server/test/fixtures/owner-phone-golden.json")
        guard let fixture = try JSONSerialization.jsonObject(
            with: Data(contentsOf: url)) as? [String: Any]
        else {
            throw OwnerPhoneWireError.notAnObject("owner signing golden fixture")
        }
        return fixture
    }

    private func projection(named name: String) throws -> [String: Any] {
        guard let projections = try fixture()["projection"] as? [String: Any],
              let projection = projections[name] as? [String: Any]
        else {
            throw OwnerPhoneWireError.invalidField("projection.\(name)")
        }
        return projection
    }

    private func signingScope(_ projection: [String: Any]) throws -> OwnerPhoneSigningRequestScope {
        let bytes = try JSONSerialization.data(withJSONObject: projection)
        let decoded = try OwnerPhoneRequestProjection.decode(bytes)
        guard case let .ownerSigningRequest(scope) = decoded.scope else {
            throw OwnerPhoneWireError.invalidField("owner signing scope")
        }
        return scope
    }

    private func facts(
        _ presentation: OwnerSigningConsentPresentation
    ) -> [String: OwnerSigningConsentFact] {
        Dictionary(uniqueKeysWithValues: presentation.sections.flatMap(\.facts).map { ($0.id, $0) })
    }

    func testRendersEveryCapturedEIP712FactFromTheGoldenValue() throws {
        let presentation = OwnerSigningConsentPresentation(
            scope: try signingScope(projection(named: "ownerSigningRequest")))
        let rendered = facts(presentation)

        XCTAssertEqual(presentation.sections.count, 10)
        XCTAssertEqual(rendered.count, 49)
        XCTAssertEqual(rendered["request.decision"]?.value, "reject only")
        XCTAssertEqual(
            rendered["request.requestHash"]?.value,
            "0x1588b0d137ab76a1f63adc58befd1137642312ea71cdca34659851e4796488ba")
        XCTAssertEqual(rendered["identity.version"]?.value, ownerPhoneSigningRequestVersion)
        XCTAssertEqual(rendered["identity.kind"]?.value, "eip712")
        XCTAssertEqual(rendered["identity.purpose"]?.value, "application")
        XCTAssertEqual(
            rendered["identity.account"]?.value,
            "0x1111111111111111111111111111111111111111")
        XCTAssertEqual(
            rendered["identity.credential.version"]?.value,
            ownerPhoneOwnerCredentialVersion)
        XCTAssertEqual(rendered["identity.credential.kind"]?.value, "p256")
        XCTAssertEqual(rendered["typedData.primaryType"]?.value, "Mail")
        XCTAssertEqual(rendered["type.Mail.field.2.name"]?.value, "contents")
        XCTAssertEqual(rendered["type.Mail.field.2.type"]?.value, "string")
        XCTAssertEqual(rendered["domain.field.chainId"]?.value, #""1""#)
        XCTAssertEqual(rendered["message.field.from.field.name"]?.value, #""Cow""#)
        XCTAssertEqual(rendered["message.field.contents"]?.value, #""Hello, Bob!""#)
        XCTAssertEqual(rendered["digest.comparison"]?.value, "matches expected digest")
        XCTAssertEqual(rendered["replay.nonce"]?.value, "0")
        XCTAssertEqual(rendered["replay.deadline"]?.value, "absent")
        XCTAssertTrue(Set(rendered.keys).contains("domain.meta.fieldCount"))
        XCTAssertTrue(Set(rendered.keys).contains("message.field.from.meta.fieldCount"))
    }

    func testRendersKernelEnablePurposeExactly() throws {
        let presentation = OwnerSigningConsentPresentation(
            scope: try signingScope(projection(named: "kernelEnableOwnerSigningRequest")))
        let rendered = facts(presentation)

        XCTAssertEqual(rendered["identity.purpose"]?.value, "kernel-enable")
        XCTAssertEqual(rendered["typedData.primaryType"]?.value, "InstallPackages")
        XCTAssertEqual(
            rendered["digest.derived"]?.value,
            "0x72781421bec5030685dd2cde6d64eb4e63ea204ddb9951bd74986b0edd69ed03")
    }

    func testPresentationFactIdsDisambiguateMetadataFromFieldNames() throws {
        var object = try projection(named: "ownerSigningRequest")
        var scope = try XCTUnwrap(object["scope"] as? [String: Any])
        var request = try XCTUnwrap(scope["request"] as? [String: Any])
        request["typedData"] = emptyArraysAndFieldCountTypedData()
        scope["request"] = request
        object["scope"] = scope

        let presentation = OwnerSigningConsentPresentation(scope: try signingScope(object))
        let allFacts = presentation.sections.flatMap(\.facts)
        XCTAssertEqual(Set(allFacts.map(\.id)).count, allFacts.count)
        let rendered = Dictionary(uniqueKeysWithValues: allFacts.map { ($0.id, $0) })
        XCTAssertEqual(rendered["message.meta.fieldCount"]?.value, "3")
        XCTAssertEqual(rendered["message.field.fieldCount"]?.value, #""literal field""#)
        XCTAssertEqual(rendered["message.field.left.meta.count"]?.value, "0")
        XCTAssertEqual(rendered["message.field.right.meta.count"]?.value, "0")
    }

    func testRendersDigestMismatchWithoutChangingRejectOnlyCapability() throws {
        var object = try projection(named: "ownerSigningRequest")
        var scope = try XCTUnwrap(object["scope"] as? [String: Any])
        var request = try XCTUnwrap(scope["request"] as? [String: Any])
        request["expectedDigest"] = "0x" + String(repeating: "55", count: 32)
        scope["request"] = request
        object["scope"] = scope

        let captured = try signingScope(object)
        let rendered = facts(OwnerSigningConsentPresentation(scope: captured))
        XCTAssertEqual(rendered["digest.comparison"]?.value, "MISMATCH — reject")
        XCTAssertEqual(
            rendered["digest.derived"]?.value,
            "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2")
    }

    func testRendersRawDigestReasonWithoutClaimingDerivation() throws {
        let presentation = OwnerSigningConsentPresentation(
            scope: try signingScope(projection(named: "rawDigestOwnerSigningRequest")))
        let rendered = facts(presentation)
        XCTAssertEqual(presentation.sections.map(\.id), ["request", "rawDigest"])
        XCTAssertEqual(rendered["rawDigest.kind"]?.value, "raw-digest")
        XCTAssertEqual(
            rendered["rawDigest.digest"]?.value,
            "0x" + String(repeating: "44", count: 32))
        XCTAssertEqual(
            rendered["rawDigest.reason"]?.value,
            #""No device-side derivation is available""#)
    }
}
#endif

private func emptyArraysAndFieldCountTypedData() -> [String: Any] {
    [
        "types": [
            "EIP712Domain": [["name": "chainId", "type": "uint256"]],
            "Payload": [
                ["name": "left", "type": "string[]"],
                ["name": "right", "type": "string[]"],
                ["name": "fieldCount", "type": "string"],
            ],
        ],
        "primaryType": "Payload",
        "domain": ["chainId": "1"],
        "message": [
            "left": [Any](),
            "right": [Any](),
            "fieldCount": "literal field",
        ],
    ]
}
