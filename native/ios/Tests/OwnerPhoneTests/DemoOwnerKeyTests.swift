/**
 EXPERIMENTAL PREVIEW — owner-key platform selection tests.

 @author taek <leekt216@gmail.com>
 */
import XCTest
@testable import OwnerPhoneDemo

final class DemoOwnerKeyTests: XCTestCase {
    func testCustodyGenerationUsesExactV3Tags() {
        XCTAssertEqual(
            DemoOwnerKeyStorage.secureEnclave.applicationTag,
            "org.oaath.owner-phone.p256.v3.enclave")
        XCTAssertEqual(
            DemoOwnerKeyStorage.softwareFallback.applicationTag,
            "org.oaath.owner-phone.p256.v3.software")
    }

    func testPhysicalIOSUsesOnlyTheSecureEnclave() {
        var attempts: [DemoOwnerKeyStorage] = []
        let selected: String? = resolveDemoOwnerKey(
            environment: .physicalIOS,
            createIfMissing: true,
            load: { storage, mayCreate in
                attempts.append(storage)
                XCTAssertTrue(mayCreate)
                return storage == .secureEnclave ? "enclave" : "software"
            })

        XCTAssertEqual(selected, "enclave")
        XCTAssertEqual(attempts, [.secureEnclave])
    }

    func testPhysicalIOSEnclaveFailureNeverAuthorizesSoftwareFallback() {
        var attempts: [DemoOwnerKeyStorage] = []
        let selected: String? = resolveDemoOwnerKey(
            environment: .physicalIOS,
            createIfMissing: true,
            load: { storage, mayCreate in
                attempts.append(storage)
                XCTAssertTrue(mayCreate)
                return nil
            })

        XCTAssertNil(selected)
        XCTAssertEqual(attempts, [.secureEnclave])
    }

    func testSimulatorOrHostUsesOnlyTheExplicitSoftwareFallback() {
        var attempts: [DemoOwnerKeyStorage] = []
        let selected: String? = resolveDemoOwnerKey(
            environment: .simulatorOrHost,
            createIfMissing: true,
            load: { storage, mayCreate in
                attempts.append(storage)
                XCTAssertTrue(mayCreate)
                return storage == .softwareFallback ? "software" : nil
            })

        XCTAssertEqual(selected, "software")
        XCTAssertEqual(attempts, [.softwareFallback])
    }

    func testPairedReloadForbidsKeyCreation() {
        var mayCreate: Bool?
        let selected: String? = resolveDemoOwnerKey(
            environment: .physicalIOS,
            createIfMissing: false,
            load: { _, createIfMissing in
                mayCreate = createIfMissing
                return nil
            })

        XCTAssertNil(selected)
        XCTAssertEqual(mayCreate, false)
    }
}
