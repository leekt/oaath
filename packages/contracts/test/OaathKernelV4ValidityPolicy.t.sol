// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.24;

import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {OaathKernelV4ValidityPolicy} from "../src/OaathKernelV4ValidityPolicy.sol";

contract PolicyAccount {
    function install(OaathKernelV4ValidityPolicy policy, bytes32 permissionId, uint48 validAfter, uint48 validUntil)
        external
    {
        policy.onInstall(abi.encodePacked(permissionId, abi.encode(validAfter, validUntil)));
    }

    function tryInstall(OaathKernelV4ValidityPolicy policy, bytes32 permissionId, uint48 validAfter, uint48 validUntil)
        external
        returns (bool)
    {
        (bool success,) = address(policy)
            .call(
                abi.encodeCall(
                    OaathKernelV4ValidityPolicy.onInstall,
                    (abi.encodePacked(permissionId, abi.encode(validAfter, validUntil)))
                )
            );
        return success;
    }

    function tryInstallRaw(OaathKernelV4ValidityPolicy policy, bytes calldata data) external returns (bool) {
        (bool success,) = address(policy).call(abi.encodeCall(OaathKernelV4ValidityPolicy.onInstall, (data)));
        return success;
    }

    function uninstall(OaathKernelV4ValidityPolicy policy, bytes32 permissionId) external {
        policy.onUninstall(abi.encodePacked(permissionId));
    }

    function tryUninstall(OaathKernelV4ValidityPolicy policy, bytes32 permissionId) external returns (bool) {
        (bool success,) = address(policy)
            .call(abi.encodeCall(OaathKernelV4ValidityPolicy.onUninstall, (abi.encodePacked(permissionId))));
        return success;
    }

    function tryUninstallRaw(OaathKernelV4ValidityPolicy policy, bytes calldata data) external returns (bool) {
        (bool success,) = address(policy).call(abi.encodeCall(OaathKernelV4ValidityPolicy.onUninstall, (data)));
        return success;
    }

    function check(OaathKernelV4ValidityPolicy policy, bytes32 permissionId, PackedUserOperation calldata userOp)
        external
        returns (uint256)
    {
        return policy.checkUserOpPolicy(permissionId, userOp);
    }

    function checkSignature(OaathKernelV4ValidityPolicy policy, bytes32 permissionId) external view returns (uint256) {
        return policy.checkSignaturePolicy(permissionId, address(this), bytes32(0), "");
    }
}

contract OaathKernelV4ValidityPolicyTest {
    bytes4 private constant EXECUTE_SELECTOR = 0xe9ae5c53;
    bytes4 private constant RANGE_SELECTOR = 0x1ba8f415;
    bytes32 private constant PERMISSION_ID = bytes32(bytes4(0x01020304));
    bytes32 private constant OTHER_PERMISSION_ID = bytes32(bytes4(0x21222324));
    uint48 private constant CEILING_AFTER = 100;
    uint48 private constant CEILING_UNTIL = 1_000;

    OaathKernelV4ValidityPolicy private policy;
    PolicyAccount private accountA;
    PolicyAccount private accountB;

    error AssertionFailed(string reason);

    function setUp() public {
        policy = new OaathKernelV4ValidityPolicy();
        accountA = new PolicyAccount();
        accountB = new PolicyAccount();
    }

    function testModuleIdentityAndSignatureRefusal() public view {
        _assertTrue(policy.isModuleType(5), "policy module type missing");
        _assertTrue(!policy.isModuleType(4), "unexpected module type");
        _assertEq(uint32(policy.VALIDITY_TIME_RANGE_MODE_SELECTOR()), uint32(RANGE_SELECTOR), "mode selector changed");
        _assertEq(accountA.checkSignature(policy, PERMISSION_ID), 1, "ERC-1271 policy unexpectedly passed");
    }

    function testDefaultModeReturnsImmutableCeiling() public {
        _installA();
        _assertTrue(policy.isInitialized(address(accountA)), "account was not initialized");
        _assertEq(
            accountA.check(policy, PERMISSION_ID, _userOperation(_defaultMode(0), "")),
            _pack(CEILING_AFTER, CEILING_UNTIL),
            "single-call default did not return ceiling"
        );
        _assertEq(
            accountA.check(policy, PERMISSION_ID, _userOperation(_defaultMode(1), "")),
            _pack(CEILING_AFTER, CEILING_UNTIL),
            "batch default did not return ceiling"
        );
    }

    function testEqualAndTighterSignedRangesReturnExactInclusiveValidationData() public {
        _installA();
        // EntryPoint v0.7 accepts at both encoded endpoints. The policy therefore
        // returns the exact ERC-7902 values instead of silently subtracting one
        // second from the requested or owner-approved validUntil.
        _assertEq(
            accountA.check(policy, PERMISSION_ID, _userOperation(_rangeMode(0, CEILING_AFTER, CEILING_UNTIL), "")),
            _pack(CEILING_AFTER, CEILING_UNTIL),
            "equal range was not accepted"
        );
        _assertEq(
            accountA.check(policy, PERMISSION_ID, _userOperation(_rangeMode(1, 200, 900), "")),
            _pack(200, 900),
            "tighter range was not returned exactly"
        );
    }

    function testInvalidModesAndRangesFailClosed() public {
        _installA();
        _assertFailure(_rangeMode(0, CEILING_AFTER - 1, 900), "earlier start passed");
        _assertFailure(_rangeMode(0, 200, CEILING_UNTIL + 1), "later end passed");
        _assertFailure(_rangeMode(0, 500, 500), "empty range passed");
        _assertFailure(_rangeMode(0, 600, 500), "inverted range passed");
        _assertFailure(_rangeMode(0, 0, 0), "unbounded end passed");
        _assertFailure(_customMode(0, 0xdeadbeef, 200, 900, 0), "unknown selector passed");
        _assertFailure(_customMode(0, bytes4(0), 200, 900, 0), "nonzero default payload passed");
        _assertFailure(_customMode(0, RANGE_SELECTOR, 200, 900, 1), "payload suffix passed");
        _assertFailure(bytes32(uint256(_rangeMode(0, 200, 900)) | (1 << 208)), "reserved bytes passed");
        _assertFailure(bytes32(uint256(_rangeMode(0, 200, 900)) | (1 << 240)), "try execution passed");
        _assertFailure(_rangeMode(2, 200, 900), "unsupported call type passed");

        PackedUserOperation memory nonemptySignature = _userOperation(_rangeMode(0, 200, 900), hex"01");
        _assertEq(accountA.check(policy, PERMISSION_ID, nonemptySignature), 1, "nonempty policy signature passed");

        PackedUserOperation memory wrongSelector = _userOperation(_rangeMode(0, 200, 900), "");
        wrongSelector.callData = abi.encodeWithSelector(bytes4(0xdeadbeef), _rangeMode(0, 200, 900), bytes(""));
        _assertEq(accountA.check(policy, PERMISSION_ID, wrongSelector), 1, "non-Kernel calldata passed");
        wrongSelector.callData = hex"e9ae5c53";
        _assertEq(accountA.check(policy, PERMISSION_ID, wrongSelector), 1, "truncated calldata passed");
    }

    function testAccountAndPermissionIdsAreIsolated() public {
        _installA();
        accountA.install(policy, OTHER_PERMISSION_ID, 400, 700);
        accountB.install(policy, PERMISSION_ID, 300, 800);

        _assertEq(
            accountA.check(policy, PERMISSION_ID, _userOperation(_defaultMode(0), "")),
            _pack(CEILING_AFTER, CEILING_UNTIL),
            "account A ceiling changed"
        );
        _assertEq(
            accountB.check(policy, PERMISSION_ID, _userOperation(_defaultMode(0), "")),
            _pack(300, 800),
            "account B ceiling changed"
        );
        _assertEq(
            accountA.check(policy, OTHER_PERMISSION_ID, _userOperation(_defaultMode(0), "")),
            _pack(400, 700),
            "account A permissions shared a ceiling"
        );
    }

    function testLifecycleForbidsOverwriteAndReinstall() public {
        _installA();
        _assertTrue(!accountA.tryInstall(policy, PERMISSION_ID, 200, 900), "live ceiling was overwritten");
        accountA.uninstall(policy, PERMISSION_ID);
        _assertTrue(!policy.isInitialized(address(accountA)), "retired account stayed initialized");
        _assertEq(
            accountA.check(policy, PERMISSION_ID, _userOperation(_defaultMode(0), "")), 1, "retired permission passed"
        );
        _assertTrue(
            !accountA.tryInstall(policy, PERMISSION_ID, CEILING_AFTER, CEILING_UNTIL), "retired ID was reinstalled"
        );
        _assertTrue(!accountA.tryUninstall(policy, PERMISSION_ID), "retired ID was uninstalled twice");
    }

    function testInstallCaptureRejectsMalformedOrInvalidCeilings() public {
        _assertTrue(!accountA.tryInstallRaw(policy, hex"0102"), "short install data passed");
        _assertTrue(
            !accountA.tryInstallRaw(
                policy, abi.encodePacked(PERMISSION_ID, abi.encode(CEILING_AFTER, CEILING_UNTIL), hex"00")
            ),
            "long install data passed"
        );
        _assertTrue(
            !accountA.tryInstall(
                policy, 0x0102030400000000000000000000000000000000000000000000000000000001, CEILING_AFTER, CEILING_UNTIL
            ),
            "noncanonical permission ID passed"
        );
        _assertTrue(
            !accountA.tryInstall(policy, PERMISSION_ID, CEILING_UNTIL, CEILING_AFTER), "inverted ceiling passed"
        );
        _assertTrue(!accountA.tryInstall(policy, PERMISSION_ID, 0, 0), "unbounded ceiling passed");
    }

    function testUninstallRequiresExactPermissionId() public {
        _installA();
        _assertTrue(!accountA.tryUninstallRaw(policy, hex"0102"), "short uninstall data passed");
        _assertTrue(
            !accountA.tryUninstallRaw(policy, abi.encodePacked(PERMISSION_ID, hex"00")), "long uninstall data passed"
        );
        _assertEq(
            accountA.check(policy, PERMISSION_ID, _userOperation(_defaultMode(0), "")),
            _pack(CEILING_AFTER, CEILING_UNTIL),
            "malformed uninstall retired permission"
        );
    }

    function testSignedRangeUsesExactOuterCallDataOffsets() public pure {
        bytes memory actual = _userOperation(_rangeMode(0, 200, 900), "").callData;
        bytes memory expected = hex"e9ae5c53" hex"0000000000001ba8f4150000000000c800000000038400000000000000000000"
            hex"0000000000000000000000000000000000000000000000000000000000000040"
            hex"0000000000000000000000000000000000000000000000000000000000000000";
        _assertTrue(actual.length == expected.length, "execute calldata length changed");
        _assertTrue(keccak256(actual) == keccak256(expected), "validity range outer offsets changed");
    }

    function testRequestedRangeChangesSignedCallData() public pure {
        PackedUserOperation memory first = _userOperation(_rangeMode(0, 200, 900), "");
        PackedUserOperation memory second = _userOperation(_rangeMode(0, 201, 900), "");
        PackedUserOperation memory omitted = _userOperation(_defaultMode(0), "");
        _assertTrue(keccak256(first.callData) != keccak256(second.callData), "changed range retained callData hash");
        _assertTrue(keccak256(first.callData) != keccak256(omitted.callData), "omitted range retained callData hash");
    }

    function _installA() private {
        accountA.install(policy, PERMISSION_ID, CEILING_AFTER, CEILING_UNTIL);
    }

    function _assertFailure(bytes32 mode, string memory reason) private {
        _assertEq(accountA.check(policy, PERMISSION_ID, _userOperation(mode, "")), 1, reason);
    }

    function _defaultMode(uint8 callType) private pure returns (bytes32) {
        return bytes32(uint256(callType) << 248);
    }

    function _rangeMode(uint8 callType, uint48 validAfter, uint48 validUntil) private pure returns (bytes32) {
        return _customMode(callType, RANGE_SELECTOR, validAfter, validUntil, 0);
    }

    function _customMode(uint8 callType, bytes4 selector, uint48 validAfter, uint48 validUntil, uint80 suffix)
        private
        pure
        returns (bytes32)
    {
        return bytes32(
            (uint256(callType) << 248) | (uint256(uint32(selector)) << 176) | (uint256(validAfter) << 128)
                | (uint256(validUntil) << 80) | suffix
        );
    }

    function _userOperation(bytes32 mode, bytes memory signature)
        private
        pure
        returns (PackedUserOperation memory userOp)
    {
        userOp.sender = address(0x1234);
        userOp.callData = abi.encodeWithSelector(EXECUTE_SELECTOR, mode, bytes(""));
        userOp.signature = signature;
    }

    function _pack(uint48 validAfter, uint48 validUntil) private pure returns (uint256) {
        return (uint256(validAfter) << 208) | (uint256(validUntil) << 160);
    }

    function _assertTrue(bool condition, string memory reason) private pure {
        if (!condition) revert AssertionFailed(reason);
    }

    function _assertEq(uint256 actual, uint256 expected, string memory reason) private pure {
        if (actual != expected) revert AssertionFailed(reason);
    }
}
