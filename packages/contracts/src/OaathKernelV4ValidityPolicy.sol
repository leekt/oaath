// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.24;

import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

/// @title OAAth Kernel v4 validity policy
/// @notice Intersects one signed operation range with the immutable inclusive
///         validity ceiling installed for a Kernel permission.
/// @dev Kernel passes each policy its own mutable signature slice, while the permission
///      signer authenticates the EntryPoint UserOperation hash without any signature bytes.
///      The requested range therefore lives in ERC-7579 execute mode bytes inside callData,
///      which EntryPoint v0.7 hashes, and the policy signature slice must remain empty.
contract OaathKernelV4ValidityPolicy {
    uint256 internal constant SIG_VALIDATION_FAILED = 1;
    uint256 internal constant MODULE_TYPE_POLICY = 5;
    bytes4 internal constant KERNEL_EXECUTE_SELECTOR = 0xe9ae5c53;

    /// @dev bytes4(keccak256("oaath.kernel-v4.validity-time-range/v1")).
    bytes4 public constant VALIDITY_TIME_RANGE_MODE_SELECTOR = 0x1ba8f415;

    enum PolicyStatus {
        Absent,
        Live,
        Retired
    }

    struct ValidityCeiling {
        uint48 validAfter;
        uint48 validUntil;
        PolicyStatus status;
    }

    error InvalidInstallData();
    error InvalidValidityCeiling();
    error PermissionAlreadyInitialized(address account, bytes32 permissionId);
    error PermissionNotLive(address account, bytes32 permissionId);

    event ValidityCeilingInstalled(
        address indexed account, bytes32 indexed permissionId, uint48 validAfter, uint48 validUntil
    );
    event ValidityCeilingRetired(address indexed account, bytes32 indexed permissionId);

    mapping(address account => mapping(bytes32 permissionId => ValidityCeiling)) public validityCeilings;
    mapping(address account => uint256 count) private livePermissionCount;

    /// @notice Installs one immutable inclusive ceiling for the calling account and permission ID.
    /// @dev Kernel supplies `bytes32(permissionId) || abi.encode(uint48,uint48)`.
    function onInstall(bytes calldata data) external payable {
        if (data.length != 96) revert InvalidInstallData();
        bytes32 permissionId = bytes32(data[:32]);
        (uint48 validAfter, uint48 validUntil) = abi.decode(data[32:], (uint48, uint48));
        // Kernel's PermissionId is bytes4 and policy calls right-pad it to bytes32.
        if ((uint256(permissionId) & type(uint224).max) != 0) revert InvalidInstallData();
        if (validUntil == 0 || validAfter >= validUntil) revert InvalidValidityCeiling();

        ValidityCeiling storage ceiling = validityCeilings[msg.sender][permissionId];
        if (ceiling.status != PolicyStatus.Absent) {
            revert PermissionAlreadyInitialized(msg.sender, permissionId);
        }

        ceiling.validAfter = validAfter;
        ceiling.validUntil = validUntil;
        ceiling.status = PolicyStatus.Live;
        ++livePermissionCount[msg.sender];
        emit ValidityCeilingInstalled(msg.sender, permissionId, validAfter, validUntil);
    }

    /// @notice Retires one live ceiling permanently; the same account and ID cannot be reused.
    function onUninstall(bytes calldata data) external payable {
        if (data.length != 32) revert InvalidInstallData();
        bytes32 permissionId = bytes32(data);
        ValidityCeiling storage ceiling = validityCeilings[msg.sender][permissionId];
        if (ceiling.status != PolicyStatus.Live) {
            revert PermissionNotLive(msg.sender, permissionId);
        }

        ceiling.status = PolicyStatus.Retired;
        --livePermissionCount[msg.sender];
        emit ValidityCeilingRetired(msg.sender, permissionId);
    }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_POLICY;
    }

    function isInitialized(address smartAccount) external view returns (bool) {
        return livePermissionCount[smartAccount] != 0;
    }

    /// @notice Returns the exact ERC-4337 inclusive validity data for this operation.
    /// @dev Mode layout is `callType | execType | reserved | selector | payload`.
    ///      The custom payload is `uint48 validAfter | uint48 validUntil | bytes10(0)`.
    function checkUserOpPolicy(bytes32 permissionId, PackedUserOperation calldata userOp)
        external
        payable
        returns (uint256)
    {
        ValidityCeiling memory ceiling = validityCeilings[msg.sender][permissionId];
        if (ceiling.status != PolicyStatus.Live || userOp.signature.length != 0) {
            return SIG_VALIDATION_FAILED;
        }
        if (userOp.callData.length < 36 || bytes4(userOp.callData[:4]) != KERNEL_EXECUTE_SELECTOR) {
            return SIG_VALIDATION_FAILED;
        }

        uint256 mode = uint256(bytes32(userOp.callData[4:36]));
        uint8 callType = uint8(mode >> 248);
        uint8 execType = uint8(mode >> 240);
        uint32 reserved = uint32(mode >> 208);
        if (callType > 1 || execType != 0 || reserved != 0) {
            return SIG_VALIDATION_FAILED;
        }

        // The existing OAAth execution codec emits a zero selector and payload.
        // That path retains the full owner-approved ceiling.
        if (uint208(mode) == 0) {
            return _packValidationData(ceiling.validAfter, ceiling.validUntil);
        }

        if (uint32(mode >> 176) != uint32(VALIDITY_TIME_RANGE_MODE_SELECTOR) || uint80(mode) != 0) {
            return SIG_VALIDATION_FAILED;
        }
        uint48 requestedAfter = uint48(mode >> 128);
        uint48 requestedUntil = uint48(mode >> 80);
        if (
            requestedUntil == 0 || requestedAfter < ceiling.validAfter || requestedAfter >= requestedUntil
                || requestedUntil > ceiling.validUntil
        ) {
            return SIG_VALIDATION_FAILED;
        }
        return _packValidationData(requestedAfter, requestedUntil);
    }

    /// @dev This policy's request is carried only by a signed UserOperation callData mode.
    ///      A scoped Grant never gains an ERC-1271 signing capability through this module.
    function checkSignaturePolicy(bytes32, address, bytes32, bytes calldata) external pure returns (uint256) {
        return SIG_VALIDATION_FAILED;
    }

    function _packValidationData(uint48 validAfter, uint48 validUntil) private pure returns (uint256) {
        return (uint256(validAfter) << 208) | (uint256(validUntil) << 160);
    }
}
