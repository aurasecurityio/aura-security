// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/**
 * @title IEAS
 * @notice Minimal EAS interface — only the functions SecurityScanEnforcer needs
 */
interface IEAS {
    struct Attestation {
        bytes32 uid;
        bytes32 schema;
        uint64 time;
        uint64 expirationTime;
        uint64 revocationTime;
        bytes32 refUID;
        address recipient;
        address attester;
        bool revocable;
        bytes data;
    }

    /**
     * @notice Retrieve an attestation by its UID
     * @param uid The UID of the attestation
     * @return The attestation data
     */
    function getAttestation(bytes32 uid) external view returns (Attestation memory);
}
