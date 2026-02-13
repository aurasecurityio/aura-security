// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "./interfaces/ICaveatEnforcer.sol";
import "./interfaces/IEAS.sol";

/**
 * @title SecurityScanEnforcer
 * @notice ERC-7710 caveat enforcer that gates delegations on Aura Security scan results.
 * @dev Reads EAS attestations published by Aura's attester address.
 *      Blocks delegation execution if the target code has critical/high findings
 *      above the thresholds set in the delegation terms, or if the scan is stale.
 *
 *      Deploy on Base mainnet. Set `auraAttester` to Aura's Base wallet address.
 *      Set `eas` to Base's EAS contract (0x4200000000000000000000000000000000000021).
 */
contract SecurityScanEnforcer is ICaveatEnforcer {
    /// @notice EAS contract on Base
    IEAS public immutable eas;

    /// @notice Aura Security's attester address — only attestations from this address are trusted
    address public immutable auraAttester;

    /// @notice Terms that a delegator sets when creating a delegation
    struct ScanTerms {
        bytes32 targetCodeHash;   // keccak256 hash of the target identifier (repo URL, contract address, etc.)
        uint256 maxAge;           // Maximum seconds since the scan was performed
        uint256 maxCritical;      // Maximum critical findings allowed (usually 0)
        uint256 maxHigh;          // Maximum high findings allowed
    }

    error NotAuraAttester(address actual, address expected);
    error StaleScan(uint256 scanTime, uint256 maxAge);
    error CodeHashMismatch(bytes32 actual, bytes32 expected);
    error TooManyCriticalFindings(uint256 count, uint256 max);
    error TooManyHighFindings(uint256 count, uint256 max);
    error AttestationRevoked(bytes32 uid);

    constructor(address _eas, address _auraAttester) {
        eas = IEAS(_eas);
        auraAttester = _auraAttester;
    }

    /**
     * @notice Validates that the delegation target has a clean Aura security scan
     * @param terms ABI-encoded ScanTerms set by the delegator
     * @param args ABI-encoded attestation UID (bytes32) provided at execution time
     * @param delegationHash Unused — hash of the delegation being executed
     */
    function beforeHook(
        bytes calldata terms,
        bytes calldata args,
        bytes32 /* delegationHash */
    ) external view override {
        ScanTerms memory t = abi.decode(terms, (ScanTerms));
        bytes32 uid = abi.decode(args, (bytes32));

        // Fetch attestation from EAS
        IEAS.Attestation memory a = eas.getAttestation(uid);

        // Verify attester is Aura Security
        if (a.attester != auraAttester) {
            revert NotAuraAttester(a.attester, auraAttester);
        }

        // Check attestation hasn't been revoked
        if (a.revocationTime != 0) {
            revert AttestationRevoked(uid);
        }

        // Check scan freshness
        if (block.timestamp - a.time > t.maxAge) {
            revert StaleScan(a.time, t.maxAge);
        }

        // Decode attestation data:
        // bytes32 codeHash, uint256 criticalCount, uint256 highCount, uint256 mediumCount, bytes32 reportHash
        (
            bytes32 codeHash,
            uint256 critical,
            uint256 high,
            ,  // mediumCount — not enforced
               // reportHash — not enforced
        ) = abi.decode(a.data, (bytes32, uint256, uint256, uint256, bytes32));

        // Verify code hash matches the delegation target
        if (codeHash != t.targetCodeHash) {
            revert CodeHashMismatch(codeHash, t.targetCodeHash);
        }

        // Check findings against thresholds
        if (critical > t.maxCritical) {
            revert TooManyCriticalFindings(critical, t.maxCritical);
        }

        if (high > t.maxHigh) {
            revert TooManyHighFindings(high, t.maxHigh);
        }

        // All checks passed — delegation is allowed to proceed
    }

    /**
     * @notice No-op after hook
     */
    function afterHook(
        bytes calldata,
        bytes calldata,
        bytes32
    ) external view override {
        // No post-execution validation needed
    }
}
