// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/**
 * @title ICaveatEnforcer
 * @notice ERC-7710 Caveat Enforcer interface
 * @dev Contracts that implement this interface can be used as caveat enforcers
 *      in the MetaMask Delegation Framework. The beforeHook is called before
 *      a delegated action executes, and afterHook is called after.
 */
interface ICaveatEnforcer {
    /**
     * @notice Called before a delegated action executes
     * @param terms The caveat terms set by the delegator
     * @param args Dynamic arguments provided at execution time
     * @param delegationHash Hash of the delegation being executed
     */
    function beforeHook(
        bytes calldata terms,
        bytes calldata args,
        bytes32 delegationHash
    ) external view;

    /**
     * @notice Called after a delegated action executes
     * @param terms The caveat terms set by the delegator
     * @param args Dynamic arguments provided at execution time
     * @param delegationHash Hash of the delegation being executed
     */
    function afterHook(
        bytes calldata terms,
        bytes calldata args,
        bytes32 delegationHash
    ) external view;
}
