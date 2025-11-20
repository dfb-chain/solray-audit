// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @notice Purposely vulnerable contract used to sanity-check Solray's EVM rules.
contract VulnerableVault {
    address public owner;
    uint256 public quorum;
    address public implementation;

    constructor() {
        owner = msg.sender;
    }

    /// @notice Missing access control triggers EVM-1001.
    function setQuorum(uint256 _quorum) external {
        quorum = _quorum;
    }

    /// @notice Missing access control + delegatecall triggers EVM-2001.
    function upgradeTo(address newImplementation) external {
        implementation = newImplementation;
        (bool ok, ) = newImplementation.delegatecall("");
        require(ok, "upgrade failed");
    }

    /// @notice Unsafe value transfer before state update triggers EVM-2002.
    function sweep(address payable target, uint256 amount) external {
        (bool ok, ) = target.call{value: amount}("");
        require(ok, "transfer failed");
    }

    /// @notice Emits EIP-712/permit markers (EVM-4001) for regex checks.
    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return keccak256("EIP712Domain(string name,uint256 chainId)");
    }

    /// @notice Frame config setter similar to HashConsensus (hits EVM-5001 rule).
    function setFrameConfig(uint256 frame) external {
        quorum = frame;
    }
}
