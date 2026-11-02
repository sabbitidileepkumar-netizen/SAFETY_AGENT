// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Guard AI Audit Registry
 * @notice Provides decentralized, tamper-evident verification for security events.
 * Only cryptographic hashes and non-sensitive metadata are stored on-chain.
 * User data, passwords, and private keys are NEVER stored here.
 */
contract AuditRegistry {
    struct AuditEntry {
        string recordId;
        bytes32 dataHash;
        string entryType;
        uint256 timestamp;
        address reporter;
        bool exists;
    }

    address public owner;
    uint256 public totalRecords;

    // Mapping from recordId string to AuditEntry
    mapping(string => AuditEntry) private _entries;
    
    // Mapping from dataHash to recordId list for inverse integrity lookup
    mapping(bytes32 => string[]) private _hashToRecords;

    event AuditRegistered(
        string indexed recordId,
        bytes32 indexed dataHash,
        string entryType,
        uint256 timestamp,
        address indexed reporter
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can perform this action");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice Register a new security event hash.
     */
    function registerAuditEntry(
        string calldata recordId,
        bytes32 dataHash,
        string calldata entryType
    ) external returns (bool) {
        require(bytes(recordId).length > 0, "Record ID required");
        require(dataHash != bytes32(0), "Invalid data hash");
        require(!_entries[recordId].exists, "Record ID already registered");

        _entries[recordId] = AuditEntry({
            recordId: recordId,
            dataHash: dataHash,
            entryType: entryType,
            timestamp: block.timestamp,
            reporter: msg.sender,
            exists: true
        });

        _hashToRecords[dataHash].push(recordId);
        totalRecords += 1;

        emit AuditRegistered(recordId, dataHash, entryType, block.timestamp, msg.sender);
        return true;
    }

    /**
     * @notice Verify whether a given data hash matches the recorded hash for a record ID.
     */
    function verifyAuditEntry(
        string calldata recordId,
        bytes32 candidateHash
    ) external view returns (bool isValid, uint256 timestamp, address reporter, string memory entryType) {
        AuditEntry memory entry = _entries[recordId];
        if (!entry.exists) {
            return (false, 0, address(0), "");
        }
        bool matches = (entry.dataHash == candidateHash);
        return (matches, entry.timestamp, entry.reporter, entry.entryType);
    }

    /**
     * @notice Retrieve an audit entry's stored hash and timestamp.
     */
    function getAuditEntry(string calldata recordId)
        external
        view
        returns (
            bytes32 dataHash,
            string memory entryType,
            uint256 timestamp,
            address reporter
        )
    {
        require(_entries[recordId].exists, "Audit record not found");
        AuditEntry memory entry = _entries[recordId];
        return (entry.dataHash, entry.entryType, entry.timestamp, entry.reporter);
    }
}
