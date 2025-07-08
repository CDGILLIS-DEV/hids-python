// SPDX-License-Identifier: MIT 
pragma solidity ^0.8.20;

contract IncidentLogger {
    struct Incident {
        address reporter;
        string fileHash;
        string description;
        string ipAddress;
        uint8 threatLevel; // 0 = harmless, 1 = suspicious, 2 = malicious
        uint256 timestamp;
    }

    Incident[] public incidents; // Public Array of incidents 

    event IncidentLogged(
        address indexed reporter,
        string fileHash,
        string description,
        string ipAddress,
        uint8 threatLevel,
        uint256 timestamp
    );

    function logIncident(
        string memory fileHash,
        string memory description,
        string memory ipAddress, 
        uint8 threatLevel
    ) public {
        incidents.push(Incident(
            msg.sender,
            fileHash,
            description,
            ipAddress,
            threatLevel,
            block.timestamp
        ));

        emit IncidentLogged(
            msg.sender,
            fileHash, 
            description, 
            ipAddress, 
            threatLevel, 
            block.timestamp
        );
    }

    function getIncident(uint index) public view returns (Incident memory) {
        require(index < incidents.length, "Index out of range");
        return incidents[index];
    }

    function getTotalIncidents() public view returns (uint) {
        return incidents.length;
    }

}

