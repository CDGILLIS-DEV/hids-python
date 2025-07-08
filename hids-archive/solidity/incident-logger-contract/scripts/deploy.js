const hre = require("hardhat");

async function main() {
    const IncidentLogger = await hre.ethers.getContractFactory("IncidentLogger");
    const contract = await IncidentLogger.deploy();

    await contract.deployed();

    console.log(`Contract deployed at address: ${contract.address}`);
}

main().catch((error) => {
    console.error("Deployment failed:", error);
    process.exitCode = 1;
});

