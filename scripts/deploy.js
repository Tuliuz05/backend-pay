import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { network } from "hardhat";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const HASHKEY_TESTNET_USDC = "0x8FE3cB719Ee4410E236Cd6b72ab1fCDC06eF53c6";
const HASHKEY_TESTNET_USDT = "0x372325443233fEbaC1F6998aC750276468c83CC6";

async function main() {
  const { ethers } = await network.connect();
  const [deployer] = await ethers.getSigners();

  console.log("Deploying with account:", deployer.address);
  console.log(
    "Account balance:",
    ethers.formatEther(await ethers.provider.getBalance(deployer.address)),
    "HSK"
  );
  const net = await ethers.provider.getNetwork();
  console.log("Network:", net.name);
  console.log("Chain ID:", net.chainId);
  console.log("------------------------------------------------");
  console.log("\n[2/5] Deploying Groth16 Verifier...");
  const Verifier = await ethers.getContractFactory("Groth16Verifier");
  const verifier = await Verifier.deploy();
  await verifier.waitForDeployment();
  const verifierAddress = await verifier.getAddress();
  console.log("Groth16Verifier deployed at:", verifierAddress);
  console.log("\n[3/5] Deploying PrivacyPool...");
  const relayerAddress = process.env.RELAYER_ADDRESS || deployer.address;
  const usdcAddress = HASHKEY_TESTNET_USDC;
  const usdtAddress = HASHKEY_TESTNET_USDT;
  const PrivacyPool = await ethers.getContractFactory("PrivacyPool");
  const privacyPool = await PrivacyPool.deploy(
    ethers.ZeroAddress,
    verifierAddress,
    relayerAddress,
    usdcAddress,
    usdtAddress
  );
  await privacyPool.waitForDeployment();
  const privacyPoolAddress = await privacyPool.getAddress();
  console.log("PrivacyPool deployed at:", privacyPoolAddress);
  console.log("\n[4/5] Deploying PaymentGateway...");
  const PaymentGateway = await ethers.getContractFactory("PaymentGateway");
  const paymentGateway = await PaymentGateway.deploy(privacyPoolAddress);
  await paymentGateway.waitForDeployment();
  const paymentGatewayAddress = await paymentGateway.getAddress();
  console.log("PaymentGateway deployed at:", paymentGatewayAddress);
  console.log("\n[5/5] Linking PrivacyPool to PaymentGateway...");
  const setGatewayTx = await privacyPool.setPaymentGateway(paymentGatewayAddress);
  await setGatewayTx.wait();
  console.log("PaymentGateway linked to PrivacyPool");
  console.log("\n------------------------------------------------");
  console.log("DEPLOYMENT COMPLETE");
  console.log("------------------------------------------------");  
  console.log("Groth16Verifier:", verifierAddress);
  console.log("PrivacyPool    :", privacyPoolAddress);
  console.log("PaymentGateway :", paymentGatewayAddress);
  console.log("Relayer        :", relayerAddress);
  console.log("USDC (testnet) :", usdcAddress);
  console.log("USDT (testnet) :", usdtAddress);
  console.log("------------------------------------------------");

  const addresses = {
    network: "hashkey-testnet",
    chainId: 133,
    deployer: deployer.address,
    verifier: verifierAddress,
    privacyPool: privacyPoolAddress,
    paymentGateway: paymentGatewayAddress,
    relayer: relayerAddress,
    usdcTestnet: usdcAddress,
    usdtTestnet: usdtAddress,
    deployedAt: new Date().toISOString(),
  };
  const outPath = path.join(__dirname, "../deployed-addresses.json");
  fs.writeFileSync(outPath, JSON.stringify(addresses, null, 2));
  console.log("\nAddresses saved to deployed-addresses.json");
  console.log("\n--- Copy these to your backend .env ---");
  console.log(`PRIVACY_POOL_ADDRESS=${privacyPoolAddress}`);
  console.log(`PAYMENT_Gateway_ADDRESS=${paymentGatewayAddress}`);
  console.log(`USDT_ADDRESS=${usdtAddress}`);
  console.log(`USDC_ADDRESS=${usdcAddress}`);
  console.log("---------------------------------------");
  console.log("\n--- Copy these to your Dashboard.jsx ---");
  console.log(`export const PRIVACY_POOL_ADDRESS = "${privacyPoolAddress}";`);
  console.log(`export const PAYMENT_GW_ADDRESS   = "${paymentGatewayAddress}";`);
  console.log(`export const USDC_ADDRESS         = "${usdcAddress}";`);
  console.log(`export const USDT_ADDRESS    = "${usdtAddress}";`);
  console.log("---------------------------------------");
}

main().catch((err) => {
  console.error("Deployment failed:", err);
  process.exit(1);
});