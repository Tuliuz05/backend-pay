import express from "express";
import { groth16 } from "snarkjs";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { ethers } from "ethers";
import { detectAnomaly } from "../ai/ai-service.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const vKey = JSON.parse(
  fs.readFileSync(path.join(__dirname, "verification_key.json"), "utf8")
);

const HASHKEY_RPC = "https://testnet.hsk.xyz";
const CHAIN_ID = 133;

const PRIVACY_POOL_ADDRESS = process.env.PRIVACY_POOL_ADDRESS;
const PAYMENT_GATEWAY_ADDRESS = process.env.PAYMENT_GATEWAY_ADDRESS;
const USDT_ADDRESS = process.env.USDT_ADDRESS;

const PRIVACY_POOL_ABI = [
  "function withdrawAndPay(bytes32 nullifier, bytes32 invoiceId, uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[3] publicSignals) external",
];

function createRelayerRouter() {
  const router = express.Router();

  router.post("/relay-withdrawal", async (req, res) => {
    const {
      proof,
      publicSignals,
      nullifierHex,
      invoiceIdHex,
      amount,
      walletAddress,
    } = req.body;

    if (!nullifierHex || !invoiceIdHex || !proof || !publicSignals) {
      return res.status(400).json({ error: "Missing required fields." });
    }

    try {
      console.log(`Processing withdrawal  Invoice: ${invoiceIdHex}`);


      const normalizedProof = proof;
      const normalizedSignals = publicSignals;

      if (process.env.OPENAI_API_KEY) {
        const aiResult = await detectAnomaly({
          walletAddress: walletAddress || "unknown",
          amount: amount ? Number(BigInt(amount)) / 1_000_000 : 0,
          invoiceId: invoiceIdHex,
          nullifierAttempts: 0,
        });

        console.log(
          `AI Risk: ${aiResult.assessment.riskLevel} (${aiResult.assessment.riskScore})`
        );

        if (aiResult.assessment.recommendation === "BLOCK") {
          console.warn("BLOCKED by AI:", aiResult.assessment.reason);
          return res.status(403).json({
            error: "Transaction flagged by security system",
            reason: aiResult.assessment.reason,
            flags: aiResult.assessment.flags,
          });
        }
      }

      const isValid = await groth16.verify(vKey, normalizedSignals, normalizedProof);
      if (!isValid) {
        return res.status(400).json({ error: "Invalid ZK Proof" });
      }
      console.log("ZK proof verified");

      const provider = new ethers.JsonRpcProvider(HASHKEY_RPC, {
        chainId: CHAIN_ID,
        name: "hashkey-testnet",
      });

      const relayerWallet = new ethers.Wallet(
        process.env.RELAYER_PRIVATE_KEY,
        provider
      );

      console.log("Relayer address:", relayerWallet.address);

      const poolContract = new ethers.Contract(
        PRIVACY_POOL_ADDRESS,
        PRIVACY_POOL_ABI,
        relayerWallet
      );

      const nullifierBytes = ethers.zeroPadValue("0x" + nullifierHex, 32);
      const invoiceBytes = ethers.zeroPadValue("0x" + invoiceIdHex, 32);

      if (!normalizedProof.pi_a || normalizedProof.pi_a.length < 2) {
        return res.status(400).json({ error: "Invalid proof: pi_a must have at least 2 elements" });
      }
      if (!normalizedProof.pi_b || normalizedProof.pi_b.length < 2 || !Array.isArray(normalizedProof.pi_b[0]) || normalizedProof.pi_b[0].length < 2) {
        return res.status(400).json({ error: "Invalid proof: pi_b must be 2x2 or larger matrix" });
      }
      if (!normalizedProof.pi_c || normalizedProof.pi_c.length < 2) {
        return res.status(400).json({ error: "Invalid proof: pi_c must have at least 2 elements" });
      }
      if (!normalizedSignals || normalizedSignals.length < 3) {
        return res.status(400).json({ error: "Invalid publicSignals: must have at least 3 elements" });
      }

      const a = normalizedProof.pi_a.slice(0, 2).map((x) => BigInt(x));
      console.log("a array:", a);

      const b = [
        [BigInt(normalizedProof.pi_b[0][1]), BigInt(normalizedProof.pi_b[0][0])],
        [BigInt(normalizedProof.pi_b[1][1]), BigInt(normalizedProof.pi_b[1][0])],
      ];
      console.log("b array:", b);

      const c = normalizedProof.pi_c.slice(0, 2).map((x) => BigInt(x));
      console.log("c array:", c);

      const ps = normalizedSignals.slice(0, 3).map((x) => BigInt(x));
      console.log("publicSignals:", ps);

      console.log("Array lengths - a:", a.length, "b:", b.length, "b[0]:", b[0].length, "c:", c.length, "ps:", ps.length);
      console.log("Broadcasting to HashKey Chain testnet...");
      
      const tx = await poolContract.withdrawAndPay(
        nullifierBytes,
        invoiceBytes,
        a,
        b,
        c,
        ps,
        { gasLimit: 500000 }
      );

      console.log("Tx sent:", tx.hash);

      const receipt = await tx.wait(1);
      console.log("Confirmed in block:", receipt.blockNumber);

      res.json({ success: true, txid: tx.hash, block: receipt.blockNumber });
    } catch (error) {
      console.error("Relay error:", error);
      res.status(500).json({ error: "Relay failed", details: error.message });
    }
  });

  return router;
}

export { createRelayerRouter };