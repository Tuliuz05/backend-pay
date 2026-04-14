import express from "express";
import {
  detectAnomaly,
  generateInvoiceFromText,
  explainTransaction,
} from "./ai-service.js";

function createAIRouter() {
  const router = express.Router();

  router.post("/check-anomaly", async (req, res) => {
    try {
      const result = await detectAnomaly(req.body);
      if (!result.ok) {
        return res.status(500).json({ error: "Anomaly detection failed" });
      }
      res.json(result.assessment);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post("/generate-invoice", async (req, res) => {
    const { description } = req.body;
    if (!description || description.trim().length === 0) {
      return res.status(400).json({ error: "Description is required" });
    }

    try {
      const result = await generateInvoiceFromText(description);
      if (!result.ok) {
        return res.status(422).json({ error: result.error });
      }
      res.json(result.invoice);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  router.post("/explain-tx", async (req, res) => {
    try {
      const result = await explainTransaction(req.body);
      if (!result.ok) {
        return res.status(500).json({ error: result.error });
      }
      res.json({ explanation: result.explanation });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  return router;
}

export { createAIRouter };