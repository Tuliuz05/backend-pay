import express from "express";
import { createHSPOrder, queryHSPPayment } from "./hsp-service.js";
import https from "https";

export function createHSPRouter() {
  const router = express.Router();

  router.post("/create-order", async (req, res) => {
    const { orderId, paymentRequestId, amount, currency, payToAddress, redirectUrl, invoiceNote } = req.body;

    if (!orderId || !amount || !currency || !payToAddress) {
      return res.status(400).json({ error: "Missing required fields: orderId, amount, currency, payToAddress" });
    }

    try {
      const order = await createHSPOrder({
        orderId,
        paymentRequestId: paymentRequestId || orderId,
        amount,
        currency,
        payToAddress,
        redirectUrl,
        invoiceNote,
      });
      res.json({ success: true, paymentUrl: order.payment_url, paymentRequestId: order.payment_request_id });
    } catch (err) {
      console.error("HSP create order error:", err.message);
      res.status(500).json({ error: err.message });
    }
  });

  router.get("/payment-status", async (req, res) => {
    const { orderId } = req.query;
    if (!orderId) return res.status(400).json({ error: "orderId required" });
    try {
      const status = await queryHSPPayment(orderId);
      res.json({ success: true, status });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  return router;
}