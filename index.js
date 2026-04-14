import "dotenv/config";
import express from "express";
import { createRelayerRouter } from "./relayer/router.js";
import { createAIRouter }      from "./ai/router.js";
import { createHSPRouter }     from "./hsp/router.js";

const app = express();

app.use((req, res, next) => {
  const origin = req.headers.origin || "";
  const allowed =
    origin === "https://aurionpay-hash.vercel.app" ||
    origin === "https://aurionpay.vercel.app"      ||
    origin.endsWith(".vercel.app")                 ||
    origin.startsWith("http://localhost");

  if (allowed || !origin) {
    res.setHeader("Access-Control-Allow-Origin",      origin || "*");
    res.setHeader("Access-Control-Allow-Methods",     "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers",     "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Max-Age",           "86400");
  }

  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }

  next();
});

app.use(express.json());
app.get("/health", (_, res) => res.json({
  status:  "ok",
  service: "AurionPay Backend",
  network: "HashKey Chain Testnet (Chain ID 133)",
}));

app.use("/relayer", createRelayerRouter());
app.use("/ai",      createAIRouter());
app.use("/hsp",     createHSPRouter());
app.use((req, res) => {
  res.status(404).json({ error: `Route not found: ${req.method} ${req.path}` });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));