import crypto from "crypto";
import axios from "axios";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const HSP_BASE_URL  = process.env.HSP_BASE_URL || "https://merchant-qa.hashkeymerchant.com";
const APP_KEY       = process.env.HSP_APP_KEY;
const APP_SECRET    = process.env.HSP_APP_SECRET;
const MERCHANT_NAME = process.env.HSP_MERCHANT_NAME || "AurionPay";

export const TOKENS = {
  USDC: { address: "0x8FE3cB719Ee4410E236Cd6b72ab1fCDC06eF53c6", decimals: 6, network: "hashkey-testnet", chain_id: 133 },
  USDT: { address: "0x372325443233fEbaC1F6998aC750276468c83CC6", decimals: 6, network: "hashkey-testnet", chain_id: 133 },
};

// 🔐 Stable JSON (deterministic)
function canonicalJSON(obj) {
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) {
    return JSON.stringify(obj);
  }
  const sorted = Object.keys(obj).sort().reduce((acc, k) => {
    acc[k] = obj[k];
    return acc;
  }, {});
  return "{" + Object.entries(sorted).map(([k, v]) =>
    JSON.stringify(k) + ":" + canonicalJSON(v)
  ).join(",") + "}";
}

// 🔐 HMAC (NOW USES RAW STRING)
function buildHmacHeaders(method, urlPath, query, bodyStr) {
  if (!APP_KEY || !APP_SECRET) {
    throw new Error("HSP_APP_KEY and HSP_APP_SECRET must be set");
  }

  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce     = crypto.randomBytes(16).toString("hex");

  const bodyHash = bodyStr
    ? crypto.createHash("sha256").update(bodyStr, "utf8").digest("hex")
    : "";

  const message = [
    method.toUpperCase(),
    urlPath,
    query || "",
    bodyHash,
    timestamp,
    nonce
  ].join("\n");

  const signature = crypto
    .createHmac("sha256", APP_SECRET)
    .update(message)
    .digest("hex");

  console.log("[HSP] Signing:", {
    method,
    urlPath,
    bodyHash: bodyHash.slice(0, 16) + "...",
    timestamp,
    nonce
  });

  return {
    "X-App-Key": APP_KEY,
    "X-Signature": signature,
    "X-Timestamp": timestamp,
    "X-Nonce": nonce,
    "Content-Type": "application/json",

    // Browser-like headers (for Cloudflare stability)
    "User-Agent": "Mozilla/5.0",
    "Accept": "application/json",
  };
}

// 🔐 Private key
function loadPrivateKeyPem() {
  if (process.env.MERCHANT_PRIVATE_KEY_PEM) {
    return process.env.MERCHANT_PRIVATE_KEY_PEM.replace(/\\n/g, "\n");
  }
  const pemPath = path.join(__dirname, "merchant_private_key.pem");
  return fs.readFileSync(pemPath, "utf8");
}

// 🔐 DER → JOSE
function derToJoseSignature(der) {
  let offset = 2;
  if (der[1] & 0x80) offset += (der[1] & 0x7f);
  offset++;
  const rLen = der[offset++];
  const r = der.slice(offset, offset + rLen); offset += rLen;
  offset++;
  const sLen = der[offset++];
  const s = der.slice(offset, offset + sLen);

  const pad = (buf) =>
    buf.length === 33 && buf[0] === 0 ? buf.slice(1)
    : buf.length < 32 ? Buffer.concat([Buffer.alloc(32 - buf.length), buf])
    : buf;

  return Buffer.concat([pad(r), pad(s)]);
}

// 🔐 JWT
function buildES256kJwt(payload, privateKeyPem) {
  const header  = Buffer.from(JSON.stringify({ alg: "ES256K", typ: "JWT" })).toString("base64url");
  const body    = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signing = `${header}.${body}`;

  const key  = crypto.createPrivateKey({ key: privateKeyPem, format: "pem" });
  const sign = crypto.createSign("SHA256");
  sign.update(signing);
  sign.end();

  return `${signing}.${derToJoseSignature(sign.sign(key)).toString("base64url")}`;
}

// 🔐 Merchant auth
function buildMerchantAuth(cartContents) {
  const privateKeyPem = loadPrivateKeyPem();

  const cartHash = crypto
    .createHash("sha256")
    .update(canonicalJSON(cartContents), "utf8")
    .digest("hex");

  const now = Math.floor(Date.now() / 1000);

  const payload = {
    iss: MERCHANT_NAME,
    sub: MERCHANT_NAME,
    aud: "HashkeyMerchant",
    iat: now,
    exp: now + 3600,
    jti: `JWT-${now}-${crypto.randomBytes(4).toString("hex")}`,
    cart_hash: cartHash,
  };

  return buildES256kJwt(payload, privateKeyPem);
}

// 🚀 CREATE ORDER (FIXED)
export async function createHSPOrder({
  orderId,
  paymentRequestId,
  amount,
  currency,
  payToAddress,
  merchantName,
  redirectUrl,
  invoiceNote,
}) {
  const token = TOKENS[currency.toUpperCase()];
  if (!token) throw new Error(`Unsupported currency`);

  const amountStr = (Number(amount) / Math.pow(10, token.decimals)).toFixed(2);

  const cartContents = {
    id: orderId,
    user_cart_confirmation_required: true,
    payment_request: {
      method_data: [{
        supported_methods: "https://www.x402.org/",
        data: {
          x402Version: 2,
          network: token.network,
          chain_id: token.chain_id,
          contract_address: token.address,
          pay_to: payToAddress,
          coin: currency.toUpperCase(),
        },
      }],
      details: {
        id: paymentRequestId,
        display_items: [{
          label: invoiceNote || "AurionPay Payment",
          amount: { currency: "USD", value: amountStr },
        }],
        total: {
          label: "Total",
          amount: { currency: "USD", value: amountStr },
        },
      },
    },
    cart_expiry: new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(),
    merchant_name: merchantName || MERCHANT_NAME,
  };

  const merchantAuth = buildMerchantAuth(cartContents);

  const body = {
    cart_mandate: {
      contents: cartContents,
      merchant_authorization: merchantAuth,
    },
    redirect_url: redirectUrl || "",
  };

  // 🔥 CRITICAL FIX
  const bodyStr = canonicalJSON(body);

  const urlPath = "/api/v1/merchant/orders";
  const headers = buildHmacHeaders("POST", urlPath, "", bodyStr);

  console.log("[HSP] POST", HSP_BASE_URL + urlPath);

  try {
    const response = await axios.post(
      `${HSP_BASE_URL}${urlPath}`,
      bodyStr, // ✅ send EXACT string
      {
        headers,
        transformRequest: [(data) => data], // ✅ prevent mutation
      }
    );

    if (response.data.code !== 0) {
      throw new Error(`HSP error ${response.data.code}: ${response.data.msg}`);
    }

    return response.data.data;

  } catch (err) {
    if (err.response) {
      console.error("[HSP] API error:", err.response.status, err.response.data);
      throw new Error(`HSP API ${err.response.status}: ${JSON.stringify(err.response.data)}`);
    }
    throw err;
  }
}