import crypto from "crypto";
import axios  from "axios";
import fs     from "fs";
import path   from "path";
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

const httpClient = axios.create({
  baseURL: HSP_BASE_URL,
  timeout: 15000,
  headers: {
    "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept":          "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection":      "keep-alive",
    "Origin":          "https://merchant-qa.hashkeymerchant.com",
    "Referer":         "https://merchant-qa.hashkeymerchant.com/",
    "Sec-Fetch-Site":  "same-origin",
    "Sec-Fetch-Mode":  "cors",
    "Sec-Fetch-Dest":  "empty",
  },
});

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

function buildHmacHeaders(method, urlPath, query, body) {
  if (!APP_KEY || !APP_SECRET) {
    throw new Error("HSP_APP_KEY and HSP_APP_SECRET must be set");
  }
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce     = crypto.randomBytes(16).toString("hex");
  const bodyHash  = body
    ? crypto.createHash("sha256").update(canonicalJSON(body), "utf8").digest("hex")
    : "";
  const message   = [method.toUpperCase(), urlPath, query || "", bodyHash, timestamp, nonce].join("\n");
  const signature = crypto.createHmac("sha256", APP_SECRET).update(message).digest("hex");

  console.log("[HSP] Signing:", { method, urlPath, bodyHash: bodyHash.slice(0, 16) + "..." });

  return {
    "X-App-Key":    APP_KEY,
    "X-Signature":  signature,
    "X-Timestamp":  timestamp,
    "X-Nonce":      nonce,
    "Content-Type": "application/json",
  };
}

function loadPrivateKeyPem() {
  if (process.env.MERCHANT_PRIVATE_KEY_PEM) {
    return process.env.MERCHANT_PRIVATE_KEY_PEM.replace(/\\n/g, "\n");
  }
  const pemPath = path.join(__dirname, "merchant_private_key.pem");
  if (!fs.existsSync(pemPath)) {
    throw new Error("merchant_private_key.pem not found. Set MERCHANT_PRIVATE_KEY_PEM env var.");
  }
  return fs.readFileSync(pemPath, "utf8");
}

function derToJoseSignature(der) {
  let offset = 2;
  if (der[1] & 0x80) offset += (der[1] & 0x7f);
  offset++;
  const rLen = der[offset++];
  const r    = der.slice(offset, offset + rLen); offset += rLen;
  offset++;
  const sLen = der[offset++];
  const s    = der.slice(offset, offset + sLen);
  const pad  = (buf) =>
    buf.length === 33 && buf[0] === 0 ? buf.slice(1)
    : buf.length < 32 ? Buffer.concat([Buffer.alloc(32 - buf.length), buf])
    : buf;
  return Buffer.concat([pad(r), pad(s)]);
}

function buildES256kJwt(payload, privateKeyPem) {
  const header  = Buffer.from(JSON.stringify({ alg: "ES256K", typ: "JWT" })).toString("base64url");
  const body    = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signing = `${header}.${body}`;
  const key     = crypto.createPrivateKey({ key: privateKeyPem, format: "pem" });
  const sign    = crypto.createSign("SHA256");
  sign.update(signing); sign.end();
  return `${signing}.${derToJoseSignature(sign.sign(key)).toString("base64url")}`;
}

function buildMerchantAuth(cartContents) {
  const privateKeyPem = loadPrivateKeyPem();
  const cartHash      = crypto.createHash("sha256").update(canonicalJSON(cartContents), "utf8").digest("hex");
  const now           = Math.floor(Date.now() / 1000);
  const payload       = {
    iss: MERCHANT_NAME, sub: MERCHANT_NAME, aud: "HashkeyMerchant",
    iat: now, exp: now + 3600,
    jti: `JWT-${now}-${crypto.randomBytes(4).toString("hex")}`,
    cart_hash: cartHash,
  };
  console.log("[HSP] JWT cart_hash:", cartHash.slice(0, 16) + "...");
  return buildES256kJwt(payload, privateKeyPem);
}

export async function createHSPOrder({
  orderId, paymentRequestId, amount, currency,
  payToAddress, merchantName, redirectUrl, invoiceNote,
}) {
  const token = TOKENS[currency.toUpperCase()];
  if (!token) throw new Error(`Unsupported currency: ${currency}. Use USDC or USDT.`);

  const amountStr = (Number(amount) / Math.pow(10, token.decimals)).toFixed(2);
  const label     = invoiceNote || "AurionPay Private Payment";

  const cartContents = {
    id: orderId,
    user_cart_confirmation_required: true,
    payment_request: {
      method_data: [{
        supported_methods: "https://www.x402.org/",
        data: {
          x402Version: 2, network: token.network, chain_id: token.chain_id,
          contract_address: token.address, pay_to: payToAddress,
          coin: currency.toUpperCase(),
        },
      }],
      details: {
        id: paymentRequestId,
        display_items: [{ label, amount: { currency: "USD", value: amountStr } }],
        total: { label: "Total", amount: { currency: "USD", value: amountStr } },
      },
    },
    cart_expiry:   new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(),
    merchant_name: merchantName || MERCHANT_NAME,
  };

  const merchantAuth = buildMerchantAuth(cartContents);
  const body         = {
    cart_mandate: { contents: cartContents, merchant_authorization: merchantAuth },
    redirect_url: redirectUrl || "",
  };

  const urlPath = "/api/v1/merchant/orders";
  const headers = buildHmacHeaders("POST", urlPath, "", body);

  console.log("[HSP] POST", HSP_BASE_URL + urlPath);

  try {
    const response = await httpClient.post(urlPath, body, { headers });
    if (response.data.code !== 0) {
      throw new Error(`HSP error ${response.data.code}: ${response.data.msg}`);
    }
    return response.data.data;
  } catch (err) {
    if (err.response) {
      const status = err.response.status;
      const body   = JSON.stringify(err.response.data);
      console.error(`[HSP] API error ${status}:`, body);
      if (typeof err.response.data === "string" && err.response.data.includes("Cloudflare")) {
        throw new Error("HSP API blocked by Cloudflare. Try again in a moment.");
      }
      throw new Error(`HSP API ${status}: ${body}`);
    }
    throw err;
  }
}

export async function queryHSPPayment(cartMandateId) {
  const urlPath = "/api/v1/merchant/payments";
  const query   = `cart_mandate_id=${cartMandateId}`;
  const headers = buildHmacHeaders("GET", urlPath, query, null);

  try {
    const response = await httpClient.get(`${urlPath}?${query}`, { headers });
    if (response.data.code !== 0) throw new Error(`HSP query error: ${response.data.msg}`);
    return response.data.data;
  } catch (err) {
    if (err.response) {
      console.error(`[HSP] Query error ${err.response.status}:`, JSON.stringify(err.response.data));
      throw new Error(`HSP API ${err.response.status}: ${JSON.stringify(err.response.data)}`);
    }
    throw err;
  }
}