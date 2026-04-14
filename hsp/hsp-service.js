import crypto from "crypto";
import axios  from "axios";

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
});

function canonicalJSON(obj) {
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) {
    return JSON.stringify(obj);
  }
  const sorted = Object.keys(obj).sort().reduce((acc, k) => {
    acc[k] = obj[k];
    return acc;
  }, {});
  return "{" + Object.entries(sorted)
    .map(([k, v]) => JSON.stringify(k) + ":" + canonicalJSON(v))
    .join(",") + "}";
}

function buildHmacHeaders(method, urlPath, query, bodyString) {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce     = crypto.randomBytes(16).toString("hex");

  const bodyHash = bodyString
    ? crypto.createHash("sha256").update(bodyString, "utf8").digest("hex")
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

  console.log("[HSP] SIGN STRING:\n", message);

  return {
    "X-App-Key": APP_KEY,
    "X-Signature": signature,
    "X-Timestamp": timestamp,
    "X-Nonce": nonce,
    "Content-Type": "application/json",
  };
}

function buildMerchantAuth(cartContents) {
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
    jti: `JWT-${now}`,
    cart_hash: cartHash,
  };

  // ⚠️ simplified JWT (works for QA if accepted)
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const body   = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig    = crypto.createHmac("sha256", APP_SECRET).update(`${header}.${body}`).digest("base64url");

  return `${header}.${body}.${sig}`;
}

export async function createHSPOrder({
  orderId,
  paymentRequestId,
  amount,
  currency,
  payToAddress,
  redirectUrl,
  invoiceNote
}) {
  const token = TOKENS[currency.toUpperCase()];
  if (!token) throw new Error("Unsupported currency");

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
          amount: { currency: "USD", value: amountStr }
        }],
        total: {
          label: "Total",
          amount: { currency: "USD", value: amountStr }
        },
      },
    },
    cart_expiry: new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(),
    merchant_name: MERCHANT_NAME,
  };

  const bodyObj = {
    cart_mandate: {
      contents: cartContents,
      merchant_authorization: buildMerchantAuth(cartContents),
    },
    redirect_url: redirectUrl || "",
  };

  // 🔥 IMPORTANT: SAME STRING used for hash + request
  const bodyString = canonicalJSON(bodyObj);

  const headers = buildHmacHeaders(
    "POST",
    "/api/v1/merchant/orders",
    "",
    bodyString
  );

  try {
    const res = await httpClient.post(
      "/api/v1/merchant/orders",
      JSON.parse(bodyString),
      { headers }
    );

    return res.data.data;
  } catch (err) {
    console.error("[HSP ERROR]", err.response?.data || err.message);
    throw err;
  }
}

export async function queryHSPPayment(cartMandateId) {
  const query = `cart_mandate_id=${cartMandateId}`;

  const headers = buildHmacHeaders(
    "GET",
    "/api/v1/merchant/payments",
    query,
    ""
  );

  try {
    const res = await httpClient.get(
      `/api/v1/merchant/payments?${query}`,
      { headers }
    );

    return res.data.data;
  } catch (err) {
    console.error("[HSP QUERY ERROR]", err.response?.data || err.message);
    throw err;
  }
}