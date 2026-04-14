import OpenAI from "openai";

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

async function detectAnomaly(paymentData) {
  const {
    walletAddress,
    amount,
    invoiceId,
    recentTransactions = [],
    nullifierAttempts = 0,
    timeSinceLastTx = null,
  } = paymentData;

  const prompt = `You are a blockchain payment security analyst for AurionPay, a zero-knowledge private payment protocol on HashKey Chain.

Analyze this payment attempt and return a JSON risk assessment.

Payment Details:
- Wallet: ${walletAddress}
- Amount: ${amount} USDCx
- Invoice ID: ${invoiceId}
- Failed nullifier attempts in last hour: ${nullifierAttempts}
- Recent transactions (last 24h): ${JSON.stringify(recentTransactions)}
- Time since last transaction: ${timeSinceLastTx || "unknown"}

Rules that indicate HIGH RISK:
1. More than 3 failed nullifier attempts (double-spend probing)
2. Amount exactly matches a known attack pattern (1, 0.001, 999999)
3. More than 10 transactions in under 1 minute (bot behavior)
4. Wallet age under 5 minutes with large amount (> 1000 USDCx)
5. Identical invoice IDs attempted multiple times

Return ONLY valid JSON in this exact format:
{
  "riskScore": <number 0-100>,
  "riskLevel": "LOW" | "MEDIUM" | "HIGH",
  "flags": [<array of specific concerns as strings>],
  "recommendation": "ALLOW" | "REVIEW" | "BLOCK",
  "reason": "<one sentence explanation>"
}`;

  try {
    const response = await client.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: prompt }],
      max_tokens: 500,
    });

    const text = response.choices[0].message.content.trim();
    const clean = text.replace(/```json|```/g, "").trim();
    return { ok: true, assessment: JSON.parse(clean) };
  } catch (err) {
    console.error("Anomaly detection error:", err.message);
    return {
      ok: true,
      assessment: {
        riskScore: 0,
        riskLevel: "LOW",
        flags: [],
        recommendation: "ALLOW",
        reason: "AI service unavailable  defaulting to allow",
      },
    };
  }
}

async function generateInvoiceFromText(description) {
  const prompt = `You are an invoice generation assistant for AurionPay, a private payment protocol.

A merchant described their payment request in natural language. Extract the structured invoice parameters.

Merchant description: "${description}"

Rules:
- Amount must be in USDCx (stablecoin, 1 USDCx = 1 USD)
- If no currency mentioned, assume USD/USDCx
- If amount is ambiguous, set confidence to "low"
- invoiceNote should be a clean merchant-facing description

Return ONLY valid JSON in this exact format:
{
  "amount": <number in USDCx, e.g. 50.00>,
  "amountMicro": <amount * 1000000 as integer>,
  "invoiceNote": "<clean description of what is being paid for>",
  "confidence": "high" | "medium" | "low",
  "suggestions": [<array of any clarifying questions if confidence is low>]
}`;

  try {
    const response = await client.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: prompt }],
      max_tokens: 300,
    });

    const text = response.choices[0].message.content.trim();
    const clean = text.replace(/```json|```/g, "").trim();
    return { ok: true, invoice: JSON.parse(clean) };
  } catch (err) {
    console.error("Invoice assistant error:", err.message);
    return { ok: false, error: "Could not parse invoice description" };
  }
}

async function explainTransaction(txData) {
  const {
    commitment,
    nullifier,
    amount,
    timestamp,
    merchantAddress,
  } = txData;

  const prompt = `You are a privacy technology explainer for AurionPay users.

A zero-knowledge private payment just completed. Explain what happened in 2-3 simple sentences that a non-technical user can understand. Focus on what privacy guarantees were provided.

Transaction data:
- Commitment hash: ${commitment}
- Nullifier: ${nullifier}
- Amount: ${amount} USDCx
- Merchant received funds: yes
- Timestamp: ${timestamp}

Do NOT use technical jargon like "Groth16", "Poseidon", or "elliptic curve".
DO explain that the payer's identity was protected.
Keep it friendly and reassuring.
Return plain text only, no JSON.`;

  try {
    const response = await client.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: prompt }],
      max_tokens: 200,
    });

    return {
      ok: true,
      explanation: response.choices[0].message.content.trim(),
    };
  } catch (err) {
    return { ok: false, error: "Could not generate explanation" };
  }
}

export { detectAnomaly, generateInvoiceFromText, explainTransaction };