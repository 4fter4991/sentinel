/**
 * Sentinel — paid token risk scan via x402 on Solana.
 *
 * POST /scan  {mint}  →  $0.25 USDC, settled to the revenue wallet.
 * Unpaid requests get HTTP 402 with payment requirements.
 *
 * Facilitator: Dexter (free) primary, PayAI free-tier fallback.
 * Picked at startup by probing /supported.
 */
const express = require("express");
const { execFile } = require("child_process");
const { paymentMiddleware } = require("x402-express");

const PORT = process.env.PORT || 4021;
const PAY_TO = "BUYM6yoGSRjE4tQ1woGo4Vs7fVNYHgjMejuVb98TG9T7"; // sentinel revenue wallet
const PRICE = "$0.25";

const FACILITATORS = [
  // PayAI verified working (2026-10-09): /supported 200, free 1,000 credits/wallet, no key needed.
  { name: "payai", url: "https://facilitator.payai.network" },
  // Dexter dropped: /verify and /supported both 404 as of 2026-10-09 — recheck before use.
];

async function pickFacilitator() {
  for (const f of FACILITATORS) {
    try {
      const ctl = new AbortController();
      const t = setTimeout(() => ctl.abort(), 8000);
      const r = await fetch(f.url + "/supported", { signal: ctl.signal });
      clearTimeout(t);
      if (r.ok) {
        console.log(`facilitator: ${f.name} (${f.url})`);
        return f;
      }
      console.log(`facilitator ${f.name}: /supported -> ${r.status}`);
    } catch (e) {
      console.log(`facilitator ${f.name}: unreachable (${e.message})`);
    }
  }
  console.log("facilitator: none reachable — using dexter URL anyway");
  return FACILITATORS[0];
}

// light per-IP rate limit (paid endpoint, but cheap insurance)
const hits = new Map();
function rateLimit(req, res, next) {
  const ip = req.ip || "?";
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter((t) => now - t < 60000);
  arr.push(now);
  hits.set(ip, arr);
  if (arr.length > 30) return res.status(429).json({ ok: false, error: "rate limited" });
  next();
}

function runScan(mint) {
  return new Promise((resolve, reject) => {
    execFile("python3", [__dirname + "/scan.py", mint], { timeout: 45000 },
      (err, stdout, stderr) => {
        if (err) return reject(new Error("scan failed: " + (stderr || err.message).slice(0, 200)));
        try {
          resolve(JSON.parse(stdout));
        } catch (e) {
          reject(new Error("scan returned invalid JSON"));
        }
      });
  });
}

async function main() {
  const fac = await pickFacilitator();
  const app = express();
  app.use(express.json({ limit: "8kb" }));
  app.set("trust proxy", true);

  // ---- public (free) ----
  app.get("/", (req, res) => res.json({
    service: "sentinel",
    description: "Token risk scan for Solana memecoins — investigative signals, not financial advice.",
    price: PRICE + " USDC per scan (x402, Solana)",
    payTo: PAY_TO,
    endpoints: {
      "POST /scan": "{mint} → risk report (paid)",
      "GET /.well-known/x402": "machine-readable service advertisement",
      "GET /health": "liveness",
    },
    operator: "4fter",
  }));

  app.get("/health", (req, res) => res.json({ ok: true, facilitator: fac.name }));

  app.get("/.well-known/x402", (req, res) => res.json({
    x402Version: 2,
    resources: [{
      url: "/scan",
      method: "POST",
      description: "Solana token risk scan: authorities, holder concentration, liquidity, age, Jupiter Shield warnings. Returns 0-100 risk score, verdict, and findings with evidence.",
      input: { mint: "solana token mint address (base58)" },
      accepts: [{ scheme: "exact", network: "solana", price: PRICE, asset: "USDC", payTo: PAY_TO }],
    }],
  }));

  // ---- paid ----
  app.use(paymentMiddleware(
    PAY_TO,
    {
      "/scan": {
        price: PRICE,
        network: "solana",
        config: { description: "Solana token risk scan — authorities, concentration, liquidity, Shield warnings" },
      },
    },
    { url: fac.url },
  ));

  app.post("/scan", rateLimit, async (req, res) => {
    const mint = (req.body && req.body.mint || "").trim();
    if (!mint) return res.status(400).json({ ok: false, error: "missing 'mint'" });
    try {
      const report = await runScan(mint);
      if (!report.ok) return res.status(422).json(report);
      console.log(`scan ${mint.slice(0, 8)}… → ${report.risk_score} ${report.verdict} (${report.scan_ms}ms)`);
      res.json(report);
    } catch (e) {
      console.error("scan error:", e.message);
      // 5xx cancels settlement on most facilitators — caller is not charged for our errors
      res.status(500).json({ ok: false, error: "scan failed, you were not charged" });
    }
  });

  app.listen(PORT, () => console.log(`sentinel listening on :${PORT}`));
}

main().catch((e) => { console.error("fatal:", e.message); process.exit(1); });
