# Sentinel — paid token risk scan (x402 / Solana)

First live endpoint of the agent security network. A buyer pays **$0.25 USDC**
per scan over the x402 protocol; no account, no API key, no checkout page.

## What it does

`POST /scan {"mint": "<solana mint>"}` → JSON risk report:

- **Authorities** — mint/freeze authority status (Helius DAS)
- **Holder concentration** — top holder / top-10 share of supply
- **Market** — pairs, liquidity, 24h volume, pair age, 5m price action (DexScreener)
- **Jupiter Shield** — security warnings (public endpoint, no key)
- **Output** — 0–100 risk score, LOW/MEDIUM/HIGH/CRITICAL verdict, findings with evidence

Calibrated 2026-10-09: USDC → 0 LOW · PAWS → 10 LOW · ;) → 75 CRITICAL.
Reports are investigative signals, not financial advice (stated in every response).

## Run

```bash
cd ~/workspace/security-network/sentinel
node server.js        # :4021
```

Unpaid `POST /scan` returns HTTP 402 with payment requirements
(`exact` scheme, Solana mainnet, 250000 = $0.25 USDC → `BUYM6yoGSRjE4tQ1woGo4Vs7fVNYHgjMejuVb98TG9T7`).
PayAI settles; on success the scan runs and the report is returned.
A 5xx from the scan path cancels settlement — callers are never charged for our errors.

Facilitator: PayAI (`facilitator.payai.network`) — free 1,000 credits per
receiving wallet, no key needed at this volume (~$0.0015/settlement after).
Dexter was dropped: its `/verify` and `/supported` both 404 as of 2026-10-09.

Free routes: `GET /` (service info), `GET /health`, `GET /.well-known/x402`
(machine-readable advertisement for crawlers: x402scan, PayAI Bazaar, zauth).

## Going public

This VM has no inbound path of its own (egress proxy blocks tunnel control
planes — Cloudflare quick tunnels and localtunnel both fail here). Options:

1. **Cloudflare named tunnel** (recommended) — needs your Cloudflare account;
   `cloudflared tunnel --url http://localhost:4021` with a named tunnel gives a
   stable `https://` URL. No code changes.
2. **Deploy elsewhere** — the service is stateless: `server.js` + `scan.py` +
   `node_modules`. Railway/Fly/VPS all work; set `PORT` env.
3. **Direct IPv6** — the VM holds a public v6 address, but inbound could not be
   verified from here; do not rely on it without an external check.

## Live-payment test (remaining)

Everything except a real $0.25 payment is verified: 402 challenge shape,
bogus-payment rejection, scan accuracy. The final check needs 0.25 USDC paid
from any Solana wallet to the revenue address above — the scan should return
and the USDC should land in `BUYM6yoGSRjE4tQ1woGo4Vs7fVNYHgjMejuVb98TG9T7`.
Fund the revenue wallet first (it currently holds nothing), then test.

## Files

- `server.js` — Express + x402 payment middleware, facilitator picker, rate limit
- `scan.py` — risk engine (stdlib only; shells to `helius.py` for RPC)
- `manifest.json` — service advertisement for registries / CodeReef package
- `package.json`, `package-lock.json`

## Revenue wallet

`BUYM6yoGSRjE4tQ1woGo4Vs7fVNYHgjMejuVb98TG9T7`
Keypair: `~/.config/sentinel/revenue.json` (0600). Isolated from trading bankroll.
