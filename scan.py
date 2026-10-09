#!/usr/bin/env python3
"""Sentinel token risk scan — $0.25 x402 endpoint backend.

Usage: scan.py <mint>
Prints a JSON risk report to stdout. Exit 0 on success, 2 on bad input,
1 on upstream failure.

Signals (all read-only):
  - Helius DAS getAsset: mint/freeze authorities, supply, metadata
  - Helius getTokenLargestAccounts: holder concentration
  - DexScreener: pairs, liquidity, volume, pair age, price action
  - Jupiter Shield (public, no key): security warnings
"""
import json
import subprocess
import sys
import time
import urllib.request

HELIUS = ["python3", "/home/hatch/workspace/skills/helius/bin/helius.py"]
DEX = "https://api.dexscreener.com/latest/dex/tokens/"
SHIELD = "https://api.jup.ag/ultra/v1/shield?mints="
TIMEOUT = 20
# When set (deployments), use plain JSON-RPC instead of the vault-backed helius CLI.
RPC_URL = __import__("os").environ.get("SOLANA_RPC_URL", "")
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"


def rpc_call(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                       "params": params}).encode()
    req = urllib.request.Request(RPC_URL, data=body,
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "sentinel-scan/1.0"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        out = json.loads(r.read().decode())
    if out.get("error"):
        raise RuntimeError(f"rpc {method}: {out['error']}")
    return out["result"]


def parse_mint(data_b64):
    """Parse SPL Token Mint layout (82 bytes) -> authorities, supply, decimals."""
    import base64, struct
    raw = base64.b64decode(data_b64)
    if len(raw) < 82:
        raise ValueError("not a mint account")
    mint_opt = struct.unpack_from("<I", raw, 0)[0]
    supply = struct.unpack_from("<Q", raw, 36)[0]
    decimals = raw[44]
    freeze_opt = struct.unpack_from("<I", raw, 46)[0]
    # bytes -> base58 (leading zero bytes become '1')
    def b2b58(raw):
        a = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        n = int.from_bytes(raw, "big")
        s = ""
        while n:
            n, r = divmod(n, 58)
            s = a[r] + s
        pad = 0
        for b in raw:
            if b == 0:
                pad += 1
            else:
                break
        return "1" * pad + (s or "")
    return {"mint_authority": b2b58(raw[4:36]) if mint_opt else None,
            "freeze_authority": b2b58(raw[50:82]) if freeze_opt else None,
            "supply_raw": supply, "decimals": decimals}


def onchain_mint_info(mint):
    """Authorities/supply/decimals via helius CLI (local) or direct RPC (deploy)."""
    if RPC_URL:
        acct = rpc_call("getAccountInfo", [mint, {"encoding": "base64"}])
        val = (acct or {}).get("value") or {}
        info = parse_mint(val["data"][0])
        supply = info["supply_raw"] / (10 ** info["decimals"])
        return {"mint_authority": info["mint_authority"],
                "freeze_authority": info["freeze_authority"],
                "supply": supply, "decimals": info["decimals"]}
    # local dev path: vault-backed helius CLI (DAS getAsset)
    asset = helius_rpc("getAsset", [mint])
    ti = asset.get("token_info") or {}
    supply_raw, decimals = ti.get("supply") or 0, ti.get("decimals") or 0
    try:
        supply = int(supply_raw) / (10 ** int(decimals)) if decimals else int(supply_raw)
    except Exception:
        supply = 0
    return {"mint_authority": ti.get("mint_authority"),
            "freeze_authority": ti.get("freeze_authority"),
            "supply": supply, "decimals": decimals}


def largest_accounts(mint):
    if RPC_URL:
        return (rpc_call("getTokenLargestAccounts", [mint]) or {}).get("value") or []
    return (helius_rpc("getTokenLargestAccounts", [mint]) or {}).get("value") or []

# Tokens whose centralized issuance is the disclosed, audited model —
# authority flags are reported as info, not risk.
KNOWN_ISSUERS = {
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": "Circle (USDC)",
    "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNY": "Tether (USDT)",
    "So11111111111111111111111111111111111111112": "Wrapped SOL",
}
AUTH_WARNING_TYPES = {"HAS_MINT_AUTHORITY", "HAS_FREEZE_AUTHORITY",
                      "MINT_AUTHORITY_ENABLED", "FREEZE_AUTHORITY_ENABLED"}


def helius_rpc(method, params):
    p = subprocess.run(
        HELIUS + ["rpc", method, json.dumps(params)],
        capture_output=True, text=True, timeout=TIMEOUT)
    out = json.loads(p.stdout or "{}")
    if not out.get("ok"):
        raise RuntimeError(f"helius {method}: {out.get('error')}")
    return out["result"]


def http_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "sentinel-scan/1.0"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode())


def valid_mint(mint):
    try:
        raw = __import__("base64").b58decode(mint) if False else None
    except Exception:
        pass
    # base58 check without deps
    alphabet = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
    if not mint or any(c not in alphabet for c in mint):
        return False
    # decode length check
    n = 0
    for c in mint:
        n = n * 58 + "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".index(c)
    size = (n.bit_length() + 7) // 8
    return 30 <= size <= 32 and len(mint) >= 32


def scan(mint):
    t0 = time.time()
    findings = []
    score = 0

    def add(pts, severity, code, message, evidence=None):
        nonlocal score
        score += pts
        f = {"severity": severity, "code": code, "message": message, "points": pts}
        if evidence is not None:
            f["evidence"] = evidence
        findings.append(f)

    # --- on-chain identity ---
    try:
        mi = onchain_mint_info(mint)
    except Exception as e:
        return {"ok": False, "error": f"asset lookup failed: {e}"}
    symbol, name = "UNKNOWN", "UNKNOWN"  # refined from DexScreener below
    mint_auth = mi["mint_authority"]
    freeze_auth = mi["freeze_authority"]
    supply = mi["supply"]
    decimals = mi["decimals"]

    issuer = KNOWN_ISSUERS.get(mint)

    if mint_auth:
        if issuer:
            findings.append({"severity": "info", "code": "ISSUER_MINT_AUTHORITY",
                             "message": f"Mint authority held by disclosed issuer {issuer}.",
                             "points": 0})
        else:
            add(35, "high", "MINT_AUTHORITY_LIVE",
                "Mint authority is still enabled — new tokens can be created at will.",
                {"mint_authority": mint_auth})
    else:
        findings.append({"severity": "info", "code": "MINT_AUTHORITY_RENOUNCED",
                         "message": "Mint authority disabled.", "points": 0})
    if freeze_auth:
        if issuer:
            findings.append({"severity": "info", "code": "ISSUER_FREEZE_AUTHORITY",
                             "message": f"Freeze authority held by disclosed issuer {issuer}.",
                             "points": 0})
        else:
            add(20, "medium", "FREEZE_AUTHORITY_LIVE",
                "Freeze authority is enabled — token accounts can be frozen.",
                {"freeze_authority": freeze_auth})

    # --- holder concentration ---
    try:
        largest = largest_accounts(mint)
        if supply and largest:
            amts = []
            for h in largest:
                try:
                    amts.append(float(h.get("uiAmountString") or 0))
                except Exception:
                    pass
            if amts:
                top1 = amts[0] / supply * 100
                top10 = sum(amts[:10]) / supply * 100
                if top1 > 80:
                    add(30, "critical", "SINGLE_HOLDER_DOMINANCE",
                        f"Top holder controls {top1:.1f}% of supply — effective central control.",
                        {"top_holder_pct": round(top1, 2)})
                elif top1 > 50:
                    add(25, "high", "SINGLE_HOLDER_DOMINANCE",
                        f"Top holder controls {top1:.1f}% of supply.",
                        {"top_holder_pct": round(top1, 2)})
                if top10 > 90:
                    add(15, "high", "HOLDER_CONCENTRATION",
                        f"Top 10 holders control {top10:.1f}% of supply.",
                        {"top10_pct": round(top10, 2)})
                elif top10 > 70:
                    add(8, "medium", "HOLDER_CONCENTRATION",
                        f"Top 10 holders control {top10:.1f}% of supply.",
                        {"top10_pct": round(top10, 2)})
    except Exception as e:
        findings.append({"severity": "info", "code": "HOLDERS_UNAVAILABLE",
                         "message": f"Holder data unavailable: {e}", "points": 0})

    # --- market data ---
    liq_usd, vol24, age_h, chg5m = 0, 0, None, None
    npairs = 0
    try:
        dex = http_json(DEX + mint)
        pairs = dex.get("pairs") or []
        npairs = len(pairs)
        if pairs:
            # prefer the highest-liquidity pair whose base token is our mint
            ours = [p for p in pairs
                    if (p.get("baseToken") or {}).get("address") == mint]
            pool = ours or pairs
            pool.sort(key=lambda p: (p.get("liquidity") or {}).get("usd") or 0,
                      reverse=True)
            p = pool[0]
            bt = p.get("baseToken") or {}
            symbol = bt.get("symbol") or symbol
            name = bt.get("name") or name
            liq_usd = (p.get("liquidity") or {}).get("usd") or 0
            vol24 = (p.get("volume") or {}).get("h24") or 0
            created = p.get("pairCreatedAt")
            if created:
                age_h = (time.time() * 1000 - created) / 3600000
            chg5m = (p.get("priceChange") or {}).get("m5")
    except Exception as e:
        findings.append({"severity": "info", "code": "MARKET_DATA_UNAVAILABLE",
                         "message": f"DexScreener unavailable: {e}", "points": 0})

    if npairs == 0:
        add(30, "critical", "NO_LIQUIDITY",
            "No trading pairs found — token may be untradeable or not yet live.")
    elif liq_usd == 0:
        add(30, "critical", "NO_EFFECTIVE_LIQUIDITY",
            "Pairs exist but report zero liquidity — effectively untradeable.",
            {"pairs": npairs})
    else:
        if liq_usd < 5000:
            add(20, "high", "LOW_LIQUIDITY",
                f"Liquidity only ${liq_usd:,.0f} — extreme slippage and rug risk.",
                {"liquidity_usd": liq_usd})
        elif liq_usd < 25000:
            add(10, "medium", "THIN_LIQUIDITY",
                f"Liquidity ${liq_usd:,.0f} is thin for the volume traded.",
                {"liquidity_usd": liq_usd})
        if age_h is not None and age_h < 6:
            add(10, "medium", "VERY_NEW_PAIR",
                f"Primary pair is only {age_h:.1f}h old.",
                {"pair_age_hours": round(age_h, 1)})
        elif age_h is not None and age_h < 24:
            add(5, "low", "NEW_PAIR",
                f"Primary pair is {age_h:.1f}h old.",
                {"pair_age_hours": round(age_h, 1)})
        if isinstance(chg5m, (int, float)) and chg5m < -50:
            add(10, "medium", "SHARP_DUMP",
                f"Price down {chg5m:.0f}% in the last 5 minutes.",
                {"chg_5m_pct": chg5m})

    # --- jupiter shield ---
    try:
        sh = http_json(SHIELD + mint).get("warnings", {}).get(mint) or []
        for w in sh:
            sev = (w.get("severity") or "info").lower()
            wtype = w.get("type") or ""
            if issuer and wtype in AUTH_WARNING_TYPES:
                findings.append({"severity": "info",
                                 "code": f"SHIELD_{wtype}",
                                 "message": f"{w.get('message', '')} (disclosed issuer: {issuer})",
                                 "points": 0})
            elif sev == "warning":
                add(10, "medium", f"SHIELD_{wtype}", w.get("message", ""),
                    {"shield_type": wtype})
            else:
                findings.append({"severity": "info",
                                 "code": f"SHIELD_{w.get('type')}",
                                 "message": w.get("message", ""), "points": 0})
    except Exception as e:
        findings.append({"severity": "info", "code": "SHIELD_UNAVAILABLE",
                         "message": f"Jupiter Shield unavailable: {e}", "points": 0})

    score = min(score, 100)
    verdict = ("CRITICAL" if score >= 75 else "HIGH" if score >= 50
               else "MEDIUM" if score >= 25 else "LOW")
    return {
        "ok": True,
        "mint": mint,
        "token": {"name": name, "symbol": symbol,
                  "supply": supply, "decimals": decimals},
        "authorities": {"mint_authority": mint_auth,
                        "freeze_authority": freeze_auth},
        "market": {"pairs": npairs, "liquidity_usd": liq_usd,
                   "volume_24h_usd": vol24, "pair_age_hours": age_h},
        "risk_score": score,
        "verdict": verdict,
        "findings": sorted(findings,
                           key=lambda f: {"critical": 0, "high": 1, "medium": 2,
                                          "low": 3, "info": 4}[f["severity"]]),
        "scan_ms": int((time.time() - t0) * 1000),
        "disclaimer": ("Investigative risk signals, not a verdict. "
                       "Verify independently before trading."),
    }


def main():
    if len(sys.argv) != 2 or not valid_mint(sys.argv[1]):
        print(json.dumps({"ok": False,
                          "error": "usage: scan.py <solana-mint-address>"}))
        sys.exit(2)
    try:
        print(json.dumps(scan(sys.argv[1])))
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)[:300]}))
        sys.exit(1)


if __name__ == "__main__":
    main()
