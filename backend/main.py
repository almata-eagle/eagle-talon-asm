"""
Eagle Talon — API
=================
Run locally for the wifi demo:

    pip install -r requirements.txt
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload

Then open frontend/index.html (it talks to http://localhost:8000 by default —
change API_BASE at the top of the <script> if you deploy the backend elsewhere).
"""
import json
import random
import sqlite3
import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from scanner import scan_domain, tier_for_score

app = FastAPI(title="Eagle Talon ASM API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # demo only — lock this down before anything resembling prod
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Persistence: every real scan is written here, not just held in memory.
# SQLite is intentional for this stage — zero extra infra, a single file you
# can back up/inspect directly, good enough until this needs multi-writer
# concurrency (at which point: Postgres/RDS, see the AWS deploy notes).
# ---------------------------------------------------------------------------
DB_PATH = Path(__file__).parent / "eagle_talon.db"


def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            domain TEXT PRIMARY KEY,
            data TEXT NOT NULL,
            scanned_at TEXT NOT NULL
        )
    """)
    return conn


def _save_scan(result: dict):
    conn = _db()
    conn.execute(
        "INSERT OR REPLACE INTO scans (domain, data, scanned_at) VALUES (?, ?, ?)",
        (result["domain"], json.dumps(result), result["scanned_at"]),
    )
    conn.commit()
    conn.close()


def _all_saved_scans() -> list[dict]:
    conn = _db()
    rows = conn.execute("SELECT data FROM scans ORDER BY scanned_at DESC").fetchall()
    conn.close()
    return [json.loads(r[0]) for r in rows]


class ScanRequest(BaseModel):
    domain: str
    watchlist: Optional[str] = "Live Scans"


@app.get("/api/debug/cve-lookup")
def debug_cve_lookup(tech: str, version: str):
    """Isolated test of the CVE lookup, bypassing the full scan pipeline.
    e.g. /api/debug/cve-lookup?tech=Apache&version=2.4.49"""
    import techstack
    return techstack.debug_lookup(tech, version)


@app.get("/api/health")
def health():
    return {"status": "ok", "time": datetime.datetime.utcnow().isoformat()}


@app.post("/api/scan")
def scan(req: ScanRequest):
    """Synchronous scan of a single real domain — passive OSINT only.
    Typically completes in 3-10s depending on the target's DNS/TLS latency."""
    if not req.domain or "." not in req.domain:
        raise HTTPException(400, "Provide a valid domain, e.g. example.com")
    try:
        result = scan_domain(req.domain)
        result["watchlist"] = req.watchlist
        _SCANS[result["domain"]] = result
        _save_scan(result)
        return result
    except Exception as e:
        raise HTTPException(500, f"Scan failed: {e}")


@app.get("/api/scan/{domain}")
def get_scan(domain: str):
    if domain not in _SCANS:
        raise HTTPException(404, "No cached scan for that domain yet — POST /api/scan first.")
    return _SCANS[domain]


@app.get("/api/scans")
def list_scans():
    """Every real scan ever run against this backend, in the same shape the
    UI's portfolio views expect — this is the actual, non-mock data."""
    saved = _all_saved_scans()
    out = []
    for i, s in enumerate(saved):
        raw = s.get("raw", {})
        out.append({
            "id": f"real-{i}",
            "domain": s["domain"],
            "sector": "Live Scans",
            "watchlist": s.get("watchlist", "Live Scans"),
            "overall_score": s["overall_score"],
            "tier": s["tier"],
            "categories": s["categories"],
            "subdomain_count": raw.get("subdomains", {}).get("count", 0),
            "trend": 0,
            "last_scanned": s["scanned_at"],
            "country": "—",
            "ti_flagged": raw.get("threat_intel", {}).get("malicious_host_reports", 0) > 0,
            "findings_flat": [f for c in s["categories"] for f in c.get("findings", [])],
            "is_demo": False,
        })
    return {"count": len(out), "domains": out}


# ---------------------------------------------------------------------------
# Demo portfolio: seeded, deterministic mock data representing hundreds of
# already-scanned domains, so the UI's scale/navigation story can be demoed
# without needing to live-scan a thousand real domains in front of a client.
# Clearly flagged is_demo:true — /api/scans above is the real data.
# ---------------------------------------------------------------------------

SECTORS = ["Payments", "Logistics", "Cloud/SaaS Vendors", "Marketing & Ad Tech",
           "Manufacturing Suppliers", "Professional Services", "Marketplace Sellers",
           "Financial Institutions", "Healthcare Vendors", "Regional Resellers"]
WATCHLISTS = ["Tier-1 Suppliers", "Insured Portfolio — Q3", "Marketplace Onboarding",
              "Tier-2 Suppliers", "M&A Diligence"]
TLDS = [".com", ".io", ".co", ".net", ".biz", ".shop", ".ai"]
ADJ = ["nova", "summit", "cobalt", "harbor", "vantage", "orbit", "grid", "atlas",
       "forge", "pioneer", "meridian", "lumen", "anchor", "keystone", "beacon",
       "crestline", "ironbridge", "solace", "granite", "wavefront"]
NOUN = ["logistics", "systems", "trade", "works", "labs", "partners", "supply",
        "commerce", "freight", "capital", "materials", "dynamics", "exchange",
        "solutions", "group", "network"]


@app.get("/api/portfolio")
def portfolio(seed: int = 42, count: int = 480):
    rng = random.Random(seed)
    domains = []
    used = set()
    for i in range(count):
        while True:
            name = f"{rng.choice(ADJ)}{rng.choice(NOUN)}{rng.choice(TLDS)}"
            if name not in used:
                used.add(name)
                break
        sector = rng.choice(SECTORS)
        watchlist = rng.choice(WATCHLISTS)

        # Skew distribution so most are fine and a realistic minority are risky —
        # matches what an actual portfolio looks like.
        roll = rng.random()
        if roll < 0.55:
            score = rng.randint(78, 99)
        elif roll < 0.80:
            score = rng.randint(58, 82)
        elif roll < 0.94:
            score = rng.randint(32, 62)
        else:
            score = rng.randint(5, 38)

        cat_defs = [("Email Security", "email_security"), ("TLS / Certificates", "tls"),
                    ("Web Hardening", "web_hardening"), ("Exposure Surface", "exposure"),
                    ("Domain Reputation", "reputation"), ("Threat Intelligence", "threat_intel"),
                    ("Known Vulnerabilities", "cve_exposure")]
        ti_flagged = rng.random() < 0.06
        subdomain_count = rng.randint(1, 340)
        cats = []
        findings_flat = []
        for cn, code in cat_defs:
            jitter = rng.randint(-18, 18)
            base = score
            if code == "threat_intel" and ti_flagged:
                base = rng.randint(5, 35)
            cat_score = max(0, min(100, base + jitter))
            cats.append({"name": cn, "code": code, "score": cat_score})

            # Synthesize one representative finding per weak category so the
            # mock portfolio demonstrates remediation/PDF without a live scan.
            if code == "email_security" and cat_score < 80:
                if cat_score < 40:
                    findings_flat.append({"code": "no_spf", "en": "No SPF record — domain can be spoofed in the From/Return-Path.", "params": {}})
                elif cat_score < 60:
                    findings_flat.append({"code": "no_dmarc", "en": "No DMARC record — spoofed mail has no enforcement path.", "params": {}})
                else:
                    findings_flat.append({"code": "dmarc_none", "en": "DMARC policy is 'none' — monitoring only, not enforced.", "params": {}})
            elif code == "tls" and cat_score < 80:
                if cat_score < 40:
                    findings_flat.append({"code": "cert_expired", "en": "Certificate has already expired.", "params": {}})
                elif cat_score < 60:
                    findings_flat.append({"code": "self_signed", "en": "Certificate is self-signed or otherwise untrusted.", "params": {}})
                else:
                    days = rng.randint(3, 25)
                    findings_flat.append({"code": "cert_expiring", "en": f"Certificate expires in {days} days.", "params": {"days": days}})
            elif code == "web_hardening" and cat_score < 80:
                headers = rng.sample(["Strict-Transport-Security", "Content-Security-Policy",
                                       "X-Frame-Options", "X-Content-Type-Options"], k=rng.randint(1, 3))
                findings_flat.append({"code": "missing_headers",
                                       "en": f"Missing security headers: {', '.join(headers)}.", "params": {"headers": headers}})
            elif code == "exposure" and cat_score < 80:
                if subdomain_count > 200:
                    findings_flat.append({"code": "large_surface",
                                           "en": f"{subdomain_count} certificate-visible subdomains — large discoverable surface.",
                                           "params": {"count": subdomain_count}})
                else:
                    findings_flat.append({"code": "some_surface",
                                           "en": f"{subdomain_count} certificate-visible subdomains.", "params": {"count": subdomain_count}})
            elif code == "reputation" and cat_score < 80:
                if cat_score < 50:
                    age = rng.randint(5, 89)
                    findings_flat.append({"code": "very_new_domain",
                                           "en": f"Domain registered only {age} days ago — common fraud/phishing signal.", "params": {"age": age}})
                else:
                    age = rng.randint(90, 360)
                    findings_flat.append({"code": "new_domain", "en": f"Domain is under a year old ({age} days).", "params": {"age": age}})
            elif code == "threat_intel" and ti_flagged:
                n = rng.randint(1, 6)
                findings_flat.append({"code": "urlhaus_hit",
                                       "en": f"This host has {n} reported malware-hosting URL(s) on record (URLhaus).",
                                       "params": {"count": n}})
            elif code == "cve_exposure" and cat_score < 80:
                # Real, long-patched, well-documented CVEs used purely as illustrative
                # demo data — not fabricated CVE IDs.
                example = rng.choice([
                    ("Apache", "2.4.49", "CVE-2021-41773", "CRITICAL",
                     "Path traversal and remote code execution in Apache HTTP Server 2.4.49."),
                    ("WordPress", "5.8", "CVE-2022-21661", "HIGH",
                     "SQL injection via WP_Query in WordPress core before 5.8.3."),
                    ("jQuery", "1.12.4", "CVE-2020-11022", "MEDIUM",
                     "Cross-site scripting via jQuery.htmlPrefilter in versions before 3.5.0."),
                    ("OpenSSL", "1.0.1", "CVE-2014-0160", "HIGH",
                     "Heartbleed — out-of-bounds read exposing process memory in OpenSSL 1.0.1 through 1.0.1f."),
                ])
                tech, ver, cve_id, sev, summary = example
                findings_flat.append({"code": "cve_detected",
                                       "en": f"{tech} {ver}: {cve_id} ({sev}) — {summary}",
                                       "params": {"tech": tech, "version": ver, "cve_id": cve_id,
                                                  "severity": sev, "summary": summary}})

        trend = rng.choice([-1, -1, 0, 0, 0, 1, 1, 2])  # mostly stable
        last_scan_days_ago = rng.randint(0, 21)

        domains.append({
            "id": i,
            "domain": name,
            "sector": sector,
            "watchlist": watchlist,
            "overall_score": score,
            "tier": tier_for_score(score),
            "categories": cats,
            "subdomain_count": subdomain_count,
            "trend": trend,  # negative = worsening, positive = improving
            "last_scanned": (datetime.datetime.utcnow() -
                              datetime.timedelta(days=last_scan_days_ago)).isoformat(),
            "country": rng.choice(["US", "JP", "DE", "GB", "SG", "BR", "IN", "NL", "CA", "AU"]),
            "ti_flagged": ti_flagged,
            "findings_flat": findings_flat,
            "is_demo": True,
        })
    return {"count": len(domains), "domains": domains}


@app.get("/")
def root():
    return {"service": "Eagle Talon ASM API", "docs": "/docs"}
