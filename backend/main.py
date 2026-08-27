"""
Eagle Talon — API
=================
Run locally for the wifi demo:

    pip install -r requirements.txt
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload

Then open frontend/index.html (it talks to http://localhost:8000 by default —
change API_BASE at the top of the <script> if you deploy the backend elsewhere).
"""
import csv
import io
import json
import os
import random
import re
import sqlite3
import threading
import uuid
import datetime
import concurrent.futures as cf
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File
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
#
# Multi-client model: clients are workspaces inside this one instance/DB —
# each client's scans are isolated by client_id, switchable in the UI
# without needing a separate deployment. For clients who need full physical
# isolation (compliance, dedicated infra) the alternative is a fully
# separate deployment of this same stack with its own .env — see README.
# ---------------------------------------------------------------------------
DB_PATH = Path(os.environ.get("EAGLE_TALON_DB_PATH", str(Path(__file__).parent / "eagle_talon.db")))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

DEFAULT_CLIENT_ID = "default"
DEFAULT_CLIENT_NAME = "Default Workspace"


def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS clients (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # Migrate from the old single-tenant schema (domain as sole primary key)
    # if this DB predates the multi-client model.
    cols = [r[1] for r in conn.execute("PRAGMA table_info(scans)").fetchall()]
    if cols and "client_id" not in cols:
        conn.execute("ALTER TABLE scans RENAME TO scans_legacy")
        conn.execute("""
            CREATE TABLE scans (
                client_id TEXT NOT NULL DEFAULT 'default',
                domain TEXT NOT NULL,
                data TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                PRIMARY KEY (client_id, domain)
            )
        """)
        conn.execute("""
            INSERT INTO scans (client_id, domain, data, scanned_at)
            SELECT 'default', domain, data, scanned_at FROM scans_legacy
        """)
        conn.execute("DROP TABLE scans_legacy")
    else:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                client_id TEXT NOT NULL DEFAULT 'default',
                domain TEXT NOT NULL,
                data TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                PRIMARY KEY (client_id, domain)
            )
        """)

    if not conn.execute("SELECT 1 FROM clients WHERE id=?", (DEFAULT_CLIENT_ID,)).fetchone():
        conn.execute("INSERT INTO clients (id, name, created_at) VALUES (?, ?, ?)",
                     (DEFAULT_CLIENT_ID, DEFAULT_CLIENT_NAME, datetime.datetime.utcnow().isoformat()))
    conn.commit()
    return conn


def _save_scan(result: dict, client_id: str = DEFAULT_CLIENT_ID):
    conn = _db()
    conn.execute(
        "INSERT OR REPLACE INTO scans (client_id, domain, data, scanned_at) VALUES (?, ?, ?, ?)",
        (client_id, result["domain"], json.dumps(result), result["scanned_at"]),
    )
    conn.commit()
    conn.close()


def _all_saved_scans(client_id: Optional[str] = None) -> list[dict]:
    conn = _db()
    if client_id:
        rows = conn.execute("SELECT data FROM scans WHERE client_id=? ORDER BY scanned_at DESC", (client_id,)).fetchall()
    else:
        rows = conn.execute("SELECT data FROM scans ORDER BY scanned_at DESC").fetchall()
    conn.close()
    return [json.loads(r[0]) for r in rows]


def _list_clients() -> list[dict]:
    conn = _db()
    rows = conn.execute("SELECT id, name, created_at FROM clients ORDER BY created_at ASC").fetchall()
    conn.close()
    return [{"id": r[0], "name": r[1], "created_at": r[2]} for r in rows]


def _create_client(name: str) -> dict:
    client_id = re.sub(r"[^a-z0-9-]", "-", name.strip().lower())[:40] or str(uuid.uuid4())[:8]
    conn = _db()
    # avoid id collisions if two clients would normalize to the same slug
    base_id, n = client_id, 1
    while conn.execute("SELECT 1 FROM clients WHERE id=?", (client_id,)).fetchone():
        n += 1
        client_id = f"{base_id}-{n}"
    created_at = datetime.datetime.utcnow().isoformat()
    conn.execute("INSERT INTO clients (id, name, created_at) VALUES (?, ?, ?)", (client_id, name.strip(), created_at))
    conn.commit()
    conn.close()
    return {"id": client_id, "name": name.strip(), "created_at": created_at}


class ScanRequest(BaseModel):
    domain: str
    watchlist: Optional[str] = "Live Scans"
    client_id: Optional[str] = DEFAULT_CLIENT_ID


@app.get("/api/debug/cve-lookup")
def debug_cve_lookup(tech: str, version: str):
    """Isolated test of the CVE lookup, bypassing the full scan pipeline.
    e.g. /api/debug/cve-lookup?tech=Apache&version=2.4.49"""
    import techstack
    return techstack.debug_lookup(tech, version)


@app.get("/api/health")
def health():
    return {"status": "ok", "time": datetime.datetime.utcnow().isoformat()}


@app.get("/api/clients")
def list_clients():
    """Client workspaces inside this single instance — switch between them
    in the UI without needing a separate deployment. For clients who need
    full physical isolation instead, deploy this same stack again with its
    own .env (separate DB path/port) — see README."""
    return {"clients": _list_clients()}


class ClientCreate(BaseModel):
    name: str


@app.post("/api/clients")
def create_client(req: ClientCreate):
    if not req.name or not req.name.strip():
        raise HTTPException(400, "Client name can't be empty.")
    return _create_client(req.name)


@app.post("/api/scan")
def scan(req: ScanRequest):
    """Synchronous scan of a single real domain — passive OSINT only.
    Typically completes in 3-10s depending on the target's DNS/TLS latency."""
    if not req.domain or "." not in req.domain:
        raise HTTPException(400, "Provide a valid domain, e.g. example.com")
    try:
        result = scan_domain(req.domain)
        result["watchlist"] = req.watchlist
        client_id = req.client_id or DEFAULT_CLIENT_ID
        _save_scan(result, client_id)
        return result
    except Exception as e:
        raise HTTPException(500, f"Scan failed: {e}")


@app.get("/api/scan/{domain}")
def get_scan(domain: str, client_id: str = DEFAULT_CLIENT_ID):
    """Most recent persisted scan for this domain, within a given client
    workspace. Not currently called by the frontend (which uses /api/scans
    for the full list) but kept as a direct lookup for scripting/debugging."""
    conn = _db()
    row = conn.execute("SELECT data FROM scans WHERE client_id=? AND domain=?", (client_id, domain)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "No cached scan for that domain/client yet — POST /api/scan first.")
    return json.loads(row[0])


@app.get("/api/scans")
def list_scans(client_id: Optional[str] = None):
    """Every real scan run against this backend for a given client workspace
    (or all of them, if client_id is omitted), in the shape the UI's
    portfolio views expect — this is the actual, non-mock data."""
    saved = _all_saved_scans(client_id)
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
# Bulk CSV upload: scans many domains at once. Runs as a background job
# rather than a single blocking request — 100 domains at ~3-10s each would
# blow past any sane HTTP timeout, and this also lets the UI show progress.
#
# Concurrency is deliberately modest (3 domains at a time): the individual
# checks inside scan_domain() already run in parallel per-domain, and several
# of the external services this hits (crt.sh, RDAP, URLhaus, NVD) are
# community-run and rate-limit-sensitive — scanning 100 domains "all at once"
# would just trade a slow job for a flaky one.
# ---------------------------------------------------------------------------
_BULK_JOBS: dict[str, dict] = {}
_BULK_LOCK = threading.Lock()
_BULK_CONCURRENCY = 3

DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$")


def _extract_domains_from_csv(raw_bytes: bytes) -> list[str]:
    text = raw_bytes.decode("utf-8-sig", errors="ignore")
    reader = csv.reader(io.StringIO(text))
    rows = [r for r in reader if r]
    if not rows:
        return []

    # Find whichever column looks like it holds domains, defaulting to column 0.
    header = [c.strip().lower() for c in rows[0]]
    col = 0
    if "domain" in header:
        col = header.index("domain")

    # Skip the header row only if it doesn't itself look like a domain
    # (covers CSVs with or without a header line).
    start = 1 if not DOMAIN_RE.match(rows[0][col].strip()) else 0

    domains, seen = [], set()
    for row in rows[start:]:
        if col >= len(row):
            continue
        candidate = row[col].strip().lower().replace("https://", "").replace("http://", "").rstrip("/")
        if candidate and DOMAIN_RE.match(candidate) and candidate not in seen:
            seen.add(candidate)
            domains.append(candidate)
    return domains


def _run_bulk_job(job_id: str, domains: list[str], watchlist: str, client_id: str):
    job = _BULK_JOBS[job_id]

    def scan_one(domain: str):
        try:
            result = scan_domain(domain)
            result["watchlist"] = watchlist
            _save_scan(result, client_id)
            with _BULK_LOCK:
                job["completed"] += 1
                job["results"].append({"domain": domain, "ok": True, "score": result["overall_score"]})
        except Exception as e:
            with _BULK_LOCK:
                job["completed"] += 1
                job["results"].append({"domain": domain, "ok": False, "error": str(e)})

    with cf.ThreadPoolExecutor(max_workers=_BULK_CONCURRENCY) as ex:
        list(ex.map(scan_one, domains))

    with _BULK_LOCK:
        job["status"] = "done"


@app.post("/api/scan/bulk")
async def scan_bulk(file: UploadFile = File(...), watchlist: str = "Bulk Upload", client_id: str = DEFAULT_CLIENT_ID):
    raw = await file.read()
    domains = _extract_domains_from_csv(raw)
    if not domains:
        raise HTTPException(400, "No valid domains found in that CSV — expected a 'domain' column or one domain per line.")
    if len(domains) > 500:
        raise HTTPException(400, f"{len(domains)} domains found — cap this run at 500 per upload and split the rest into another batch.")

    job_id = str(uuid.uuid4())
    _BULK_JOBS[job_id] = {"total": len(domains), "completed": 0, "results": [], "status": "running"}
    threading.Thread(target=_run_bulk_job, args=(job_id, domains, watchlist, client_id), daemon=True).start()
    return {"job_id": job_id, "total": len(domains)}


@app.get("/api/scan/bulk/{job_id}")
def get_bulk_job(job_id: str):
    job = _BULK_JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "No such bulk job — it may have completed and the server since restarted.")
    return job


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
