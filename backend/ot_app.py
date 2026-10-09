"""Talon OT on its own: `uvicorn ot_app:app` serves only the OT API and its page.

For on-prem and DDIL sites (ADR 0007): no Talon DB, no SOC, no scanner, no
outbound calls. Data goes to OT_DATA_DIR (default ./data/ot). The page is
served from OT_STATIC_DIR (default ../frontend), so one folder can be copied
to a disconnected laptop and run with Python alone.
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, RedirectResponse

os.environ.setdefault("OT_DATA_DIR", str(Path(__file__).resolve().parent / "data" / "ot"))

import ot.api as ot_api  # noqa: E402  (after OT_DATA_DIR is settled)

STATIC = Path(os.environ.get("OT_STATIC_DIR", str(Path(__file__).resolve().parent.parent / "frontend")))
SECURITY_HEADERS = {"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
                    "X-Frame-Options": "DENY"}

app = FastAPI(title="Eagle Talon OT", version=ot_api.VERSION, docs_url=None, redoc_url=None, openapi_url=None)
ot_api.init()
app.include_router(ot_api.router)


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/ot.html")


@app.get("/ot.html", include_in_schema=False)
def page():
    return FileResponse(STATIC / "ot.html", headers=SECURITY_HEADERS)


@app.get("/{name}.png", include_in_schema=False)
def icon(name: str):
    if name not in ("logo-icon", "favicon-32", "favicon-64"):
        return RedirectResponse("/ot.html")
    return FileResponse(STATIC / f"{name}.png")
