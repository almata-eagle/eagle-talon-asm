"""
Eagle SOC — country lookup for the traffic map (Phase 3).

The FortiGate already tags every session with a country name from its own
geo database (src_country / dst_country). This module turns those names into
an ISO code, Japanese name and a map point (the country's centroid). The
table is generated offline by tools/build-world-map.js and committed, so
nothing is downloaded at runtime. See ADR 0005.

Country names come from logs and are attacker-influenced only in the weak
sense that an attacker picks where they connect from; they're still treated
as data. Lookups are exact matches against a fixed table, so an unexpected
value can't do anything but miss.
"""
from __future__ import annotations

import json
import re
import unicodedata
from functools import lru_cache
from pathlib import Path
from typing import Optional

TABLE_FILE = Path(__file__).parent / "soc_geo_countries.json"

# Where "us" is on the map. The home lab sits in Tokyo.
HOME = {"label": "Home lab (Tokyo)", "label_ja": "ホームラボ（東京）", "lat": 35.68, "lon": 139.77}

# Values that aren't countries: private ranges, anonymizers, regions.
NOT_A_COUNTRY = {"reserved", "", "n/a", "unknown", "anonymous proxy", "satellite provider",
                 "europe", "asia/pacific region", "european union", "-"}

_PUNCT = re.compile(r"[^a-z0-9]+")


def _norm(name: str) -> str:
    s = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode("ascii").lower()
    s = _PUNCT.sub(" ", s).strip()
    if s.startswith("the "):
        s = s[4:]
    return s


@lru_cache(maxsize=1)
def _table() -> tuple[dict, dict]:
    try:
        countries = json.loads(TABLE_FILE.read_text(encoding="utf-8"))["countries"]
    except (OSError, ValueError, KeyError):
        return {}, {}
    index: dict[str, str] = {}
    for iso2, c in countries.items():
        for n in [c.get("en") or "", *c.get("aliases", [])]:
            if n:
                index.setdefault(_norm(n), iso2)
        index.setdefault(iso2.lower(), iso2)
    return countries, index


def lookup(name: Optional[str]) -> Optional[dict]:
    """Country name (any common spelling, or an ISO alpha-2 code) → place, or None."""
    if not name or not isinstance(name, str) or len(name) > 80:
        return None
    if name.strip().lower() in NOT_A_COUNTRY:
        return None
    countries, index = _table()
    iso2 = index.get(_norm(name))
    if not iso2:
        return None
    c = countries[iso2]
    return {"iso2": iso2, "name": c["en"], "name_ja": c.get("ja") or c["en"], "lat": c["lat"], "lon": c["lon"]}


def is_country(name: Optional[str]) -> bool:
    return bool(name) and name.strip().lower() not in NOT_A_COUNTRY
