"""Talon OT local accounts: PBKDF2 passwords, bearer session tokens, three roles.

Local on purpose: an OT deployment must work on a disconnected site with no
identity provider. Tokens are random, stored only as SHA-256 hashes, and
expire after SESSION_HOURS.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import os
import re
import secrets
import time
from typing import Optional

from fastapi import Header, HTTPException

from . import db

PBKDF2_ITER = 240_000
SESSION_HOURS = 12
MIN_PASSWORD = 12
_USER_RE = re.compile(r"^[a-zA-Z0-9._@-]{3,40}$")
_attempts: dict[str, list[float]] = {}
MAX_ATTEMPTS = 8
ATTEMPT_WINDOW_S = 900


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ITER)
    return f"pbkdf2_sha256${PBKDF2_ITER}${salt.hex()}${dk.hex()}"


def check_password(pw: str, stored: str) -> bool:
    try:
        algo, it, salt, dk = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        test = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), int(it))
        return hmac.compare_digest(test.hex(), dk)
    except (ValueError, TypeError):
        return False


def validate_new(username: str, password: str, role: str) -> None:
    if not _USER_RE.match(username or ""):
        raise HTTPException(422, "username: 3-40 letters, digits, . _ @ -")
    if len(password or "") < MIN_PASSWORD:
        raise HTTPException(422, f"password must be at least {MIN_PASSWORD} characters")
    if role not in db.ROLES:
        raise HTTPException(422, "role must be admin, assessor or viewer")


def user_count() -> int:
    con = db.connect()
    try:
        return con.execute("SELECT count(*) FROM ot_users").fetchone()[0]
    finally:
        con.close()


def create_user(username: str, password: str, role: str, actor: Optional[str]) -> dict:
    validate_new(username, password, role)
    con = db.connect()
    try:
        if con.execute("SELECT 1 FROM ot_users WHERE username = ?", (username,)).fetchone():
            raise HTTPException(409, "that username exists")
        con.execute("INSERT INTO ot_users (username, pw_hash, role, created_at) VALUES (?,?,?,?)",
                    (username, hash_password(password), role, db.now_iso()))
        db.audit(con, actor or username, "user.create", "user", username, {"role": role})
        con.commit()
    finally:
        con.close()
    return {"username": username, "role": role}


def _throttled(username: str) -> bool:
    now = time.time()
    hits = [t for t in _attempts.get(username, []) if now - t < ATTEMPT_WINDOW_S]
    _attempts[username] = hits
    return len(hits) >= MAX_ATTEMPTS


def login(username: str, password: str) -> dict:
    if _throttled(username):
        raise HTTPException(429, "too many attempts; wait 15 minutes")
    con = db.connect()
    try:
        u = con.execute("SELECT * FROM ot_users WHERE username = ? AND disabled = 0", (username,)).fetchone()
        if not u or not check_password(password, u["pw_hash"]):
            _attempts.setdefault(username, []).append(time.time())
            db.audit(con, username, "login.failed", "user", username)
            con.commit()
            raise HTTPException(401, "wrong username or password")
        token = secrets.token_urlsafe(32)
        exp = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=SESSION_HOURS)
        con.execute("INSERT INTO ot_sessions (token_hash, username, created_at, expires_at) VALUES (?,?,?,?)",
                    (_th(token), username, db.now_iso(), exp.isoformat(timespec="seconds")))
        con.execute("DELETE FROM ot_sessions WHERE expires_at < ?", (db.now_iso(),))
        db.audit(con, username, "login", "user", username)
        con.commit()
        _attempts.pop(username, None)
        return {"token": token, "username": username, "role": u["role"], "expires_at": exp.isoformat(timespec="seconds")}
    finally:
        con.close()


def logout(token: str) -> None:
    con = db.connect()
    try:
        con.execute("DELETE FROM ot_sessions WHERE token_hash = ?", (_th(token),))
        con.commit()
    finally:
        con.close()


def _th(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _user_for(token: str) -> Optional[dict]:
    con = db.connect()
    try:
        r = con.execute(
            "SELECT u.username, u.role FROM ot_sessions s JOIN ot_users u ON u.username = s.username "
            "WHERE s.token_hash = ? AND s.expires_at > ? AND u.disabled = 0", (_th(token), db.now_iso())).fetchone()
    finally:
        con.close()
    return db.row(r)


def current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "login required")
    u = _user_for(authorization[7:].strip())
    if not u:
        raise HTTPException(401, "session expired; log in again")
    return u


def require(user: dict, *roles: str) -> None:
    if user["role"] not in roles:
        raise HTTPException(403, "your role can't do that")


def setup_code_ok(code: Optional[str]) -> bool:
    """Optional extra guard for first-run setup on shared networks (OT_SETUP_CODE)."""
    want = os.environ.get("OT_SETUP_CODE", "").strip()
    return not want or hmac.compare_digest(want, (code or "").strip())
