"""Talon OT HTTP API, mounted at /api/ot. Every route needs a login except
status, first-run setup and login itself; every change is audited."""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from pathlib import Path
from typing import Optional
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Response, UploadFile
from pydantic import BaseModel

from . import auth, db, sheets

router = APIRouter(prefix="/api/ot", tags=["ot"])
VERSION = "ot-1"

MAX_EVIDENCE = 25 * 1024 * 1024
EVIDENCE_EXT = {"jpg", "jpeg", "png", "gif", "webp", "heic", "pdf", "txt", "log", "csv", "json", "xml", "cfg", "conf",
                "ini", "yaml", "yml", "xlsx", "docx", "pptx", "pcap", "pcapng", "zip", "7z"}
INLINE_IMAGES = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "gif": "image/gif", "webp": "image/webp"}
UPLOAD_TTL_S = 3600
_FNAME_RE = re.compile(r"[^A-Za-z0-9._ ()\-぀-ヿ一-鿿]")


def init() -> None:
    db.init_db()
    db.evidence_dir().mkdir(parents=True, exist_ok=True)
    (db.data_dir() / "tmp").mkdir(parents=True, exist_ok=True)


# ------------------------------------------------------------------ helpers

def _one(con, sql: str, args: tuple, what: str) -> dict:
    r = db.row(con.execute(sql, args).fetchone())
    if not r:
        raise HTTPException(404, f"{what} not found")
    return r


def _choice(v: Optional[str], allowed: tuple, field: str) -> Optional[str]:
    if v in (None, ""):
        return None
    if v not in allowed:
        raise HTTPException(422, f"{field} must be one of: {', '.join(allowed)}")
    return v


def _counts(con, system_ids: list[int]) -> dict[int, dict]:
    out = {sid: {k: 0 for k in db.STATUSES} for sid in system_ids}
    if not system_ids:
        return out
    q = ",".join("?" * len(system_ids))
    for r in con.execute(f"SELECT system_id, status, count(*) FROM ot_items WHERE system_id IN ({q}) GROUP BY 1, 2",
                         system_ids):
        out[r[0]][r[1] if r[1] in db.STATUSES else "not_assessed"] += r[2]
    return out


# ------------------------------------------------------------------ status, setup, login

class Cred(BaseModel):
    username: str
    password: str
    code: Optional[str] = None


@router.get("/status")
def ot_status():
    return {"version": VERSION, "users_exist": auth.user_count() > 0, "setup_code_required": not auth.setup_code_ok(None),
            "statuses": db.STATUSES, "categories": db.CCI_CATEGORIES, "system_types": db.SYSTEM_TYPES,
            "phases": db.PHASES, "impact": db.IMPACT, "levels": db.LEVELS, "severities": db.SEVERITIES,
            "fields": sheets.FIELDS, "roles": db.ROLES}


@router.post("/setup")
def ot_setup(req: Cred):
    if auth.user_count() > 0:
        raise HTTPException(409, "already set up; log in")
    if not auth.setup_code_ok(req.code):
        raise HTTPException(403, "setup code is wrong")
    auth.create_user(req.username, req.password, "admin", None)
    return auth.login(req.username, req.password)


@router.post("/login")
def ot_login(req: Cred):
    return auth.login(req.username, req.password)


@router.post("/logout")
def ot_logout(authorization: Optional[str] = Header(None)):
    if authorization and authorization.lower().startswith("bearer "):
        auth.logout(authorization[7:].strip())
    return {"ok": True}


@router.get("/me")
def ot_me(user: dict = Depends(auth.current_user)):
    return user


# ------------------------------------------------------------------ users (admin)

class NewUser(BaseModel):
    username: str
    password: str
    role: str = "assessor"


class UserPatch(BaseModel):
    role: Optional[str] = None
    disabled: Optional[bool] = None
    password: Optional[str] = None


@router.get("/users")
def ot_users(user: dict = Depends(auth.current_user)):
    auth.require(user, "admin")
    con = db.connect()
    try:
        return {"users": [db.row(r) for r in con.execute("SELECT username, role, created_at, disabled FROM ot_users ORDER BY username")]}
    finally:
        con.close()


@router.post("/users")
def ot_user_add(req: NewUser, user: dict = Depends(auth.current_user)):
    auth.require(user, "admin")
    return auth.create_user(req.username, req.password, req.role, user["username"])


@router.patch("/users/{username}")
def ot_user_patch(username: str, req: UserPatch, user: dict = Depends(auth.current_user)):
    auth.require(user, "admin")
    con = db.connect()
    try:
        _one(con, "SELECT * FROM ot_users WHERE username = ?", (username,), "user")
        if req.role is not None:
            _choice(req.role, db.ROLES, "role")
            if username == user["username"] and req.role != "admin":
                raise HTTPException(422, "you can't remove your own admin role")
            con.execute("UPDATE ot_users SET role = ? WHERE username = ?", (req.role, username))
        if req.disabled is not None:
            if username == user["username"] and req.disabled:
                raise HTTPException(422, "you can't disable yourself")
            con.execute("UPDATE ot_users SET disabled = ? WHERE username = ?", (1 if req.disabled else 0, username))
            if req.disabled:
                con.execute("DELETE FROM ot_sessions WHERE username = ?", (username,))
        if req.password is not None:
            if len(req.password) < auth.MIN_PASSWORD:
                raise HTTPException(422, f"password must be at least {auth.MIN_PASSWORD} characters")
            con.execute("UPDATE ot_users SET pw_hash = ? WHERE username = ?", (auth.hash_password(req.password), username))
            con.execute("DELETE FROM ot_sessions WHERE username = ?", (username,))
        db.audit(con, user["username"], "user.update", "user", username,
                 {"role": req.role, "disabled": req.disabled, "password_changed": req.password is not None})
        con.commit()
    finally:
        con.close()
    return {"ok": True}


# ------------------------------------------------------------------ engagements

class EngagementReq(BaseModel):
    name: Optional[str] = None
    client: Optional[str] = None
    site: Optional[str] = None
    contract_ref: Optional[str] = None
    marking: Optional[str] = None
    ai_allowed: Optional[bool] = None
    notes: Optional[str] = None


@router.get("/engagements")
def ot_engagements(user: dict = Depends(auth.current_user)):
    con = db.connect()
    try:
        es = [db.row(r) for r in con.execute("SELECT * FROM ot_engagements ORDER BY updated_at DESC")]
        for e in es:
            sids = [r[0] for r in con.execute("SELECT id FROM ot_systems WHERE engagement_id = ?", (e["id"],))]
            c = _counts(con, sids)
            e["systems"] = len(sids)
            e["counts"] = {k: sum(x[k] for x in c.values()) for k in db.STATUSES}
        return {"engagements": es}
    finally:
        con.close()


@router.post("/engagements")
def ot_engagement_add(req: EngagementReq, user: dict = Depends(auth.current_user)):
    auth.require(user, "admin", "assessor")
    if not db.clean(req.name, 200):
        raise HTTPException(422, "name is required")
    con = db.connect()
    try:
        cur = con.execute(
            "INSERT INTO ot_engagements (name, client, site, contract_ref, marking, ai_allowed, notes, created_at, "
            "updated_at, created_by) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (db.clean(req.name, 200), db.clean(req.client, 200), db.clean(req.site, 200), db.clean(req.contract_ref, 200),
             db.clean(req.marking, 80), 1 if req.ai_allowed else 0, db.clean(req.notes), db.now_iso(), db.now_iso(),
             user["username"]))
        db.audit(con, user["username"], "engagement.create", "engagement", cur.lastrowid, {"name": req.name})
        con.commit()
        return {"id": cur.lastrowid}
    finally:
        con.close()


@router.get("/engagements/{eid}")
def ot_engagement(eid: int, user: dict = Depends(auth.current_user)):
    con = db.connect()
    try:
        e = _one(con, "SELECT * FROM ot_engagements WHERE id = ?", (eid,), "engagement")
        systems = [db.row(r) for r in con.execute("SELECT * FROM ot_systems WHERE engagement_id = ? ORDER BY id", (eid,))]
        c = _counts(con, [s["id"] for s in systems])
        for s in systems:
            tpl = json.loads(s.pop("template")) if s.get("template") else None
            s["template"] = {"filename": tpl.get("filename"), "sheet": tpl.get("sheet"), "imported_at": tpl.get("imported_at")} if tpl else None
            s["counts"] = c[s["id"]]
            s["evidence"] = con.execute("SELECT count(*) FROM ot_evidence WHERE item_id IN "
                                        "(SELECT id FROM ot_items WHERE system_id = ?)", (s["id"],)).fetchone()[0]
        e["systems"] = systems
        return e
    finally:
        con.close()


@router.patch("/engagements/{eid}")
def ot_engagement_patch(eid: int, req: EngagementReq, user: dict = Depends(auth.current_user)):
    auth.require(user, "admin", "assessor")
    con = db.connect()
    try:
        _one(con, "SELECT id FROM ot_engagements WHERE id = ?", (eid,), "engagement")
        sets, args = [], []
        for f, n in (("name", 200), ("client", 200), ("site", 200), ("contract_ref", 200), ("marking", 80), ("notes", 2000)):
            v = getattr(req, f)
            if v is not None:
                if f == "name" and not db.clean(v, n):
                    raise HTTPException(422, "name can't be empty")
                sets.append(f"{f} = ?")
                args.append(db.clean(v, n))
        if req.ai_allowed is not None:
            sets.append("ai_allowed = ?")
            args.append(1 if req.ai_allowed else 0)
        if sets:
            con.execute(f"UPDATE ot_engagements SET {', '.join(sets)}, updated_at = ? WHERE id = ?", (*args, db.now_iso(), eid))
            db.audit(con, user["username"], "engagement.update", "engagement", eid, req.model_dump(exclude_none=True))
            con.commit()
        return {"ok": True}
    finally:
        con.close()


@router.delete("/engagements/{eid}")
def ot_engagement_delete(eid: int, user: dict = Depends(auth.current_user)):
    auth.require(user, "admin")
    con = db.connect()
    try:
        e = _one(con, "SELECT * FROM ot_engagements WHERE id = ?", (eid,), "engagement")
        con.execute("DELETE FROM ot_engagements WHERE id = ?", (eid,))
        db.audit(con, user["username"], "engagement.delete", "engagement", eid, {"name": e["name"]})
        con.commit()
        return {"deleted": True}
    finally:
        con.close()


# ------------------------------------------------------------------ systems

class SystemReq(BaseModel):
    name: Optional[str] = None
    system_type: Optional[str] = None
    phase: Optional[str] = None
    impact_c: Optional[str] = None
    impact_i: Optional[str] = None
    impact_a: Optional[str] = None
    impact_set_by: Optional[str] = None
    notes: Optional[str] = None


def _system_values(req: SystemReq) -> dict:
    v = {}
    if req.name is not None:
        if not db.clean(req.name, 200):
            raise HTTPException(422, "name can't be empty")
        v["name"] = db.clean(req.name, 200)
    for f, allowed in (("system_type", db.SYSTEM_TYPES), ("phase", db.PHASES), ("impact_c", db.IMPACT),
                       ("impact_i", db.IMPACT), ("impact_a", db.IMPACT)):
        x = getattr(req, f)
        if x is not None:
            v[f] = _choice(x, allowed, f)
    if req.impact_set_by is not None:
        v["impact_set_by"] = db.clean(req.impact_set_by, 200)
    if req.notes is not None:
        v["notes"] = db.clean(req.notes)
    return v


@router.post("/engagements/{eid}/systems")
def ot_system_add(eid: int, req: SystemReq, user: dict = Depends(auth.current_user)):
    auth.require(user, "admin", "assessor")
    v = _system_values(req)
    if not v.get("name"):
        raise HTTPException(422, "name is required")
    con = db.connect()
    try:
        _one(con, "SELECT id FROM ot_engagements WHERE id = ?", (eid,), "engagement")
        if any(k.startswith("impact_") and k != "impact_set_by" for k in v):
            v["impact_set_at"] = db.now_iso()
        cols = ["engagement_id", *v.keys(), "created_at", "updated_at"]
        cur = con.execute(f"INSERT INTO ot_systems ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                          (eid, *v.values(), db.now_iso(), db.now_iso()))
        con.execute("UPDATE ot_engagements SET updated_at = ? WHERE id = ?", (db.now_iso(), eid))
        db.audit(con, user["username"], "system.create", "system", cur.lastrowid, v)
        con.commit()
        return {"id": cur.lastrowid}
    finally:
        con.close()


@router.patch("/systems/{sid}")
def ot_system_patch(sid: int, req: SystemReq, user: dict = Depends(auth.current_user)):
    auth.require(user, "admin", "assessor")
    v = _system_values(req)
    con = db.connect()
    try:
        s = _one(con, "SELECT * FROM ot_systems WHERE id = ?", (sid,), "system")
        if any(k in v for k in ("impact_c", "impact_i", "impact_a")):
            v["impact_set_at"] = db.now_iso()
        if v:
            con.execute(f"UPDATE ot_systems SET {', '.join(f'{k} = ?' for k in v)}, updated_at = ? WHERE id = ?",
                        (*v.values(), db.now_iso(), sid))
            con.execute("UPDATE ot_engagements SET updated_at = ? WHERE id = ?", (db.now_iso(), s["engagement_id"]))
            db.audit(con, user["username"], "system.update", "system", sid, v)
            con.commit()
        return {"ok": True}
    finally:
        con.close()


@router.delete("/systems/{sid}")
def ot_system_delete(sid: int, user: dict = Depends(auth.current_user)):
    auth.require(user, "admin")
    con = db.connect()
    try:
        s = _one(con, "SELECT * FROM ot_systems WHERE id = ?", (sid,), "system")
        con.execute("DELETE FROM ot_systems WHERE id = ?", (sid,))
        db.audit(con, user["username"], "system.delete", "system", sid, {"name": s["name"]})
        con.commit()
        return {"deleted": True}
    finally:
        con.close()


# ------------------------------------------------------------------ items

class ItemReq(BaseModel):
    ref: Optional[str] = None
    control: Optional[str] = None
    requirement: Optional[str] = None
    category: Optional[str] = None
    responsible: Optional[str] = None
    level: Optional[str] = None
    status: Optional[str] = None
    owner: Optional[str] = None
    notes: Optional[str] = None
    finding: Optional[str] = None
    remediation: Optional[str] = None
    severity: Optional[str] = None
    due_date: Optional[str] = None


_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _item_values(req: ItemReq) -> dict:
    v = {}
    for f, n in (("ref", 100), ("control", 200), ("requirement", 4000), ("responsible", 100), ("owner", 100),
                 ("notes", 4000), ("finding", 4000), ("remediation", 4000)):
        x = getattr(req, f)
        if x is not None:
            v[f] = db.clean(x, n)
    if req.category is not None:
        v["category"] = req.category if req.category in db.CCI_CATEGORIES else db.clean(req.category, 60)
    if req.level is not None:
        v["level"] = _choice(req.level, db.LEVELS, "level")
    if req.status is not None:
        v["status"] = _choice(req.status, db.STATUSES, "status") or "not_assessed"
    if req.severity is not None:
        v["severity"] = _choice(req.severity, db.SEVERITIES, "severity")
    if req.due_date is not None:
        if req.due_date and not _DATE_RE.match(req.due_date):
            raise HTTPException(422, "due_date must be YYYY-MM-DD")
        v["due_date"] = req.due_date or None
    return v


@router.get("/systems/{sid}/items")
def ot_items(sid: int, user: dict = Depends(auth.current_user)):
    con = db.connect()
    try:
        s = _one(con, "SELECT * FROM ot_systems WHERE id = ?", (sid,), "system")
        tpl = json.loads(s["template"]) if s.get("template") else None
        items = [db.row(r) for r in con.execute("SELECT * FROM ot_items WHERE system_id = ? ORDER BY sort, id", (sid,))]
        ev: dict[int, list] = {}
        for r in con.execute("SELECT id, item_id, filename, sha256, size, mime, note, uploaded_at, uploaded_by FROM ot_evidence "
                             "WHERE item_id IN (SELECT id FROM ot_items WHERE system_id = ?) ORDER BY id", (sid,)):
            ev.setdefault(r["item_id"], []).append(db.row(r))
        for it in items:
            src = json.loads(it.pop("source_row")) if it.get("source_row") else None
            it["source"] = ({h or f"#{i + 1}": (src[i] if i < len(src) else "") for i, h in enumerate(tpl["headers"])}
                            if (tpl and src) else None)
            it["evidence"] = ev.get(it["id"], [])
        s.pop("template", None)
        s["template"] = {"filename": tpl.get("filename"), "sheet": tpl.get("sheet"), "mapping": tpl.get("mapping"),
                         "headers": tpl.get("headers")} if tpl else None
        return {"system": s, "items": items}
    finally:
        con.close()


@router.post("/systems/{sid}/items")
def ot_item_add(sid: int, req: ItemReq, user: dict = Depends(auth.current_user)):
    auth.require(user, "admin", "assessor")
    v = _item_values(req)
    con = db.connect()
    try:
        _one(con, "SELECT id FROM ot_systems WHERE id = ?", (sid,), "system")
        sort = con.execute("SELECT COALESCE(max(sort), 0) + 1 FROM ot_items WHERE system_id = ?", (sid,)).fetchone()[0]
        v.setdefault("status", "not_assessed")
        cols = ["system_id", "sort", *v.keys(), "updated_at", "updated_by"]
        cur = con.execute(f"INSERT INTO ot_items ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                          (sid, sort, *v.values(), db.now_iso(), user["username"]))
        db.audit(con, user["username"], "item.create", "item", cur.lastrowid, v)
        con.commit()
        return {"id": cur.lastrowid}
    finally:
        con.close()


@router.patch("/items/{iid}")
def ot_item_patch(iid: int, req: ItemReq, user: dict = Depends(auth.current_user)):
    auth.require(user, "admin", "assessor")
    v = _item_values(req)
    con = db.connect()
    try:
        old = _one(con, "SELECT * FROM ot_items WHERE id = ?", (iid,), "item")
        if v:
            con.execute(f"UPDATE ot_items SET {', '.join(f'{k} = ?' for k in v)}, updated_at = ?, updated_by = ? WHERE id = ?",
                        (*v.values(), db.now_iso(), user["username"], iid))
            changes = {k: {"from": old.get(k), "to": x} for k, x in v.items() if old.get(k) != x}
            if changes:
                db.audit(con, user["username"], "item.update", "item", iid, changes)
            con.commit()
        return db.row(con.execute("SELECT * FROM ot_items WHERE id = ?", (iid,)).fetchone()) | {"source_row": None}
    finally:
        con.close()


@router.delete("/items/{iid}")
def ot_item_delete(iid: int, user: dict = Depends(auth.current_user)):
    auth.require(user, "admin")
    con = db.connect()
    try:
        it = _one(con, "SELECT * FROM ot_items WHERE id = ?", (iid,), "item")
        con.execute("DELETE FROM ot_items WHERE id = ?", (iid,))
        db.audit(con, user["username"], "item.delete", "item", iid, {"ref": it["ref"]})
        con.commit()
        return {"deleted": True}
    finally:
        con.close()


# ------------------------------------------------------------------ import

def _tmp(upload_id: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_-]{20,64}", upload_id or ""):
        raise HTTPException(422, "bad upload id")
    return db.data_dir() / "tmp" / upload_id


@router.post("/import/preview")
async def ot_import_preview(file: UploadFile = File(...), user: dict = Depends(auth.current_user)):
    auth.require(user, "admin", "assessor")
    data = await file.read(sheets.MAX_UPLOAD + 1)
    try:
        prev = sheets.preview(data, file.filename or "")
    except ValueError as e:
        raise HTTPException(422, str(e))
    tmpdir = db.data_dir() / "tmp"
    tmpdir.mkdir(parents=True, exist_ok=True)
    for old in tmpdir.iterdir():   # forget abandoned uploads
        if time.time() - old.stat().st_mtime > UPLOAD_TTL_S:
            old.unlink(missing_ok=True)
    uid = secrets.token_urlsafe(24)
    (tmpdir / uid).write_bytes(data)
    (tmpdir / f"{uid}.name").write_text(file.filename or "upload.xlsx", encoding="utf-8")
    prev["upload_id"] = uid
    return prev


class ImportReq(BaseModel):
    upload_id: str
    sheet: str
    header_row: int
    mapping: dict[str, Optional[int]]


@router.post("/systems/{sid}/import")
def ot_import(sid: int, req: ImportReq, user: dict = Depends(auth.current_user)):
    auth.require(user, "admin", "assessor")
    p = _tmp(req.upload_id)
    if not p.exists():
        raise HTTPException(410, "upload expired; choose the file again")
    name_file = p.with_name(p.name + ".name")
    filename = name_file.read_text(encoding="utf-8") if name_file.exists() else "upload.xlsx"
    try:
        tables = {t["name"]: t for t in sheets.read_table(p.read_bytes(), filename)}
    except ValueError as e:
        raise HTTPException(422, str(e))
    sheet = tables.get(req.sheet)
    if not sheet:
        raise HTTPException(422, "sheet not found in the file")
    if not (0 <= req.header_row < max(1, len(sheet["rows"]))):
        raise HTTPException(422, "header row out of range")
    bad = [f for f in req.mapping if f not in sheets.FIELDS]
    if bad:
        raise HTTPException(422, "unknown fields: " + ", ".join(bad))
    con = db.connect()
    try:
        s = _one(con, "SELECT * FROM ot_systems WHERE id = ?", (sid,), "system")
        n = sheets.import_rows(con, sid, filename, sheet, req.header_row,
                               {k: v for k, v in req.mapping.items() if v is not None}, user["username"])
        con.execute("UPDATE ot_engagements SET updated_at = ? WHERE id = ?", (db.now_iso(), s["engagement_id"]))
        con.commit()
    finally:
        con.close()
    p.unlink(missing_ok=True)
    name_file.unlink(missing_ok=True)
    return {"imported": n}


# ------------------------------------------------------------------ evidence

def _disposition(kind: str, name: str) -> str:
    """Header-safe filename: ASCII fallback plus the UTF-8 name (RFC 6266), so Japanese names work."""
    ascii_name = re.sub(r'[^A-Za-z0-9._ ()-]', "_", name) or "file"
    return f"{kind}; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(name, safe='')}"


def _safe_name(name: str) -> str:
    base = Path(name or "file").name
    return (_FNAME_RE.sub("_", base)[:120] or "file")


@router.post("/items/{iid}/evidence")
async def ot_evidence_add(iid: int, file: UploadFile = File(...), note: str = Form(""),
                          user: dict = Depends(auth.current_user)):
    auth.require(user, "admin", "assessor")
    name = _safe_name(file.filename or "")
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in EVIDENCE_EXT:
        raise HTTPException(422, "file type not accepted for evidence")
    data = await file.read(MAX_EVIDENCE + 1)
    if len(data) > MAX_EVIDENCE:
        raise HTTPException(413, "evidence files are limited to 25 MB")
    if not data:
        raise HTTPException(422, "empty file")
    sha = hashlib.sha256(data).hexdigest()
    con = db.connect()
    try:
        _one(con, "SELECT id FROM ot_items WHERE id = ?", (iid,), "item")
        path = db.evidence_dir() / sha[:2] / sha
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_bytes(data)
        cur = con.execute("INSERT INTO ot_evidence (item_id, filename, sha256, size, mime, note, uploaded_at, uploaded_by) "
                          "VALUES (?,?,?,?,?,?,?,?)", (iid, name, sha, len(data), INLINE_IMAGES.get(ext, "application/octet-stream"),
                                                      db.clean(note, 500), db.now_iso(), user["username"]))
        con.execute("UPDATE ot_items SET updated_at = ?, updated_by = ? WHERE id = ?", (db.now_iso(), user["username"], iid))
        db.audit(con, user["username"], "evidence.add", "item", iid, {"file": name, "sha256": sha, "size": len(data)})
        con.commit()
        return {"id": cur.lastrowid, "sha256": sha, "filename": name, "size": len(data)}
    finally:
        con.close()


@router.get("/evidence/{evid}/file")
def ot_evidence_file(evid: int, user: dict = Depends(auth.current_user)):
    con = db.connect()
    try:
        e = _one(con, "SELECT * FROM ot_evidence WHERE id = ?", (evid,), "evidence")
    finally:
        con.close()
    path = db.evidence_dir() / e["sha256"][:2] / e["sha256"]
    if not path.exists():
        raise HTTPException(410, "evidence file missing from storage")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != e["sha256"]:
        raise HTTPException(500, "evidence file failed its integrity check")
    inline = e["mime"] in INLINE_IMAGES.values()
    return Response(content=data, media_type=e["mime"] if inline else "application/octet-stream", headers={
        "Content-Disposition": _disposition("inline" if inline else "attachment", e["filename"]),
        "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "sandbox; default-src 'none'"})


@router.delete("/evidence/{evid}")
def ot_evidence_delete(evid: int, user: dict = Depends(auth.current_user)):
    auth.require(user, "admin", "assessor")
    con = db.connect()
    try:
        e = _one(con, "SELECT * FROM ot_evidence WHERE id = ?", (evid,), "evidence")
        con.execute("DELETE FROM ot_evidence WHERE id = ?", (evid,))
        # The file stays on disk while any other record uses the same content.
        still = con.execute("SELECT count(*) FROM ot_evidence WHERE sha256 = ?", (e["sha256"],)).fetchone()[0]
        db.audit(con, user["username"], "evidence.delete", "item", e["item_id"], {"file": e["filename"], "sha256": e["sha256"]})
        con.commit()
    finally:
        con.close()
    if not still:
        (db.evidence_dir() / e["sha256"][:2] / e["sha256"]).unlink(missing_ok=True)
    return {"deleted": True}


# ------------------------------------------------------------------ export, report, audit

@router.get("/engagements/{eid}/export.xlsx")
def ot_export(eid: int, user: dict = Depends(auth.current_user)):
    con = db.connect()
    try:
        e = _one(con, "SELECT * FROM ot_engagements WHERE id = ?", (eid,), "engagement")
        data = sheets.export_workbook(con, eid)
        db.audit(con, user["username"], "engagement.export", "engagement", eid, {"bytes": len(data)})
        con.commit()
    finally:
        con.close()
    fname = re.sub(r"[\\/:*?\"<>|\s]+", "_", e["name"])[:60] or "engagement"
    return Response(content=data, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": _disposition("attachment", f"talon-ot-{fname}.xlsx")})


@router.get("/engagements/{eid}/report")
def ot_report(eid: int, user: dict = Depends(auth.current_user)):
    con = db.connect()
    try:
        e = _one(con, "SELECT * FROM ot_engagements WHERE id = ?", (eid,), "engagement")
        systems = [db.row(r) for r in con.execute("SELECT * FROM ot_systems WHERE engagement_id = ? ORDER BY id", (eid,))]
        c = _counts(con, [s["id"] for s in systems])
        for s in systems:
            s.pop("template", None)
            s["counts"] = c[s["id"]]
            s["open_items"] = [db.row(r) for r in con.execute(
                "SELECT id, ref, control, requirement, status, finding, remediation, severity, owner, due_date, category, level "
                "FROM ot_items WHERE system_id = ? AND status IN ('not_implemented','partial') ORDER BY "
                "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'moderate' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, sort",
                (s["id"],))]
        e["systems"] = systems
        e["generated_at"] = db.now_iso()
        return e
    finally:
        con.close()


@router.get("/audit")
def ot_audit(limit: int = 200, user: dict = Depends(auth.current_user)):
    auth.require(user, "admin")
    con = db.connect()
    try:
        return {"audit": [db.row(r) for r in con.execute("SELECT * FROM ot_audit ORDER BY id DESC LIMIT ?",
                                                          (max(1, min(limit, 1000)),))]}
    finally:
        con.close()
