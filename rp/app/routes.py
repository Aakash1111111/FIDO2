"""HTTP API of the relying party.

Standard WebAuthn ceremonies (H§18 endpoint names):
  POST /register/options, /register/verify, /login/options, /login/verify
Project-specific: /logout, /me (dashboard data), DELETE /credentials/{id}, /healthz
Research-only (token-gated): /admin/api, /experiment/events.csv
"""
import base64
import csv
import hmac
import io
import re
import secrets
import time

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from . import webauthn_service as wa
from .errors import RPError

router = APIRouter()
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
PROJECT_AAGUID = "ba17f247-df28-46ce-819d-8488f3b2278c"


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def ctx(request: Request):
    return request.app.state.settings, request.app.state.db, request.app.state.challenges


def session_id(request: Request) -> str:
    sid = request.session.get("sid")
    if not sid:
        sid = secrets.token_urlsafe(24)
        request.session["sid"] = sid
    return sid


def fail(db, ceremony, reason, status=400, **kw):
    db.log_event(ceremony, "failure", reason=reason, **kw)
    return JSONResponse({"ok": False, "reason": reason}, status_code=status)


async def json_body(request: Request) -> dict:
    try:
        body = await request.json()
    except ValueError:
        raise RPError("MALFORMED_REQUEST")
    if not isinstance(body, dict):
        raise RPError("MALFORMED_REQUEST")
    return body


def client_meta(body: dict, request: Request) -> dict:
    ms = body.get("client_total_ms")
    return {
        "client_total_ms": float(ms) if isinstance(ms, (int, float)) else None,
        "run_id": str(body["run_id"])[:64] if body.get("run_id") else None,
        "user_agent": request.headers.get("user-agent", "")[:200],
    }


# ---------------------------------------------------------------- registration

@router.post("/register/options")
async def register_options(request: Request):
    s, db, ch = ctx(request)
    body = await json_body(request)
    username = str(body.get("username", "")).strip()
    if not USERNAME_RE.match(username):
        raise RPError("INVALID_USERNAME")
    user = db.get_user(username)
    if user is None:
        user = db.create_user(username, secrets.token_bytes(32))
    elif db.credentials_for(user["id"]) and request.session.get("uid") != user["id"]:
        # Adding a key to an existing account requires being logged in to it:
        # otherwise anyone could attach THEIR key to YOUR account (TH12).
        return fail(db, "reg", "USER_EXISTS_AUTH_REQUIRED", 403, username=username,
                    user_agent=request.headers.get("user-agent", "")[:200])
    existing = [bytes(c["credential_id"]) for c in db.credentials_for(user["id"])]
    challenge = ch.issue(session_id(request), "reg", user["id"])
    return wa.registration_options(s, username, bytes(user["user_handle"]), challenge, existing)


@router.post("/register/verify")
async def register_verify(request: Request):
    s, db, ch = ctx(request)
    body = await json_body(request)
    meta = client_meta(body, request)
    credential = body.get("credential")
    try:
        challenge, uid = ch.consume(session_id(request), "reg")
    except RPError as e:
        return fail(db, "reg", e.reason, **meta)
    user = db.get_user_by_id(uid)
    if not isinstance(credential, dict) or user is None:
        return fail(db, "reg", "MALFORMED_REQUEST", **meta)
    t0 = time.perf_counter_ns()
    try:
        v, fmt = wa.verify_registration(s, credential, challenge)
    except RPError as e:
        return fail(db, "reg", e.reason, username=user["username"],
                    server_verify_us=(time.perf_counter_ns() - t0) // 1000, **meta)
    verify_us = (time.perf_counter_ns() - t0) // 1000
    if db.get_credential(v.credential_id) is not None:
        return fail(db, "reg", "CREDENTIAL_ALREADY_REGISTERED", username=user["username"], **meta)
    db.add_credential(v.credential_id, uid, v.credential_public_key, v.sign_count,
                      str(v.aaguid), fmt, wa.transports_of(credential))
    db.log_event("reg", "success", username=user["username"], credential_id=v.credential_id,
                 server_verify_us=verify_us, **meta)
    request.session["uid"] = uid
    return {"ok": True, "username": user["username"], "credential_id": b64url(v.credential_id),
            "fmt": fmt, "server_verify_ms": verify_us / 1000}


# --------------------------------------------------------------- authentication

@router.post("/login/options")
async def login_options(request: Request):
    s, db, ch = ctx(request)
    body = await json_body(request)
    username = str(body.get("username", "")).strip()
    user = db.get_user(username) if USERNAME_RE.match(username) else None
    creds = db.credentials_for(user["id"]) if user else []
    if not creds:
        # Reveals whether the account exists: accepted for this local research
        # RP (see RISKS Q-ENUM); a production site would return decoy options.
        return fail(db, "auth", "UNKNOWN_USER", 404, username=username or None,
                    user_agent=request.headers.get("user-agent", "")[:200])
    challenge = ch.issue(session_id(request), "auth", user["id"])
    return wa.authentication_options(s, challenge, [bytes(c["credential_id"]) for c in creds])


@router.post("/login/verify")
async def login_verify(request: Request):
    s, db, ch = ctx(request)
    body = await json_body(request)
    meta = client_meta(body, request)
    credential = body.get("credential")
    try:
        challenge, uid = ch.consume(session_id(request), "auth")
    except RPError as e:
        return fail(db, "auth", e.reason, **meta)
    user = db.get_user_by_id(uid)
    if not isinstance(credential, dict) or user is None or not isinstance(credential.get("rawId"), str):
        return fail(db, "auth", "MALFORMED_REQUEST", **meta)
    try:
        cred_id = b64url_decode(credential["rawId"])
    except (ValueError, TypeError):
        return fail(db, "auth", "MALFORMED_REQUEST", **meta)
    row = db.get_credential(cred_id)
    if row is None or row["user_id"] != uid:
        return fail(db, "auth", "UNKNOWN_CREDENTIAL", username=user["username"], credential_id=cred_id, **meta)
    t0 = time.perf_counter_ns()
    try:
        v = wa.verify_authentication(s, credential, challenge, bytes(row["public_key"]), row["sign_count"])
    except RPError as e:
        return fail(db, "auth", e.reason, username=user["username"], credential_id=cred_id,
                    server_verify_us=(time.perf_counter_ns() - t0) // 1000, **meta)
    verify_us = (time.perf_counter_ns() - t0) // 1000
    db.update_counter(cred_id, v.new_sign_count)
    db.log_event("auth", "success", username=user["username"], credential_id=cred_id,
                 server_verify_us=verify_us, **meta)
    request.session["uid"] = uid
    return {"ok": True, "username": user["username"], "sign_count": v.new_sign_count,
            "server_verify_ms": verify_us / 1000}


@router.post("/logout")
async def logout(request: Request):
    request.session.pop("uid", None)
    return {"ok": True}


# -------------------------------------------------------------------- dashboard

def credential_view(c) -> dict:
    return {
        "id": b64url(bytes(c["credential_id"])),
        "created_at": c["created_at"],
        "last_used_at": c["last_used_at"],
        "sign_count": c["sign_count"],
        "aaguid": c["aaguid"],
        "is_project_token": c["aaguid"] == PROJECT_AAGUID,
        "fmt": c["fmt"],
        "transports": c["transports"],
    }


def event_view(e) -> dict:
    return {
        "ts": e["ts"], "ceremony": e["ceremony"], "username": e["username"], "result": e["result"],
        "reason": e["reason"],
        "credential_id": b64url(bytes(e["credential_id"]))[:12] if e["credential_id"] else None,
        "server_verify_ms": e["server_verify_us"] / 1000 if e["server_verify_us"] is not None else None,
        "client_total_ms": e["client_total_ms"], "run_id": e["run_id"], "user_agent": e["user_agent"],
    }


@router.get("/me")
async def me(request: Request):
    _, db, _ = ctx(request)
    uid = request.session.get("uid")
    user = db.get_user_by_id(uid) if uid else None
    if user is None:
        return JSONResponse({"ok": False, "reason": "NOT_LOGGED_IN"}, status_code=401)
    return {"ok": True, "username": user["username"], "created_at": user["created_at"],
            "credentials": [credential_view(c) for c in db.credentials_for(uid)],
            "events": [event_view(e) for e in db.events(user["username"], 50)]}


@router.delete("/credentials/{cred_b64}")
async def delete_credential(cred_b64: str, request: Request):
    _, db, _ = ctx(request)
    uid = request.session.get("uid")
    if not uid:
        return JSONResponse({"ok": False, "reason": "NOT_LOGGED_IN"}, status_code=401)
    if len(db.credentials_for(uid)) <= 1:
        return JSONResponse({"ok": False, "reason": "LAST_CREDENTIAL"}, status_code=409)
    try:
        cred_id = b64url_decode(cred_b64)
    except ValueError:
        return JSONResponse({"ok": False, "reason": "MALFORMED_REQUEST"}, status_code=400)
    if db.delete_credential(cred_id, uid) == 0:
        return JSONResponse({"ok": False, "reason": "UNKNOWN_CREDENTIAL"}, status_code=404)
    return {"ok": True}


# -------------------------------------------------------- research / admin only

def require_admin(request: Request):
    s = request.app.state.settings
    token = request.headers.get("x-admin-token", "")
    if not s.admin_token or not hmac.compare_digest(token.encode(), s.admin_token.encode()):
        raise RPError("ADMIN_TOKEN_REQUIRED", 403)


@router.get("/admin/api")
async def admin_api(request: Request):
    require_admin(request)
    _, db, _ = ctx(request)
    users = db.all("SELECT u.*, (SELECT COUNT(*) FROM credentials c WHERE c.user_id = u.id) AS n"
                   " FROM users u ORDER BY u.id")
    creds = db.all("SELECT c.*, u.username FROM credentials c JOIN users u ON u.id = c.user_id"
                   " ORDER BY c.created_at")
    stats = db.all("SELECT ceremony, result, COUNT(*) AS n, AVG(server_verify_us) AS avg_us,"
                   " AVG(client_total_ms) AS avg_client_ms FROM auth_events GROUP BY ceremony, result")
    reasons = db.all("SELECT ceremony, reason, COUNT(*) AS n FROM auth_events WHERE result = 'failure'"
                     " GROUP BY ceremony, reason ORDER BY n DESC")
    return {
        "users": [{"username": u["username"], "created_at": u["created_at"], "credentials": u["n"]} for u in users],
        "credentials": [dict(credential_view(c), username=c["username"]) for c in creds],
        "stats": [dict(r) for r in stats],
        "failure_reasons": [dict(r) for r in reasons],
        "events": [event_view(e) for e in db.events(None, 200)],
    }


@router.get("/experiment/events.csv")
async def export_events(request: Request):
    require_admin(request)
    s, db, _ = ctx(request)
    if not s.experiment_mode:
        raise RPError("EXPERIMENT_MODE_DISABLED", 404)
    rows = db.all("SELECT * FROM auth_events ORDER BY id")
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "ts", "run_id", "ceremony", "username", "credential_id", "result", "reason",
                "server_verify_us", "client_total_ms", "user_agent"])
    for r in rows:
        w.writerow([r["id"], r["ts"], r["run_id"], r["ceremony"], r["username"],
                    b64url(bytes(r["credential_id"])) if r["credential_id"] else "", r["result"],
                    r["reason"], r["server_verify_us"], r["client_total_ms"], r["user_agent"]])
    return PlainTextResponse(buf.getvalue(), media_type="text/csv")


@router.get("/healthz")
async def healthz(request: Request):
    s = request.app.state.settings
    return {"ok": True, "rp_id": s.rp_id, "origins": s.origins,
            "admin": bool(s.admin_token), "experiment_mode": s.experiment_mode}
