"""Relying-party configuration from environment variables, validated at startup.

RP_ID            WebAuthn RP ID (default "localhost"). Must be the host name
                 (or a parent domain) of every origin below.
RP_ORIGIN        Comma-separated allowed origins (default "http://localhost:8000").
                 For the phone test use the HTTPS tunnel URL, e.g.
                 RP_ID=abc.ngrok-free.app RP_ORIGIN=https://abc.ngrok-free.app
RP_NAME          Display name shown by the browser.
DB_PATH          SQLite file (default rp.sqlite3).
SESSION_SECRET   Cookie-signing key. If unset a random one is generated per run
                 (fine locally: everyone is simply logged out on restart).
RP_ADMIN_TOKEN   Enables the research/admin dashboard (/admin) for holders of
                 this token. Unset = admin dashboard disabled.
RP_EXPERIMENT_MODE=1  Enables CSV export of auth events (research only).
"""
import os
import secrets
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse


@dataclass(frozen=True)
class Settings:
    rp_id: str
    rp_name: str
    origins: List[str]
    db_path: str
    session_secret: str
    admin_token: Optional[str]
    experiment_mode: bool
    challenge_ttl_s: int = 120
    user_verification: str = "discouraged"  # token has no PIN / UV (see spec §9)

    @property
    def secure_cookies(self) -> bool:
        return all(o.startswith("https://") for o in self.origins)


def load_settings(env=os.environ) -> Settings:
    rp_id = env.get("RP_ID", "localhost").strip().lower()
    origins = [o.strip().rstrip("/") for o in env.get("RP_ORIGIN", "http://localhost:8000").split(",") if o.strip()]
    for o in origins:
        u = urlparse(o)
        host = (u.hostname or "").lower()
        if u.scheme not in ("http", "https") or not host:
            raise ValueError(f"RP_ORIGIN {o!r} is not a valid origin")
        if u.scheme == "http" and host != "localhost" and not host.endswith(".localhost"):
            # WebAuthn only works in a secure context: https, or http://localhost.
            raise ValueError(f"RP_ORIGIN {o!r}: plain http is only allowed for localhost")
        if host != rp_id and not host.endswith("." + rp_id):
            raise ValueError(f"RP_ORIGIN {o!r} does not belong to RP_ID {rp_id!r}")
    secret = env.get("SESSION_SECRET") or secrets.token_urlsafe(32)
    admin = env.get("RP_ADMIN_TOKEN") or None
    if admin is not None and len(admin) < 16:
        raise ValueError("RP_ADMIN_TOKEN must be at least 16 characters")
    return Settings(
        rp_id=rp_id,
        rp_name=env.get("RP_NAME", "FIDO2 Token Research RP"),
        origins=origins,
        db_path=env.get("DB_PATH", "rp.sqlite3"),
        session_secret=secret,
        admin_token=admin,
        experiment_mode=env.get("RP_EXPERIMENT_MODE") == "1",
    )
