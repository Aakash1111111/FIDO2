"""Single-use, expiring WebAuthn challenges bound to (session, ceremony type, user).

A challenge is deleted the first time anyone tries to use it, whether the
verification then succeeds or fails, so a captured response can never be
replayed (threat TH3, test T09).
"""
import secrets
import time

from .errors import RPError


class ChallengeStore:
    def __init__(self, db, ttl_s: int):
        self.db = db
        self.ttl_s = ttl_s

    def issue(self, session_id: str, ctype: str, user_id: int) -> bytes:
        challenge = secrets.token_bytes(32)
        self.db.execute("DELETE FROM challenges WHERE expires_at < ?", (time.time(),))
        self.db.execute(
            "INSERT OR REPLACE INTO challenges (session_id, type, challenge, user_id, expires_at)"
            " VALUES (?,?,?,?,?)", (session_id, ctype, challenge, user_id, time.time() + self.ttl_s))
        return challenge

    def consume(self, session_id: str, ctype: str):
        row = self.db.one("SELECT * FROM challenges WHERE session_id = ? AND type = ?", (session_id, ctype))
        if row is None:
            raise RPError("CHALLENGE_NOT_FOUND")
        self.db.execute("DELETE FROM challenges WHERE session_id = ? AND type = ?", (session_id, ctype))
        if row["expires_at"] < time.time():
            raise RPError("CHALLENGE_EXPIRED")
        return bytes(row["challenge"]), row["user_id"]
