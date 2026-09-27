"""SQLite persistence: users, credentials (public keys only), challenges, auth_events."""
import sqlite3
import threading
from datetime import datetime, timezone

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
  id          INTEGER PRIMARY KEY,
  username    TEXT NOT NULL UNIQUE,
  user_handle BLOB NOT NULL UNIQUE,
  created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS credentials (
  credential_id BLOB PRIMARY KEY,
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key    BLOB NOT NULL,
  sign_count    INTEGER NOT NULL DEFAULT 0,
  aaguid        TEXT,
  fmt           TEXT,
  transports    TEXT,
  created_at    TEXT NOT NULL,
  last_used_at  TEXT
);
CREATE TABLE IF NOT EXISTS challenges (
  session_id TEXT NOT NULL,
  type       TEXT NOT NULL CHECK (type IN ('reg','auth')),
  challenge  BLOB NOT NULL,
  user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
  expires_at REAL NOT NULL,
  PRIMARY KEY (session_id, type)
);
CREATE TABLE IF NOT EXISTS auth_events (
  id               INTEGER PRIMARY KEY,
  ts               TEXT NOT NULL,
  run_id           TEXT,
  ceremony         TEXT NOT NULL CHECK (ceremony IN ('reg','auth')),
  username         TEXT,
  credential_id    BLOB,
  result           TEXT NOT NULL CHECK (result IN ('success','failure')),
  reason           TEXT,
  server_verify_us INTEGER,
  client_total_ms  REAL,
  user_agent       TEXT
);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    def __init__(self, path: str):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def execute(self, sql, params=()):
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def one(self, sql, params=()):
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    def all(self, sql, params=()):
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    # ---- users ----
    def get_user(self, username):
        return self.one("SELECT * FROM users WHERE username = ?", (username,))

    def get_user_by_id(self, uid):
        return self.one("SELECT * FROM users WHERE id = ?", (uid,))

    def create_user(self, username, user_handle):
        cur = self.execute("INSERT INTO users (username, user_handle, created_at) VALUES (?,?,?)",
                           (username, user_handle, now_iso()))
        return self.get_user_by_id(cur.lastrowid)

    # ---- credentials ----
    def credentials_for(self, uid):
        return self.all("SELECT * FROM credentials WHERE user_id = ? ORDER BY created_at", (uid,))

    def get_credential(self, cred_id):
        return self.one("SELECT * FROM credentials WHERE credential_id = ?", (cred_id,))

    def add_credential(self, cred_id, uid, public_key, sign_count, aaguid, fmt, transports):
        self.execute(
            "INSERT INTO credentials (credential_id, user_id, public_key, sign_count, aaguid, fmt,"
            " transports, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (cred_id, uid, public_key, sign_count, aaguid, fmt, transports, now_iso()))

    def update_counter(self, cred_id, sign_count):
        self.execute("UPDATE credentials SET sign_count = ?, last_used_at = ? WHERE credential_id = ?",
                     (sign_count, now_iso(), cred_id))

    def delete_credential(self, cred_id, uid):
        return self.execute("DELETE FROM credentials WHERE credential_id = ? AND user_id = ?",
                            (cred_id, uid)).rowcount

    # ---- events ----
    def log_event(self, ceremony, result, reason=None, username=None, credential_id=None,
                  server_verify_us=None, client_total_ms=None, user_agent=None, run_id=None):
        self.execute(
            "INSERT INTO auth_events (ts, run_id, ceremony, username, credential_id, result, reason,"
            " server_verify_us, client_total_ms, user_agent) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (now_iso(), run_id, ceremony, username, credential_id, result, reason,
             server_verify_us, client_total_ms, user_agent))

    def events(self, username=None, limit=200):
        if username is None:
            return self.all("SELECT * FROM auth_events ORDER BY id DESC LIMIT ?", (limit,))
        return self.all("SELECT * FROM auth_events WHERE username = ? ORDER BY id DESC LIMIT ?",
                        (username, limit))
