"""End-to-end scenarios: token <-> browser-like client (python-fido2) <-> relying party.

The relying party runs in-process (FastAPI TestClient), so no web server or
browser is needed. The same scenarios run against:
  * the real ESP32-S3 token over USB   -> harness/e2e_check.py   (evidence for the paper)
  * the software sim of the firmware   -> rp/tests/test_e2e_sim.py (CI; NOT evidence)

Covers T07, T08, T09, T10, T11, T-CNT, TH12, the UP flag check, and counter regression.
"""
import base64
import hashlib
import json
import os
import sys
import tempfile
import time

from fido2.client import Fido2Client, UserInteraction
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "rp"))
os.environ.setdefault("RP_NO_AUTOCREATE", "1")

from fastapi.testclient import TestClient  # noqa: E402

from app.config import load_settings  # noqa: E402
from app.main import create_app  # noqa: E402

ORIGIN = "http://localhost:8000"
RP_ID = "localhost"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Prompt(UserInteraction):
    def __init__(self, say):
        self.say = say

    def prompt_up(self):
        self.say("    >>> press the BOOT button on the token <<<")


def creation_options_to_fido2(o: dict) -> dict:
    o = dict(o)
    o.pop("hints", None)
    o["challenge"] = unb64u(o["challenge"])
    o["user"] = dict(o["user"], id=unb64u(o["user"]["id"]))
    o["excludeCredentials"] = [dict(c, id=unb64u(c["id"])) for c in o.get("excludeCredentials", [])]
    return o


def request_options_to_fido2(o: dict) -> dict:
    o = dict(o)
    o.pop("hints", None)
    o["challenge"] = unb64u(o["challenge"])
    o["allowCredentials"] = [dict(c, id=unb64u(c["id"])) for c in o.get("allowCredentials", [])]
    return o


def attestation_json(r) -> dict:
    cred_id = r.attestation_object.auth_data.credential_data.credential_id
    return {"id": b64u(cred_id), "rawId": b64u(cred_id), "type": "public-key", "clientExtensionResults": {},
            "response": {"clientDataJSON": b64u(bytes(r.client_data)),
                         "attestationObject": b64u(bytes(r.attestation_object)), "transports": ["usb"]}}


def assertion_json(a) -> dict:
    cid = a.credential_id
    return {"id": b64u(cid), "rawId": b64u(cid), "type": "public-key", "clientExtensionResults": {},
            "response": {"clientDataJSON": b64u(bytes(a.client_data)),
                         "authenticatorData": b64u(bytes(a.authenticator_data)),
                         "signature": b64u(a.signature),
                         "userHandle": b64u(a.user_handle) if a.user_handle else None}}


class Runner:
    def __init__(self, device, say=print, run_id=None, db_path=None):
        self.device = device
        self.say = say
        self.run_id = run_id or time.strftime("run-%Y%m%d-%H%M%S")
        self.db_path = db_path or os.path.join(tempfile.mkdtemp(), "rp.sqlite3")
        settings = load_settings({"RP_ID": RP_ID, "RP_ORIGIN": ORIGIN, "DB_PATH": self.db_path,
                                  "RP_ADMIN_TOKEN": "research-admin-token-0001", "RP_EXPERIMENT_MODE": "1"})
        self.app = create_app(settings)
        self.results = []
        self.timings = []   # (ceremony, trial, host_ms incl. button, server_verify_ms)

    # ---- plumbing ----
    def http(self):
        return TestClient(self.app, base_url=ORIGIN)

    def client(self, origin=ORIGIN):
        return Fido2Client(self.device, origin, verify=lambda rp_id, o: True, user_interaction=Prompt(self.say))

    def check(self, test, case, expected, observed):
        ok = expected == observed
        self.results.append((test, case, str(expected), str(observed), "PASS" if ok else "FAIL"))
        self.say(f"  [{'PASS' if ok else 'FAIL'}] {test} {case}: expected {expected}, got {observed}")
        return ok

    def register(self, http, username, origin=ORIGIN):
        r = http.post("/register/options", json={"username": username})
        if r.status_code != 200:
            return r.json(), None
        t0 = time.perf_counter()
        att = self.client(origin).make_credential(creation_options_to_fido2(r.json()))
        cred = attestation_json(att)
        v = http.post("/register/verify", json={"credential": cred, "run_id": self.run_id,
                                                "client_total_ms": (time.perf_counter() - t0) * 1000}).json()
        return v, cred

    def get_assertion(self, http, username, origin=ORIGIN):
        r = http.post("/login/options", json={"username": username})
        assert r.status_code == 200, r.text
        t0 = time.perf_counter()
        sel = self.client(origin).get_assertion(request_options_to_fido2(r.json()))
        return assertion_json(sel.get_response(0)), (time.perf_counter() - t0) * 1000

    def verify_login(self, http, cred, host_ms=None):
        return http.post("/login/verify", json={"credential": cred, "run_id": self.run_id,
                                                "client_total_ms": host_ms}).json()

    # ---- scenarios ----
    def run(self, login_trials=3):
        user = "alice"
        http = self.http()

        self.say("T07 registration")
        v, cred = self.register(http, user)
        self.check("T07", "register ok", True, v.get("ok"))
        self.check("T07", "attestation format", "packed", v.get("fmt"))
        cred_id = unb64u(cred["id"]) if cred else b""

        self.say(f"T08 login x{login_trials} (+T-CNT counter strictly increasing)")
        last = 0
        for i in range(login_trials):
            a, host_ms = self.get_assertion(http, user)
            res = self.verify_login(http, a, host_ms)
            self.check("T08", f"login {i + 1}", True, res.get("ok"))
            cnt = res.get("sign_count", -1)
            self.check("T-CNT", f"counter {i + 1} > previous", True, cnt > last)
            last = cnt
            self.timings.append(("auth", i, host_ms, res.get("server_verify_ms")))

        self.say("T09 replay / stale / altered challenge")
        a, _ = self.get_assertion(http, user)
        self.check("T09", "fresh login ok", True, self.verify_login(http, a).get("ok"))
        self.check("T09", "replay of the same assertion", "CHALLENGE_NOT_FOUND", self.verify_login(http, a).get("reason"))
        http.post("/login/options", json={"username": user})          # new challenge issued...
        self.check("T09", "old assertion vs new challenge", "CHALLENGE_MISMATCH",
                   self.verify_login(http, a).get("reason"))            # ...old assertion rejected
        b, _ = self.get_assertion(http, user)
        cd = json.loads(unb64u(b["response"]["clientDataJSON"]))
        cd["challenge"] = b64u(os.urandom(32))
        b["response"]["clientDataJSON"] = b64u(json.dumps(cd).encode())
        self.check("T09", "altered challenge in clientDataJSON", "CHALLENGE_MISMATCH",
                   self.verify_login(http, b).get("reason"))

        self.say("T10 wrong origin / wrong RP")
        http.post("/login/options", json={"username": user})
        c, _ = self.get_assertion(http, user, origin="https://evil.example")
        self.check("T10", "assertion made for another origin", "ORIGIN_MISMATCH",
                   self.verify_login(http, c).get("reason"))
        ctap = Ctap2(self.device)
        try:
            ctap.get_assertion("evil.example", hashlib.sha256(b"x").digest(),
                               [{"type": "public-key", "id": cred_id}])
            observed = "signature returned"
        except CtapError as e:
            observed = e.code.name
        self.check("T10", "token: real credential ID under another rpId", "NO_CREDENTIALS", observed)

        self.say("T11 unknown credential")
        try:
            ctap.get_assertion(RP_ID, hashlib.sha256(b"x").digest(),
                               [{"type": "public-key", "id": os.urandom(16)}])
            observed = "signature returned"
        except CtapError as e:
            observed = e.code.name
        self.check("T11", "token: unknown credential ID", "NO_CREDENTIALS", observed)
        d, _ = self.get_assertion(http, user)
        d["rawId"] = d["id"] = b64u(os.urandom(16))
        self.check("T11", "server: unknown credential ID", "UNKNOWN_CREDENTIAL", self.verify_login(http, d).get("reason"))

        self.say("UP flag: a silent (up=false) assertion is not accepted as a login")
        opts = http.post("/login/options", json={"username": user}).json()
        client_data = json.dumps({"type": "webauthn.get", "challenge": opts["challenge"],
                                  "origin": ORIGIN, "crossOrigin": False}).encode()
        resp = ctap.get_assertion(RP_ID, hashlib.sha256(client_data).digest(),
                                  [{"type": "public-key", "id": cred_id}], options={"up": False})
        silent = {"id": b64u(cred_id), "rawId": b64u(cred_id), "type": "public-key", "clientExtensionResults": {},
                  "response": {"clientDataJSON": b64u(client_data), "authenticatorData": b64u(bytes(resp.auth_data)),
                               "signature": b64u(resp.signature), "userHandle": None}}
        self.check("UP", "token did not set UP flag", False, bool(resp.auth_data.flags & 0x01))
        self.check("UP", "server rejects up=false assertion", "UP_NOT_SET", self.verify_login(http, silent).get("reason"))

        self.say("TH12 another session cannot add a key to an existing account")
        other = self.http()
        r = other.post("/register/options", json={"username": user})
        self.check("TH12", "register options for existing user", 403, r.status_code)

        self.say("Clone detection: counter regression is rejected")
        self.app.state.db.execute("UPDATE credentials SET sign_count = 1000000")
        e, _ = self.get_assertion(http, user)
        self.check("CLONE", "assertion with lower counter", "COUNTER_REGRESSION", self.verify_login(http, e).get("reason"))

        fails = sum(1 for r in self.results if r[4] == "FAIL")
        self.say(f"\n{len(self.results) - fails}/{len(self.results)} checks passed")
        return fails == 0
