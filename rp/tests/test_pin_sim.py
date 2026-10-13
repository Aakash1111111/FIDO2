"""PIN protocol interoperability and bypass tests against the real portable core.
These simulate storage/button/USB; they do not certify hardware or browsers.
"""
import hashlib
import pytest
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin
from test_e2e_sim import sim  # noqa: F401

PIN = "482916"

@pytest.fixture
def protected(sim):
    lib, dev = sim
    assert lib.sim_enable_pin() == 0
    ctap = Ctap2(dev)
    return lib, ctap


def error(code, call):
    with pytest.raises(CtapError) as exc:
        call()
    assert exc.value.code == code


def make(ctap, pin=PIN, rp="localhost", cdh=None):
    cdh = cdh or hashlib.sha256(b"registration").digest()
    cp = ClientPin(ctap)
    token = cp.get_pin_token(pin)
    return ctap.make_credential(cdh, {"id": rp, "name": rp},
                                {"id": b"alice", "name": "alice"},
                                [{"type": "public-key", "alg": -7}],
                                pin_uv_param=cp.protocol.authenticate(token, cdh), pin_uv_protocol=1)


def assertion(ctap, cred_id, token=None, pin=PIN, cdh=None, rp="localhost", **kwargs):
    cdh = cdh or hashlib.sha256(b"authentication").digest()
    cp = ClientPin(ctap)
    token = token or cp.get_pin_token(pin)
    return ctap.get_assertion(rp, cdh, [{"type": "public-key", "id": cred_id}],
                              pin_uv_param=cp.protocol.authenticate(token, cdh), pin_uv_protocol=1, **kwargs)


def test_setup_single_pin_two_sites_and_no_pin_bypass(protected):
    lib, ctap = protected
    assert ctap.get_info().options["clientPin"] is False
    assert ctap.get_info().pin_uv_protocols == [1]
    cp = ClientPin(ctap)
    error(CtapError.ERR.PIN_NOT_SET, lambda: cp.get_pin_token(PIN))
    cp.set_pin(PIN)
    ctap = Ctap2(ctap.device)
    assert ctap.get_info().options["clientPin"] is True
    for rp in ["localhost", "third-party.example"]:
        att = make(ctap, rp=rp)
        assert att.auth_data.is_user_verified() and att.auth_data.is_user_present()
        cid = att.auth_data.credential_data.credential_id
        error(CtapError.ERR.PUAT_REQUIRED, lambda: ctap.get_assertion(rp, bytes(32), [{"id":cid,"type":"public-key"}]))
        out = assertion(ctap, cid, rp=rp)
        assert out.auth_data.is_user_verified() and out.auth_data.counter == 1
    error(CtapError.ERR.PUAT_REQUIRED, lambda: ctap.make_credential(bytes(32), {"id":"localhost"},
          {"id":b"b"}, [{"type":"public-key","alg":-7}]))


def test_retry_lockouts_persist_across_power_cycle(protected):
    lib, ctap = protected
    ClientPin(ctap).set_pin(PIN)
    cp = ClientPin(Ctap2(ctap.device))
    for attempt in range(8):
        expected = CtapError.ERR.PIN_BLOCKED if attempt == 7 else \
                   CtapError.ERR.PIN_AUTH_BLOCKED if attempt in (2, 5) else CtapError.ERR.PIN_INVALID
        error(expected, lambda: cp.get_pin_token("000000"))
        assert cp.get_pin_retries()[0] == 7 - attempt
        if attempt in (2, 5):
            error(CtapError.ERR.PIN_AUTH_BLOCKED, lambda: cp.get_pin_token(PIN))
            assert lib.sim_power_cycle() == 0
            assert cp.get_pin_retries()[0] == 7 - attempt
    assert lib.sim_power_cycle() == 0
    error(CtapError.ERR.PIN_BLOCKED, lambda: cp.get_pin_token(PIN))


def test_change_pin_preserves_credentials_and_invalidates_tokens(protected):
    lib, ctap = protected
    ClientPin(ctap).set_pin(PIN)
    ctap = Ctap2(ctap.device); cp = ClientPin(ctap)
    cid = make(ctap).auth_data.credential_data.credential_id
    token = cp.get_pin_token(PIN)
    cp.change_pin(PIN, "935284")
    error(CtapError.ERR.PIN_TOKEN_EXPIRED, lambda: assertion(ctap, cid, token=token))
    error(CtapError.ERR.PIN_INVALID, lambda: cp.get_pin_token(PIN))
    assert assertion(ctap, cid, pin="935284").auth_data.is_user_verified()
    assert lib.sim_power_cycle() == 0
    assert assertion(ctap, cid, pin="935284").auth_data.is_user_verified()


def test_token_expiry_disconnect_consumption_and_wrong_rp(protected):
    lib, ctap = protected
    ClientPin(ctap).set_pin(PIN)
    ctap = Ctap2(ctap.device); cp = ClientPin(ctap)
    cid = make(ctap).auth_data.credential_data.credential_id
    token = cp.get_pin_token(PIN)
    assert assertion(ctap, cid, token=token).auth_data.is_user_verified()
    error(CtapError.ERR.PIN_TOKEN_EXPIRED, lambda: assertion(ctap, cid, token=token))
    token = cp.get_pin_token(PIN)
    lib.sim_advance_seconds(31)
    error(CtapError.ERR.PIN_TOKEN_EXPIRED, lambda: assertion(ctap, cid, token=token))
    token = cp.get_pin_token(PIN)
    assert lib.sim_disconnect() == 0
    error(CtapError.ERR.PIN_TOKEN_EXPIRED, lambda: assertion(ctap, cid, token=token))
    error(CtapError.ERR.NO_CREDENTIALS, lambda: assertion(ctap, cid, rp="evil.example"))
    token = cp.get_pin_token(PIN)
    probe = assertion(ctap, cid, token=token, options={"up":False})
    assert probe.auth_data.is_user_verified() and not probe.auth_data.is_user_present()
    assert assertion(ctap, cid, token=token).auth_data.is_user_present()


def test_presence_timeout_and_tampered_auth(protected):
    lib, ctap = protected
    ClientPin(ctap).set_pin(PIN)
    ctap = Ctap2(ctap.device); cp = ClientPin(ctap)
    cid = make(ctap).auth_data.credential_data.credential_id
    cp.get_pin_token(PIN)
    for i in range(3):
        error(CtapError.ERR.PIN_AUTH_BLOCKED if i==2 else CtapError.ERR.PIN_AUTH_INVALID,
              lambda: ctap.get_assertion("localhost", bytes(32), [{"id":cid,"type":"public-key"}],
                                         pin_uv_param=bytes(16), pin_uv_protocol=1))
    assert lib.sim_power_cycle() == 0
    lib.sim_set_up_mode(1)
    error(CtapError.ERR.USER_ACTION_TIMEOUT, lambda: assertion(ctap, cid))
    lib.sim_set_up_mode(0)
    assert assertion(ctap, cid).auth_data.counter == 1  # failed requests did not advance it


def test_failed_storage_and_corruption_fail_closed(protected):
    lib, ctap = protected
    ClientPin(ctap).set_pin(PIN)
    ctap = Ctap2(ctap.device); cp = ClientPin(ctap)
    lib.sim_fail_writes(1)
    error(CtapError.ERR.OTHER, lambda: cp.get_pin_token(PIN))
    lib.sim_fail_writes(0)
    error(CtapError.ERR.OTHER, lambda: ctap.get_info())
    assert lib.sim_power_cycle() == 0
    lib.sim_corrupt_pin()
    assert lib.sim_power_cycle() == -1
    error(CtapError.ERR.OTHER, lambda: cp.get_pin_token(PIN))


def test_reset_requires_window_and_presence_and_erases_all(protected):
    lib, ctap = protected
    ClientPin(ctap).set_pin(PIN)
    ctap = Ctap2(ctap.device)
    cid = make(ctap).auth_data.credential_data.credential_id
    lib.sim_set_up_mode(1)
    error(CtapError.ERR.USER_ACTION_TIMEOUT, lambda: ctap.reset())
    assert ctap.get_info().options["clientPin"]
    lib.sim_set_up_mode(0); lib.sim_advance_seconds(11)
    error(CtapError.ERR.NOT_ALLOWED, lambda: ctap.reset())
    assert lib.sim_power_cycle() == 0
    ctap.reset()
    assert ctap.get_info().options["clientPin"] is False
    ClientPin(ctap).set_pin(PIN)
    ctap = Ctap2(ctap.device)
    error(CtapError.ERR.NO_CREDENTIALS, lambda: assertion(ctap, cid))


def test_fido_client_to_rp_requires_pin_and_uv(protected, tmp_path):
    from fido2.client import Fido2Client, UserInteraction
    import rp_scenarios
    from app.config import load_settings
    from app.main import create_app
    from fastapi.testclient import TestClient
    lib, ctap = protected
    ClientPin(ctap).set_pin(PIN)
    class User(UserInteraction):
        def request_pin(self, permissions, rp_id): return PIN
    settings = load_settings({"DB_PATH":str(tmp_path / "rp.sqlite3")})
    http = TestClient(create_app(settings), base_url="http://localhost:8000")
    client = Fido2Client(ctap.device, "http://localhost:8000", user_interaction=User())
    o = http.post("/register/options", json={"username":"alice"}).json()
    assert o["authenticatorSelection"]["userVerification"] == "required"
    cred = rp_scenarios.attestation_json(client.make_credential(rp_scenarios.creation_options_to_fido2(o)))
    assert http.post("/register/verify",json={"credential":cred}).json()["ok"]
    o = http.post("/login/options",json={"username":"alice"}).json()
    assert o["userVerification"] == "required"
    sel = client.get_assertion(rp_scenarios.request_options_to_fido2(o))
    cred = rp_scenarios.assertion_json(sel.get_response(0))
    assert http.post("/login/verify",json={"credential":cred}).json()["ok"]


def test_server_rejects_valid_signature_without_uv(sim, tmp_path):
    from dataclasses import replace
    from app.config import load_settings
    from app.webauthn_service import verify_registration, verify_authentication
    from app.errors import RPError
    from fido2.client import Fido2Client
    import rp_scenarios
    lib, dev = sim  # legacy baseline: UP but no PIN/UV support
    s = load_settings({"DB_PATH": str(tmp_path / "rp.sqlite3")})
    runner = rp_scenarios.Runner(dev, db_path=s.db_path)
    http = runner.http()
    options = http.post("/register/options", json={"username":"alice"}).json()
    client = Fido2Client(dev, rp_scenarios.ORIGIN)
    att = client.make_credential(rp_scenarios.creation_options_to_fido2(options))
    cred = rp_scenarios.attestation_json(att)
    challenge = rp_scenarios.unb64u(options["challenge"])
    with pytest.raises(RPError): verify_registration(s, cred, challenge)
    verified, _ = verify_registration(replace(s, user_verification="discouraged"), cred, challenge)
    assert http.post("/register/verify", json={"credential":cred}).json()["ok"]
    options = http.post("/login/options", json={"username":"alice"}).json()
    sel = client.get_assertion(rp_scenarios.request_options_to_fido2(options))
    cred = rp_scenarios.assertion_json(sel.get_response(0))
    with pytest.raises(RPError):
        verify_authentication(s, cred, rp_scenarios.unb64u(options["challenge"]),
                              verified.credential_public_key, 0)


def test_short_pin_and_malformed_client_pin_requests(protected):
    lib, ctap = protected
    # Authenticate a too-short padded PIN using the reference PIN protocol.
    cp = ClientPin(ctap)
    peer, secret = cp._get_shared_secret()
    enc = cp.protocol.encrypt(secret, b"123" + bytes(61))
    error(CtapError.ERR.PIN_POLICY_VIOLATION, lambda: ctap.client_pin(1, 3, peer,
          cp.protocol.authenticate(secret, enc), enc))
    assert ctap.get_info().options["clientPin"] is False
    error(CtapError.ERR.INVALID_PARAMETER, lambda: ctap.client_pin(2, 1))
    error(CtapError.ERR.MISSING_PARAMETER, lambda: ctap.client_pin(1, 3))
    peer[-2] = bytes(32); peer[-3] = bytes(32)  # point is not on P-256
    error(CtapError.ERR.PIN_AUTH_INVALID, lambda: ctap.client_pin(1, 3, peer, bytes(16), bytes(64)))
