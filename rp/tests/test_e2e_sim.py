"""CI end-to-end test: firmware logic (compiled for the host, simulated button)
<-> python-fido2 client <-> relying party. Validates code paths only; the
software token is NOT the hardware token and produces no research results.

Requires the sim library built by firmware/test/host (CMake target sim_token):
    SIM_TOKEN_LIB=/path/to/libsim_token.so pytest rp/tests
"""
import ctypes
import os
import sys
import time

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "harness"))

from fido2.hid import CtapHidDevice  # noqa: E402
from fido2.hid.base import CtapHidConnection, HidDescriptor  # noqa: E402

LIB = os.environ.get("SIM_TOKEN_LIB")


class SimConnection(CtapHidConnection):
    def __init__(self, lib):
        self.lib = lib

    def write_packet(self, data):
        self.lib.sim_write(ctypes.c_char_p(bytes(data)))

    def read_packet(self):
        buf = ctypes.create_string_buffer(64)
        while not self.lib.sim_read(buf):
            time.sleep(0.001)
        return buf.raw

    def close(self):
        pass


@pytest.fixture()
def sim():
    if not LIB or not os.path.exists(LIB):
        pytest.skip("SIM_TOKEN_LIB not set (build firmware/test/host first)")
    lib = ctypes.CDLL(LIB)
    assert lib.sim_init() == 0
    desc = HidDescriptor("sim", 0x303A, 0x4004, 64, 64, "sim", None)
    return lib, CtapHidDevice(desc, SimConnection(lib))


def test_all_scenarios(sim, tmp_path):
    import rp_scenarios
    lib, dev = sim
    runner = rp_scenarios.Runner(dev, say=print, db_path=str(tmp_path / "rp.sqlite3"))
    assert runner.run(login_trials=3), [r for r in runner.results if r[4] == "FAIL"]


def test_get_info(sim):
    from fido2.ctap2 import Ctap2
    lib, dev = sim
    info = Ctap2(dev).get_info()
    assert info.versions == ["FIDO_2_0"]
    assert info.aaguid.hex() == "ba17f247df2846ce819d8488f3b2278c"
    assert info.options == {"rk": False, "up": True, "plat": False}
    assert info.max_msg_size == 1200


def test_no_button_press_times_out(sim, tmp_path):
    from fido2.client import ClientError
    import rp_scenarios
    lib, dev = sim
    runner = rp_scenarios.Runner(dev, say=print, db_path=str(tmp_path / "rp.sqlite3"))
    http = runner.http()
    v, _ = runner.register(http, "bob")
    assert v["ok"]
    lib.sim_set_up_mode(1)       # simulated: nobody presses the button
    with pytest.raises(ClientError):
        runner.get_assertion(http, "bob")


def test_dashboard_and_admin(sim, tmp_path):
    import rp_scenarios
    lib, dev = sim
    runner = rp_scenarios.Runner(dev, say=print, db_path=str(tmp_path / "rp.sqlite3"))
    http = runner.http()
    assert http.get("/me").status_code == 401
    v, cred = runner.register(http, "carol")
    me = http.get("/me").json()
    assert me["username"] == "carol" and len(me["credentials"]) == 1
    assert me["credentials"][0]["is_project_token"] is True
    assert "public_key" not in me["credentials"][0]
    assert http.delete(f"/credentials/{cred['id']}").json()["reason"] == "LAST_CREDENTIAL"
    assert http.get("/admin/api").status_code == 403
    adm = http.get("/admin/api", headers={"X-Admin-Token": "research-admin-token-0001"}).json()
    assert adm["users"][0]["username"] == "carol"
    csv = http.get("/experiment/events.csv", headers={"X-Admin-Token": "research-admin-token-0001"}).text
    assert csv.startswith("id,ts,run_id") and "success" in csv
    assert http.get("/").headers["content-security-policy"].startswith("default-src 'self'")
