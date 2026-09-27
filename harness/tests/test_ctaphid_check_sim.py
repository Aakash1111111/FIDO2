"""Runs harness/ctaphid_check.py end-to-end against the firmware's CTAPHID code
compiled for the host (harness/sim). Validates the harness logic only; the
numbers it produces are NOT token measurements.

    python harness/tests/test_ctaphid_check_sim.py
"""
import ctypes
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "harness"))

from fido2.hid import CtapHidDevice  # noqa: E402
from fido2.hid.base import CtapHidConnection, HidDescriptor  # noqa: E402

import ctaphid_check  # noqa: E402


def build_sim():
    out = os.path.join(tempfile.mkdtemp(), "libsimtoken.so")
    core = os.path.join(ROOT, "firmware", "components", "fido_core")
    subprocess.check_call(["cc", "-shared", "-fPIC", "-O1", "-Wall", "-Werror",
                           "-I", os.path.join(core, "include"),
                           os.path.join(HERE, "..", "sim", "sim_token.c"),
                           os.path.join(core, "ctaphid", "ctaphid.c"), "-o", out])
    return ctypes.CDLL(out)


class SimConnection(CtapHidConnection):
    def __init__(self, lib):
        self.lib = lib

    def write_packet(self, data):
        assert len(data) == 64
        self.lib.sim_write(ctypes.c_char_p(bytes(data)))

    def read_packet(self):
        buf = ctypes.create_string_buffer(64)
        while not self.lib.sim_read(buf):
            time.sleep(0.005)
        return buf.raw

    def close(self):
        pass


def main():
    lib = build_sim()
    lib.sim_init()
    desc = HidDescriptor("sim", 0x303A, 0x4004, 64, 64, "ESP32-S3 FIDO2 Token (SIM)", None)
    CtapHidDevice.list_devices = classmethod(lambda cls: iter([CtapHidDevice(desc, SimConnection(lib))]))
    sys.argv = ["ctaphid_check.py", "--trials", "3", "--out", tempfile.mkdtemp()]
    rc = ctaphid_check.main()
    print("SIM RESULT:", "OK" if rc == 0 else "FAIL")
    return rc


if __name__ == "__main__":
    sys.exit(main())
