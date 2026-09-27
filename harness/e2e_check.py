#!/usr/bin/env python3
"""End-to-end security/functional check against the REAL ESP32-S3 token.

Runs T07, T08, T09, T10, T11, T-CNT, the UP-flag check, TH12 and clone
(counter-regression) detection with the relying party running in-process.
You will be asked to press the BOOT button several times (~10 presses with
the default settings).

Windows: run from an Administrator terminal (direct FIDO HID access).
    python -m pip install -r rp/requirements.txt "fido2>=1.1,<2"
    python harness/e2e_check.py --out results/phase3_e2e
"""
import argparse
import csv
import os
import platform
import sys
import time

from fido2.hid import CtapHidDevice

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rp_scenarios  # noqa: E402

VID, PID = 0x303A, 0x4004


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="results/phase3_e2e")
    ap.add_argument("--login-trials", type=int, default=3, help="successful logins in T08 (each needs a press)")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    dev = next((d for d in CtapHidDevice.list_devices()
                if d.descriptor.vid == VID and d.descriptor.pid == PID), None)
    if dev is None:
        sys.exit("Token not found: connect the NATIVE USB port (and use an Administrator terminal on Windows).")
    print(f"Token found: {dev.descriptor.product_name} (device version {dev.device_version})")

    runner = rp_scenarios.Runner(dev, db_path=os.path.join(args.out, "rp.sqlite3"))
    ok = runner.run(login_trials=args.login_trials)

    with open(os.path.join(args.out, "checks.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["test", "case", "expected", "observed", "result"])
        w.writerows(runner.results)
    with open(os.path.join(args.out, "login_timings.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ceremony", "trial", "host_total_ms_incl_button", "server_verify_ms"])
        w.writerows(runner.timings)
    http = runner.http()
    events = http.get("/experiment/events.csv", headers={"X-Admin-Token": "research-admin-token-0001"}).text
    with open(os.path.join(args.out, "auth_events.csv"), "w", newline="") as f:
        f.write(events)
    import fido2
    with open(os.path.join(args.out, "environment.txt"), "w") as f:
        f.write(f"host_os={platform.platform()}\npython={platform.python_version()}\n"
                f"python_fido2={fido2.__version__}\ndevice_version={dev.device_version}\n"
                f"run_id={runner.run_id}\ndate={time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    print(f"Results written to {args.out}/")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
