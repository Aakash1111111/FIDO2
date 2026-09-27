#!/usr/bin/env python3
"""Phase 2 hardware check for the ESP32-S3 FIDO token (tests T01, T03, T04, metric M3).

Talks to the token directly over USB HID with python-fido2 (no browser).

  T01  the token enumerates as a FIDO HID device (usage page 0xF1D0)
  T03  CTAPHID_INIT and PING with payloads from 0 to 7609 bytes echo correctly
  T04  malformed packets are rejected with the correct CTAPHID error and the
       token stays responsive
  M3   PING round-trip latency per payload size -> CSV

Windows: run from an **Administrator** terminal (Windows only lets elevated
processes open FIDO HID devices directly). Linux: needs a udev rule or sudo.

  python -m pip install "fido2>=1.1,<2"
  python harness/ctaphid_check.py --trials 50 --out results/phase2_ctaphid
"""
import argparse
import concurrent.futures
import csv
import os
import platform
import statistics
import struct
import sys
import time

try:
    from fido2.ctap import CtapError
    from fido2.hid import CTAPHID, CtapHidDevice
except ImportError:
    sys.exit('python-fido2 is missing: python -m pip install "fido2>=1.1,<2"')

VID, PID = 0x303A, 0x4004
BROADCAST = 0xFFFFFFFF
# Raw command bytes as they appear on the wire (python-fido2's CTAPHID enum
# omits the 0x80 "initialization packet" bit).
PING, LOCK, INIT, CBOR, ERROR, VENDOR_C0 = 0x81, 0x84, 0x86, 0x90, 0xBF, 0xC0
ERR = {0x01: "INVALID_CMD", 0x02: "INVALID_PAR", 0x03: "INVALID_LEN", 0x04: "INVALID_SEQ",
       0x05: "MSG_TIMEOUT", 0x06: "CHANNEL_BUSY", 0x0B: "INVALID_CHANNEL", 0x7F: "OTHER"}
PING_SIZES = [0, 1, 57, 58, 64, 116, 117, 512, 1024, 4096, 7609]

results = []  # (test, case, expected, observed, pass)


def record(test, case, expected, observed):
    ok = expected == observed
    results.append((test, case, str(expected), str(observed), "PASS" if ok else "FAIL"))
    print(f"  [{'PASS' if ok else 'FAIL'}] {test} {case}: expected {expected}, got {observed}")
    return ok


def find_token():
    devs = list(CtapHidDevice.list_devices())
    for d in devs:
        if d.descriptor.vid == VID and d.descriptor.pid == PID:
            return d
    names = [f"{d.descriptor.vid:04x}:{d.descriptor.pid:04x}" for d in devs]
    sys.exit(f"Token {VID:04x}:{PID:04x} not found. FIDO devices seen: {names or 'none'}.\n"
             "Is the NATIVE USB port connected? On Windows, is this an Administrator terminal?")


def raw_packet(cid, b4, payload=b"", bcnt=None):
    if b4 & 0x80:
        hdr = struct.pack(">IBH", cid, b4, len(payload) if bcnt is None else bcnt)
    else:
        hdr = struct.pack(">IB", cid, b4)
    return (hdr + payload).ljust(64, b"\0")[:64]


def read_with_timeout(conn, timeout=3.0):
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        return ex.submit(conn.read_packet).result(timeout=timeout)
    finally:
        ex.shutdown(wait=False)  # a stuck read must not block the harness


def expect_error(dev, test, case, packets, want_code, want_cid, delay=0.0):
    conn = dev._connection  # raw access: python-fido2's public API never sends malformed packets
    for i, p in enumerate(packets):
        if delay and i == len(packets) - 1:
            time.sleep(delay)
        conn.write_packet(p)
    try:
        resp = read_with_timeout(conn)
    except concurrent.futures.TimeoutError:
        record(test, case, f"ERROR {ERR[want_code]}", "no response (timeout)")
        # The abandoned read would swallow later replies, so stop here.
        sys.exit("Token did not answer; aborting (replug the token and rerun).")
    cid, cmd = struct.unpack(">IB", resp[:5])
    observed = f"ERROR {ERR.get(resp[7], hex(resp[7]))}" if cmd == ERROR else f"cmd {cmd:#x}"
    ok = record(test, case, f"ERROR {ERR[want_code]}", observed)
    if cid != want_cid:
        record(test, case + " (reply CID)", hex(want_cid), hex(cid))
        ok = False
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=50, help="PING trials per payload size (M3)")
    ap.add_argument("--out", default="results/phase2_ctaphid", help="output directory for CSV files")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    print("T01 enumeration")
    dev = find_token()
    d = dev.descriptor
    record("T01", "VID:PID", f"{VID:04x}:{PID:04x}", f"{d.vid:04x}:{d.pid:04x}")
    record("T01", "report size in/out", "64/64", f"{d.report_size_in}/{d.report_size_out}")
    print(f"  product={d.product_name!r} ctaphid_version={dev.version} "
          f"device_version={dev.device_version} capabilities={dev.capabilities:#04x}")
    record("T03", "INIT protocol version", 2, dev.version)
    record("T03", "capabilities (CBOR|NMSG)", "0x0c", f"{dev.capabilities:#04x}")

    print("T03 PING echo + M3 latency")
    rows = []
    for size in PING_SIZES:
        lat = []
        for t in range(args.trials):
            payload = os.urandom(size)
            t0 = time.perf_counter_ns()
            echo = dev.ping(payload)
            dt = (time.perf_counter_ns() - t0) / 1e6
            if echo != payload:
                record("T03", f"PING {size} B trial {t}", "echo", "mismatch")
                break
            lat.append(dt)
            rows.append({"payload_bytes": size, "trial": t, "rtt_ms": f"{dt:.3f}"})
        else:
            record("T03", f"PING {size} B x{args.trials}", "echo", "echo")
            print(f"      mean {statistics.mean(lat):.2f} ms, median {statistics.median(lat):.2f} ms, "
                  f"min {min(lat):.2f}, max {max(lat):.2f}")
    with open(os.path.join(args.out, "ping_rtt.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["payload_bytes", "trial", "rtt_ms"])
        w.writeheader()
        w.writerows(rows)

    print("CBOR / MSG placeholders (Phase 2: CTAP2 not implemented yet)")
    resp = dev.call(CTAPHID.CBOR, b"\x04")
    record("P2", "getInfo -> CTAP1_ERR_INVALID_COMMAND", "01", resp.hex())

    print("T04 malformed packets")
    cid = dev._channel_id
    expect_error(dev, "T04", "unknown command 0xC0", [raw_packet(cid, VENDOR_C0)], 0x01, cid)
    expect_error(dev, "T04", "LOCK not supported", [raw_packet(cid, LOCK, b"\x01")], 0x01, cid)
    expect_error(dev, "T04", "BCNT 7610 > max", [raw_packet(cid, PING, bcnt=7610)], 0x03, cid)
    expect_error(dev, "T04", "BCNT 0xFFFF", [raw_packet(cid, PING, bcnt=0xFFFF)], 0x03, cid)
    expect_error(dev, "T04", "INIT with 7-byte nonce",
                 [raw_packet(BROADCAST, INIT, b"\x01" * 7)], 0x03, BROADCAST)
    expect_error(dev, "T04", "CID 0", [raw_packet(0, PING, b"x")], 0x0B, 0)
    expect_error(dev, "T04", "PING on broadcast CID", [raw_packet(BROADCAST, PING, b"x")],
                 0x0B, BROADCAST)
    expect_error(dev, "T04", "unallocated CID", [raw_packet(0x7FFFFFF0, PING, b"x")],
                 0x0B, 0x7FFFFFF0)
    expect_error(dev, "T04", "wrong continuation SEQ",
                 [raw_packet(cid, PING, b"a" * 57, bcnt=100), raw_packet(cid, 1, b"b" * 43)],
                 0x04, cid)
    expect_error(dev, "T04", "empty CBOR request", [raw_packet(cid, CBOR, bcnt=0)], 0x03, cid)
    expect_error(dev, "T04", "incomplete message times out (0.5 s)",
                 [raw_packet(cid, PING, b"a" * 57, bcnt=100)], 0x05, cid)

    print("T04 token still responsive")
    try:
        record("T04", "PING after malformed suite", "echo", "echo" if dev.ping(b"alive") == b"alive" else "bad")
    except (CtapError, OSError) as e:
        record("T04", "PING after malformed suite", "echo", repr(e))

    with open(os.path.join(args.out, "checks.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["test", "case", "expected", "observed", "result"])
        w.writerows(results)
    with open(os.path.join(args.out, "environment.txt"), "w") as f:
        import fido2
        f.write(f"host_os={platform.platform()}\npython={platform.python_version()}\n"
                f"python_fido2={fido2.__version__}\ntrials={args.trials}\n"
                f"device_version={dev.device_version}\nproduct={d.product_name}\n"
                f"date={time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    fails = sum(1 for r in results if r[4] == "FAIL")
    print(f"\n{len(results) - fails}/{len(results)} checks passed. CSVs written to {args.out}/")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
