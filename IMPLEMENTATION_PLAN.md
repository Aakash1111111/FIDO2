# Implementation Plan

Status: **proposal awaiting approval.** The phases follow the build order [DECIDED] in H§20 (run code → USB → crypto → storage → CTAP2 → WebAuthn → end-to-end tests) and the deadline priority in H§HANDOFF: getInfo + makeCredential + getAssertion with button presence → local RP end to end → T07–T11 → latency and size.

**Who can execute what**
- **[C]** = Claude can do this in the cloud container: code, host-side unit tests, RP, harness code, docs.
- **[HW]** = needs the physical ESP32-S3 and a human (Author B): flashing, USB enumeration, button presses, browser ceremonies, measurements.

**Timeline against the deadline (30 Sep 2026)** [NEW]

| Day | Target |
|---|---|
| 27 Sep | P0–P1 done; P2–P6 code written with host tests green [C]; RP (P7) and frontend (P8) done [C]; Author B flashes P1/P2 [HW] |
| 28 Sep | P2–P6 verified on hardware [HW]; P9 end-to-end in the browser; P10 security tests |
| 29 Sep | P11 measurements (N trials); P12 analysis → tables/figures; evidence screenshots |
| 30 Sep | Paper integration only. **No new features.** Stretch items become "future work / not implemented" |

If a hardware phase slips, the fallback is to report only what was verified and label the rest as proposed. No result is fabricated (H§28).

---

## Phase 0 — Environment and reproducibility setup
- **Goal:** pinned, documented toolchains on the development machine and on Author B's machine.
- **Files:** `README.md`, `firmware/sdkconfig.defaults`, `firmware/main/idf_component.yml`, `rp/pyproject.toml`, `harness/pyproject.toml`, `tools/70-fido-esp32.rules`, `.gitignore`, `.github/workflows/ci.yml` (host tests + RP tests + optional ESP-IDF build through the `espressif/idf` container).
- **Dependencies:** answers to Q1 (board) and Q8 (backend stack).
- **Tasks:** pin the ESP-IDF version (e.g., v5.3.x); install it; add managed components `espressif/esp_tinyusb` and `espressif/cbor` (versions locked in `dependencies.lock`); set up a Python 3.11 venv with locked requirements; add the udev rule (Linux); write the environment capture script stub.
- **Output:** `idf.py build` of an empty app succeeds; `pytest` runs (0 tests); CI green.
- **Tests:** CI job runs.
- **Done when:** a fresh clone + README steps reproduce the build on a second machine (Author B confirms) [HW].

## Phase 1 — Firmware skeleton and HAL
- **Goal:** the board boots, logs over UART, reads the button, and timestamps work (**T02**).
- **Files:** `firmware/main/main.c`, `components/fido_core/include/hal.h`, `components/hal_esp32s3/{button_gpio,rng_esp,time_esp,log}.c`, `partitions.csv` (`fido` NVS partition), `Kconfig.projbuild` (`FIDO_UP_GPIO`, `FIDO_UP_TIMEOUT_MS`, `FIDO_METRICS`).
- **Dependencies:** P0; Q4 (GPIO).
- **Tasks:** init order per ARCHITECTURE §2.3; button debounce (active-low, 20 ms); `EVT,BUTTON` log; RNG init (see R-RNG); `BOOT_OK` line.
- **Output:** boot log on the UART port; a button press is logged.
- **Tests:** [HW] T02; [C] host build compiles `fido_core` against a fake HAL.
- **Done when:** T02 passes 3 consecutive power cycles; boot log saved to `docs/evidence/`.

## Phase 2 — USB HID enumeration
- **Goal:** the host sees a FIDO HID device on the native USB port (**T01**).
- **Files:** `hal_esp32s3/usb_hid_tinyusb.c` (device/config/HID report descriptors: usage page 0xF1D0, usage 0x01, 64-byte IN/OUT, interrupt endpoints).
- **Dependencies:** P1; Q1 (which connector is native USB).
- **Tasks:** TinyUSB config; VID/PID (see R-VIDPID); serial string; RX callback → CTAPHID input; TX function with a completion wait.
- **Output:** `lsusb -v` / `usbhid-dump` shows the FIDO usage page; Chrome's `chrome://device-log` lists the device.
- **Tests:** [HW] T01; the `python-fido2` `list_devices()` finds it.
- **Done when:** descriptor dump saved to `docs/evidence/`; it enumerates on at least 2 host OSes (or 1, with the limitation noted).

## Phase 3 — CTAPHID transport
- **Goal:** correct framing, channels and errors (**T03, T04**).
- **Files:** `fido_core/ctaphid/{ctaphid.c,ctaphid.h}`, `fido_core/up/` (keepalive/cancel hooks), `firmware/test/host/test_ctaphid.c`.
- **Dependencies:** P2 for on-device checks; host tests can run first [C].
- **Tasks:** INIT (broadcast CID, nonce echo, CID allocation, capabilities); PING; ERROR codes; multi-packet reassembly up to max message size; SEQ checks; inter-packet timeout; CHANNEL_BUSY; CANCEL; KEEPALIVE sender; response fragmentation.
- **Output:** a device that answers INIT/PING and rejects malformed packets.
- **Tests:** host unit tests (≥20 cases, including every error code); [HW] harness T03 (PING at 1/57/64/512/1024/7609 B) and T04 (malformed-packet suite).
- **Done when:** all host tests pass; T03/T04 pass on the device; the device is still responsive after the whole T04 suite.

## Phase 4 — Crypto module
- **Goal:** vetted P-256/SHA-256 primitives with zeroization.
- **Files:** `fido_core/fido_crypto/{crypto.c,crypto.h,cose.c}`, `firmware/test/host/test_crypto.c`, `firmware/test/host/verify_sig.py`.
- **Dependencies:** P0.
- **Tasks:** DRBG seeding from the HAL RNG; keygen; public key export (uncompressed x,y); COSE_Key canonical encode; ECDSA sign → DER; SHA-256; `crypto_zeroize`.
- **Output:** a crypto API used by ctap2.
- **Tests:** host: sign → verify with Python `cryptography` (independent implementation); NIST P-256 test vector for SHA-256; COSE bytes decoded by `cbor2` and checked; [HW] timing of keygen/sign on the target (feeds M1/M2 sub-phases).
- **Done when:** cross-verification passes 1000/1000 random messages on the host and 50/50 on the device.

## Phase 5 — Credential store
- **Goal:** persistent, integrity-checked records (**T06** foundation).
- **Files:** `fido_core/cred_store/{record.c,store.c,store.h}`, `hal_esp32s3/nvs_kv.c`, `firmware/test/host/test_store.c`.
- **Dependencies:** P4 (record holds the key); P1 (NVS partition).
- **Tasks:** record codec (version, CRC32); put/get/find-by-(credId, rpIdHash)/count/update-counter; atomic commit; boot validation and quarantine; capacity limit → `KEY_STORE_FULL`; measure M7.
- **Output:** a store API with RAM and NVS backends.
- **Tests:** host (RAM backend): codec round-trip, corruption detection, capacity; [HW] reboot persistence, counter persistence across reboot, `nvs_get_stats` per credential.
- **Done when:** a record written, board power-cycled, record read back and valid; M7 measured.

## Phase 6 — CTAP2 core (getInfo, makeCredential, getAssertion, user presence)
- **Goal:** a browser-acceptable authenticator (**T05, T11 CTAP-level, T-UP**).
- **Files:** `fido_core/ctap2/{cbor_util.c,dispatch.c,get_info.c,make_credential.c,get_assertion.c,status.h}`, `fido_core/up/up.c`, `fido_core/auth_state/`, `fido_core/metrics/`, host tests with **captured real browser CBOR requests** as vectors.
- **Dependencies:** P3, P4, P5; Q3, Q5, Q6, Q7, Q12.
- **Tasks:** getInfo (canonical CBOR); makeCredential: param validation, ES256 check, excludeList, `rk`/`uv` option handling, zero-length `pinAuth` probe handling [SPEC-VERIFY], UP wait, keygen, store, authData (UP|AT), attestation (packed self or none); getAssertion: allowList + rpIdHash match, `up:false` silent probe (no wait, UP flag clear), UP wait, counter-before-sign, authData, sign; METRIC instrumentation excluding the UP wait.
- **Output:** a token that completes CTAP2 ceremonies with python-fido2.
- **Tests:** host: every status-code path; authData byte layout vs the spec; response parses with `python-fido2`'s own parsers (in host tests via a Python shim). [HW] harness T05, T11 (random credId), T10a (other rpId), T-UP (no press → timeout), T-CNT.
- **Done when:** `python-fido2`'s `Ctap2` client completes makeCredential + getAssertion against the board, and the signature verifies independently.

## Phase 7 — Local relying party backend (in parallel with P1–P6) [C]
- **Goal:** full server-side WebAuthn verification with evidence logging.
- **Files:** `rp/app/*` per ARCHITECTURE §3; `rp/tests/*`.
- **Dependencies:** Q8, Q7 (attestation policy), Q-ENUM.
- **Tasks:** config validation; SQLite schema (spec §12.1); challenge issue/consume/expire; four H§18 endpoints plus `/me`, `/logout`, `/healthz`; py_webauthn calls isolated in `webauthn_service.py`; reason-code mapping; `auth_events`; credential-injection rule; cookie/CSP headers; experiment endpoint behind a flag.
- **Output:** `uvicorn app.main:app` serving on `http://localhost:8000`.
- **Tests:** pytest with a **test-only** software authenticator: happy path reg/auth; each reason code (challenge missing/expired/mismatch/replayed, origin, rpIdHash, UP not set, bad signature, counter regression, unknown credential, unsupported alg, injection rule).
- **Done when:** all RP tests pass in CI; coverage of `webauthn_service.py` + `challenges.py` ≥ 90%.

## Phase 8 — Frontend [C]
- **Goal:** a usable page for T07/T08 and screenshots.
- **Files:** `rp/static/{index.html,app.js,webauthn.js,styles.css}`.
- **Dependencies:** P7.
- **Tasks:** username + two buttons; base64url helpers; create/get calls; result/error display; `performance.now()` timings posted to the verify endpoints; secure-context/feature checks.
- **Output:** the page works with a virtual authenticator.
- **Tests:** optional Playwright + CDP virtual authenticator E2E (RP validation only).
- **Done when:** register + login succeed in headless Chromium with a virtual authenticator in CI.

## Phase 9 — End-to-end integration with the real token [HW]
- **Goal:** registration success criteria (spec §8) satisfied in real browsers (**T07, T08**, T06 at system level).
- **Dependencies:** P6, P7, P8; Q9.
- **Tasks:** run the RP locally; register → login in Chrome (then Firefox, Edge if available); replug the token → login again; capture screenshots, serial logs and `auth_events`.
- **Output:** evidence for contributions 1–4 (H§4).
- **Tests:** T06, T07, T08 in each tested browser.
- **Done when:** all five success criteria are met in ≥1 browser, with evidence stored in `docs/evidence/`.

## Phase 10 — Security and negative testing [C code, HW run]
- **Goal:** evidence for the threat model (**T04, T09, T10, T11, T-UP, T-RST, T-CNT**).
- **Files:** `harness/fidoharness/tests/*`, `harness/fidoharness/rawhid.py`, `harness/fidoharness/rp_client.py`.
- **Dependencies:** P6, P7.
- **Tasks:** the harness acts as a scripted client: it builds clientDataJSON, gets real assertions from the token and submits them to the RP with manipulations (replay, altered challenge, wrong origin, expired challenge); CTAP-level wrong rpId and unknown credId; malformed HID suite; restart-mid-state (manual unplug prompts); log scan for key material.
- **Output:** `results/<run_id>/security.csv` (test, expected, observed, pass).
- **Tests:** these are the tests.
- **Done when:** every row passes, or a failure is explained and fixed/documented; `docs/security_analysis.md` maps each threat → test → result.

## Phase 11 — Performance and resource measurement [C code, HW run]
- **Goal:** M1–M8 over N trials (**T12**).
- **Files:** `harness/run_experiment.py`, `harness/fidoharness/serial_metrics.py`, `harness/analysis/report.py`.
- **Dependencies:** P9, P10; Q9 (N), Q13.
- **Tasks:** warm-up runs discarded (e.g., 3); N makeCredential + N getAssertion trials with human button presses (UP wait recorded separately); PING latency sweep; `idf.py size` / `size-components`; heap/stack after the run; NVS stats; browser M4 over a smaller manual sample (e.g., 10 trials per browser); capture the environment.
- **Output:** `results/<run_id>/{metrics.csv, ping.csv, size.txt, env.json, uart.log}`.
- **Tests:** a sanity check script flags outliers or missing METRIC lines.
- **Done when:** complete CSVs for the agreed N, committed, with the run ID noted.

## Phase 12 — Analysis and paper integration
- **Goal:** tables and figures traceable to raw data.
- **Files:** `harness/analysis/report.py` → `results/<run_id>/report.md` (+ LaTeX tables, plots); `docs/test_results.md`.
- **Dependencies:** P11.
- **Tasks:** stats per spec §17; T01–T12 pass/fail table; resource table; limitations updated with facts (hardening on/off, browsers tested); figure-correction checklist (spec §7–8); verify every claim in H§4 has evidence.
- **Done when:** Author A can paste tables with no manual number entry.

## Phase 13 — Stretch (only if P0–P12 are done before 29 Sep evening)
In this order: (a) CTAP1/U2F over CTAPHID_MSG (+ `U2F_V2` in getInfo, flip NMSG); (b) discoverable credentials + getNextAssertion; (c) hardened build (flash encryption + secure boot + JTAG disable) measured once. **Warning:** enabling secure boot/flash encryption in release mode is irreversible on the chip; see R-HARDEN. Each stretch item needs its own tests before it is claimed.

## Phase 14 — Documentation (continuous)
- The README status matrix is updated at the end of every phase (Proposed / Implemented / Tested / Evidence).
- An ADR in `docs/decisions/` for every approved Q-item decision.
- ARCHITECTURE/SPEC updated in the same commit as any architectural change.
