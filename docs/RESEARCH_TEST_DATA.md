# Research Test Data: FIDO2/U2F Authentication Token on ESP32-S3

**Paper:** *Design and Implementation of a FIDO2/U2F Compliant Authentication Token for Secure Passwordless Authentication*
**Data as of:** 27 September 2026 · repository branch `claude/fido2-research-plan-j7rtm4`
**Raw data:** `results/` · **Hardware record:** `docs/evidence/hardware_record.md` · **Design:** `PROJECT_SPECIFICATION.md`, `ARCHITECTURE.md`, `docs/decisions/`

---

## 0. How to use this document (read first)

Every number below carries one of these evidence labels. **Only 🟢 items may be reported as measured results of the hardware token.**

| Label | Meaning | May the paper report it as a token result? |
|---|---|---|
| 🟢 **HW-MEASURED** | Measured on the physical ESP32-S3-N16R8 board | **Yes** |
| 🔵 **BUILD** | Output of the firmware build tools (size, memory map) | Yes, as build/resource figures (state the ESP-IDF version) |
| 🟡 **SW-VERIFIED** | The firmware's own C code, compiled for a PC and tested there (unit tests, fuzzing, and a software stand-in for the token with a *simulated* button) | Only as "implementation verification" or "software validation", **never as hardware results** |
| ⚪ **DERIVED** | Calculated from measured values (formula shown) | Only as an estimate, labelled as such |
| 🔴 **PENDING** | Not yet run on hardware | **No.** Leave the placeholder or omit it |

Rules carried over from the research handoff (H§28): no fabricated numbers; no claim of FIDO certification, tamper resistance or commercial interoperability unless proven; keep proposed / implemented / tested / future work separate.

---

## 1. Experimental setup

### 1.1 Hardware 🟢 (from `esptool.py flash_id` and Windows `Get-PnpDevice`, 27 Sep 2026)

| Item | Value |
|---|---|
| Board | ESP32-S3-N16R8 development board, two USB-C ports |
| SoC | ESP32-S3 (QFN56), silicon revision v0.2, dual-core Xtensa LX7 |
| Clock | 40 MHz crystal; CPU configured at **240 MHz** (run 2) / 160 MHz (run 1) |
| Flash | 16 MB, quad SPI (eFuse), 3.3 V, DIO mode 80 MHz, chip vendor "boya" |
| PSRAM | 8 MB embedded (AP_3v3). **Disabled in firmware** so keys stay in on-chip SRAM |
| Radios | Wi-Fi and BLE present, **unused** |
| USB-to-UART port | WCH CH343, `USB\VID_1A86&PID_55D3`, Windows COM8 (flashing and logs) |
| Native USB port | FIDO HID interface of the token: VID 0x303A, PID 0x4004 (Espressif test IDs) |
| User-presence button | On-board BOOT button, GPIO0, active low |
| Host PC | Windows (exact version: 🔴 record with `winver`) |

### 1.2 Software

| Item | Version | Where |
|---|---|---|
| Firmware framework (device builds) | **ESP-IDF v5.3.6** | Implementer's Windows PC 🟢 |
| Crypto library on device | **mbedTLS 3.6.7** (bundled with ESP-IDF) | Boot log `EVT,ENV` 🟢 |
| Cloud/CI firmware build | ESP-IDF v5.3.2, mbedTLS 3.6.2 | Size figures in §4 🔵 |
| Host unit tests | mbedTLS 3.6.2, GCC with AddressSanitizer + UndefinedBehaviorSanitizer | 🟡 |
| USB stack | TinyUSB via esp_tinyusb 1.7.6~1 (tinyusb 0.18.x) | |
| Flash tool | esptool.py v4.12.0 | 🟢 |
| Relying party | Python 3.11, FastAPI 0.141.1, **py_webauthn 2.7.1**, SQLite | |
| Test client | python-fido2 1.2.0 | |
| Independent crypto verifier | pyca/cryptography (OpenSSL backend), cbor2 | 🟡 |

### 1.3 Firmware configuration

| Parameter | Value |
|---|---|
| Firmware versions measured | 0.1.0-phase1 (run 1), 0.1.1-phase1 (run 2) |
| Compiler optimisation | `-Og` (run 1) → `-O2` (run 2) |
| mbedTLS options | ECDSA deterministic (RFC 6979) ON; P-256 ON; HW SHA + HW MPI acceleration ON; ECP fixed-point tables OFF (run 1) → ON (run 2); NIST-optimised reduction ON |
| DRBG | CTR-DRBG (AES-256), seeded from HW RNG (SAR-ADC entropy source enabled); run 1: prediction resistance on every call; run 2 onward: explicit reseed before each key generation |
| Hardening in build | Stack protector (strong), memory protection ON. Flash encryption / secure boot / JTAG disable: **OFF** (limitation) |
| Partition table | nvs 24 KB @0x9000 · phy_init 4 KB @0xF000 · factory app 2 MB @0x10000 · **fido** (credentials) 256 KB @0x210000 |

---

## 2. Protocol and design parameters (as implemented)

| Parameter | Value | Source / tag |
|---|---|---|
| Transport | USB HID, usage page 0xF1D0, usage 0x01, 64-byte IN/OUT reports, no report ID, 5 ms poll interval | CTAP 2.x §11.2 |
| CTAPHID max message | 7609 bytes (57 + 128 × 59) | CTAP 2.x |
| CTAPHID capabilities flag | 0x0C (CBOR supported; NMSG = U2F `CTAPHID_MSG` not implemented) | |
| CTAPHID inter-packet timeout | 500 ms | Project |
| CTAP version advertised | `FIDO_2_0` only | Project (Q12) |
| Commands implemented | authenticatorGetInfo (0x04), authenticatorMakeCredential (0x01), authenticatorGetAssertion (0x02) | |
| getInfo options | rk = false, up = true, plat = false; no clientPin, no uv; maxMsgSize 1200 | |
| AAGUID | `ba17f247-df28-46ce-819d-8488f3b2278c` (random, self-assigned, not in FIDO MDS) | |
| Algorithm | ECDSA P-256 + SHA-256 (COSE ES256, alg −7) | H§10 |
| Signed data | `authenticatorData ‖ clientDataHash` | WebAuthn |
| Attestation | "packed" **self-attestation** (no certificate) | Q7 |
| Credential type | Non-discoverable; 16-byte random credential ID indexing an on-device record | |
| On-device record | 155 bytes: version 1, flags 1, credId 16, rpIdHash 32, userHandle len 1 + 64, private key 32, signCount 4, CRC-32 4 | |
| Credential capacity | 128 (firmware limit) | |
| Signature counter | Per credential, persisted **before** signing | |
| User-presence timeout | 30 s | |
| RP challenge | 32 random bytes, single use, TTL 120 s, bound to session + ceremony + user | |
| RP options | attestation "direct", authenticatorAttachment "cross-platform", residentKey "discouraged", userVerification "discouraged", hints ["security-key"], transports ["usb"], timeout 60 s | |

### 2.1 Message sizes 🟡 (produced by the firmware code; protocol-determined, identical on device)

| Item | Size |
|---|---|
| getInfo response (status + CBOR) | 51 bytes |
| makeCredential authenticatorData | 148 bytes = rpIdHash 32 + flags 1 + signCount 4 + AAGUID 16 + credIdLen 2 + credId 16 + COSE_Key 77 |
| makeCredential response | 244–246 bytes → **5** CTAPHID packets |
| getAssertion authenticatorData | 37 bytes = rpIdHash 32 + flags 1 + signCount 4 |
| getAssertion response | 152–155 bytes → **3** CTAPHID packets |
| COSE_Key (EC2, P-256) | 77 bytes |
| DER ECDSA signature | 69–72 bytes; n = 230: mean 70.96; distribution 69 B ×1, 70 B ×52, 71 B ×132, 72 B ×45 |
| Flags | makeCredential 0x41 (UP + AT); getAssertion 0x01 (UP); silent probe (`up=false`) 0x00 |

---

## 3. Measured cryptographic performance on the ESP32-S3 🟢

Timer: `esp_timer_get_time()` (µs). Workload shaped like WebAuthn: 37-byte authenticatorData + 32-byte clientDataHash.
Definitions: **keygen_total** = DRBG reseed + P-256 key generation + pairwise-consistency test (sign + verify of a test message); **pct** = the pairwise-consistency test alone; **keygen_only** = keygen_total − pct (⚪ derived per iteration); **sign** = ES256 signature (RFC 6979, with blinding); **verify** = ECDSA verification.

### 3.1 Table: optimised configuration (run 2), n = 20, `results/phase1_run2_optimized/`

| Operation | Mean | SD | Median | Min | Max | 95 % CI of mean |
|---|---|---|---|---|---|---|
| Key generation + pairwise test | **214.030 ms** | 0.106 ms | 214.018 ms | 213.836 ms | 214.243 ms | ±0.050 ms |
| Key generation only ⚪ | **35.632 ms** | 0.072 ms | 35.620 ms | 35.474 ms | 35.751 ms | ±0.034 ms |
| Pairwise-consistency test | 178.399 ms | 0.099 ms | 178.404 ms | 178.180 ms | 178.632 ms | ±0.046 ms |
| **ES256 sign** | **40.927 ms** | 0.047 ms | 40.926 ms | 40.844 ms | 41.018 ms | ±0.022 ms |
| ES256 verify | 137.496 ms | 0.073 ms | 137.487 ms | 137.383 ms | 137.655 ms | ±0.034 ms |
| DER signature size | 70.80 B | 0.83 B | 71 B | 70 B | 72 B | ±0.39 B |
| Power-on self-test (all KATs, n = 1) | 316.062 ms | – | – | – | – | – |

Observations for the paper:
- Timing is effectively constant: the standard deviation is ≤ 0.2 % of the mean for every operation, and max − min ≤ 0.41 ms.
- Verification is about 3.4× slower than signing. Signing and key generation use the fixed base point G, which benefits from the precomputed tables; verification also needs a variable-point multiplication.
- The pairwise-consistency test accounts for **83 %** of key-generation time (178.4 of 214.0 ms). This is a measurable cost of a safety feature.

### 3.2 Table: effect of optimisation (run 1 vs run 2)

Run 1 (config A: `-Og`, 160 MHz, no ECP tables, DRBG prediction resistance on every call), n = 4 (iterations 16–19; partial log). Run 2 (config B: `-O2`, 240 MHz, ECP tables, reseed per keygen), n = 20.

| Operation | Run 1 mean (range) | Run 2 mean | Speed-up |
|---|---|---|---|
| Key generation + pairwise test | 672.10 ms (655.82–720.61) | 214.03 ms | **3.14×** |
| ES256 sign | 169.95 ms (169.80–170.05) | 40.93 ms | **4.15×** |
| ES256 verify | 327.46 ms (327.21–327.64) | 137.50 ms | **2.38×** |

Caveat for the paper: four settings changed together, so the speed-up **cannot be attributed to any single setting**. Run 1 has n = 4 only. Report it as "unoptimised vs optimised build configuration".

### 3.3 Derived lower bounds for the CTAP operations ⚪ (until M1/M2 are measured)

| Operation | Lower bound from primitives | Not included |
|---|---|---|
| makeCredential (excluding button wait) | ≥ 214.0 + 40.9 = **≈ 255 ms** | CBOR parsing, SHA-256(rpId), NVS write, USB transfer |
| getAssertion (excluding button wait) | ≥ **≈ 41 ms** | Credential lookup, counter NVS write, USB transfer |

Replace these with 🟢 values from the `METRIC,mc_*` / `METRIC,ga_*` log lines once the Phase 3 firmware runs on the board.

---

## 4. Resource usage

### 4.1 Firmware size 🔵

| Build | App binary | Bootloader | Share of 2 MB app partition |
|---|---|---|---|
| Phase 1.1 (crypto only), device build, ESP-IDF 5.3.6 🟢 | 285,072 B (0x45990) | 21,552 B | 13.6 % |
| Phase 3 (complete token), CI build, ESP-IDF 5.3.2 | **344,752 B** (0x542B0) | 21,648 B | 16.4 % |

Phase 3 memory map (CI build, `idf.py size`):

| Region | Used | Available | Use |
|---|---|---|---|
| Flash code (.text) | 189,376 B | – | – |
| Flash read-only data (.rodata) | 83,684 B | – | – |
| Internal DIRAM (static) | 73,983 B | 341,760 B | 21.65 % |
| – of which .bss | 19,040 B | | |
| – of which .data | 11,328 B | | |
| IRAM | 16,383 B | 16,384 B | 99.99 % (ESP-IDF placement) |

Size by component (Phase 3, total bytes in the image):

| Component | Size | Notes |
|---|---|---|
| mbedTLS (libmbedcrypto) | 66,145 B | incl. ≈ 29 KB fixed-point tables (flash) |
| main (boot, worker task, buffers) | 17,463 B | 15,309 B are RAM buffers: CTAPHID request (7.6 KB) + response (7.6 KB) |
| TinyUSB | 14,308 B | |
| fido_core (CTAPHID + CTAP2 + CBOR + store + crypto wrapper) | **12,539 B** | the project's own authenticator logic |
| esp_tinyusb | 1,543 B | |
| hal_esp32s3 (RNG, button, USB descriptors, NVS) | 1,261 B | |

🔴 Record `idf.py size` from the implementer's own Phase 3 build (ESP-IDF 5.3.6) for the final table.

### 4.2 Runtime memory 🟢 (Phase 1.1 at boot)

| Metric | Value |
|---|---|
| Free heap at `BOOT_OK` | 373,532 B |
| Minimum free heap since boot | 369,992 B |

🔴 Phase 3 heap/stack figures after N ceremonies: pending.

### 4.3 Credential storage

| Metric | Value | Label |
|---|---|---|
| Record payload per credential | 155 B | 🟡 fixed by format |
| NVS `fido` partition capacity | 8,064 entries (32 B each), 0 used at first boot | 🟢 |
| NVS entries per credential | ≈ 7 (1 header + 5 data + 1 blob index) ≈ 224 B | ⚪ estimate; 🔴 measure `used_entries` before/after one registration |
| Credential capacity | 128 (firmware limit) | 🟡 |

---

## 5. Implementation verification (software) 🟡

The firmware's C sources were compiled for Linux and tested under AddressSanitizer/UndefinedBehaviorSanitizer. The cryptography was additionally cross-checked with an independent implementation (OpenSSL through pyca/cryptography).

| Suite | What it checks | Result |
|---|---|---|
| Crypto unit tests | SHA-256 known-answer tests (FIPS 180-2), RFC 6979 P-256 known-answer test (exact bytes), invalid keys (0, n, >n), buffer and argument checks, verification rejection (altered message, altered signature, trailing byte, off-curve key), 200 key pairs unique and consistent | **21,740 checks, 0 failures** |
| Independent cross-verification | 50 signatures verified by OpenSSL; strict DER; COSE_Key canonical CBOR; RFC 6979 constants re-derived | **50/50 + constants OK** |
| CTAPHID transport | INIT/PING (0–7609 B), all error codes, sequence errors, busy channel, timeouts, CANCEL, KEEPALIVE, **300,000 random packets** | **161,357 checks, 0 failures, no crash** |
| CTAP2 + storage + CBOR | Ceremonies, RP binding, counter, UP timeout/cancel, excludeList, unsupported algorithm/options, corruption detection, capacity, failed-write abort, CRC-32 check value, **60,000 fuzzed + random requests** | **60,034 checks, 0 failures, no crash** |
| Transport harness (sim) | `ctaphid_check.py` logic vs the firmware transport code | **30/30** |
| End-to-end (sim) | Firmware code ↔ python-fido2 client ↔ relying party with py_webauthn | **20/20 security checks** (§6) |
| Relying-party tests | Config validation, dashboard, admin gating, CSV export, security headers, UP timeout | **10/10 tests pass** |
| Web UI | Register → login → dashboard → admin in headless Chromium (CDP virtual authenticator), 390×844 phone viewport | Pass; no JavaScript errors besides expected 401/403 responses |

---

## 6. Security test matrix

| ID | Test | Expected | Software result 🟡 | Hardware result |
|---|---|---|---|---|
| T01 | Token enumerates as FIDO HID device | VID:PID 303A:4004, 64/64-byte reports | – | 🔴 `ctaphid_check.py` |
| T02 | Flash and boot | Boots, self-test passes | – | 🟢 **PASS** (run 2: self-test passed, `BOOT_OK`) |
| T03 | Valid packets (INIT, PING 0–7609 B, getInfo) | Correct echo / response | PASS | 🔴 |
| T04 | Malformed packets (bad CID, BCNT > max, bad SEQ, short INIT, unknown/LOCK command, empty CBOR, message timeout) | Correct CTAPHID error, device stays responsive | PASS (11 cases + 300k fuzz) | 🔴 |
| T05 | Credential generation | Valid packed attestation, record stored | PASS | 🔴 |
| T06 | Credential persists after restart | Login after replug | – (RAM in sim) | 🔴 |
| T07 | Registration on local RP | Server accepts, stores public key | PASS | 🔴 |
| T08 | Authentication | Server accepts assertion | PASS (3/3) | 🔴 |
| T09 | Replay / stale / altered challenge | Rejected | PASS: `CHALLENGE_NOT_FOUND`, `CHALLENGE_MISMATCH` ×2 | 🔴 |
| T10 | Wrong origin / wrong RP | Rejected | PASS: RP `ORIGIN_MISMATCH`; token `NO_CREDENTIALS` for another rpId | 🔴 |
| T11 | Unknown credential | Error | PASS: token `NO_CREDENTIALS`; RP `UNKNOWN_CREDENTIAL` | 🔴 |
| T12 | Repeated ceremonies (N trials) | Consistent | – | 🔴 |
| T13 | Cross-device (PC register → Android login) | Success | – | 🔴 |
| T-UP | No button press | Timeout, no signature | PASS: `USER_ACTION_TIMEOUT`; cancel → `KEEPALIVE_CANCEL` | 🔴 |
| T-UPF | Silent (`up=false`) assertion used as a login | RP rejects | PASS: UP flag = 0, RP `UP_NOT_SET` | 🔴 |
| T-CNT | Counter strictly increasing | Monotonic | PASS | 🔴 |
| T-CLONE | Assertion with lower counter than stored | Rejected | PASS: `COUNTER_REGRESSION` | 🔴 |
| TH12 | Another session adds a key to an existing account | Refused | PASS: HTTP 403 `USER_EXISTS_AUTH_REQUIRED` | n/a (server) |
| T-CORRUPT | Corrupted credential record | Never used | PASS: `NO_CREDENTIALS`, counted invalid | 🔴 (optional) |
| T-RST | Unplug during operation | No corrupted record | – | 🔴 |

Threat → mitigation → evidence mapping: `PROJECT_SPECIFICATION.md` §10.

---

## 7. Metric status (M1–M8)

| ID | Metric | Status | Value / source |
|---|---|---|---|
| M1 | Credential creation time (token-internal, excluding button) | 🔴 pending (⚪ ≥ 255 ms) | `METRIC,mc_total_excl_up_us` |
| M2 | Authentication time (token-internal, excluding button) | 🔴 pending (⚪ ≥ 41 ms) | `METRIC,ga_total_excl_up_us` |
| M3 | USB latency (PING round trip, 0–7609 B) | 🔴 pending | `results/phase2_ctaphid/ping_rtt.csv` |
| M4 | End-to-end ceremony time (browser, includes human press) | 🔴 pending | dashboard / `auth_events.client_total_ms` |
| M5 | Firmware size | 🔵 344,752 B (Phase 3, CI build); 🟢 285,072 B (Phase 1.1 device build) | §4.1 |
| M6 | RAM usage | 🔵 static DIRAM 73,983 B; 🟢 free heap 373,532 B (Phase 1.1) | §4.1–4.2 |
| M7 | Storage per credential | 🟡 155 B record; ⚪ ≈ 224 B in NVS | §4.3 |
| M8 | Authentication success rate | 🔴 pending | `e2e_check.py` + dashboard |
| – | Crypto primitives (keygen, sign, verify, pairwise test, self-test) | 🟢 **measured** | §3 |

---

## 8. Figure data (corrected flows for Figs. 2 and 3)

**Registration (Fig. 2):**
1. The user clicks "Register security key".
2. The RP issues a 32-byte random challenge and `PublicKeyCredentialCreationOptions`.
3. The browser calls `navigator.credentials.create()` and sends `authenticatorMakeCredential` over CTAPHID.
4. The token checks for ES256.
5. The token waits for the **BOOT button**.
6. The token generates a P-256 key pair from the hardware RNG and runs the pairwise test.
7. The token stores the record in **on-device flash (NVS)**.
8. The token builds authData (148 B) and signs the packed self-attestation.
9. The token responds in 5 USB packets.
10. The RP verifies challenge, origin, rpIdHash, UP flag, algorithm and attestation, then stores the public key and credential ID.

**Authentication (Fig. 3):**
1. The user clicks "Login with security key".
2. The RP issues a fresh challenge, the RP ID and allowCredentials.
3. The browser calls `navigator.credentials.get()` and sends `authenticatorGetAssertion`.
4. The token finds the credential by credential ID **and** rpIdHash.
5. The token waits for the **BOOT button**.
6. The token increments the counter and **persists it first**.
7. The token builds authData = rpIdHash ‖ flags ‖ counter (37 B).
8. The token signs `authData ‖ clientDataHash`.
9. The token responds in 3 USB packets.
10. The RP verifies challenge, origin, RP ID, flags, counter and signature.

No PIN appears in either figure.

---

## 9. Claims supported so far, and limitations

**May be stated now:**
- The token firmware (USB FIDO HID, CTAPHID, CTAP2 subset, ES256 via mbedTLS, NVS credential store, button user presence) is **implemented**.
- Cryptographic primitives run on the ESP32-S3 at the times in §3, with power-on known-answer tests passing on hardware.
- The implementation passes the software verification in §5, including large-scale fuzzing.

**May be stated only after the pending hardware runs:** "registration and login succeed in Chrome/Edge on Windows" (T07/T08), "rejects replay / wrong RP / unknown credential on hardware" (T09–T11), "works with GitHub 2FA", "works on Android", M1–M4, M8.

**Limitations to state:**
- Private keys are stored unencrypted in flash (NVS). A physical flash dump can extract them.
- Flash encryption, secure boot and JTAG disable are **off**.
- There is no PIN or user verification, so a stolen token plus a button press is enough to authenticate.
- Credentials are non-discoverable only (username-first login).
- CTAP1/U2F is not implemented (the title says "FIDO2/U2F"; decide on wording).
- There is no FIDO certification and the attestation is self-attestation only.
- A random AAGUID is not registered in the FIDO Metadata Service.
- The device uses Espressif's development USB IDs.
- Interoperability is limited to the tested browsers and devices.

**Future work (exactly three):** secure element; NFC transport; credential-management utility.

---

## 10. Remaining data to collect (checklist)

1. Phase 3 boot log: `EVT,ENV`, `EVT,CREDS`, self-test, `BOOT_OK` heap.
2. `python harness\ctaphid_check.py --trials 50 --out results\phase2_ctaphid` gives T01, T03, T04 and M3.
3. `python harness\e2e_check.py --out results\phase3_e2e` gives T05, T07–T11, T-UP flag, T-CNT and clone detection on hardware, plus the matching `METRIC,mc_*` / `ga_*` lines from the serial log (M1, M2).
4. Browser runs at http://localhost:8000 in Chrome and Edge give T07, T08 and M4, plus screenshots of the Windows security-key dialog and the dashboards.
5. Unplug/replug, then log in again (T06). Record `EVT,STORAGE used_entries` before and after one registration (M7).
6. N = 50 login trials for M2/M8 statistics.
7. Optional: Android over USB-C via the HTTPS tunnel (T13), and GitHub 2FA registration and login.
8. Record Windows version, browser versions and the local `idf.py size` output.

---

## Appendix A: Raw data, run 2 (🟢, µs)

| i | keygen_total | pct | sign | verify | sig B |
|---|---|---|---|---|---|
| 0 | 214078 | 178327 | 40930 | 137490 | 71 |
| 1 | 213883 | 178180 | 40882 | 137452 | 72 |
| 2 | 214172 | 178456 | 40894 | 137557 | 71 |
| 3 | 213901 | 178343 | 40856 | 137576 | 70 |
| 4 | 214243 | 178632 | 40952 | 137583 | 70 |
| 5 | 213930 | 178456 | 40844 | 137483 | 71 |
| 6 | 214124 | 178443 | 40912 | 137475 | 71 |
| 7 | 214009 | 178390 | 40959 | 137481 | 70 |
| 8 | 214127 | 178409 | 40914 | 137409 | 70 |
| 9 | 214094 | 178351 | 41018 | 137383 | 71 |
| 10 | 213966 | 178374 | 40959 | 137431 | 71 |
| 11 | 214027 | 178428 | 40944 | 137525 | 70 |
| 12 | 213942 | 178291 | 40943 | 137420 | 70 |
| 13 | 213975 | 178443 | 40971 | 137448 | 72 |
| 14 | 213836 | 178245 | 40969 | 137409 | 70 |
| 15 | 214138 | 178546 | 40923 | 137655 | 72 |
| 16 | 213993 | 178398 | 40866 | 137514 | 72 |
| 17 | 214043 | 178412 | 41009 | 137493 | 72 |
| 18 | 214008 | 178388 | 40903 | 137526 | 70 |
| 19 | 214119 | 178462 | 40898 | 137607 | 70 |

## Appendix B: Raw data, run 1 (🟢, µs, partial)

| i | keygen + pct | sign | verify | sig B |
|---|---|---|---|---|
| 16 | 720614 | 170016 | 327641 | 71 |
| 17 | 655959 | 170047 | 327210 | 72 |
| 18 | 656011 | 169803 | 327347 | 71 |
| 19 | 655823 | 169917 | 327629 | 71 |

Run 1 also triggered a task-watchdog warning (the benchmark loop did not yield for about 24 s). There was no reset; this was fixed in 0.1.1.

## Appendix C: Reproducing the numbers

| Data | Command |
|---|---|
| Crypto timings | Flash firmware with `CONFIG_FIDO_BENCH_ITERATIONS=20`; read the `METRIC,*` lines from `idf.py -p COM8 monitor` |
| Host verification | `cmake -S firmware/test/host -B build-host && cmake --build build-host && ctest --test-dir build-host` |
| End-to-end (sim) | `SIM_TOKEN_LIB=build-host/libsim_token.so pytest rp/tests` |
| Size | `idf.py size` and `idf.py size-components` |
