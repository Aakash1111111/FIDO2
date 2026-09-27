# Proposed Architecture

Status: **proposal awaiting approval.** Tags as defined in [`PROJECT_SPECIFICATION.md`](PROJECT_SPECIFICATION.md) §0. Every important decision has a **Why** line.

---

## 1. Classification of functionality

| Class | What falls in it | Where in code |
|---|---|---|
| **A. FIDO2/WebAuthn standard** | CTAPHID framing; CTAP2 getInfo/makeCredential/getAssertion; authData layout; COSE_Key; ES256 signing; packed/none attestation; WebAuthn options and verification on the RP; browser API calls | `firmware/components/ctaphid`, `ctap2`, `fido_crypto`; `rp/app/webauthn_service.py`; `rp/static/webauthn.js` |
| **B. Project-specific** | ESP32-S3 HAL (TinyUSB, GPIO button, RNG, timer); NVS record format and integrity; username-first account model; credential-injection rule; auth_events logging; config | `firmware/components/hal_esp32s3`, `cred_store`; `rp/app/*` (non-WebAuthn parts) |
| **C. Research / experimental** | Firmware metrics instrumentation (compile-time switch); evaluation harness T01–T12; malformed-packet generator; statistics/reporting; environment capture; `/experiment/events` export | `firmware/components/metrics`; `harness/`; `rp` only behind `RP_EXPERIMENT_MODE` |

**Rule [NEW]:** Class C code can be removed or disabled without changing Class A/B behaviour. Firmware metrics compile to no-ops when `CONFIG_FIDO_METRICS=n`. The RP experiment endpoint returns 404 unless explicitly enabled. **Why:** the paper must report the behaviour of the production build, and instrumentation must not become an attack surface.

## 2. Firmware architecture

### 2.1 Layers

```
┌──────────────────────────────────────────────────────────────────────────┐
│ main.c  — init order, FreeRTOS tasks                                     │
├──────────────────────────────────────────────────────────────────────────┤
│ hal_esp32s3 (ESP-specific)                                               │
│   usb_hid_tinyusb.c   button_gpio.c   rng_esp.c   time_esp.c   nvs_kv.c  │
├───────────────▲──────────────────────────────────────────────▲───────────┤
│               │ hal.h (portable interface, function table)   │           │
├───────────────┴──────────────────────────────────────────────┴───────────┤
│ PORTABLE CORE (no ESP-IDF headers; builds on Linux for unit tests)       │
│  ctaphid/   reassembly, fragmentation, channels, INIT/PING/CBOR/MSG/     │
│             CANCEL/KEEPALIVE/ERROR, timeouts                             │
│  ctap2/     cbor_util (canonical encode, strict decode), dispatcher,     │
│             get_info, make_credential, get_assertion, status codes       │
│  u2f/       (stretch) register/authenticate over CTAPHID_MSG             │
│  fido_crypto/ mbedTLS wrapper: keygen, sign(DER), sha256, cose_key,      │
│             zeroize                                                      │
│  cred_store/ record codec (version+CRC), store API; backends:            │
│             nvs (via hal kv) | ram (tests)                               │
│  auth_state/ AAGUID, config, counters                                    │
│  up/        user-presence state machine (wait, keepalive, cancel,        │
│             timeout)                                                     │
│  metrics/   METRIC() macros → hal log; no-op when disabled               │
└──────────────────────────────────────────────────────────────────────────┘
```

**Why a portable core behind a HAL [NEW]:** (1) Protocol, CBOR and crypto logic become unit-testable on any Linux machine and in CI without the board. This matters because only Author B has hardware and the deadline is 3 days away. (2) Failures can be isolated to USB, parsing, storage or crypto, which is the rule stated in H§6. (3) The same core could later serve NFC (future work #2).

### 2.2 Tasks and concurrency

| Task | Priority | Role |
|---|---|---|
| TinyUSB device task | high | USB stack (`tud_task`) |
| `fido_task` | medium | Single worker: takes complete CTAPHID messages from a queue, runs the CTAP command, sends the response |
| UP wait | inside `fido_task` | Polls the button at 10 ms and sends `KEEPALIVE(UPNEEDED)` every 100 ms. Checks for `CANCEL` from the RX path |

The HID RX callback only reassembles packets and posts complete messages to a queue. Only one transaction runs at a time; other channels get `ERR_CHANNEL_BUSY` [SPEC-VERIFY]. **Why:** CTAPHID is defined as one transaction at a time. A single worker avoids locking around NVS and crypto state.

### 2.3 Boot sequence

`nvs_flash_init_partition("fido")` → validate every credential record (CRC + version; invalid records are logged and quarantined, never silently used) → crypto init (entropy + CTR-DRBG seeded from the HW RNG) → load auth_state → button init → USB init → ready log line `BOOT_OK creds=<n> store_ver=<v>`.

**Why USB last:** the host must not see the device before storage and crypto are ready (H§7, "Boot recovery").

## 3. Directory structure

```
FIDO2/
├── README.md                         # entry point, quick start, status matrix
├── PROJECT_SPECIFICATION.md
├── ARCHITECTURE.md
├── IMPLEMENTATION_PLAN.md
├── RISKS_AND_OPEN_QUESTIONS.md
├── docs/
│   ├── research/FIDO2_Token_Handoff.md   # primary research source (read-only)
│   ├── decisions/ADR-000x-*.md           # one file per approved decision
│   ├── security_analysis.md              # threat → control → test evidence
│   ├── test_results.md                   # generated summary of T01–T12
│   └── evidence/                         # screenshots, lsusb dumps, logs for the paper
├── firmware/                             # ESP-IDF project (C)
│   ├── CMakeLists.txt
│   ├── sdkconfig.defaults                # pinned config (USB OTG, mbedTLS options, metrics on/off)
│   ├── sdkconfig.defaults.hardened       # [OPEN] flash encryption / secure boot variant
│   ├── partitions.csv                    # adds dedicated 'fido' NVS partition
│   ├── main/{main.c, CMakeLists.txt, idf_component.yml, Kconfig.projbuild}
│   ├── components/
│   │   ├── fido_core/                    # PORTABLE: ctaphid/, ctap2/, u2f/, fido_crypto/,
│   │   │                                 #   cred_store/, auth_state/, up/, metrics/, include/hal.h
│   │   └── hal_esp32s3/                  # ESP-specific implementations of hal.h
│   └── test/
│       ├── host/                         # CMake build of fido_core for Linux + Unity tests + vectors
│       └── target/                       # ESP-IDF Unity test app (NVS, RNG, timing on the device)
├── rp/                                   # Relying party (Python)
│   ├── pyproject.toml, requirements.lock
│   ├── app/
│   │   ├── main.py            # FastAPI app, middleware, static mount
│   │   ├── config.py          # env-driven settings, validation at startup
│   │   ├── db.py              # SQLite schema + migrations + queries
│   │   ├── challenges.py      # issue / consume / expire
│   │   ├── webauthn_service.py# ONLY place that calls py_webauthn (class A)
│   │   ├── routes.py          # /register/*, /login/*, /me, /logout, /healthz
│   │   ├── errors.py          # reason codes, exception mapping
│   │   └── experiment.py      # class C, mounted only in experiment mode
│   ├── static/{index.html, app.js, webauthn.js, styles.css}
│   └── tests/                 # pytest; soft authenticator (tests only); optional Playwright
├── harness/                              # Evaluation (Python, class C)
│   ├── pyproject.toml, requirements.lock
│   ├── fidoharness/
│   │   ├── device.py          # find/open FIDO HID device (python-fido2)
│   │   ├── rawhid.py          # raw hidraw report writer for malformed tests
│   │   ├── serial_metrics.py  # parse METRIC lines from UART
│   │   ├── rp_client.py       # drives the RP HTTP API, builds clientDataJSON like a browser
│   │   ├── env_capture.py     # environment.json
│   │   └── tests/t01..t12, t_up, t_rst, t_cnt
│   ├── run_experiment.py      # CLI: --run-id --trials N --tests ...
│   └── analysis/report.py     # CSV → stats tables (markdown/LaTeX) + plots
├── results/                               # one folder per run_id (raw CSV + environment.json), committed
└── tools/
    ├── 70-fido-esp32.rules    # Linux udev rule for hidraw access
    └── mkcert.md              # optional HTTPS setup for non-localhost demos
```

**Why a monorepo:** firmware, RP and harness versions must match for reproducible results. One commit hash identifies a whole experiment run.

**Why the frontend is served by the RP (no separate SPA):** WebAuthn binds to origin and RP ID. Same-origin serving removes CORS, cookie and RP-ID mismatch problems and has no build step.

## 4. API endpoints

See [`PROJECT_SPECIFICATION.md`](PROJECT_SPECIFICATION.md) §13 for bodies and reason codes. Endpoint paths follow H§18 exactly: `POST /register/options`, `POST /register/verify`, `POST /login/options`, `POST /login/verify`. The extra endpoints (`/logout`, `/me`, `/healthz`, `/experiment/events`) are [NEW].

**Token "API" (CTAP commands), CTAP 2.0 subset:**

| CTAPHID cmd | Byte [SPEC-VERIFY] | Supported | Behaviour |
|---|---|---|---|
| PING | 0x81 | yes | Echo |
| MSG | 0x83 | stretch | U2F. Until implemented: respond with U2F status `0x6D00` (INS not supported) |
| INIT | 0x86 | yes | Allocate CID; returns nonce, CID, protocol version 2, device version, capabilities (CBOR=0x04; NMSG=0x08 while U2F is absent) |
| WINK | 0x88 | optional | Blink LED if present |
| CBOR | 0x90 | yes | CTAP2 |
| CANCEL | 0x91 | yes | Abort UP wait → `CTAP2_ERR_KEEPALIVE_CANCEL` |
| KEEPALIVE | 0xBB | sent | STATUS_PROCESSING=1, STATUS_UPNEEDED=2 |
| ERROR | 0xBF | sent | INVALID_CMD 0x01, INVALID_PAR 0x02, INVALID_LEN 0x03, INVALID_SEQ 0x04, MSG_TIMEOUT 0x05, CHANNEL_BUSY 0x06, INVALID_CHANNEL 0x0B, OTHER 0x7F |

| CTAP2 command | Byte [SPEC-VERIFY] | Supported |
|---|---|---|
| authenticatorMakeCredential | 0x01 | yes |
| authenticatorGetAssertion | 0x02 | yes |
| authenticatorGetInfo | 0x04 | yes: `{1: versions ["FIDO_2_0"(, "U2F_V2")], 2: [] , 3: AAGUID, 4: {rk:false, up:true, plat:false}, 5: maxMsgSize}` (no `clientPin` key = PIN not supported) |
| authenticatorClientPIN | 0x06 | no → `CTAP1_ERR_INVALID_COMMAND` |
| authenticatorReset | 0x07 | [OPEN] useful for experiments; needs UP and must happen within 10 s of power-up per spec [SPEC-VERIFY] |
| authenticatorGetNextAssertion | 0x08 | only with rk (stretch) |

## 5. Cryptographic and key-management flow

All primitives come from mbedTLS [REQ: no hand-written crypto].

```
Entropy: ESP32-S3 HW RNG (esp_random / esp_fill_random) ──► mbedtls_entropy ──► mbedtls_ctr_drbg (seeded at boot,
         reseeded by mbedTLS policy)
Keygen:  mbedtls_ecp_gen_keypair(SECP256R1, ctr_drbg) → d (32 B), Q=(x,y)
         d → cred_store record (NVS) ; Q → COSE_Key {1:2, 3:-7, -1:1, -2:x, -3:y}  (canonical order)  [SPEC-VERIFY]
         buffers holding d: mbedtls_platform_zeroize() before return
Sign:    msg = authData ‖ clientDataHash ; h = SHA-256(msg) ; (r,s) = ECDSA(d, h, ctr_drbg) → DER (≤72 B)
Hashes:  rpIdHash = SHA-256(rpId) ; clientDataHash computed by the CLIENT (the token never sees clientDataJSON)
Attest:  "packed" self: attStmt = {alg:-7, sig: ECDSA(d_cred, authData ‖ clientDataHash)}  (no x5c)
         "none": attStmt = {}
Verify:  RP (py_webauthn): ECDSA_Verify(pk from COSE_Key, authData ‖ SHA-256(clientDataJSON), sig)
```

- **Credential ID = 16 random bytes that index an NVS record** [NEW]. **Why:** the research stores the private key on the device (H§8 step 8). Key-wrapping credential IDs (encrypting the key into the credential ID) would send a wrapped private key to the host, which conflicts with "private key never leaves the token" as the paper phrases it. The trade-off is a finite capacity (M7 reports it).
- **Sign counter: per credential, incremented and committed to NVS before the signature is computed** [NEW]. **Why:** if power is lost after commit, the counter only skips a value (allowed). If it were committed after signing, a crash could reuse a value and break the monotonicity that clone detection relies on.
- **RNG caveat** [ASSUMED/OPEN]: Espressif documents `esp_random()` as true-random only while the RF subsystem is on or `bootloader_random_enable()` is active (to verify). Plan: call `bootloader_random_enable()` for the key-generation window, or document the entropy source used. See RISKS R-RNG.
- **Attestation:** packed self-attestation is recommended (Q7). **Why:** it shows a real signature at registration time without a fake vendor certificate, and it is honest ("self"). The AAGUID is a fixed random value published in the README, and no FIDO metadata is claimed.

## 6. Error-handling strategy

| Layer | Rule |
|---|---|
| HID RX | Never trust lengths. Validate CID, CMD bit, BCNT ≤ max (7609 B [SPEC-VERIFY]), SEQ order, per-transaction timeout (~500 ms between packets). On violation send `CTAPHID_ERROR` and reset that channel's state. Never assert or crash |
| CTAP2 decode | Strict CBOR: expected major types, required keys present, byte-string lengths checked (clientDataHash = 32), nesting depth bounded, unknown map keys ignored. Map to CTAP2 codes: `INVALID_CBOR 0x12`, `CBOR_UNEXPECTED_TYPE 0x11`, `MISSING_PARAMETER 0x14`, `UNSUPPORTED_ALGORITHM 0x26`, `UNSUPPORTED_OPTION 0x2B`, `CREDENTIAL_EXCLUDED 0x19`, `NO_CREDENTIALS 0x2E`, `USER_ACTION_TIMEOUT 0x2F`, `KEEPALIVE_CANCEL 0x2D`, `KEY_STORE_FULL 0x28`, `OTHER 0x7F` [SPEC-VERIFY] |
| Crypto / storage | Every mbedTLS/NVS return code is checked. Any failure returns `CTAP1_ERR_OTHER` and **no partial response**. A failed NVS write aborts makeCredential before anything is returned (no orphan credential on the host side) |
| Fail-closed | No path returns a signature unless (UP satisfied or up=false requested) AND the credential matched the rpIdHash |
| RP | Library exceptions → `reason` code (spec §13). HTTP 400 with the code; details only in server logs. Challenge consumed even on failure |
| Frontend | Show `DOMException.name` + RP `reason`; never retry automatically |

## 7. Logging strategy

- **Firmware:** logs go to the UART port (the native USB port is HID). Levels: `E/W/I` in production, `D` in development. Machine lines: `METRIC,<seq>,<cmd>,<phase>,<t_us>` and `EVT,<name>,<k=v>...`. **Never logged:** private keys, raw signatures before sending, user handles (log only lengths or hashes) [NEW]. A harness test scans captured logs for any 32-byte hex run matching generated key material in test builds.
- **RP:** JSON lines (ts, level, route, ceremony, username, credential_id prefix, reason, durations). No challenges or full public keys. Every verification also goes to the `auth_events` table.
- **Harness:** raw CSV per test + `environment.json` + a copy of the firmware UART log per run. All of it is committed under `results/<run_id>/`.

## 8. Security controls (summary)

See the spec §9. Architectural placement:
- **Token:** input validation (ctaphid/ctap2), UP gate (up/), rpIdHash-bound lookup (cred_store), counter-before-sign (ctap2 + cred_store), zeroization (fido_crypto), CRC + version (cred_store), metrics compile switch (metrics/).
- **RP:** single-use expiring challenges (challenges.py), library verification only (webauthn_service.py), credential-injection rule (routes.py), cookie flags + CSP headers (main.py), experiment endpoint gated (experiment.py).
- **Build:** pinned versions (`dependencies.lock`, `requirements.lock`), `sdkconfig.defaults` committed, optional hardened profile.

## 9. Testing structure

| Level | Location | Needs hardware? | Content |
|---|---|---|---|
| Unit (firmware core) | `firmware/test/host` | No | CTAPHID fragmentation/reassembly edge cases; CBOR decode of captured real browser requests; authData byte layout; COSE_Key encoding; ES256 sign → verified independently by Python `cryptography` (cross-check); record codec CRC/version; UP state machine with a fake clock |
| Unit (on target) | `firmware/test/target` | Yes | NVS round-trip, power-loss simulation via reboot, RNG smoke check, timing overhead of metrics |
| Unit (RP) | `rp/tests` | No | Challenge lifecycle; every reason code, using a **test-only** software authenticator; credential-injection rule; DB constraints |
| Integration (RP + frontend) | `rp/tests/e2e` (optional) | No | Playwright + Chromium CDP virtual authenticator: full browser ceremony. **Validates the RP only, never reported as token results** |
| System | `harness/` T01–T12 | Yes | Real token over HID + RP over HTTP + browser manual runs |
| Security | `harness/` T04, T09–T11, T-UP, T-RST, T-CNT | Yes | Negative cases |
| Conformance (optional) | FIDO Conformance Tools, if access is available | Yes | Informational only; not a certification claim |
