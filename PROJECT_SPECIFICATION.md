# FIDO2 Project Specification

**Paper title (fixed, do not change):** *Design and Implementation of a FIDO2/U2F Compliant Authentication Token for Secure Passwordless Authentication*
**Paper deadline:** 30 September 2026 (IEEE-style)
**Primary source:** [`docs/research/FIDO2_Token_Handoff.md`](docs/research/FIDO2_Token_Handoff.md) (cited below as **H§n**, meaning handoff section *n*)
**Companion documents:** [`ARCHITECTURE.md`](ARCHITECTURE.md) · [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) · [`RISKS_AND_OPEN_QUESTIONS.md`](RISKS_AND_OPEN_QUESTIONS.md)

---

## 0. Tag legend

The research tags are reused unchanged. One tag is added to mark what this plan introduces.

| Tag | Meaning |
|---|---|
| **[REQ]** | Confirmed requirement: comes from the FIDO/WebAuthn/CTAP specs or from the project's non-negotiable rules (H§0) |
| **[DECIDED]** | Decision the team has already made (H§20) |
| **[PROPOSED]** | Suggested in the research but not yet confirmed |
| **[ASSUMED]** | Assumption that has not been verified |
| **[OPEN]** | Still to be decided or verified |
| **[SPEC-VERIFY]** | Protocol detail that must be checked against the official CTAP 2.x and WebAuthn specs before relying on it |
| **[NEW]** | **Introduced by this plan, not by the research.** Implementation proposal that needs team approval |

**Implementation status:** nothing is implemented or verified yet. The repository was empty when this specification was written (H§0).

---

## 1. Research Problem

Passwords are vulnerable to phishing, reuse across services, database breaches, keyloggers and social engineering. SMS OTP and some second factors can be intercepted or phished. Commercial FIDO security keys fix this, but they are closed, fixed-function products. **The problem:** build a **low-cost, customizable, transparent** hardware authenticator on a general-purpose microcontroller (ESP32-S3) that performs origin-bound public-key authentication through FIDO2 (CTAP2 + WebAuthn), with CTAP1/U2F in the architecture. Then evaluate its correctness, performance, security and limitations. (H§1)

The research contribution is the **transparent, measurable, layer-by-layer implementation and evaluation**. It is **not** a new algorithm and **not** a production-grade key (H§4).

## 2. Objectives

| # | Objective | Tag |
|---|---|---|
| O1 | USB-connected authenticator on an ESP32-S3 development board, with no custom PCB | [DECIDED] |
| O2 | Enumerate as a USB HID device using FIDO HID framing (CTAPHID) | [REQ] |
| O3 | Implement CTAP2 `authenticatorMakeCredential` and `authenticatorGetAssertion` (plus `authenticatorGetInfo`, which browsers need). CTAP1/U2F appears in Fig. 1 | [REQ] (CTAP1 scope [OPEN]) |
| O4 | Generate ECDSA P-256 key pairs on the device. The private key never leaves the token | [REQ] |
| O5 | Keep credentials across power cycles | [REQ] (H§3.5) |
| O6 | Require a local user-presence (UP) action before signing | [REQ] objective, implementation [OPEN] |
| O7 | Demonstrate registration and login against a controlled local WebAuthn relying party | [DECIDED] |
| O8 | Measure correctness, latency, resource usage and failure handling, and analyse security and limitations | [REQ] |

## 3. Scope

**In scope (core, needed by the deadline; priority from H§HANDOFF):**
1. ESP32-S3 firmware: USB HID, CTAPHID, CTAP2 `getInfo` / `makeCredential` / `getAssertion`, P-256/SHA-256 through mbedTLS, NVS credential store, button user presence.
2. Local WebAuthn relying party (RP): backend with a maintained server library, frontend with Register/Login buttons, and the DB tables `users` / `credentials` / `challenges`.
3. Evaluation harness: T01–T12, metrics M1–M8 exported as CSV, and an environment record.

**Stretch (only after the core works end to end, per H§HANDOFF priority):** CTAP1/U2F over `CTAPHID_MSG`, discoverable (resident) credentials, flash encryption / secure boot hardening.

**Out of scope (future work, exactly three, per H§Future work):** secure element (ATECC608A-class), NFC transport, and a credential-management utility.

**Explicitly excluded:** clientPIN / user verification (unless the team decides otherwise, see [OPEN] Q5), commercial website interoperability claims, FIDO certification, vendor attestation, BLE.

## 4. Proposed Solution

A three-entity FIDO2 system (Fig. 1, H§6):

1. **ESP32-S3 token:** enumerates as a FIDO HID device and runs a modular CTAP stack. It generates P-256 keys from the hardware RNG, stores them in on-device flash (NVS), signs `authenticatorData ‖ clientDataHash` after a physical button press, and never exports private keys.
2. **Client device:** an unmodified browser (WebAuthn API) plus the OS CTAP/HID stack.
3. **Relying party:** a local web application that issues single-use random challenges, verifies attestation and assertion objects with a maintained WebAuthn library, stores only public keys and credential IDs, and logs every verification result with a reason code.

A fourth, research-only element, the **evaluation harness** [NEW, derived from H§22 and H§HANDOFF-C], drives the token directly over CTAP/HID and drives the RP over HTTP. It runs T01–T12 repeatably and collects timing and resource metrics.

## 5. System Architecture

```
                      User (button press = user presence)
                                  │
┌─────────────────────────────────▼──────────────┐   HTTPS or http://localhost   ┌───────────────────────────────────┐
│ Client device                                   │◄────────────────────────────►│ Relying party (local)              │
│  • Browser: navigator.credentials.create()/get()│   JSON (base64url fields)    │  • /register/options, /verify      │
│  • OS CTAP2 / HID stack                          │                              │  • /login/options,    /verify      │
└─────────────────────────────────▲──────────────┘                              │  • challenge store (single-use)    │
                                  │ CTAP2 (CTAPHID_CBOR) [+ CTAP1 via            │  • users / credentials (pubkeys)   │
                                  │ CTAPHID_MSG, if in scope] over USB HID       │  • auth_events log [NEW]           │
┌─────────────────────────────────▼──────────────┐                              └───────────────────────────────────┘
│ ESP32-S3 token (native USB OTG port)            │
│  USB HID ─► CTAPHID ─► CTAP dispatcher          │        ┌─────────────────────────────┐
│     getInfo · makeCredential · getAssertion     │◄──────►│ Evaluation harness [NEW]    │
│  crypto (mbedTLS) · credential store (NVS)      │  HID   │  python-fido2 + pyserial    │
│  auth state (AAGUID, counters) · UP button      │        │  T01–T12, metrics → CSV     │
│  metrics log ─► UART (separate port) ───────────┼───────►│                             │
└────────────────────────────────────────────────┘        └─────────────────────────────┘
```

The detailed architecture (layers, directory structure, APIs, schema, error handling, logging, testing) is in [`ARCHITECTURE.md`](ARCHITECTURE.md).

## 6. Components

| Component | Responsibility | Source / tag |
|---|---|---|
| USB HID driver | Descriptors (usage page 0xF1D0, usage 0x01), 64-byte IN/OUT reports | H§14 [SPEC-VERIFY]; TinyUSB [PROPOSED] |
| CTAPHID transport | INIT/CONT reassembly and fragmentation, channel allocation, PING, MSG, CBOR, ERROR, KEEPALIVE, CANCEL, timeouts | H§HANDOFF-A1 [REQ] |
| CTAP2 dispatcher | CBOR decode and validation, command routing, canonical CBOR responses, CTAP2 status codes | H§HANDOFF-A2 [REQ] |
| U2F/CTAP1 handler | Register/Authenticate through `CTAPHID_MSG` | [OPEN] stretch |
| Crypto engine | P-256 keygen, SHA-256, ECDSA sign, DER encoding, COSE_Key encoding, zeroization | H§10 [REQ]; mbedTLS [PROPOSED] |
| Credential store | Persistent records, power-loss-safe updates, boot validation | H§HANDOFF-A6 [PROPOSED] |
| Authenticator state | AAGUID, per-credential sign counters, config, storage version | H§6 [PROPOSED] |
| User presence | GPIO button, timeout, keepalive while waiting | H§HANDOFF-A7 [PROPOSED] (GPIO [OPEN]) |
| Metrics / logging | Timestamped UART log lines for M1–M2 and M6–M7 | H§HANDOFF-A9 [PROPOSED] |
| RP backend | Options, verification, persistence, logging | H§15, H§18 [DECIDED]/[PROPOSED] |
| RP frontend | Register/Login UI, base64url handling, client timing | H§16 [PROPOSED] |
| Evaluation harness | Scripted T01–T12, metrics collection, CSV export, statistics | H§22–23, H§HANDOFF-C; tooling [NEW] |

## 7. Authentication Flow

This is Fig. 3 with the corrections [DECIDED] in H§9 applied. **Standard WebAuthn/CTAP2 behaviour, except where marked.**

```
User      Browser/Platform          RP backend                    ESP32-S3 token
 │ click "Login with security key"     │                               │
 │──────────►│ POST /login/options {username}                         │
 │           │─────────────────────►│ challenge = CSPRNG(32 B), store(session, 'auth', TTL)
 │           │                      │ PublicKeyCredentialRequestOptions{challenge, rpId,
 │           │◄─────────────────────│   allowCredentials=[user's credIds], userVerification:"discouraged" [NEW]}
 │           │ navigator.credentials.get()                           │
 │           │ clientDataJSON{type:"webauthn.get", challenge, origin}  │
 │           │ clientDataHash = SHA-256(clientDataJSON)               │
 │           │── CTAPHID_CBOR: authenticatorGetAssertion(0x02) ──────────►│ 1. parse/validate CBOR
 │           │    {rpId, clientDataHash, allowList, options{up:true}}  │ 2. find credential: credId ∈ allowList
 │           │                                                        │    AND record.rpIdHash == SHA-256(rpId)
 │           │                                                        │    → none: CTAP2_ERR_NO_CREDENTIALS
 │           │◄── CTAPHID_KEEPALIVE(UPNEEDED) every ≤100 ms ───────────│ 3. wait for button (timeout)
 │ press button ─────────────────────────────────────────────────────►│
 │           │                                                        │ 4. signCount++ and persist BEFORE signing
 │           │                                                        │ 5. authData = rpIdHash‖flags(UP)‖signCount
 │           │                                                        │ 6. sig = ECDSA-P256-SHA256(sk, authData‖clientDataHash)
 │           │◄── {credential, authData, signature, [user]} ───────────│ 7. zeroize sk copy in RAM
 │           │ POST /login/verify {assertion (base64url)}             │
 │           │─────────────────────►│ consume challenge (single-use), verify:
 │           │                      │  type, challenge, origin, rpIdHash, UP flag,
 │           │                      │  signCount > stored (if non-zero), signature with stored pk
 │           │                      │ update sign_count/last_used_at; log auth_event [NEW]
 │◄──────────│◄─────────────────────│ {ok:true} / {ok:false, reason}
```

Notes:
- The challenge is **not** in authenticatorData. It reaches the signature through `clientDataHash` (H§9 correction, [REQ]).
- "PIN" is removed from the figure unless clientPIN is implemented (H§9, [DECIDED]).
- The final RP step is labelled "Verify challenge, origin, RP ID, flags, counter, and signature" (H§9, [DECIDED]).
- **Username-first login** follows from using non-discoverable credentials, which need an allowList [NEW, see Q6].

## 8. Registration Flow

This is Fig. 2 with the corrections [DECIDED] in H§8 applied.

```
User      Browser/Platform          RP backend                    ESP32-S3 token
 │ enter username, click "Register security key"                      │
 │──────────►│ POST /register/options {username}                      │
 │           │─────────────────────►│ create/lookup user (user_handle = CSPRNG 32 B) [NEW rule: see §9]
 │           │                      │ challenge = CSPRNG(32 B), store(session,'reg',TTL)
 │           │◄─────────────────────│ PublicKeyCredentialCreationOptions{rp{id,name}, user{id,name,displayName},
 │           │                      │  challenge, pubKeyCredParams:[{type:"public-key",alg:-7}],
 │           │                      │  excludeCredentials, authenticatorSelection{residentKey:"discouraged",
 │           │                      │  userVerification:"discouraged"} [NEW], attestation [OPEN Q7]}
 │           │ navigator.credentials.create()                        │
 │           │── CTAPHID_CBOR: authenticatorMakeCredential(0x01) ────────►│ 1. parse/validate; ES256 (−7) in params?
 │           │   {clientDataHash, rp, user, pubKeyCredParams,          │    else CTAP2_ERR_UNSUPPORTED_ALGORITHM
 │           │    excludeList, options}                               │ 2. excludeList hit for this rpIdHash?
 │           │                                                        │    → wait UP, CTAP2_ERR_CREDENTIAL_EXCLUDED
 │           │◄── KEEPALIVE(UPNEEDED) ────────────────────────────────│ 3. wait for button (timeout)
 │ press button ─────────────────────────────────────────────────────►│
 │           │                                                        │ 4. (sk, pk) = P-256 keygen (HW RNG → mbedTLS CTR-DRBG)
 │           │                                                        │ 5. credId = random 16 B; record = {credId, rpIdHash,
 │           │                                                        │    userHandle, sk, signCount=0, flags, version, CRC}
 │           │                                                        │    → NVS write + commit (on-device flash/NVS)
 │           │                                                        │ 6. authData = rpIdHash‖flags(UP|AT)‖signCount(0)‖
 │           │                                                        │    AAGUID‖credIdLen‖credId‖COSE_Key(pk)
 │           │                                                        │ 7. attStmt: "none" {} OR "packed" self {alg:−7, sig}
 │           │◄── {fmt, authData, attStmt} ───────────────────────────│
 │           │ POST /register/verify {attestation (base64url)}        │
 │           │─────────────────────►│ consume challenge; verify type, challenge, origin, rpIdHash,
 │           │                      │  UP flag, alg == −7, attestation per policy;
 │           │                      │  store {credential_id, user_id, public_key(COSE), sign_count, aaguid, transports}
 │◄──────────│◄─────────────────────│ {ok:true} / {ok:false, reason}; log auth_event [NEW]
```

Corrections [DECIDED] (H§8): use `navigator.credentials.create()`, not "createCredential". Fix the numbering gap 4→8. Show the user-presence step only if it is implemented. Write **"on-device flash/NVS"**, not "secure memory".

**Registration success criteria [DECIDED]:** (1) the browser accepts the response, (2) the server validates it, (3) the server stores the credential, (4) the credential survives a token restart, (5) a later login with it succeeds.

## 9. Security Model

| Control | Where | Tag |
|---|---|---|
| Private key generated on the device and never returned by any command or log | Token | [REQ] |
| RP stores only the public key and credential ID | RP | [REQ] |
| Origin binding: `clientDataJSON.origin` + `rpIdHash` in authData | Browser + RP + token | [REQ] |
| Fresh, random, single-use, expiring challenge per ceremony | RP | [REQ] |
| Signature over `authData ‖ clientDataHash`, never over the raw challenge | Token | [REQ] (H§21) |
| Per-credential signature counter, incremented and persisted before signing | Token | [REQ]; persistence strategy [NEW] |
| Counter regression check (clone signal) | RP (library) | [REQ] |
| UP flag set **only** after a physical button press. `up:false` requests never wait and never set UP | Token | [PROPOSED]; the `up:false` rule is [SPEC-VERIFY] |
| Credential lookup bound to rpIdHash, so a credential ID from RP-A is unusable at RP-B | Token | [REQ] |
| Strict CTAPHID/CBOR input validation, fail closed, bounded buffers | Token | [PROPOSED] |
| Record integrity (CRC32 + version) and boot-time validation | Token | [PROPOSED] |
| Key-buffer zeroization (`mbedtls_platform_zeroize`) after use | Token | [NEW] |
| No key material in logs (enforced by code review + a test that greps logs) | Token + harness | [NEW] |
| A new credential for an **existing** username needs an authenticated session (prevents credential injection / account takeover) | RP | [NEW] |
| Session cookie: HttpOnly, SameSite=Strict, Secure when on HTTPS | RP | [NEW] |
| Vetted libraries only: mbedTLS on the token, a maintained WebAuthn library on the RP | Both | [REQ] |
| Flash encryption, secure boot, JTAG/USB-JTAG disable | Token | [OPEN]; a stated limitation if not done |
| clientPIN / UV | Token | [OPEN]; not claimed unless implemented |

Security properties the paper **may** claim if T07–T11 pass: phishing resistance through origin binding, no reusable server-side secret, replay resistance, and physical-presence gating. The paper **must not** claim tamper resistance, certification, or protection against a stolen token without PIN (H§26, H§28).

## 10. Threat Model

**Assets:** credential private keys (token), per-credential counters (token), user↔credential bindings (RP), challenges (RP), and session state (RP).
**Trust assumptions [ASSUMED]:** the browser correctly enforces origin/RP-ID rules, the OS HID stack is not compromised during a ceremony, and the RP host is trusted.

| # | Threat | Attacker capability | Mitigation | Residual / limitation | Test |
|---|---|---|---|---|---|
| TH1 | Password phishing / fake RP | Controls a look-alike origin | Browser puts the real origin in clientDataJSON. RP checks origin + rpIdHash. The token only finds credentials whose rpIdHash matches | Depends on a correct browser + RP | T10 |
| TH2 | RP database theft | Reads `credentials` | Only public keys stored; cannot forge assertions | Privacy leak of usernames/credIds | Design argument |
| TH3 | Assertion replay | Captures a valid assertion | Single-use challenge; clientDataHash is inside the signature | None expected | T09 |
| TH4 | Credential ID misuse across RPs | Presents RP-A's credId to RP-B | Token checks rpIdHash → `CTAP2_ERR_NO_CREDENTIALS` | — | T10 (CTAP level) |
| TH5 | Host malware | Sends CTAP requests | UP button blocks silent signing | Malware can still ride a legitimate press | T-UP (silent signing) |
| TH6 | Malformed / fuzzed USB input | Arbitrary HID reports | Strict length/seq/CID checks, CTAPHID_ERROR, no crash | Firmware bugs undiscovered by tests | T04 |
| TH7 | Physical theft | Holds the token | UP only; no PIN | **Holder can authenticate.** Stated limitation | Limitation |
| TH8 | Flash extraction / cloning | Dumps flash over UART/JTAG | Counter regression may reveal clone use | **Plain NVS: keys recoverable** unless flash encryption is on. Limitation | Limitation / [OPEN] hardening |
| TH9 | Compromised firmware | Reflashes the device | Secure boot [OPEN] | Undermines all guarantees if absent | Limitation |
| TH10 | Power loss / restart mid-operation | Unplugs during write | NVS atomic commits, CRC validation at boot, counter persisted before signing | Counter may skip values (acceptable) | T06, T-restart |
| TH11 | Debug-port access | USB-Serial-JTAG / UART | Disable JTAG in hardened build [OPEN] | Limitation if absent | Limitation |
| TH12 | Credential injection on RP [NEW] | Registers their own key under a victim username | Adding a credential to an existing user needs an authenticated session | — | RP unit test |

Attack scenarios in H§13 map to: changed/stale challenge → T09. Wrong RP/origin → T10. Unknown credential ID → T11. Malformed CTAPHID → T04. Silent signing → T-UP. Restart mid-state → T06 / T-restart. Theft, flash dump and debug port → analytical limitations.

## 11. Technology Stack

| Layer | Choice | Status | Why |
|---|---|---|---|
| Board | ESP32-S3 dev board with a **native USB** connector (e.g., ESP32-S3-DevKitC-1: "USB" = native OTG on GPIO19/20, "UART" = USB-UART bridge) | Family [DECIDED]; model [OPEN] | Native USB OTG is needed for a custom HID class; the second (UART) port keeps logs available while the native port is HID |
| Cable | Data cable matching the board connector | [DECIDED] | — |
| Firmware framework | ESP-IDF **v5.x, exact version pinned** (e.g., v5.3.x LTS) | [PROPOSED]; version pin [NEW] | Official framework; reproducible builds |
| USB stack | TinyUSB through the `espressif/esp_tinyusb` managed component | [PROPOSED] | Supported HID class on ESP32-S3 |
| Crypto | mbedTLS (bundled with ESP-IDF): `ecp`, `ecdsa`, `sha256`, `ctr_drbg`, `entropy` | [PROPOSED] | Vetted; hardware-accelerated SHA; no hand-written ECC |
| CBOR | TinyCBOR (`espressif/cbor` managed component) | [OPEN] → recommend [NEW] | Small, streaming encoder/decoder in C; see Q-CBOR |
| Storage | ESP-IDF NVS on a dedicated `fido` partition | [PROPOSED]; dedicated partition [NEW] | Wear levelling and atomic key-value commits |
| RP backend | **Python 3.11+, FastAPI, `webauthn` (py_webauthn), SQLite** | [OPEN] → recommend [NEW] | Maintained, spec-compliant verification. Same language as the harness. SQLite = zero-setup reproducibility |
| RP frontend | Plain HTML + vanilla JS, served by the RP (same origin) | [NEW] | No build step. Same origin avoids CORS and RP-ID mismatch |
| Harness | Python: `fido2` (Yubico python-fido2) for CTAPHID/CTAP2, `pyserial` for UART metrics, `requests`/`httpx`, `pandas`/`numpy` for stats | [NEW] | Drives the token directly for repeatable trials and negative cases a browser cannot produce |
| Host unit tests (firmware core) | Portable C core built on Linux with CMake + mbedTLS + TinyCBOR + Unity | [NEW] | Protocol/crypto logic can be tested without hardware (see ARCHITECTURE §6) |
| RP / frontend tests | `pytest` with a software authenticator (test only). Optional Playwright + Chromium virtual authenticator | [NEW] | Tests the RP independently of the token |
| Browsers | Chrome/Edge/Firefox | [OPEN] which ones and which OS | — |

## 12. Database Design

### 12.1 RP database (SQLite)

Tables `users`, `credentials` and `challenges` come from H§17 [PROPOSED]. Column types and constraints are [NEW]. `auth_events` is [NEW] (research logging required by H§15: "log verification failures with reasons").

```sql
CREATE TABLE users (
  id            INTEGER PRIMARY KEY,
  username      TEXT    NOT NULL UNIQUE,
  user_handle   BLOB    NOT NULL UNIQUE,          -- WebAuthn user.id, 32 random bytes, no PII
  created_at    TEXT    NOT NULL                  -- ISO-8601 UTC
);

CREATE TABLE credentials (
  credential_id BLOB    PRIMARY KEY,              -- raw bytes from authenticator
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key    BLOB    NOT NULL,                 -- COSE_Key bytes as returned by library
  sign_count    INTEGER NOT NULL DEFAULT 0,
  aaguid        BLOB,
  fmt           TEXT,                             -- attestation format received [NEW]
  transports    TEXT,                             -- JSON array, e.g. ["usb"]
  created_at    TEXT    NOT NULL,
  last_used_at  TEXT
);

CREATE TABLE challenges (
  session_id    TEXT    NOT NULL,
  challenge     BLOB    NOT NULL,
  type          TEXT    NOT NULL CHECK (type IN ('reg','auth')),
  user_id       INTEGER REFERENCES users(id),     -- binds ceremony to user [NEW]
  expires_at    TEXT    NOT NULL,
  PRIMARY KEY (session_id, type)                  -- one outstanding ceremony per type per session
);

CREATE TABLE auth_events (                        -- research evidence [NEW]
  id              INTEGER PRIMARY KEY,
  ts              TEXT    NOT NULL,
  run_id          TEXT,                           -- experiment run identifier (NULL for manual use)
  ceremony        TEXT    NOT NULL CHECK (ceremony IN ('reg','auth')),
  username        TEXT,
  credential_id   BLOB,
  result          TEXT    NOT NULL CHECK (result IN ('success','failure')),
  reason          TEXT,                           -- machine-readable code, e.g. CHALLENGE_MISMATCH
  server_verify_us INTEGER,                       -- time spent in verification only
  client_total_ms REAL,                           -- reported by frontend (includes human UP time)
  user_agent      TEXT
);
```

### 12.2 On-token credential record (NVS)

H§17 [PROPOSED] fields. The layout and sizes below are [NEW] and get measured for M7.

| Field | Size (B) | Notes |
|---|---|---|
| `version` | 1 | Record format version (starts at 1) |
| `flags` | 1 | bit0 = discoverable (reserved), others reserved |
| `cred_id` | 16 | Random from HW RNG. Also the NVS lookup key (hex prefix) |
| `rp_id_hash` | 32 | SHA-256(rpId). The RP ID string itself is not needed for matching |
| `user_handle_len` + `user_handle` | 1 + ≤64 | WebAuthn user.id (needed for discoverable credentials and assertion `user`) |
| `private_key` | 32 | P-256 scalar. **Plain NVS unless flash encryption is enabled. Must not be called "secure storage"** |
| `sign_count` | 4 | Per-credential, big-endian in authData |
| `crc32` | 4 | Over all preceding fields |
| **Total (payload)** | **≈155 max** | Plus NVS entry overhead (32-byte entries). The real figure is measured with `nvs_get_stats` |

Global state namespace: `aaguid` (16 B, compile-time constant), `store_version`, `cred_count`.

## 13. API Design

Endpoints from H§18 [PROPOSED]. Request/response bodies and the extra endpoints are [NEW]. All binary fields are base64url without padding. JSON over `POST`.

| Method | Path | Request | Response | Notes |
|---|---|---|---|---|
| POST | `/register/options` | `{username, displayName?}` | `PublicKeyCredentialCreationOptionsJSON` | Creates user if new. If the user exists and has credentials, needs an authenticated session (TH12) |
| POST | `/register/verify` | `RegistrationResponseJSON` + `{client_total_ms?, run_id?}` | `{ok, credential_id?, reason?}` | Challenge consumed on any attempt |
| POST | `/login/options` | `{username}` | `PublicKeyCredentialRequestOptionsJSON` | Unknown username → still returns options with no credentials? See Q-ENUM |
| POST | `/login/verify` | `AuthenticationResponseJSON` + `{client_total_ms?, run_id?}` | `{ok, username?, reason?}` | Updates `sign_count`, `last_used_at`; sets session |
| POST | `/logout` | — | `{ok}` | [NEW] |
| GET | `/me` | — | `{username, credentials:[{id, created_at, last_used_at, sign_count}]}` | [NEW] for UI; no key material (public keys are not needed in the UI either) |
| GET | `/healthz` | — | `{ok, rp_id, origin, version}` | [NEW] harness pre-check |
| GET | `/experiment/events?run_id=` | — | CSV of `auth_events` | [NEW] **research-only; disabled unless `RP_EXPERIMENT_MODE=1`** |

Error codes returned in `reason` (and logged): `CHALLENGE_NOT_FOUND`, `CHALLENGE_EXPIRED`, `CHALLENGE_MISMATCH`, `ORIGIN_MISMATCH`, `RPID_HASH_MISMATCH`, `UP_NOT_SET`, `UNSUPPORTED_ALG`, `ATTESTATION_INVALID`, `SIGNATURE_INVALID`, `COUNTER_REGRESSION`, `UNKNOWN_CREDENTIAL`, `USER_EXISTS_AUTH_REQUIRED`, `MALFORMED_REQUEST`. The library's exception types get mapped to these codes.

## 14. Frontend Requirements

H§16 [PROPOSED], plus [NEW] details:
- One page with a username field and **Register security key** / **Login with security key** buttons.
- Calls `navigator.credentials.create()` and `navigator.credentials.get()`, with base64url ↔ ArrayBuffer conversion for `challenge`, `user.id`, `allowCredentials[].id`, `excludeCredentials[].id` and all response buffers.
- Feature detection (`window.PublicKeyCredential`) and a secure-context check (`window.isSecureContext`) with clear messages.
- Shows success/failure, the RP `reason` code, and browser `DOMException` names (`NotAllowedError`, `InvalidStateError`, etc.).
- Client timing with `performance.now()`: `t_options`, `t_ceremony` (includes human button time), `t_verify`, `t_total`. The values are sent to the RP and labelled **"includes user-presence time"** (H§23).
- Hides nothing security-relevant. No inline secrets. Strict CSP [NEW].

## 15. Backend Requirements

H§15 [DECIDED]/[PROPOSED], plus [NEW] where marked:
1. Challenges: 32 bytes from `secrets.token_bytes`, bound to the server-side session and the ceremony type, TTL 120 s [NEW], deleted on first verify attempt (single-use), expired rows purged.
2. Options: `rp.id`, `rp.name`, `user.id` (= user_handle), `user.name`, `pubKeyCredParams=[ES256]`, `excludeCredentials` / `allowCredentials`, `timeout=60000`, `userVerification="discouraged"`, `residentKey="discouraged"` [NEW, pending Q5/Q6], `attestation` per Q7.
3. Registration verification: type, challenge, origin, rpIdHash, UP flag, public key alg, attestation per policy (accept `none` and `packed` self-attestation; reject others) [NEW policy].
4. Authentication verification: type, challenge, origin, rpIdHash, UP (UV not required), signCount (reject regression when stored > 0), signature.
5. Config through environment variables: `RP_ID` (default `localhost`), `RP_ORIGIN` (default `http://localhost:8000`), `RP_NAME`, `DB_PATH`, `SESSION_SECRET` (required, no default in production mode), `RP_EXPERIMENT_MODE`.
6. Serve on `http://localhost` (a secure context) or HTTPS with a locally trusted certificate (mkcert) for non-localhost demos [SPEC-VERIFY].
7. Structured JSON logs with a reason code for every failure, plus a row in `auth_events`.

## 16. Experimental Methodology

Unit → integration → system → security testing (H§22).

| ID | Test | Level / driver | Expected | Tag |
|---|---|---|---|---|
| T01 | Connect board | OS (`lsusb -v`, hidraw descriptor dump) + harness enumerates FIDO device | FIDO HID device (usage page 0xF1D0) detected | H§22 |
| T02 | Flash + restart | `idf.py flash monitor` | Boots; boot log shows store validated | H§22 |
| T03 | Valid USB packet | Harness: CTAPHID_INIT, PING (1 B … 7609 B), getInfo | Correct echoes/response | H§22 |
| T04 | Malformed packet | Harness: raw hidraw reports (bad CID, bad SEQ, oversize BCNT, CONT without INIT, unknown cmd, truncated CBOR, wrong types) | CTAPHID_ERROR / CTAP2 error; **device stays responsive** | H§22; case list [NEW] |
| T05 | Generate credential | Harness: makeCredential | Valid attestation; record created; independent verification of signature/COSE key | H§22 |
| T06 | Restart after registration | Harness + manual replug | getAssertion with stored credId still succeeds | H§22 |
| T07 | Register on local site | Browser, manual | RP returns ok; row in `credentials` | H§22 |
| T08 | Authenticate | Browser, manual | RP returns ok; sign_count increases | H§22 |
| T09 | Altered / stale challenge | Harness vs RP: replay a captured assertion; flip a byte in clientDataJSON challenge; use an expired challenge | RP rejects with a specific reason code | H§22 |
| T10 | Wrong RP / origin | (a) CTAP: getAssertion with a different rpId + real credId → `NO_CREDENTIALS`. (b) RP: assertion whose clientDataJSON origin ≠ RP origin → `ORIGIN_MISMATCH` | Rejected at both levels | H§22; split [NEW] |
| T11 | Unknown credential | CTAP: random credId in allowList → `CTAP2_ERR_NO_CREDENTIALS`. RP: unknown credId → `UNKNOWN_CREDENTIAL` | Correct error | H§22 |
| T12 | Repeated registration/login | Harness loop N trials | Consistent; feeds metrics | H§22 |
| T-UP | Silent signing | Harness: getAssertion with up=true, no press | `CTAP2_ERR_USER_ACTION_TIMEOUT`; no signature emitted | H§13 → [NEW] test ID |
| T-RST | Restart mid-state | Unplug during UP wait / right after makeCredential | No corrupted records at boot; counters monotonic | H§13 → [NEW] test ID |
| T-CNT | Counter behaviour | Consecutive assertions | Strictly increasing signCount; survives reboot | [NEW] |

**Record for reproducibility (H§22):** board model and revision, ESP-IDF version (git describe), toolchain version, component versions (`dependencies.lock`), flashing method, firmware size, compile issues and fixes, boot log, flash time, USB descriptors, report size/framing, host OS + kernel, browser versions, python/package versions (`requirements.lock`), and number of trials. The harness writes `results/<run_id>/environment.json` automatically [NEW].

**User-presence handling in measurements:** firmware timestamps exclude the time spent waiting for the button (H§23 [PROPOSED]). The button wait is reported as a separate column. Harness trials need a human to press the button, unless the team approves the experiment-only auto-confirm build discussed in RISKS R-UP-AUTO (**not recommended**).

## 17. Evaluation Metrics

H§23. Operational definitions are [NEW].

| ID | Metric | Unit | Definition / measurement point | Source |
|---|---|---|---|---|
| M1 | Credential creation time | ms | Token-internal: CBOR request fully reassembled → response CBOR ready, **minus UP wait**. Sub-phases: parse, keygen, NVS write, authData build, attestation sign | Firmware `esp_timer_get_time()` → UART `METRIC` lines |
| M2 | Authentication time | ms | Same for getAssertion. Sub-phases: lookup, counter persist, sign | Firmware |
| M3 | USB/transport latency | ms | Host round-trip of `CTAPHID_PING` at 1, 57, 64, 512, 1024, 7609 B; plus host RTT(cmd) − M1/M2 − UP wait | Harness (`time.perf_counter_ns`) |
| M4 | End-to-end ceremony time | ms | Browser: options request → verify response. **Includes human UP time; reported separately** | Frontend → `auth_events.client_total_ms` |
| M5 | Firmware size | KB | `idf.py size` (flash image, `.text`/`.rodata`), `idf.py size-components` | Build output |
| M6 | RAM usage | bytes | Static DRAM/IRAM from `idf.py size`. Runtime minimum free heap (`esp_get_minimum_free_heap_size`) and task stack high-water marks after N ceremonies | Build + firmware log |
| M7 | Storage per credential | bytes | Record payload size + NVS overhead measured as `used_entries` delta × 32 B via `nvs_get_stats`; max credential capacity | Firmware log |
| M8 | Authentication success rate | % | Successful positive trials / attempted positive trials (T07/T08/T12). Negative tests report **correct-rejection rate** | Harness + `auth_events` |

**Statistics [NEW]:** for each timing metric report N, mean, SD, median, min, max, p95, and 95% CI of the mean. Report the RP-side verification time (`server_verify_us`) separately. N is **[OPEN]**: 30 or 50 per H§22, and this plan recommends 50.

## 18. Expected Results

H§25: qualitative only until measured.
- Successful registration and login on the local RP in the tested browsers.
- Rejection of altered/stale challenge, wrong RP/origin and unknown credential.
- Credential persistence across reboot.
- Measured M1–M8 tables. **No number is written in the paper before it is measured and saved in `results/`.**

## 19. Research Paper Integration

| Paper section | Artifact produced by the project |
|---|---|
| Proposed system / architecture (Fig. 1) | `ARCHITECTURE.md` §1–2 (layer diagram, component table) |
| Registration flow (Fig. 2) | §8 of this document, with the corrections applied |
| Authentication flow (Fig. 3) | §7 of this document, with the corrections applied |
| Cryptographic design | §8–9 + `ARCHITECTURE.md` §5 (equations, authData layout, COSE_Key) |
| Implementation | `firmware/` + `rp/` READMEs; `docs/decisions/` ADRs; statement of what was written vs. reused (Q2) |
| Experimental setup | `results/<run_id>/environment.json` |
| Results | `results/<run_id>/*.csv` → `harness/analysis/report.py` → tables/plots |
| Security analysis | §10 of this document + `docs/security_analysis.md` (test evidence per threat) |
| Limitations | H§26 list, updated with facts: which hardening is or is not enabled |
| Future work | Exactly three items: secure element, NFC, credential-management utility |
| Screenshots | Browser success/failure, `lsusb` output, serial logs (captured in `docs/evidence/`) |

The captions say "developed", and the paper claims contributions 1–5 of H§4. Each claim is backed by an evidence item in `docs/evidence/` before submission [REQ].

## 20. Open Questions / Decisions Required

Full list with recommendations: [`RISKS_AND_OPEN_QUESTIONS.md`](RISKS_AND_OPEN_QUESTIONS.md) §B. Summary:

| # | Question | Recommendation |
|---|---|---|
| Q1 | Exact board model and native-USB port | DevKitC-1 (N8R8 or similar): "USB" port = HID, "UART" port = logs/flash |
| Q2 | Write from scratch or adapt an open-source stack | From scratch for CTAPHID/CTAP2 glue (small, transparent, clear licence), using vetted mbedTLS + TinyCBOR |
| Q3 | CTAP1/U2F in scope? | Stretch; getInfo lists only `FIDO_2_0` until implemented |
| Q4 | Button and GPIO | Onboard BOOT button (GPIO0), active-low, used after boot |
| Q5 | clientPIN/UV | Not implemented; RP uses `userVerification:"discouraged"` |
| Q6 | Discoverable credentials | Non-discoverable in core (username-first login); rk as stretch |
| Q7 | Attestation format + AAGUID | `packed` self-attestation; RP requests `attestation:"direct"`; random AAGUID fixed in source |
| Q8 | Backend stack | Python + FastAPI + py_webauthn + SQLite |
| Q9 | Browsers/OS, N trials | Chrome + Firefox on Linux (+ Edge/Windows if available); N = 50 |
| Q10 | Flash encryption / secure boot | Off for development; optionally evaluate once as a hardened variant; otherwise a stated limitation |
| Q11 | What exists already | Confirm: the repo is empty. Is there firmware code outside the repo? |
| Q12 | CTAP version claimed | CTAP 2.0 subset (`FIDO_2_0`), not 2.1 |
| Q13 | Human button press for N trials vs auto-confirm experiment build | Human press; UP wait excluded by firmware timing |
