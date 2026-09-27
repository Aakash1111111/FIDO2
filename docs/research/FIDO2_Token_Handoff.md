# Technical Handoff: FIDO2/U2F Hardware Authentication Token on ESP32-S3

**Prepared:** 27 September 2026
**Paper deadline:** 30 September 2026 (IEEE-style paper)
**Official paper title (do not change):** *Design and Implementation of a FIDO2/U2F Compliant Authentication Token for Secure Passwordless Authentication*
(Earlier working title, now superseded: *Design and Implementation of a FIDO2/WebAuthn-Compliant Hardware Security Token for Passwordless Authentication*)

---

## 0. How to read this document

Every item is tagged with one of these labels:

| Tag | Meaning |
|---|---|
| **[REQ]** | Established requirement: comes from the FIDO/WebAuthn/CTAP specifications or from the project's non-negotiable rules |
| **[DECIDED]** | Decision explicitly made by the team during the conversation |
| **[PROPOSED]** | Idea suggested during planning but not confirmed as implemented or adopted |
| **[ASSUMED]** | Assumption that has not been verified |
| **[OPEN]** | Still needs to be decided or verified |
| **[SPEC-VERIFY]** | Standard protocol detail included for the implementer; confirm against the official FIDO CTAP 2.x and W3C WebAuthn specifications before relying on it |

**Implementation status:** The conversation did not confirm which parts of the firmware, WebAuthn test site, or measurements are complete. Treat all implementation as **not yet verified** until the implementing partner confirms it. The figure captions in the paper use the word "developed", which must be true by submission.

**Team split [DECIDED]:**
- Author A (paper): writing, literature survey, research gap, introduction, problem statement, objectives, proposed system, architecture, methodology, cryptographic design, security analysis, limitations, future work, conclusion, IEEE formatting, references, paraphrasing.
- Author B (implementation): ESP32-S3 firmware, USB HID, CTAP2, crypto integration, prototype, WebAuthn integration, testing, screenshots, performance measurements, actual results.

---

## 1. Research problem

Password-based authentication is vulnerable to phishing, credential reuse across services, database breaches, keyloggers, and social engineering. SMS OTPs and some second factors can be intercepted or phished. Commercial FIDO security keys solve this but are closed, fixed-function products. The problem addressed is building a **low-cost, customizable, transparent** hardware authenticator on a general-purpose microcontroller that performs origin-bound public-key authentication via FIDO2/U2F.

## 2. Research motivation

- Passwordless and phishing-resistant authentication is central to identity management and zero-trust security.
- A server that stores only public keys cannot leak reusable secrets.
- Building the authenticator from a development board exposes every layer (USB transport, protocol, cryptography, storage) for study and evaluation, which commercial keys do not.
- Application areas: enterprise employee access, privileged/admin accounts, banking, cloud platforms, DevOps services.

## 3. Research objectives

1. **[DECIDED]** Build a USB-connected authenticator on an ESP32-S3 development board (no custom PCB).
2. **[REQ]** Enumerate as a USB HID device using FIDO HID framing (CTAPHID).
3. **[REQ]** Implement CTAP2 credential creation (`authenticatorMakeCredential`) and assertion (`authenticatorGetAssertion`); Fig. 1 also lists CTAP1/U2F processing.
4. **[REQ]** Generate ECDSA P-256 key pairs on-device; the private key never leaves the token.
5. Persist credentials across power cycles.
6. Require a local user-presence action before signing.
7. Demonstrate registration and login against a controlled local WebAuthn relying party.
8. Measure correctness, latency, resource usage, and failure handling; analyse security and limitations.

## 4. Proposed contribution / novelty

Stated as potential contributions, to be claimed **only if actually completed** [REQ]:
1. Low-cost USB hardware authenticator prototype on ESP32-S3.
2. Integration of embedded USB HID transport with a FIDO2 (and U2F) authenticator stack.
3. Implementation or adaptation of credential creation and assertion generation.
4. On-device private-key management using the selected storage approach.
5. Experimental evaluation of correctness, latency, resource usage, and limitations.

**Must NOT claim:** a new cryptographic algorithm, commercial-grade tamper resistance, FIDO certification, or universal interoperability with commercial websites, unless proven.

## 5. Existing approaches discussed

| Approach | Weakness noted |
|---|---|
| Passwords | Phishable, reusable, breachable |
| SMS OTP / some 2FA | Interceptable, phishable |
| FIDO U2F | Earlier FIDO protocol, mainly second factor |
| FIDO2 (WebAuthn + CTAP2) | Modern standard; the target of this project |
| Commercial hardware keys | Closed, fixed-function (comparison point) |

**[OPEN]** The literature survey references have not yet been collected or verified. No paper, author, or DOI may be invented. Primary references should be the official W3C WebAuthn and FIDO Alliance CTAP specifications, plus peer-reviewed papers that are individually verified.

## 6. Proposed FIDO2/WebAuthn architecture

Three entities (Fig. 1 of the paper):

```
            User
              │
┌─────────────▼─────────────┐   WebAuthn API / HTTPS   ┌──────────────────────────────┐
│ Client device             │◄────────────────────────►│ Relying party (web app)      │
│  • Browser / WebAuthn API │                          │  • Registration              │
│  • CTAP / USB HID stack   │                          │  • Public-key credential DB  │
└─────────────▲─────────────┘                          │  • Challenge generation      │
              │ CTAP2 (and CTAP1/U2F) over USB HID      │  • Authentication verification│
┌─────────────▼─────────────┐                          └──────────────────────────────┘
│ ESP32-S3 token            │
│  • USB HID interface      │
│  • CTAP1/U2F + CTAP2      │
│  • ECDSA P-256 / SHA-256  │
│  • Credential storage     │
│  • User interaction       │
└───────────────────────────┘
```

**Firmware layering [PROPOSED]:**

```
USB HID transport (CTAPHID framing)
        ↓ request buffer
CTAP command parser / dispatcher
   ├── makeCredential (registration)
   ├── getAssertion  (authentication)
   └── U2F register / authenticate (CTAP1)
        ↓
Shared services: crypto engine · credential store · authenticator state (counters) · user presence
        ↓
Response construction → USB HID transport
```

Rule [PROPOSED]: modules communicate only through defined interfaces so failures can be isolated to USB, parsing, storage, or crypto.

**Proposed source layout [PROPOSED]:**

```
FIDO2_Hardware_Token/
├── main/
│   ├── main.c                     # init + task/event loop
│   ├── usb_hid.c/.h               # descriptors, CTAPHID framing, send/receive
│   ├── ctap2.c/.h                 # CBOR parse, command dispatch, responses
│   ├── crypto.c/.h                # keygen, ECDSA sign, SHA-256, RNG wrapper
│   ├── credential_store.c/.h      # persistent credential records
│   └── authenticator_state.c/.h   # counters, config, AAGUID
├── test/{crypto_tests,usb_tests,protocol_tests}/
├── docs/{architecture.md,test_results.md,security_analysis.md}
└── README.md
```

## 7. Complete system workflow

```
Power on → hardware init → storage init/validate → crypto init → USB init → load authenticator state
→ wait for host requests
→ USB HID receives CTAPHID frames → reassemble message → CTAP dispatcher
→ makeCredential | getAssertion | getInfo | U2F command
→ credential store + crypto + user presence
→ build response → fragment into CTAPHID frames → host
→ browser returns result to relying party → RP verifies → success/failure
```

## 8. Registration flow (Fig. 2)

1. User clicks "Register security key".
2. Client requests registration options from RP.
3. RP generates a random challenge and returns `PublicKeyCredentialCreationOptions` (rp, user, challenge, pubKeyCredParams, etc.).
4. Browser calls **`navigator.credentials.create()`**; platform sends **`authenticatorMakeCredential`** over CTAP/USB HID.
5. Token validates request and algorithm (ES256 supported).
6. Token requests **user presence** (button press) — **[OPEN]** confirm it is implemented.
7. Token generates ECDSA P-256 key pair using hardware RNG.
8. Token stores private key + credential metadata in **on-device flash/NVS** (not "secure memory" unless encrypted storage/secure element is implemented).
9. Token builds authenticator data (with attested credential data) and attestation statement; returns over CTAP/USB HID.
10. Browser forwards response to RP.
11. RP validates (challenge, origin, rpIdHash, flags, attestation per its policy) and stores public key + credential ID linked to the user.

**Registration success criteria [DECIDED]:** browser accepts response; server validates it; server stores credential; credential survives token restart; a later login succeeds with it.

**Required figure corrections [DECIDED]:** rename "createCredential" → `navigator.credentials.create()`; fix numbering gap 4→8; add user-presence step if implemented; replace "secure memory" with "on-device flash/NVS".

## 9. Authentication flow (Fig. 3)

1. User clicks "Login with security key".
2. Client requests authentication options.
3. RP generates a **fresh** challenge; returns `PublicKeyCredentialRequestOptions` (challenge, rpId, allowCredentials).
4. Browser calls **`navigator.credentials.get()`**; platform sends **`authenticatorGetAssertion`** over CTAP/USB HID.
5. Token locates credential matching RP ID (and allowList credential ID).
6. Token requires user presence (button press).
7. Token builds authenticator data: **rpIdHash, flags, signCount** (the challenge is NOT in authenticator data; it is inside clientDataJSON).
8. Token signs `authenticatorData ‖ clientDataHash` with the stored private key (ECDSA P-256).
9. Token returns assertion (credential ID, authData, signature; user handle if applicable).
10. Browser forwards to RP.
11. RP verifies challenge, origin, RP ID hash, UP/UV flags, counter behaviour, and signature with the stored public key, then grants access.

**Required figure corrections [DECIDED]:** rename "getAssertion" API box → `navigator.credentials.get()` (getAssertion is the CTAP command); change "(challenge, counter, etc.)" → "(RP ID hash, flags, counter)"; add missing step 6; remove "PIN" unless CTAP2 clientPIN is implemented (PIN is entered on the host, not the token); change "Verify signature" → "Verify challenge, origin, RP ID, flags, counter, and signature".

## 10. Cryptographic operations

**[DECIDED]** Algorithm: ECDSA on NIST P-256 with SHA-256 (COSE algorithm ES256, identifier −7 [SPEC-VERIFY]).
**[REQ]** Use a vetted library, never hand-written ECC/ECDSA. **[PROPOSED]** mbedTLS (bundled with ESP-IDF).

Equations:

```
clientDataHash = SHA-256(clientDataJSON)
rpIdHash       = SHA-256(rpId)
Signature      = ECDSA_Sign(sk, authenticatorData ‖ clientDataHash)
Valid          = ECDSA_Verify(pk, authenticatorData ‖ clientDataHash, Signature)
```

Key generation: RNG → private key sk → public key pk = sk·G → store sk → return pk (COSE_Key, uncompressed x,y) inside attested credential data.

**Authenticator data layout [SPEC-VERIFY]:**

```
rpIdHash (32) | flags (1) | signCount (4, big-endian) | [attestedCredentialData] | [extensions]
flags: bit0 UP (user present), bit2 UV (user verified), bit6 AT (attested cred data), bit7 ED (extensions)
attestedCredentialData: AAGUID (16) | credIdLength (2) | credentialId | credentialPublicKey (COSE, CBOR)
```

**U2F/CTAP1 [SPEC-VERIFY]** (only if U2F support is kept): Register signature over `0x00 ‖ appParam ‖ challengeParam ‖ keyHandle ‖ userPublicKey`; Authenticate signature over `appParam ‖ userPresenceByte ‖ counter ‖ challengeParam`.

**Attestation [OPEN]:** "none" or "packed" self-attestation. No vendor attestation certificate exists; do not imply FIDO-certified attestation.

**RNG [ASSUMED/OPEN]:** ESP32-S3 hardware RNG via `esp_random()`; verify its true-randomness conditions from Espressif documentation and document them.

## 11. Security mechanisms

| Mechanism | Status |
|---|---|
| Private key generated and kept on device; never returned | [REQ] |
| RP stores only public key + credential ID | [REQ] |
| Origin binding via clientDataJSON + rpIdHash | [REQ] (browser + RP enforce) |
| Fresh RP challenge per ceremony (replay resistance) | [REQ] |
| Signature counter | [REQ]/[OPEN] persistence strategy |
| User presence via physical button | [PROPOSED]; claim only if implemented |
| PIN / user verification (clientPIN) | [OPEN]; do not claim unless implemented |
| Malformed/invalid packet rejection, credential-not-found errors, cancellation | [PROPOSED] |
| Storage corruption detection, power-loss-safe writes | [PROPOSED] |
| Flash encryption / secure boot / JTAG disable (ESP32-S3 features) | [OPEN] hardening; limitation if absent |
| Secure element (e.g., ATECC608A-class) | Future work only |

## 12. Threat model

| Threat | Protection / limitation |
|---|---|
| Password phishing | No password; origin-bound public-key authentication |
| Credential database theft | RP holds public keys only; cannot forge assertions |
| Replay of old assertions | Fresh challenge + clientDataHash in signature |
| Fake relying party | Origin and RP ID checks (when correctly implemented) |
| Malware on host | Can trigger requests; user presence mitigates silent use, not all attacks |
| Physical token theft | Depends on UP/PIN; without PIN, holder can authenticate |
| Flash extraction | Plain MCU flash offers weak tamper resistance — acknowledged limitation |
| Compromised firmware | Could undermine all guarantees; secure boot not confirmed |

## 13. Attack scenarios considered (test-driven)

Changed/stale challenge, wrong relying party / origin, unknown credential ID, malformed CTAPHID packets, silent signing without user action, token restart mid-state, physical theft, flash dump, debug-port access.

## 14. Technologies / frameworks / libraries

| Item | Status |
|---|---|
| ESP32-S3 dev board with **native USB device** port (many boards have separate "USB" and "UART" connectors — use native USB for HID) | [DECIDED] board family; exact model [OPEN] |
| USB-A-to-USB-C (or board-matching) **data** cable | [DECIDED]; USB-A-to-USB-A rejected |
| ESP-IDF (official Espressif framework); `idf.py build / flash / monitor` | [PROPOSED] |
| USB device stack: TinyUSB via ESP-IDF | [PROPOSED] |
| Crypto: mbedTLS | [PROPOSED] |
| CBOR encoder/decoder (e.g., TinyCBOR or equivalent) | [OPEN] |
| Storage: ESP-IDF NVS / dedicated flash partition | [PROPOSED] |
| Reuse of an existing open-source FIDO firmware stack vs. writing from scratch | [OPEN]; if reused, verify licence and ESP32-S3 support, and state clearly in the paper what was adapted |
| Browser: Chrome/Edge/Firefox with WebAuthn | [OPEN] which ones tested |

**CTAPHID transport details [SPEC-VERIFY]:** HID usage page 0xF1D0, usage 0x01; 64-byte input/output reports; init packets (CID 4 B, CMD 1 B with bit7 set, BCNT 2 B, data) and continuation packets (CID, SEQ, data); commands include CTAPHID_INIT, CTAPHID_MSG (U2F), CTAPHID_CBOR (CTAP2), CTAPHID_PING, CTAPHID_ERROR, CTAPHID_KEEPALIVE, CTAPHID_CANCEL. CTAP2 command bytes: 0x01 makeCredential, 0x02 getAssertion, 0x04 getInfo (getInfo must be implemented for browsers to accept the device).

## 15. Backend requirements (local relying party)

[DECIDED] Test with a **local controlled WebAuthn application first**, not commercial sites.
Language/framework and WebAuthn server library: **[OPEN]** (use a maintained, spec-compliant server library rather than hand-rolled verification).

Must:
- Generate cryptographically random challenges, bind them to a session, expire after use.
- Produce creation/request options with rp.id, rp.name, user.id, user.name, pubKeyCredParams [ES256], allowCredentials.
- Verify registration: type, challenge, origin, rpIdHash, UP flag, credential public key, attestation per policy.
- Verify authentication: challenge, origin, rpIdHash, UP (and UV if required), signCount behaviour, signature.
- Serve over HTTPS or `http://localhost` (WebAuthn requires a secure context) [SPEC-VERIFY].
- Log verification failures with reasons (needed for test evidence).

## 16. Frontend requirements

- Page with **Register security key** and **Login with security key** buttons.
- Calls `navigator.credentials.create()` / `navigator.credentials.get()`; base64url-encodes binary fields to/from the server.
- Displays success/failure and error messages; optional timing capture for latency metrics.

## 17. Database schema [PROPOSED]

```
users(
  id           PK,
  username     UNIQUE,
  user_handle  BLOB UNIQUE      -- WebAuthn user.id, random
)
credentials(
  credential_id  BLOB PK,
  user_id        FK → users.id,
  public_key     BLOB,          -- COSE key
  sign_count     INTEGER,
  aaguid         BLOB,
  transports     TEXT,
  created_at     TIMESTAMP,
  last_used_at   TIMESTAMP
)
challenges(
  session_id, challenge BLOB, type ('reg'|'auth'), expires_at
)
```

**On-token credential record [PROPOSED]:** credential ID, RP ID (or rpIdHash), user handle/metadata, private key, signature counter, flags, storage version.

## 18. API requirements [PROPOSED]

| Endpoint | Purpose |
|---|---|
| `POST /register/options` | Create challenge + creation options |
| `POST /register/verify` | Verify attestation response, store credential |
| `POST /login/options` | Create challenge + request options |
| `POST /login/verify` | Verify assertion, update sign_count, return result |

## 19. Algorithms / pseudocode

**Firmware main [PROPOSED; architectural, not literal ESP-IDF code]:**

```c
void app_main(void) {
    hardware_init();
    storage_init();        // open + validate credential store
    crypto_init();
    usb_init();            // HID descriptors, CTAPHID
    authenticator_init();  // load counters, AAGUID, config
    while (1) {
        usb_process_events();
        process_authenticator_requests();
        handle_pending_responses();
    }
}
```

**makeCredential:**
```
receive request → validate params & algorithm (ES256)
→ require user presence → RNG → generate P-256 key pair
→ create credential ID → store {credId, rpId, user, sk, counter, flags}
→ authData = rpIdHash ‖ flags(UP|AT) ‖ signCount ‖ attestedCredData(pk)
→ attestation stmt ("none" or packed self) → CBOR response → USB
```

**getAssertion:**
```
receive request → validate → find credential by rpId (+ allowList)
→ if none: return CTAP2_ERR_NO_CREDENTIALS [SPEC-VERIFY]
→ require user presence → increment + persist signCount
→ authData = rpIdHash ‖ flags(UP) ‖ signCount
→ sig = ECDSA_Sign(sk, authData ‖ clientDataHash)
→ CBOR response {credential, authData, signature, [user]} → USB
```

**Boot recovery:** firmware init → open storage → validate data → load state → ready.

## 20. Design decisions already made

- ESP32-S3 development board; no custom PCB.
- Proper data cable matching the board connector (not USB-A-to-USB-A).
- USB HID transport; CTAP2 core, with CTAP1/U2F shown in the architecture.
- ECDSA P-256 + SHA-256.
- Vetted crypto library; no hand-written crypto.
- Build in layers: run code → USB → crypto → storage → CTAP2 → WebAuthn → end-to-end tests.
- Validate first against a local WebAuthn test site.
- Private key never leaves the token.
- Figure API naming and authData corrections listed in §8–9.

## 21. Alternatives considered and rejected

| Alternative | Why rejected / deferred |
|---|---|
| Custom PCB | Unnecessary for a prototype |
| USB-A-to-USB-A cable | Not a normal or safe connection for this setup |
| STM32 or nRF52840 boards | Considered; ESP32-S3 chosen |
| Hand-written ECC/ECDSA | Security risk; use tested library |
| Testing first on GitHub/Google | Unknown attestation/policy requirements; not controllable or repeatable |
| Secure element in core build | Deferred to future work (provisioning/driver effort) |
| NFC transport | Deferred; needs extra hardware (controller, antenna) |
| Calling storage "secure memory" | Overclaims plain flash |
| Signing only the raw challenge | Incorrect; WebAuthn signs authData ‖ clientDataHash |

## 22. Experimental methodology

Unit → integration → system → security testing.

| ID | Test | Expected |
|---|---|---|
| T01 | Connect board | Detected as intended USB device |
| T02 | Flash + restart | Boots |
| T03 | Valid USB test packet | Correct response |
| T04 | Malformed packet | Rejected safely |
| T05 | Generate credential | Key pair + record created |
| T06 | Restart after registration | Credential persists |
| T07 | Register on local site | Server accepts |
| T08 | Authenticate | Server accepts assertion |
| T09 | Altered challenge | Fails |
| T10 | Wrong RP | Rejected / verification fails |
| T11 | Unknown credential | Appropriate error |
| T12 | Repeated registration/login | Consistent, measurable |

Record: board model, ESP-IDF version, programming method, firmware size, compile issues and fixes, boot logs, flash time, USB descriptors, packet size/framing, browser + OS versions, number of trials (e.g., 30 or 50 — **[OPEN]**).

## 23. Evaluation metrics

Credential creation time (ms); authentication time (ms); USB latency (ms); firmware size (KB); RAM usage (bytes); persistent storage per credential (bytes); authentication success rate (%). Report mean and spread over the stated number of trials. **Exclude user-presence wait time from latency or report it separately [PROPOSED].**

## 24. Baseline / comparison methods

**[OPEN]** Not decided. Candidate [PROPOSED]: qualitative/feature comparison with password login, SMS OTP, and commercial FIDO keys (cost, openness, protections). Any quantitative comparison with a commercial key requires actual measurement on the same setup.

## 25. Expected results

Qualitative only: successful registration and login on the local RP; rejection of altered-challenge, wrong-RP, and unknown-credential cases; credential persistence across reboot. **No numeric results may be written until measured.**

## 26. Limitations (to state in paper)

- Keys in ordinary MCU flash/NVS; no secure element; weak against physical extraction.
- Flash encryption, secure boot, debug lockout: not confirmed.
- No FIDO certification; no trusted vendor attestation.
- PIN/UV likely absent; stolen token + button press may suffice.
- Interoperability tested only on the local RP and the listed browsers.
- Compromised firmware or host malware remain risks.

## 27. Open questions

1. Exact ESP32-S3 board model and which USB port carries native USB.
2. Written from scratch or adapted from an existing open-source stack? Which one, which licence?
3. Is U2F/CTAP1 actually implemented, or only CTAP2?
4. Is a physical user-presence button implemented? Which GPIO?
5. Is clientPIN/UV implemented?
6. Resident (discoverable) vs non-discoverable credentials?
7. Attestation format: none or packed self-attestation? AAGUID value?
8. Backend language and WebAuthn server library.
9. Browsers/OS tested; number of trials.
10. Any flash encryption / secure boot enabled?
11. Which parts are complete and tested as of now (must be confirmed before the 30 Sep deadline).

## 28. Must NOT change

- Paper title (above).
- ESP32-S3 platform; USB HID transport; ECDSA P-256/SHA-256.
- Private key generated and retained on-device; never exported.
- Use of a vetted crypto library.
- No fabricated results, references, authors, DOIs.
- No claim of FIDO certification, commercial-grade tamper resistance, or unproven interoperability.
- Keep proposed / implemented / tested / future work clearly separated.
- Figure corrections in §8–9 (correct API names, authData contents).

## Future work (exactly three upgrades) [DECIDED]

1. **Secure element** (e.g., ATECC608A-class): hardware key protection; verify P-256 support and provisioning. Feasibility: medium.
2. **NFC transport**: shared CTAP2 core; needs NFC controller + antenna. Feasibility: medium–high.
3. **Credential management utility**: list counts/metadata, rename labels, authenticated deletion, storage usage; must never expose private keys. Feasibility: high. Most practical if time is limited.

---

# HANDOFF TO CLAUDE CODE

**Build two deliverables and an evaluation harness.**

### A. ESP32-S3 firmware (ESP-IDF, C)
1. Native USB HID device: FIDO usage page 0xF1D0, 64-byte reports, CTAPHID framing (INIT/CONT packets, channel allocation via CTAPHID_INIT, PING, MSG, CBOR, ERROR, KEEPALIVE, CANCEL).
2. CTAP2 over CBOR: `authenticatorGetInfo` (versions include "FIDO_2_0", plus "U2F_V2" if CTAP1 is supported; algorithm ES256), `authenticatorMakeCredential`, `authenticatorGetAssertion`; correct CTAP2 error codes.
3. Optional CTAP1/U2F register/authenticate via CTAPHID_MSG (paper architecture lists it; confirm scope).
4. Crypto via mbedTLS: P-256 keygen from hardware RNG, SHA-256, ECDSA sign over `authData ‖ clientDataHash`, DER signature encoding, COSE_Key public key encoding.
5. Authenticator data: `rpIdHash ‖ flags ‖ signCount ‖ [attestedCredentialData]`; attestation "none" or packed self-attestation.
6. Credential store in NVS: {credId, rpIdHash/rpId, userHandle, privKey, signCount, flags, version}; power-loss-safe updates; validation at boot.
7. User presence: physical button (GPIO TBD); UP flag set only after press; timeout → error.
8. Reject malformed packets, unknown commands, unknown credentials cleanly.
9. Serial logging with timestamps for metrics (creation/assertion time, sizes).

### B. Local WebAuthn relying party
- Backend (framework TBD) with a maintained WebAuthn server library; endpoints `POST /register/options`, `/register/verify`, `/login/options`, `/login/verify`; single-use expiring challenges; full verification (challenge, origin, rpIdHash, flags, counter, signature); DB tables `users`, `credentials`, `challenges` as in §17.
- Frontend: Register/Login buttons using `navigator.credentials.create()`/`.get()`, base64url handling, result display, client-side timing.
- Run on `https://` or `http://localhost`.

### C. Evaluation
- Scripted tests T01–T12 (§22), including negative cases (altered challenge, wrong RP/origin, unknown credential, malformed HID packet, reboot persistence).
- Collect metrics (§23) over N trials (N to be set), excluding button-wait time; export CSV.
- Record board model, ESP-IDF version, browser/OS versions, firmware size, RAM usage.

### Constraints
Never export private keys; no hand-written crypto; no fabricated numbers; do not describe NVS as secure storage; do not claim FIDO certification; confirm every [SPEC-VERIFY] item against the official CTAP 2.x and WebAuthn specifications.

**Priority given the 30 Sep 2026 deadline:** getInfo + makeCredential + getAssertion over USB HID with button presence → local RP end-to-end → T07/T08/T09/T10/T11 → latency and size measurements. U2F, PIN, and upgrades only after this works.
