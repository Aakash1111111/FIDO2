# Risks and Open Questions

Severity: **H** = can block the deadline or invalidate a claim; **M** = costs time or weakens a claim; **L** = minor.
No workaround listed here is implemented until its security implications have been accepted by the team.

## A. Risks

| ID | Area | Risk | Sev | Mitigation | Security implication of the workaround |
|---|---|---|---|---|---|
| R-TIME | Schedule | 3 days to deadline; firmware not started; hardware steps only on Author B's machine | H | Portable core + host tests let code progress without the board; RP/harness built in parallel; strict priority (IMPLEMENTATION_PLAN timeline); stretch items are cut first | None. The risk is overclaiming: anything not verified is written as "proposed" |
| R-USBPORT | Board | Using the "UART" connector (USB-UART bridge) for HID: it cannot enumerate as HID | H | Use the native USB port (GPIO19/20); use the UART port for logs/flashing; confirm the board model (Q1) | — |
| R-CONSOLE | Board | With TinyUSB on the native port, the USB-Serial-JTAG console/flashing on that port is lost; boards with a single native port lose logs | M | Board with two connectors, or an external USB-UART on UART0 pins. Flash through the UART port or enter download mode (BOOT+RESET) | — |
| R-BROWSER | Compatibility | Chrome/Firefox/Windows behave differently: Windows routes CTAP through `webauthn.dll` (the harness cannot open HID without admin); Linux needs a udev rule; Chrome sends silent `up:false` preflights and zero-length `pinAuth` probes; unexpected getInfo contents can make a browser reject the device | H | Implement `up:false` and `pinAuth` probe handling per spec [SPEC-VERIFY]; canonical CBOR; test on Linux Chrome first; record exact browser versions; claim interoperability only for tested combinations | Handling `up:false` correctly means the token **will** return a signature without a button press, with UP=0. This is standard; the RP must (and will) reject UP=0 assertions |
| R-UV | User verification | RP defaults (`userVerification:"preferred"`) are fine, but `"required"` fails without clientPIN; some platforms push PIN setup for resident keys | M | RP uses `userVerification:"discouraged"`, `residentKey:"discouraged"`; non-discoverable credentials in the core | No second factor on the token: whoever holds the token and presses the button authenticates (stated limitation TH7) |
| R-PLATFORM | Platform vs roaming | Browsers may offer the platform authenticator (Windows Hello, Touch ID, passkey sync) first, which confuses tests | M | Set `authenticatorSelection.authenticatorAttachment:"cross-platform"` and `hints:["security-key"]` where supported; record which UI path was used | None; this restricts the RP to roaming authenticators for the experiment only |
| R-CBOR | CTAP encoding | Non-canonical CBOR, or wrong key types in responses, get rejected by strict clients | H | Canonical encoder helper + host tests that decode with python-fido2/cbor2 in strict mode; captured browser requests as vectors | — |
| R-RPID | RP ID / origin | `127.0.0.1` is not a valid RP ID; a port mismatch between `RP_ORIGIN` and the actual URL gives ORIGIN_MISMATCH; LAN access over `http://192.168.x.x` is not a secure context | H | Always use `http://localhost:8000` with `RP_ID=localhost`; startup check prints the configured origin; mkcert HTTPS + a hostname for multi-device demos | **Do not** disable origin checks in the library to "make it work": that removes phishing resistance, the main claim |
| R-HTTPS | Secure context | WebAuthn needs a secure context; self-signed certificates not trusted by the browser fail | M | localhost exception, or mkcert-trusted local CA | A mkcert root CA installed on the machine is powerful; remove it after the demo |
| R-CRYPTO | Crypto verification | DER vs raw signature, wrong COSE key params, or signing the wrong bytes (e.g., the raw challenge) makes verification fail | H | Sign only `authData ‖ clientDataHash` (H§21); host cross-verification with an independent library; RP library does the verification | — |
| R-RNG | Randomness | `esp_random()` is only true-random with RF on or `bootloader_random_enable()` [ASSUMED/OPEN]; weak randomness breaks ECDSA (nonce reuse leaks the key) | H | Verify in Espressif docs; enable an entropy source during keygen/sign; mbedTLS CTR-DRBG seeded from HW RNG. Also consider deterministic ECDSA (RFC 6979, `mbedtls_ecdsa_sign_det_ext`) so nonces don't depend on the RNG at sign time [NEW] | If the entropy condition is not met and not fixed, key generation is weak; this must be stated in the paper |
| R-CHAL | Challenge generation | Predictable or reused challenges enable replay | M | `secrets.token_bytes(32)`, single-use delete-on-attempt, TTL, bound to session + type + user | — |
| R-REPLAY | Replay | A captured assertion is resubmitted | M | Single-use challenge (tested in T09); counter check | — |
| R-CLONE | Credential cloning | Plain NVS keys can be dumped and cloned; counter detection only works if both copies are used and the RP enforces it | H (claim) | State as a limitation; optional flash encryption (R-HARDEN); RP rejects counter regression | Do not claim clone resistance |
| R-COUNTER | Counter persistence | NVS write on every assertion → flash wear, latency; power loss between sign and commit → reuse | M | Commit before signing; NVS wear levelling; report the counter-persist time as an M2 sub-phase | Skipped counter values are harmless; reused ones are not, which is why the order is commit-then-sign |
| R-UP-AUTO | Measurement | 50+ trials need 50+ button presses; tempting to auto-confirm UP in firmware | M | **Recommend human presses** (feasible: ~200 presses total); UP wait excluded by firmware timing | An auto-confirm build signs with UP=1 without a human, i.e., silent signing. If ever used, it must be a separate build flag, off by default, unmistakably labelled in the boot log and USB serial string, never flashed for demos, and disclosed in the paper. Not recommended |
| R-UPGPIO | User presence | BOOT button (GPIO0) is a strapping pin; held at reset → download mode | L | Only read it after boot; document "don't hold during plug-in"; or use an external button on a free GPIO | — |
| R-STORE | Credential storage | Store full, corruption, record format change | M | Capacity limit → `KEY_STORE_FULL`; CRC + version; quarantine invalid records | Quarantined records are never used for signing (fail closed) |
| R-DB | RP database security | SQLite file holds usernames + public keys; session secret handling | L | File permissions; `SESSION_SECRET` from env, required; no secrets in the repo; DB excluded from git (except anonymised experiment exports) | Leaking the DB does not allow authentication (public keys only) |
| R-ENUM | Username enumeration | `/login/options` reveals whether a username exists (empty allowCredentials) | L | See Q-ENUM | Acceptable for a local research RP; state it |
| R-VIDPID | USB identity | No vendor VID; using another vendor's VID/PID impersonates a product | M | Use Espressif's test VID `0x303A` with a PID from Espressif's range intended for testing / TinyUSB default [SPEC-VERIFY], or pid.codes; never copy a commercial key's VID/PID | Copying a commercial VID/PID would misrepresent the device and may trigger vendor-specific host behaviour |
| R-HARDEN | Hardening | Enabling secure boot / flash encryption in release mode is **irreversible** (eFuses); a mistake can brick the board | M | Only in stretch, on a spare board, development mode first; otherwise a documented limitation | Without it: flash dump exposes keys (TH8) and malicious firmware can be flashed (TH9) |
| R-JTAG | Debug access | USB-Serial-JTAG / JTAG enabled by default | M | Hardened profile disables it via eFuse [OPEN]; else a limitation | — |
| R-LOCALDEV | Local development | The cloud dev container has no USB device; ESP-IDF install is large | M | Host tests + CI; hardware steps on Author B's machine; the harness runs locally | — |
| R-DEPLOY | Deployment | Public deployment needs a real domain + TLS; RP ID becomes that domain and credentials are not portable between RP IDs | L | Out of scope; local RP only (H§15) | — |
| R-CLAIMS | Research integrity | Captions say "developed"; contributions must be claimed only if completed | H | README status matrix + evidence folder; Phase 12 claim checklist | — |
| R-LIT | References | Literature references not yet collected; must not be invented | M | Author A's task; the specs (W3C WebAuthn L2/L3, FIDO CTAP 2.0/2.1) are the primary references | — |

## B. Open questions (decisions needed)

| ID | Question (source) | Options | Recommendation | Blocks |
|---|---|---|---|---|
| Q1 | Exact ESP32-S3 board; which connector is native USB (H§27.1) | DevKitC-1 / other | Tell us the model; a DevKitC-1 style board with two USB-C ports is ideal | P1–P2 |
| Q2 | From scratch vs adapt an open-source stack (H§27.2) | (a) from scratch with mbedTLS+TinyCBOR; (b) port SoloKeys (Apache-2.0/MIT) or similar; (c) Rust OpenSK | **(a)**: small, transparent, fits "transparent" motivation, clean licence; the paper states which libraries were reused | P3–P6 |
| Q3 | CTAP1/U2F implemented? (H§27.3) | core / stretch / drop | **Raised to "high priority after CTAP2 works"** (was stretch): mobile support needs it (see §D), and the title says "FIDO2/U2F". Its value on Android must still be confirmed by testing [SPEC-VERIFY] | Title claim, Android |
| Q4 | Button and GPIO (H§27.4) | BOOT (GPIO0) / external | **BOOT button**, UP timeout 30 s | P1, P6 |
| Q5 | clientPIN/UV (H§27.5) | implement / not | **Not implemented** (deadline); a stated limitation | P6, P7 |
| Q6 | Discoverable credentials (H§27.6) | rk yes / no | **No** in core (username-first); rk stretch | P6, P7, UI |
| Q7 | Attestation + AAGUID (H§27.7) | none / packed-self | **packed self**, RP `attestation:"direct"`, accepts `none`+`packed`(self); random AAGUID fixed in source | P6, P7 |
| Q8 | Backend stack (H§27.8) | Python/FastAPI/py_webauthn; Node/SimpleWebAuthn; Go | **Python** (shared with harness) | P7 |
| Q9 | Browsers/OS; N (H§27.9, H§22) | 30 / 50 | **Windows 10/11 (Chrome, Edge, Firefox) + Android Chrome over USB-OTG (+ iPhone Safari over USB-C if available)**; **N = 50** CTAP-level, 10 per browser/device end to end | P9, P11 |
| Q10 | Flash encryption / secure boot (H§27.10) | off / dev-mode / release | **Off** for the core, stated limitation; optional stretch evaluation | P13 |
| Q11 | What is already complete (H§27.11) | — | Confirm: nothing exists yet? Any existing firmware code should be committed to the repo first | Plan |
| Q12 | CTAP version claimed [NEW] | 2.0 / 2.1 | **CTAP 2.0 subset** (`FIDO_2_0`); 2.1 adds mandatory features we won't implement | P6, paper wording |
| Q13 | Measurement UP handling [NEW] | human press / auto-confirm build | **Human press** (see R-UP-AUTO) | P11 |
| Q-CBOR | CBOR library (H§14 [OPEN]) | TinyCBOR / hand-rolled minimal encoder | **TinyCBOR**: vetted, streaming, small | P6 |
| Q-ENUM | Unknown username at `/login/options` [NEW] | 404 (reveals existence) / fake options | **404 with `UNKNOWN_USER`** for the local research RP (simpler test evidence); enumeration noted as out of scope | P7 |
| Q-RESET | Implement `authenticatorReset` [NEW] | yes / no | **Yes, if time** (resets the store between experiment runs; needs UP) | P11 convenience |
| Q-BASELINE | Baseline comparison (H§24 [OPEN]) | qualitative table / measured commercial key | **Qualitative feature table** unless a commercial key is available to measure on the same setup | Paper |

## C. Contradictions and gaps found in the research

1. **Title vs scope:** the title says "FIDO2/U2F Compliant", but U2F is optional/stretch (H§HANDOFF-A3) and "compliant" can read as certification. → Decide Q3; the paper should define "compliant" as "implements the specified message formats and passes the listed tests", not certification (H§28).
2. **"Secure memory" vs NVS:** already resolved in favour of "on-device flash/NVS" (H§8). Also apply to the text, not just the figures.
3. **UP is an objective (H§3.6) but its implementation is [OPEN] (H§8.6, H§11).** The plan treats it as required core; confirm.
4. **Discoverable credentials [OPEN] vs the on-token record containing a user handle:** the record keeps the user handle anyway so rk can be added later without a format change.
5. **N trials unspecified (30 or 50).** → Q9.
6. **Metrics say "USB latency"** without a definition → operationalised as the PING sweep + RTT decomposition (spec §17 M3); confirm.
7. **Backend "log verification failures"** but no schema → `auth_events` table added [NEW].
8. **No statement of which browser/OS is the primary target**; Windows changes the host-side architecture (webauthn.dll), so the harness should run on Linux/macOS.

## D. Platform decisions (Windows development machine, PC + mobile targets) [NEW, 27 Sep]

**Windows is enough; Linux is not required.**
- ESP-IDF: the official Windows installer or the VS Code ESP-IDF extension. `idf.py build flash monitor` works from the ESP-IDF PowerShell/CMD.
- RP backend (Python/FastAPI) and frontend: run natively on Windows.
- Browsers on Windows 10 1903+ (Chrome, Edge, Firefox) do not talk to the key themselves. They go through the Windows WebAuthn API (`webauthn.dll`), which shows the "Windows Security" dialog. This is the real-world Windows path, so the browser tests stay valid.
- **The one restriction:** Windows blocks non-administrator programs from opening FIDO HID devices directly. The evaluation harness (python-fido2, raw malformed packets for T04) must therefore run from an **Administrator** terminal. *Security implication:* the harness gets full access to the key (and admin rights on a lab PC). That is acceptable for a local test machine: run only the project's harness elevated, never the RP or browser. Alternative: WSL2 + `usbipd-win` to hand the USB device to Linux. That is more setup, so it is not recommended under the deadline.
- udev rules (`tools/70-fido-esp32.rules`) are only needed if a Linux host is used.

**PC + mobile compatibility means the web app is mobile-ready and the key works when plugged into a phone. No native app is planned.** The same web RP serves both. A native Android/iOS app would need Digital Asset Links / Associated Domains and platform FIDO APIs, which is out of scope for the deadline.

| Target | How the key connects | Status / caveat |
|---|---|---|
| Windows PC (Chrome/Edge/Firefox) | USB-C/A cable to the native USB port | Through `webauthn.dll`; expected to work with CTAP2 |
| Android (Chrome) | USB-C OTG (USB-C↔USB-C data cable, or OTG adapter) | Uses Google Play Services FIDO. [ASSUMED/SPEC-VERIFY] Android has historically used **CTAP1/U2F** with USB security keys for non-discoverable credentials, so U2F support may be required for Android. Verify by testing: check getInfo traffic vs CTAPHID_MSG in the UART log |
| iPhone 15+ (USB-C, Safari/any iOS browser) | USB-C cable | iOS supports FIDO security keys over USB-C/Lightning/NFC [SPEC-VERIFY]. Optional test if a device is available |
| Older iPhone (Lightning) | Lightning→USB camera adapter | Power budget may be too low; optional |

**Consequences for the architecture:**
1. **HTTPS with a real hostname is mandatory for mobile.** The phone cannot use `http://localhost`, `http://192.168.x.x` is not a secure context, and IP addresses are not valid RP IDs. Options:
   - (a) A tunnel with a **fixed** hostname (ngrok static domain or Cloudflare named tunnel) in front of the RP running on the PC. **Recommended.**
   - (b) Deploy the RP to a small cloud host with TLS.
   - (c) mkcert, with the local CA installed on the phone. Fiddly, and not recommended.
   - The RP ID must equal that hostname, and **must stay the same for the whole experiment**: credentials are bound to the RP ID, so a key registered on `localhost` will not log in on the tunnel hostname.
   - *Security implication:* the RP becomes reachable from the internet. So: `RP_EXPERIMENT_MODE` off, rate limiting on `/register/*` and `/login/*`, a strong `SESSION_SECRET`, Secure cookies, no real user data, and the tunnel shut down after testing.
2. **Same credential on both devices:** because the key carries the credential, a user registered on the PC can log in on the phone with the same token under the same RP ID. This is a good cross-device demo for the paper (new test **T13**).
3. **RP options for mobile:** `allowCredentials[].transports = ["usb"]`, `authenticatorAttachment: "cross-platform"`, `hints: ["security-key"]`. These stop phones from steering users to built-in passkeys / Google Password Manager.
4. **Frontend:** responsive layout (single column, 44 px touch targets, viewport meta), no hover-only UI, readable error messages for mobile `NotAllowedError`.
5. **Power:** the phone powers the ESP32-S3 over OTG. Keep Wi-Fi/BT off in the firmware; measure current if possible.
6. **Evaluation matrix:** M4 and M8 are reported per (device, OS, browser). Interoperability is claimed only for combinations actually tested.
