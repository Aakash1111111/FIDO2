# FIDO2/U2F Authentication Token on ESP32-S3

Research project: *Design and Implementation of a FIDO2/U2F Compliant Authentication Token for Secure Passwordless Authentication*.

**Status: Phase 1 verified on the ESP32-S3. Phases 2–4 (USB HID/CTAPHID, CTAP2 authenticator, local website + dashboards) implemented and tested end-to-end in software; awaiting on-device runs.**

| Document | Purpose |
|---|---|
| [docs/research/FIDO2_Token_Handoff.md](docs/research/FIDO2_Token_Handoff.md) | Primary research source |
| [PROJECT_SPECIFICATION.md](PROJECT_SPECIFICATION.md) | Consolidated specification (confirmed / proposed / assumed / open) |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Proposed architecture and rationale |
| [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) | Phased roadmap against the 30 Sep 2026 deadline |
| [RISKS_AND_OPEN_QUESTIONS.md](RISKS_AND_OPEN_QUESTIONS.md) | Risks, decisions needed, contradictions |

## Status matrix

| Component | Proposed | Implemented | Tested | Evidence |
|---|---|---|---|---|
| USB HID / CTAPHID | ✔ | ✔ | host ✔ (unit + 300k-packet fuzz) / device – | – |
| CTAP2 getInfo / makeCredential / getAssertion | ✔ | ✔ | host ✔ (60k fuzz + E2E with py_webauthn) / device – | – |
| Crypto (mbedTLS P-256, RFC 6979, self-tests) | ✔ | ✔ | host ✔ / device ✔ | results/phase1_run2_optimized |
| Credential store (NVS, CRC, counter-before-sign) | ✔ | ✔ | host ✔ / device – | – |
| User presence (button) | ✔ | ✔ (HAL) | – | – |
| CTAP1/U2F | stretch | – | – | – |
| Local relying party + frontend + dashboards | ✔ | ✔ | E2E ✔ (sim) + headless Chromium ✔ | – |
| Evaluation harness (T01–T12, M1–M8) | ✔ | ✔ ctaphid_check.py, e2e_check.py | sim ✔ | – |

Decisions: [docs/decisions/](docs/decisions/). Firmware build/flash on Windows: [firmware/README.md](firmware/README.md).
