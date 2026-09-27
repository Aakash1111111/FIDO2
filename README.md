# FIDO2/U2F Authentication Token on ESP32-S3

Research project: *Design and Implementation of a FIDO2/U2F Compliant Authentication Token for Secure Passwordless Authentication*.

**Status: planning. No implementation yet; the architecture is awaiting approval.**

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
| USB HID / CTAPHID | ✔ | – | – | – |
| CTAP2 getInfo / makeCredential / getAssertion | ✔ | – | – | – |
| Crypto (mbedTLS P-256) | ✔ | – | – | – |
| Credential store (NVS) | ✔ | – | – | – |
| User presence (button) | ✔ | – | – | – |
| CTAP1/U2F | stretch | – | – | – |
| Local relying party + frontend | ✔ | – | – | – |
| Evaluation harness (T01–T12, M1–M8) | ✔ | – | – | – |
