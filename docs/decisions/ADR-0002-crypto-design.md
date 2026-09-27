# ADR-0002: Cryptographic design of the token

**Status:** accepted 27 Sep 2026 for items 1–5; item 6 is **proposed** (needs a team decision, since it burns an eFuse).

## Context
The team asked for "sophisticated crypto to make the token much more secure". The research fixes ECDSA P-256 + SHA-256, requires a vetted library, and forbids claiming a new cryptographic algorithm (H§4, H§10, H§28).

## Decision: no custom algorithm
A custom or modified signature algorithm would make the token **less** secure (no public cryptanalysis) and **non-functional**: browsers and every WebAuthn server accept only registered COSE algorithms, and the paper would violate its own "no new algorithm" rule. Security is instead raised by **how** the standard algorithm is implemented and protected:

| # | Measure | Threat addressed | Status |
|---|---|---|---|
| 1 | ES256 (ECDSA P-256/SHA-256) via mbedTLS 3.6.2 | Interoperability; vetted implementation | Implemented |
| 2 | **Deterministic nonces (RFC 6979)** + DRBG-based blinding | Nonce reuse or bias leaks the private key (e.g. the PS3 ECDSA failure); side channels | Implemented |
| 3 | **CTR-DRBG (AES-256) with prediction resistance**, seeded from the ESP32-S3 hardware RNG with the SAR-ADC entropy source enabled, personalized with the chip MAC | Weak or predictable keys and credential IDs | Implemented |
| 4 | **Power-on self-tests** (SHA-256 KAT, RFC 6979 ECDSA KAT with exact signature bytes, verify KAT incl. a negative case, DRBG health) and a **pairwise-consistency test** on every new key; token halts on failure | Silent crypto/hardware faults producing bad keys or signatures | Implemented |
| 5 | Private-key validation (1 ≤ d ≤ n−1), on-curve public-key checks, strict DER, zeroization of all secret buffers, keys kept in internal SRAM (PSRAM disabled) | Invalid-key and memory-remanence issues | Implemented |
| 6 | **Keys encrypted at rest**: ESP-IDF NVS encryption with the HMAC-peripheral scheme. The key-encryption key is derived in hardware from an eFuse key that software cannot read, so a flash dump alone no longer reveals credential private keys | TH8 flash extraction / cloning | **Proposed.** Irreversibly burns one eFuse key block; evaluate once the core works |

Implemented in `firmware/components/fido_core/fido_crypto/`; verified by `firmware/test/host` (unit tests under ASan/UBSan + independent cross-verification with pyca/cryptography/OpenSSL).

## What the paper may claim
Items 1–5 as "hardening of a standard ES256 implementation". Item 6 only if enabled and tested. Never "a new/improved cryptographic algorithm".
