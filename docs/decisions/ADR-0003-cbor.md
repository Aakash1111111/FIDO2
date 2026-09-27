# ADR-0003: Small in-tree CBOR codec instead of TinyCBOR

**Status:** accepted 27 Sep 2026.

**Context:** CTAP2 messages are CBOR. The plan proposed TinyCBOR (Q-CBOR). The token needs only a small subset: maps with integer or text keys, byte and text strings, arrays, integers, booleans.

**Decision:** `fido_core/ctap2/cbor_lite.c` (~300 lines), a strict and bounded reader plus a writer.

**Why:**
- Only definite lengths are accepted, every length is checked against the remaining input, nesting depth is capped at 8, and there is no dynamic allocation. That is a small, auditable attack surface for host-controlled input.
- Canonical CTAP2 encoding of responses is by construction: fixed key order, shortest-form integers.
- No extra registry dependency, so builds are reproducible offline.

**Verification:**
- `firmware/test/host/test_ctap2.c` feeds 60k fuzzed and random requests under ASan/UBSan.
- `rp/tests/test_e2e_sim.py` parses every token response with python-fido2, and py_webauthn verifies it (independent CBOR implementations).

**Consequence:** this is encoding code, not cryptography. The "no hand-written crypto" rule is unaffected.
