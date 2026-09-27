# Phase 1, run 2: optimized crypto timings on the ESP32-S3-N16R8

- Date: 27 Sep 2026. Firmware **0.1.1-phase1** (commit 6b4dbc1), built locally with **ESP-IDF v5.3.6, mbedTLS 3.6.7** (from the `EVT,ENV` line).
- Config B: `-O2`, CPU **240 MHz**, mbedTLS ECP fixed-point tables ON, CTR-DRBG reseeded from hardware entropy before each keygen.
- Boot evidence: `crypto self-test passed (SHA-256 KAT, RFC 6979 ECDSA KAT, verify KAT, DRBG health)`; self-test time 316.062 ms; `EVT,BOOT_OK` with 373,532 B free heap (min 369,992 B); `fido` NVS partition: 8064 entries total, 0 used.
- n = 20 iterations (research instrumentation; benchmark on the same core as the idle task, with a 10 ms yield between iterations).
- `keygen_only_us` is derived: `keygen_total_us − pct_us` (reseed + P-256 key generation, without the pairwise test).

| Metric | n | mean | SD | median | min | max | 95% CI (mean) |
|---|---|---|---|---|---|---|---|
| keygen_total_us | 20 | 214.030 ms | 0.106 ms | 214.018 ms | 213.836 ms | 214.243 ms | ±0.050 ms |
| keygen_only_us | 20 | 35.632 ms | 0.072 ms | 35.620 ms | 35.474 ms | 35.751 ms | ±0.034 ms |
| pct_us | 20 | 178.399 ms | 0.099 ms | 178.404 ms | 178.180 ms | 178.632 ms | ±0.046 ms |
| sign_us | 20 | 40.927 ms | 0.047 ms | 40.926 ms | 40.844 ms | 41.018 ms | ±0.022 ms |
| verify_us | 20 | 137.496 ms | 0.073 ms | 137.487 ms | 137.383 ms | 137.655 ms | ±0.034 ms |
| sig_der_bytes | 20 | 70.80 B | 0.83 B | 71.00 B | 70.00 B | 72.00 B | ±0.39 B |

## Before vs after (run 1 baseline, config A: -Og, 160 MHz, prediction resistance on every RNG call; n = 4)
| Operation | Run 1 (A) | Run 2 (B) | Speed-up |
|---|---|---|---|
| keygen incl. pairwise test | 656–721 ms | 214.0 ms | ~3.1× |
| sign (ES256) | ~170.0 ms | 40.9 ms | ~4.2× |
| verify | ~327.5 ms | 137.5 ms | ~2.4× |

Observations:
- The pairwise-consistency test (178 ms) is ~83% of key-generation time; the key generation itself is ~36 ms. Verification dominates the test because it is a variable-base multiplication (no precomputed tables).
- Very low variance (SD well below 1% of the mean): the operations are effectively constant-time at this granularity.
- DER signature length varies 70–72 bytes as expected (r/s leading-zero/high-bit padding).
