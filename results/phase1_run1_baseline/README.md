# Phase 1, run 1: baseline crypto timings on the ESP32-S3-N16R8

- Date: 27 Sep 2026. Firmware 0.1.0-phase1, built locally by the implementer with ESP-IDF **v5.3.6** (per source paths in the panic backtrace; Windows).
- Config A (unoptimized baseline): `-Og` (debug), CPU 160 MHz, no ECP fixed-point tables, CTR-DRBG prediction resistance ON (reseed before every RNG call).
- **Partial log:** only iterations 16–19 of 20 were captured; the beginning of the log (ENV line, self-test result) was not pasted.
- The task watchdog fired during the benchmark (the loop ran ~24 s on CPU0 without yielding). It is a warning only (no reset); fixed in 0.1.1 by yielding between iterations.

`keygen_pct_us` = DRBG + key generation + pairwise-consistency test (sign + verify).
Summary for iterations 16–19 (n = 4): keygen_pct 656–721 ms, sign ≈ 170 ms, verify ≈ 327 ms, DER signature 71–72 bytes.
Too few samples for statistics; kept as the "before optimization" reference point.
