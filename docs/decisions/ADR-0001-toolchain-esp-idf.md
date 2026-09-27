# ADR-0001: ESP-IDF (not Arduino IDE) for the firmware

**Status:** accepted 27 Sep 2026 (plan approved by the team; the Arduino alternative was discussed with the implementer).

## Context
The implementer develops on Windows and asked whether to use the Arduino IDE. The Arduino-ESP32 core (v3.x) is built on ESP-IDF and includes TinyUSB, mbedTLS and NVS, so it *can* compile similar code.

## Decision
Use **ESP-IDF v5.3.2** (Windows installer or the VS Code ESP-IDF extension).

## Why
1. **USB descriptor control.** A FIDO key must expose a raw HID interface: usage page 0xF1D0, 64-byte reports, **no report ID**. Arduino's `USBHID` wrapper is designed for keyboard/mouse devices, combines devices with report IDs, and adds a CDC serial interface by default. ESP-IDF + TinyUSB gives full control of the descriptors.
2. **Security configuration.** `sdkconfig` controls mbedTLS options (deterministic ECDSA, curve set), stack protection, the dedicated `fido` NVS partition, and later NVS encryption / flash encryption / secure boot / JTAG disable. Most of these are not reachable from the Arduino IDE.
3. **Reproducibility (research requirement).** `idf.py build` from a pinned version + `sdkconfig.defaults` + `partitions.csv` in git reproduces the exact binary; the size report (`idf.py size`) feeds metric M5 directly.
4. **Testing.** The portable core builds on the host with the same mbedTLS 3.6.2 for unit tests; CI can build the firmware headlessly.

## Consequences
- A slightly steeper setup than Arduino; mitigated by `firmware/README.md` (Windows step-by-step).
- The crypto module (`fido_crypto.c`) uses only mbedTLS and standard C, so it remains portable to Arduino if ever needed.
