# PIN update validation — 2026-10-13

- ESP-IDF 5.3.2, target ESP32-S3, new `sdkconfig.pin`: full firmware build passed.
  Image size: 0x59160 (364,896 bytes), 83% of the 2 MiB app partition remains free.
  Pinned TinyUSB dependency resolution is recorded in `firmware/dependencies.lock`.
- Host portable core builds against mbedTLS 3.6.2 with `-Wall -Wextra -Werror`.
- Python RP/protocol suite: 20 tests passed using python-fido2 1.2.0,
  py_webauthn 2.7.1 and FastAPI 0.141.1.
- Four C test groups: crypto unit, independent OpenSSL signature cross-check,
  CTAPHID fuzz, and CTAP2/store/parser fuzz passed. The new PIN parser includes
  20,000 malformed-input checks under address/undefined-behavior sanitizers.
  LeakSanitizer was disabled because this runner cannot expose process threads
  through `/proc`; address and undefined-behavior checks remained enabled.
- Covered: device-wide PIN across two RP IDs; missing-PIN/auth bypass rejection;
  PIN setup/change and credential preservation; short/malformed PIN requests;
  invalid ECDH points; durable attempts, temporary/permanent lockouts, power-cycle
  behavior; altered auth MACs; token expiry/use/disconnect; presence timeout;
  storage failure/corruption; interrupted-reset marker rejection; reset window,
  fresh presence, credential erasure; FIDO-client-to-RP registration/login;
  rejection of otherwise-valid WebAuthn responses without UV.

Build-only infrastructure workaround: the installed component manager's Linux
process-tree lookup was changed in this scratch runtime to use `os.getppid()`
because `/proc` process visibility is restricted. No ESP-IDF or component-manager
source changes are included in the repository; this does not alter firmware.

No physical ESP32 flash, Windows browser, Android, GitHub or Google account test
was performed. Software test results must not be reported as hardware results,
third-party interoperability evidence, or FIDO certification.
