# ESP32-S3 firmware (ESP-IDF v5.3.2)

Any ESP-IDF v5.3.x works (tested: v5.3.2 cloud build, v5.3.6 on the implementer's PC) (record the exact version you build with; the boot log prints it).

Board: **ESP32-S3-N16R8** (16 MB flash, 8 MB PSRAM; PSRAM intentionally unused).
Current phase: **Phase 1** (boot, hardware entropy, crypto with self-tests, NVS, user-presence button). USB HID/CTAP come next.

## Which USB-C port is which
Most N16R8 boards have two USB-C connectors:

| Label (varies) | Windows Device Manager shows | Used for |
|---|---|---|
| **COM** / UART | "USB-SERIAL CH343 (COMx)" or "Silicon Labs CP210x (COMx)" | **Flashing + logs** (now) |
| **USB** / OTG | "USB JTAG/serial debug unit" (VID 303A) | Becomes the **FIDO security key** from Phase 2 |

If the COM port shows no COM number, install the WCH CH343 (or CP210x) driver.

## Windows setup (one time)
1. Install **ESP-IDF v5.3.2** with the Espressif Windows installer (choose v5.3.2), *or* VS Code → Extensions → "ESP-IDF" → Configure → v5.3.2.
2. Open the **"ESP-IDF 5.3 CMD"** (or PowerShell) shortcut the installer creates.

## Build, flash, monitor
```bat
cd path\to\FIDO2\firmware
idf.py set-target esp32s3
idf.py build
idf.py -p COM5 flash monitor      :: replace COM5 with your COM port
```
Exit the monitor with `Ctrl+]`. If flashing fails to connect: hold **BOOT**, tap **RESET**, release BOOT, retry.

## What a correct boot looks like (format; numbers are yours to measure)
```
EVT,ENV,fw=0.1.0-phase1,idf=v5.3.2,mbedtls=3.6.2,chip_rev=...,cores=2
I (...) hal_rng: hardware entropy source enabled (SAR ADC noise)
EVT,STORAGE,used_entries=...,free_entries=...,total_entries=...
I (...) fido: crypto self-test passed (SHA-256 KAT, RFC 6979 ECDSA KAT, verify KAT, DRBG health)
METRIC,selftest_us,0,<t>
METRIC,keygen_total_us,0,<t>  (x20: reseed + keygen + pairwise test)
METRIC,pct_us,0,<t>           (pairwise test alone)
METRIC,sign_us,0,<t>
METRIC,verify_us,0,<t>
METRIC,sig_der_bytes,0,<70..72>
EVT,BOOT_OK,phase=1,heap_free=...,heap_min=...
EVT,UP_WAIT,timeout_ms=30000
```
Press **BOOT** → `EVT,UP_PRESS,wait_us=...`; no press for 30 s → `EVT,UP_TIMEOUT`.
Any `EVT,HALT,reason=...` line means a security check failed and the token refuses to continue; send the full log.

**Please save the full monitor output** (`idf.py -p COMx monitor > boot_log.txt` or copy it) and send it back: it is the first evidence item (T02) and the first crypto timing data.

## Host unit tests (no board needed)
```
cmake -S test/host -B build-host
cmake --build build-host
ctest --test-dir build-host --output-on-failure
```
Requires CMake, a C compiler, and Python with `cryptography` + `cbor2`. (Runs on Linux/macOS; on Windows use WSL or MSYS2, as the test uses AddressSanitizer.)

## Espressif-IDE (Eclipse) instead of the command line
1. File → Import → Espressif → **Existing IDF Project** → select the `firmware` folder.
2. In the toolbar's launch-target dropdown choose **esp32s3** and set the serial port to your **COM/UART** port.
3. Build (hammer icon), then Launch/Run to flash; open the IDF Serial Monitor (Terminal view → ESP-IDF Serial Monitor) at 115200.
