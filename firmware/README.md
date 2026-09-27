# ESP32-S3 firmware (ESP-IDF v5.3.2)

Any ESP-IDF v5.3.x works (tested: v5.3.2 cloud build, v5.3.6 on the implementer's PC) (record the exact version you build with; the boot log prints it).

Board: **ESP32-S3-N16R8** (16 MB flash, 8 MB PSRAM; PSRAM intentionally unused).
Current phase: **Phase 2**: Phase 1 (boot, hardware entropy, crypto self-tests, NVS, button) + the native USB port as a FIDO HID device with the full CTAPHID transport. CTAP2 commands (getInfo / makeCredential / getAssertion) come in Phase 3; until then CBOR requests get `CTAP1_ERR_INVALID_COMMAND`.

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

## Phase 2 test: the native USB port as a FIDO device (T01, T03, T04, M3)
The first build after pulling downloads two small ESP components (`esp_tinyusb`, `tinyusb`) from the Espressif registry.

1. Build + flash exactly as before over the **COM** port (`idf.py -p COM8 flash monitor`).
2. **Also plug the board's other USB-C port (native USB)** into the PC. Keep COM connected for logs.
   The monitor should print `EVT,USB,MOUNTED`.
3. In PowerShell, check Windows sees it (T01):
   ```powershell
   Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match 'VID_303A&PID_4004' } | Select-Object Class, FriendlyName, InstanceId
   ```
   Expect `HIDClass` entries (e.g. "USB Input Device" / "HID-compliant device"). Save the output.
4. Run the harness from an **Administrator** PowerShell (Windows only lets elevated programs talk to FIDO devices directly):
   ```powershell
   cd C:\Users\aakas\Documents\FIDO2
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install "fido2>=1.1,<2"
   python harness\ctaphid_check.py --trials 50 --out results\phase2_ctaphid
   ```
   (Use any Python 3.9+. If `Activate.ps1` is blocked: `Set-ExecutionPolicy -Scope Process Bypass`.)
   Expect `28/28 checks passed`. The CSVs in `results\phase2_ctaphid\` are the M3 (USB latency) data.
