# Device PIN update (firmware 0.4.0-clientpin)

One PIN belongs to the ESP32-S3, shared across all relying parties. Each site
still has a separate credential. Type the PIN into the browser/OS dialog, never
into a website field. Connecting USB alone does not launch a dialog.

## Build and flash on Windows

Open your ESP-IDF 5.3.2 PowerShell. From the repository root:

```powershell
git pull
cd firmware
idf.py -D SDKCONFIG=sdkconfig.pin -p YOUR_CH343_PORT build flash monitor
```

Replace `YOUR_CH343_PORT` with the board's UART/CH343 COM port. Use that port
for flashing/logging and the native USB port for the security key. This chooses
a new `sdkconfig.pin` so old benchmark settings do not delay startup; no eFuse
changes or flash encryption are enabled. Do NOT run `erase-flash`: normal app
flashing preserves credentials and the new PIN record in the `fido` partition.
Exit monitor with Ctrl+]. Expect firmware `0.4.0-clientpin`, `EVT,PIN,...`, and
`EVT,BOOT_OK,phase=3`. Existing prebuilt phase-1 images have no PIN support.

## Set the PIN once

Close browser security-key dialogs. Open **PowerShell as Administrator** if
Windows restricts direct FIDO HID access. From the repository root:

```powershell
python -m pip install "fido2>=1.1,<2"
python tools/security_key_pin.py status
python tools/security_key_pin.py set
```

Choose a memorable PIN (at least 4 Unicode characters, at most 63 UTF-8 bytes;
6+ digits recommended). Input is hidden. Do not put it in source code, command
arguments, logs, screenshots, or environment variables.

```powershell
python tools/security_key_pin.py verify
python tools/security_key_pin.py change
```

Changing the PIN preserves credentials. PIN retries live in flash: three wrong
attempts cause temporary `PIN_AUTH_BLOCKED`; remove BOTH cables to power-cycle.
Eight failed attempts across power cycles cause permanent `PIN_BLOCKED`.
A correct PIN restores the attempt allowance unless permanently blocked.
Disconnecting only native USB while UART still supplies power does not clear
temporary attempt blocking. It does invalidate authorization.

## Restart the website

The default server policy is now `userVerification=required` for BOTH option
generation and server verification. Restart uvicorn; do not merely refresh.
From the `rp` folder, retaining your existing database and admin token:

```powershell
.\.venv\Scripts\Activate.ps1
$env:RP_ID = "stand-backpack-drone.ngrok-free.dev"
$env:RP_ORIGIN = "https://stand-backpack-drone.ngrok-free.dev"
python -m uvicorn app.main:app --host 127.0.0.1 --port 5050
```

Keep your existing ngrok tunnel running, or restart it in another window:

```powershell
.\ngrok.exe http 5050 --url "https://stand-backpack-drone.ngrok-free.dev"
```

Open the public address and refresh (Ctrl+Shift+R). Existing credentials at this
RP ID remain usable. Register again only if changing RP ID or after reset.
The browser should ask for the ESP32 PIN, then BOOT confirmation. A Windows
Hello PIN is a different PIN: choose the external USB security key.
Third-party services do not need this server/tunnel. Their browser/platform
must support CTAP2 protocol 1. U2F-only clients cannot use this PIN policy.
Test GitHub/Google with backup sign-in methods retained; compatibility is not
claimed until actually tested on that browser/OS.

## Forgotten PIN / reset

Reset destroys ALL on-key credentials AND the PIN. You must register again on
every website; this is not a PIN-recovery feature.

```powershell
python tools/security_key_pin.py reset
```

The tool requires typing `RESET`. Power-cycle BOTH cables, reconnect native
USB, continue immediately, and press BOOT AFTER the reset request. Do not hold
BOOT while reconnecting (that enters the ESP download bootloader). The reset
must complete within 10 seconds of firmware boot. Reset outside that window
returns `NOT_ALLOWED`. A fresh press is required; timeout/cancel does not reset.
If reset loses power mid-write, a persistent marker makes subsequent boot halt
rather than allowing old credentials under a new PIN. Recovery then requires
explicitly erasing the `fido` partition using its offset/size from your partition
table, which also destroys every credential. Never erase the partition as an
ordinary upgrade step.

## Security policy and limits

- Implements CTAP 2.0 `clientPIN` protocol 1: getRetries, getKeyAgreement,
  setPIN, changePIN, getPinToken. getInfo advertises `clientPin` and protocol 1.
- Every credential creation and assertion needs valid PIN authorization.
  No unverified signing fallback is enabled on hardware, even when a site
  requests user verification as optional.
- The PIN verifier is salted; retries are durably decremented before comparison.
  IO failures/corrupt records fail closed. PIN and private keys are never logged.
- Temporary tokens expire after 30 seconds, are cleared on power loss, detected
  USB session changes/suspend, PIN change/reset, and successful user-present
  credential operations. A new getPinToken invalidates the earlier token.
- PIN-authorized silent credential-selection probes (`up=false`) are supported
  for interoperability. They return UP=0, cannot authenticate to this RP, and
  do not consume the token. The actual login still needs BOOT and UP=1.
- The host may request PIN authorization again after expiry. No global permanent
  "unlocked" flag exists. There is no PIN prompt merely on cable insertion.
- Physical storage remains the project's existing unencrypted NVS; firmware
  is not secure-boot protected. The PIN protects normal CTAP access, not flash
  extraction, reflashing, compromised hosts, or physical key theft with those
  capabilities. No certification or hardware tamper resistance is claimed.
- Discoverable credentials/passkeys and CTAP2.1 protocol 2/permission tokens
  are not added. This is a non-discoverable credential research authenticator.

Protocol reference: FIDO CTAP 2.0 proposed standard, §§5.5–5.6:
https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html

## Reproduce host checks

```sh
cmake -S firmware/test/host -B build-host
cmake --build build-host -j4
ctest --test-dir build-host --output-on-failure
SIM_TOKEN_LIB="$PWD/build-host/libsim_token.so" python -m pytest rp/tests -q
```

Install `rp/requirements-dev.txt` first. Legacy simulator tests intentionally
retain the pre-PIN baseline. `test_pin_sim.py` enables the same production PIN
code and tests the protected path using python-fido2 and py_webauthn. Software
results are not USB/hardware measurements.
