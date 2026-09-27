# Prebuilt firmware (no local toolchain needed)

These images are built in the cloud dev environment for testers with slow internet.
The source of truth is always the code in `firmware/`; a local ESP-IDF build of the same commit should behave the same.

| File | Phase | Built from | ESP-IDF | SHA-256 |
|---|---|---|---|---|
| `fido2_token_phase1_v0.1.1_merged.bin` | 1 (boot, crypto self-tests, button; -O2, 240 MHz) | this commit | v5.3.2 (mbedTLS 3.6.2) | `d6a598561d7f3c1e3a9fde397bb3b1ae5cf648378bd6788b6180cbed3e9ea335` |

Merged image = bootloader (0x0) + partition table (0x8000) + app (0x10000), flash mode DIO, 16 MB. **Flash it at address 0x0.**

## Flash from the browser (Chrome or Edge, nothing to install)
1. Plug the board's **COM/UART** USB-C port into the PC.
2. Open **https://espressif.github.io/esptool-js/**.
3. Baudrate 460800 → **Connect** → pick the CH343/CP210x COM port.
   If it won't connect: hold **BOOT**, tap **RESET**, release BOOT, then Connect again.
4. Flash Address `0x0`, choose `fido2_token_phase1_v0.1.1_merged.bin` → **Program**.
5. When done, press **RESET** on the board. Use the page's **Console** section (baud **115200**) → Start, to see the boot log.
6. Copy the whole console output and send it back.

## Verify the download (optional, PowerShell)
```
Get-FileHash .\fido2_token_phase1_v0.1.1_merged.bin -Algorithm SHA256
```
Must equal the SHA-256 above.
