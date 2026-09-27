# Hardware record (experimental setup)

Captured 27 Sep 2026 by the implementer on Windows (`Get-PnpDevice`, `esptool.py flash_id`).

| Item | Value |
|---|---|
| Board | ESP32-S3-N16R8 development board (two USB-C ports) |
| Chip | ESP32-S3 (QFN56), silicon revision v0.2, 40 MHz crystal |
| Flash | 16 MB, quad (4 data lines, per eFuse), 3.3 V |
| PSRAM | 8 MB embedded (AP_3v3), **disabled in firmware** (keys stay in internal SRAM) |
| Radio features | Wi-Fi, BLE present, **not used** by the firmware |
| COM/UART port | WCH CH343 USB-serial, `USB\VID_1A86&PID_55D3`, Windows COM8 (flashing + logs) |
| Native USB port | reserved for the FIDO HID interface (Phase 2) |
| Host OS | Windows (version to be recorded) |
| ESP-IDF on host | v5.3.1 (local); esptool.py v4.12.0 |

The device MAC address is deliberately not recorded here (device identifier, not needed for reproducibility).
