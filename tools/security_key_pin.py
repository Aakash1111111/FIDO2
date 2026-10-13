"""Manage the project's device PIN using standard CTAP2 (not a website PIN).

Run in an elevated Windows PowerShell if Windows denies direct HID access.
Install: python -m pip install "fido2>=1.1,<2"
"""
import argparse
from getpass import getpass
import sys

from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin
from fido2.hid import CtapHidDevice

AAGUID = "ba17f247df2846ce819d8488f3b2278c"


def new_pin():
    pin = getpass("New security key PIN (4+ characters, 6+ digits recommended): ")
    if len(pin) < 4 or len(pin.encode("utf-8")) > 63 or "\0" in pin:
        raise ValueError("PIN must contain 4+ characters and at most 63 UTF-8 bytes, with no NUL.")
    if getpass("Confirm new PIN: ") != pin:
        raise ValueError("PIN entries do not match. No change made.")
    return pin


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["status", "set", "change", "verify", "reset"])
    args = parser.parse_args()
    devices = [d for d in CtapHidDevice.list_devices()
               if d.descriptor.vid == 0x303A and d.descriptor.pid == 0x4004]
    try:
        if len(devices) != 1:
            raise ValueError("Connect exactly one ESP32-S3 key through native USB. On Windows, run PowerShell as Administrator if HID access is denied.")
        ctap = Ctap2(devices[0])
        if ctap.info.aaguid.hex() != AAGUID:
            raise ValueError("The connected device does not have the project's expected AAGUID.")
        if "clientPin" not in ctap.info.options:
            raise ValueError("This firmware has no PIN support. Build and flash the new firmware first.")
        cp = ClientPin(ctap)
        if args.action == "status":
            print(f"PIN configured: {bool(ctap.info.options['clientPin'])}")
            print(f"PIN attempts remaining: {cp.get_pin_retries()[0]}")
        elif args.action == "set":
            if ctap.info.options["clientPin"]:
                raise ValueError("A PIN is already set. Use 'change' with the current PIN.")
            cp.set_pin(new_pin())
            print("Device PIN set. Use this same PIN on compatible websites.")
        elif args.action == "change":
            current = getpass("Current security key PIN: ")
            replacement = new_pin()
            cp.change_pin(current, replacement)
            print("PIN changed. Existing credentials are preserved.")
        elif args.action == "verify":
            cp.get_pin_token(getpass("Security key PIN: "))
            print("PIN verified. Unplug native USB before your browser test to clear temporary authorization.")
        else:
            print("Factory reset deletes the device PIN AND ALL credentials, including third-party keys.")
            if input("Type RESET to continue: ") != "RESET":
                print("Cancelled."); return 0
            input("Power-cycle the board (remove BOTH cables), reconnect native USB, then press Enter immediately: ")
            # Re-enumerate: the OS handle may change after reconnecting.
            for d in devices: d.close()
            devices = [d for d in CtapHidDevice.list_devices()
                       if d.descriptor.vid == 0x303A and d.descriptor.pid == 0x4004]
            if len(devices) != 1: raise ValueError("Connect exactly one project key.")
            ctap = Ctap2(devices[0])
            if ctap.info.aaguid.hex() != AAGUID: raise ValueError("Wrong authenticator.")
            print("Press BOOT now. Reset must finish within 10 seconds of boot.")
            ctap.reset()
            print("Factory reset completed. Set a new PIN and register again on every website.")
        return 0
    except CtapError as exc:
        print(f"Security key returned: {exc}", file=sys.stderr)
        print("After PIN_AUTH_BLOCKED: remove BOTH USB cables to power-cycle. PIN_BLOCKED requires factory reset.", file=sys.stderr)
        return 1
    except (ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr); return 1
    finally:
        for d in devices: d.close()


if __name__ == "__main__":
    sys.exit(main())
