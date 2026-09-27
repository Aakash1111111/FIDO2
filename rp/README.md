# Local relying party (test website + dashboards)

Python / FastAPI / py_webauthn / SQLite. Serves:
- `/`: register and log in with the security key (works on PC and mobile browsers)
- `/dashboard`: your registered keys (public data only), sign counters and login history; add or remove keys
- `/admin`: research dashboard: all users, keys, success rates, rejection reasons, event log (needs `RP_ADMIN_TOKEN`)

## Run on Windows (PC test)
```powershell
cd C:\Users\aakas\Documents\FIDO2\rp
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:RP_ADMIN_TOKEN = "choose-a-long-random-admin-token"
uvicorn app.main:app --port 8000
```
Open **http://localhost:8000** in Chrome or Edge (exactly this address: WebAuthn binds keys to it). Plug in the token's **native USB** port, enter a username, then click **Register security key** and press **BOOT** when asked. **Login** works the same way.

## Phone test (Android, same key over USB-C OTG)
A phone cannot open `localhost`, and WebAuthn needs HTTPS with a real host name. Use a tunnel with a **fixed** host name (for example an ngrok static domain) pointing to port 8000:
```powershell
$env:RP_ID = "your-name.ngrok-free.app"
$env:RP_ORIGIN = "https://your-name.ngrok-free.app"
uvicorn app.main:app --port 8000
ngrok http --domain=your-name.ngrok-free.app 8000
```
Keys are bound to the RP ID, so register again under the tunnel address. Then log in from both the PC and the phone with the same token (test T13). Security note: the site is reachable from the internet while the tunnel runs. Use test usernames only and stop the tunnel afterwards.

## Tests
`SIM_TOKEN_LIB=<build-host>/libsim_token.so pytest rp/tests` runs the full ceremonies against the firmware code compiled for the PC (simulated button). This checks the code only; hardware results come from `harness/e2e_check.py`.
