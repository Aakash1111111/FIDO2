import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
os.environ.setdefault("RP_NO_AUTOCREATE", "1")

from app.config import load_settings  # noqa: E402


def test_defaults():
    s = load_settings({})
    assert s.rp_id == "localhost" and s.origins == ["http://localhost:8000"]
    assert s.admin_token is None and not s.secure_cookies


@pytest.mark.parametrize("env", [
    {"RP_ORIGIN": "http://192.168.1.5:8000"},                       # insecure context
    {"RP_ID": "example.com", "RP_ORIGIN": "https://evil.com"},      # origin not under RP ID
    {"RP_ORIGIN": "ftp://localhost"},
    {"RP_ADMIN_TOKEN": "short"},
])
def test_rejects_bad_config(env):
    with pytest.raises(ValueError):
        load_settings(env)


def test_tunnel_config():
    s = load_settings({"RP_ID": "abc.ngrok-free.app", "RP_ORIGIN": "https://abc.ngrok-free.app"})
    assert s.secure_cookies
