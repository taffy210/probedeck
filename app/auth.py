"""Optional session-cookie auth.

Enabled only when PROBEDECK_AUTH_USER and PROBEDECK_AUTH_PASS are both set;
otherwise the app stays open (the LAN default). A successful login sets a
signed cookie; the signing key is derived from the password, so it survives
restarts without another env var to manage, and changing the password
invalidates every existing session.
"""
import base64
import hashlib
import hmac
import json
import os
import time

USER = os.environ.get("PROBEDECK_AUTH_USER", "")
PASS = os.environ.get("PROBEDECK_AUTH_PASS", "")
ENABLED = bool(USER and PASS)

COOKIE_NAME = "probedeck_session"
MAX_AGE = 7 * 24 * 3600  # session lifetime, seconds

_SECRET = hashlib.sha256(b"probedeck-session\x00" + PASS.encode()).digest()


def check_credentials(user: str, pw: str) -> bool:
    """Constant-time credential check. Always False when auth is disabled."""
    if not ENABLED:
        return False
    return (hmac.compare_digest(user or "", USER)
            & hmac.compare_digest(pw or "", PASS))


def issue_token() -> str:
    """Mint a signed `<payload>.<sig>` token carrying the issue time."""
    payload = base64.urlsafe_b64encode(
        json.dumps({"iat": int(time.time())}).encode()).decode()
    sig = hmac.new(_SECRET, payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def valid_token(token: str) -> bool:
    """Verify signature (constant-time) and that the token is within MAX_AGE."""
    if not token or "." not in token:
        return False
    payload, _, sig = token.partition(".")
    expected = hmac.new(_SECRET, payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return False
    try:
        data = json.loads(base64.urlsafe_b64decode(payload))
        return (int(time.time()) - int(data["iat"])) < MAX_AGE
    except Exception:
        return False
