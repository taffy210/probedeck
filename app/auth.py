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
import threading
import time

USER = os.environ.get("PROBEDECK_AUTH_USER", "")
PASS = os.environ.get("PROBEDECK_AUTH_PASS", "")
ENABLED = bool(USER and PASS)

COOKIE_NAME = "probedeck_session"
MAX_AGE = 7 * 24 * 3600  # session lifetime, seconds

# Set when the app sits behind TLS so the session cookie is only ever sent over
# https. Left off for the plain-http LAN default (a Secure cookie would never
# be sent and login would appear to silently fail).
SECURE_COOKIE = os.environ.get("PROBEDECK_SECURE_COOKIE", "").lower() in (
    "1", "true", "yes", "on")

_SECRET = hashlib.sha256(b"probedeck-session\x00" + PASS.encode()).digest()

# --- brute-force throttling ----------------------------------------------
# In-memory per-IP failure tracking. After LOGIN_MAX_TRIES failures inside
# LOGIN_WINDOW seconds an IP is locked out for LOGIN_LOCKOUT seconds. State is
# process-local and resets on restart — enough to blunt online guessing on a
# single-container app without a datastore.
LOGIN_MAX_TRIES = int(os.environ.get("PROBEDECK_LOGIN_MAX_TRIES", "5"))
LOGIN_WINDOW = float(os.environ.get("PROBEDECK_LOGIN_WINDOW", "300"))
LOGIN_LOCKOUT = float(os.environ.get("PROBEDECK_LOGIN_LOCKOUT", "300"))

_fail_lock = threading.Lock()
_failures = {}       # ip -> [monotonic timestamps of recent failures]
_locked_until = {}   # ip -> monotonic time the lockout ends


def login_locked(ip: str) -> int:
    """Seconds of lockout remaining for this IP, or 0 if it may try now."""
    now = time.monotonic()
    with _fail_lock:
        until = _locked_until.get(ip, 0.0)
        if until > now:
            return int(until - now) + 1
        if until:
            _locked_until.pop(ip, None)
    return 0


def record_login_failure(ip: str) -> None:
    now = time.monotonic()
    with _fail_lock:
        xs = [t for t in _failures.get(ip, []) if now - t < LOGIN_WINDOW]
        xs.append(now)
        if len(xs) >= LOGIN_MAX_TRIES:
            _locked_until[ip] = now + LOGIN_LOCKOUT
            _failures.pop(ip, None)
        else:
            _failures[ip] = xs


def record_login_success(ip: str) -> None:
    with _fail_lock:
        _failures.pop(ip, None)
        _locked_until.pop(ip, None)


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
