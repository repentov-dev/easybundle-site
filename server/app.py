#!/usr/bin/env python3
"""EASYBUNDLE free-trial registration + account API.

Typical registration fields collected:
  first/last name, email, company (opt), country, VAT/Tax ID (opt), terms.

On registration:
  - create account (hashed password)
  - generate signed license key valid for a free 3-month trial
  - ensure signing key exists in /Users/repentov/Desktop/EASYBUNDLE_OS/key
  - email password + license (SMTP or Mail.app / outbox fallback)

Privacy:
  All personally identifiable data (email, names, company, country, VAT)
  and license payloads are encrypted at rest with AES-256-GCM. The key is
  kept in /Users/repentov/Desktop/EASYBUNDLE_OS/key/easybundle_data.key (0600).
  Only opaque hashes (email_hash, license_key_hash) are stored in plaintext
  so accounts can be looked up without revealing the data.

Admin (god mode):
  The account whose email equals GOD_EMAIL (default i@am.god) is promoted to
  role 'admin'. Admins can list users, issue/revoke licenses, reset passwords
  and delete accounts via the /api/admin/* endpoints and /admin.html.
"""

from __future__ import annotations

import base64
import calendar
import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import sqlite3
import string
import struct
import time
from urllib.parse import urlsplit
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from functools import wraps
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, jsonify, request, send_from_directory, session

ROOT = Path(__file__).resolve().parent.parent
SERVER_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("EASYBUNDLE_DATA_DIR") or (SERVER_DIR / "data"))
DB_PATH = DATA_DIR / "easybundle.db"
KEY_DIR = Path("/Users/repentov/Desktop/EASYBUNDLE_OS/key")
PRIVATE_KEY_PATH = KEY_DIR / "easybundle_signing.key"
PUBLIC_KEY_PATH = KEY_DIR / "easybundle_signing.pub"
OUTBOX_DIR = KEY_DIR / "Email"
DATA_KEY_PATH = KEY_DIR / "easybundle_data.key"
SESSION_SECRET_PATH = KEY_DIR / "easybundle_session.secret"

PRODUCT = "EASYBUNDLE"
PLUGINS = ["CAESAR", "CAPSULE", "REFLECT", "SLOPE", "METROOM", "AIMPULSE"]
TRIAL_MONTHS = 3
GOD_EMAIL = os.environ.get("GOD_EMAIL", "i@am.god").strip().lower()

app = Flask(__name__, static_folder=str(ROOT), static_url_path="")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)


# ── storage ──────────────────────────────────────────────────────────

def db() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def load_or_create_bytes(path: Path, length: int = 32) -> bytes:
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raw = path.read_bytes()
        if len(raw) == length:
            return raw
    blob = secrets.token_bytes(length)
    path.write_bytes(blob)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return blob


app.secret_key = load_or_create_bytes(SESSION_SECRET_PATH)


# ── security: sessions, CSRF, brute force ───────────────────────────

@app.before_request
def security_guards():
    # Sliding session: any request re-arms the idle/absolute timeout.
    if session.get("user_email") or session.get("pending_2fa_email"):
        session.permanent = True
        session.modified = True
    # Reject cross-origin state changes (defense-in-depth over SameSite=Lax).
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        origin = request.headers.get("Origin")
        if origin:
            host = urlsplit(origin).netloc
            if host and host != request.host:
                return jsonify({"ok": False, "error": "Cross-origin request rejected"}), 403


_attempts: dict[str, list[float]] = {}
_ATTEMPT_LIMIT = 5
_ATTEMPT_WINDOW = 300.0  # seconds
_LOCKOUT_SECS = 900.0  # 15 min


def _too_many(key: str) -> bool:
    now = time.monotonic()
    hits = [t for t in _attempts.get(key, []) if now - t < _ATTEMPT_WINDOW]
    _attempts[key] = hits
    return len(hits) >= _ATTEMPT_LIMIT


def _record_failure(key: str) -> None:
    _attempts.setdefault(key, []).append(time.monotonic())


def _clear_failures(key: str) -> None:
    _attempts.pop(key, None)


def _attempt_key(email: str) -> str:
    ip = request.remote_addr or "?"
    return f"{ip}|{email.lower().strip()}"


def check_rate_limit(email: str):
    """Raise a 429 if the email/IP has failed too often lately."""
    if _too_many(_attempt_key(email)):
        return jsonify(
            {"ok": False, "error": "Too many failed attempts. Try again in 15 minutes."}
        ), 429
    return None


def _rate_failed(email: str) -> None:
    _record_failure(_attempt_key(email))


def _rate_ok(email: str) -> None:
    _clear_failures(_attempt_key(email))


# ── field encryption (AES-256-GCM) ───────────────────────────────────

_data_key = None


def data_key() -> bytes:
    global _data_key
    if _data_key is None:
        _data_key = load_or_create_bytes(DATA_KEY_PATH)
    return _data_key


def encrypt_str(plain: str | None) -> str | None:
    if plain is None:
        return None
    nonce = secrets.token_bytes(12)
    ct = AESGCM(data_key()).encrypt(nonce, plain.encode("utf-8"), None)
    return base64.urlsafe_b64encode(nonce + ct).decode("ascii")


def decrypt_str(token: str | None) -> str | None:
    if not token:
        return None
    raw = base64.urlsafe_b64decode(token.encode("ascii"))
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(data_key()).decrypt(nonce, ct, None).decode("utf-8")


def email_hash(email: str) -> str:
    return hashlib.sha256((email or "").strip().lower().encode("utf-8")).hexdigest()


def license_key_hash(key: str) -> str:
    return hashlib.sha256((key or "").strip().upper().encode("utf-8")).hexdigest()


# ── schema / migration ───────────────────────────────────────────────

USERS_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email_hash TEXT NOT NULL UNIQUE,
  email_enc TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  first_name_enc TEXT NOT NULL,
  last_name_enc TEXT NOT NULL,
  company_enc TEXT,
  country_enc TEXT NOT NULL,
  vat_enc TEXT,
  license_key_hash TEXT NOT NULL UNIQUE,
  license_key_enc TEXT NOT NULL,
  license_payload_enc TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  revoked INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT,
  device_id_enc TEXT,
  device_bound_at TEXT,
  totp_secret TEXT,
  created_at TEXT NOT NULL
)
"""

ADMIN_LOG_SCHEMA = """
CREATE TABLE IF NOT EXISTS admin_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_hash TEXT NOT NULL,
  action TEXT NOT NULL,
  target_id INTEGER,
  detail_enc TEXT,
  created_at TEXT NOT NULL
)
"""


def table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}


def migrate_legacy(conn: sqlite3.Connection) -> None:
    """Convert a plaintext users table into the encrypted schema."""
    legacy = "users"
    if "email_enc" in table_columns(conn, legacy):
        return
    if "email" not in table_columns(conn, legacy):
        return

    conn.execute("DROP TABLE IF EXISTS users_new")
    conn.execute(USERS_SCHEMA.replace("users", "users_new"))
    rows = conn.execute(
        "SELECT * FROM users ORDER BY id"
    ).fetchall()

    for row in rows:
        email = (row["email"] or "").strip().lower()
        license_key = (row["license_key"] or "").strip()
        role = "admin" if email == GOD_EMAIL else "user"
        conn.execute(
            """
            INSERT INTO users_new (
              email_hash, email_enc, password_hash,
              first_name_enc, last_name_enc, company_enc, country_enc, vat_enc,
              license_key_hash, license_key_enc, license_payload_enc,
              role, revoked, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
            """,
            (
                email_hash(email),
                encrypt_str(email),
                row["password_hash"],
                encrypt_str(row["first_name"]),
                encrypt_str(row["last_name"]),
                encrypt_str(row["company"]),
                encrypt_str(row["country"]),
                encrypt_str(row["vat"]),
                license_key_hash(license_key),
                encrypt_str(license_key),
                encrypt_str(row["license_payload"]),
                role,
                row["created_at"],
            ),
        )
    conn.execute("DROP TABLE users")
    conn.execute("ALTER TABLE users_new RENAME TO users")


def init_db() -> None:
    with db() as conn:
        migrate_legacy(conn)
        conn.execute(USERS_SCHEMA)
        conn.execute(ADMIN_LOG_SCHEMA)
        # Add expires_at to tables created before expiry support.
        if "expires_at" not in table_columns(conn, "users"):
            conn.execute("ALTER TABLE users ADD COLUMN expires_at TEXT")
        # Device binding (added after v2 hardening).
        if "device_id_enc" not in table_columns(conn, "users"):
            conn.execute("ALTER TABLE users ADD COLUMN device_id_enc TEXT")
        if "device_bound_at" not in table_columns(conn, "users"):
            conn.execute("ALTER TABLE users ADD COLUMN device_bound_at TEXT")
        # TOTP 2FA for admin accounts (added with god-mode hardening).
        if "totp_secret" not in table_columns(conn, "users"):
            conn.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, dig_hex = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
        return hmac.compare_digest(digest.hex(), dig_hex)
    except Exception:
        return False


# ── TOTP 2FA (RFC 6238, stdlib only) ────────────────────────────────

_B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def _b32encode(raw: bytes) -> str:
    bits = 0
    value = 0
    out = []
    for b in raw:
        value = (value << 8) | b
        bits += 8
        while bits >= 5:
            out.append(_B32_ALPHABET[(value >> (bits - 5)) & 31])
            bits -= 5
    if bits:
        out.append(_B32_ALPHABET[(value << (5 - bits)) & 31])
    return "".join(out)


def _b32decode(s: str) -> bytes:
    s = (s or "").strip().upper().replace(" ", "")
    s = "".join(c for c in s if c in _B32_ALPHABET)
    bits = 0
    value = 0
    out = bytearray()
    for c in s:
        value = (value << 5) | _B32_ALPHABET.index(c)
        bits += 5
        if bits >= 8:
            out.append((value >> (bits - 8)) & 0xFF)
            bits -= 8
    return bytes(out)


def generate_totp_secret() -> str:
    return _b32encode(secrets.token_bytes(20))


def totp_code(secret_b32: str, at_ms: int | None = None) -> str:
    raw = _b32decode(secret_b32)
    step = int((at_ms if at_ms is not None else time.time() * 1000) // 30000)
    msg = struct.pack(">Q", step)
    digest = hmac.new(raw, msg, hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


def totp_verify(secret_b32: str, code: str, window: int = 1) -> bool:
    code = (code or "").strip()
    if not code.isdigit():
        return False
    now_ms = int(time.time() * 1000)
    for skew in range(-window, window + 1):
        expected = totp_code(secret_b32, now_ms + skew * 30000)
        if hmac.compare_digest(expected, code):
            return True
    return False


def otpauth_uri(secret_b32: str, email: str) -> str:
    label = f"EASYBUNDLE ({email})"
    return (
        f"otpauth://totp/{label}?secret={secret_b32}"
        f"&issuer=EASYBUNDLE&period=30&digits=6"
    )


def totp_enabled_for(row: sqlite3.Row) -> bool:
    return bool(row["totp_secret"] if "totp_secret" in row.keys() else None)


# ── crypto / license ─────────────────────────────────────────────────

def ensure_signing_keys() -> Ed25519PrivateKey:
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    if PRIVATE_KEY_PATH.exists():
        raw = PRIVATE_KEY_PATH.read_bytes()
        return Ed25519PrivateKey.from_private_bytes(raw)

    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    PRIVATE_KEY_PATH.write_bytes(private_bytes)
    PUBLIC_KEY_PATH.write_text(public_bytes.hex() + "\n", encoding="utf-8")
    try:
        os.chmod(PRIVATE_KEY_PATH, 0o600)
    except OSError:
        pass

    readme = KEY_DIR / "README.txt"
    if not readme.exists():
        readme.write_text(
            "EASYBUNDLE license signing keys\n"
            "================================\n"
            "easybundle_signing.key — private Ed25519 key (keep secret)\n"
            "easybundle_signing.pub — public key (embed in plugins to verify)\n"
            "easybundle_data.key — AES-256-GCM key for PII at rest (keep secret)\n"
            "easybundle_session.secret — Flask session signing secret\n"
            "Email/ — email deliveries when SMTP is not configured\n",
            encoding="utf-8",
        )
    return private


def generate_password(length: int = 14) -> str:
    alphabet = string.ascii_letters + string.digits
    # Avoid ambiguous characters
    alphabet = alphabet.replace("O", "").replace("0", "").replace("l", "").replace("I", "")
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_license(
    email: str,
    private: Ed25519PrivateKey,
    expires_at: datetime | None = None,
    device_id: str | None = None,
) -> tuple[str, str]:
    """Return (human license key, signed payload b64).

    expires_at embeds an epoch-ms `expires` claim the plugins verify offline.
    None → lifetime license (no expiry claim).
    device_id, when given, embeds a `device` claim; plugins bound to that
    device reject the payload elsewhere.
    """
    body = secrets.token_hex(8).upper()
    groups = [body[i : i + 4] for i in range(0, 16, 4)]
    human = "EB-" + "-".join(groups)

    payload = {
        "product": PRODUCT,
        "plugins": PLUGINS,
        "email": email.lower(),
        "key": human,
        "issued": datetime.now(timezone.utc).isoformat(),
    }
    if expires_at is not None:
        payload["expires"] = int(expires_at.timestamp() * 1000)
    if device_id:
        payload["device"] = device_id

    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = private.sign(raw)
    sealed = base64.urlsafe_b64encode(raw + b"." + sig).decode("ascii")
    return human, sealed


def months_from_now(months: int) -> datetime:
    """Add N calendar months to now (UTC), clamped to the target month's length."""
    now = datetime.now(timezone.utc)
    total = now.year * 12 + (now.month - 1) + max(0, int(months))
    year, month0 = divmod(total, 12)
    month = month0 + 1
    day = min(now.day, calendar.monthrange(year, month)[1])
    return now.replace(year=year, month=month, day=day)


def iso_to_epoch_ms(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except Exception:
        return None


def iso_to_dt(iso: str | None) -> datetime | None:
    """Parse a stored ISO timestamp into an aware datetime (or None)."""
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def server_now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def re_sign_for_device(
    email: str,
    human_key: str,
    expires_at: str | None,
    device_id: str | None,
    private: Ed25519PrivateKey,
) -> str:
    """Re-sign a device-bound payload, keeping the original key/expiry."""
    payload = {
        "product": PRODUCT,
        "plugins": PLUGINS,
        "email": email.lower(),
        "key": human_key,
        "issued": datetime.now(timezone.utc).isoformat(),
    }
    ms = iso_to_epoch_ms(expires_at)
    if ms is not None:
        payload["expires"] = ms
    if device_id:
        payload["device"] = device_id

    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = private.sign(raw)
    return base64.urlsafe_b64encode(raw + b"." + sig).decode("ascii")


def license_ok(expires_at: str | None, revoked: int) -> tuple[bool, str | None]:
    """Return (valid, expiry_error). Lifetime licenses never expire."""
    if revoked:
        return False, "This license has been revoked"
    if not expires_at:
        return True, None
    ms = iso_to_epoch_ms(expires_at)
    if ms is None:
        return True, None
    if ms <= datetime.now(timezone.utc).timestamp() * 1000:
        return False, "License expired"
    return True, None


# ── email ────────────────────────────────────────────────────────────

def build_email(to: str, first_name: str, password: str, license_key: str) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = f"Your free {PRODUCT} trial license & account"
    msg["From"] = os.environ.get("SMTP_FROM", "licenses@easybundle.local")
    msg["To"] = to
    msg.set_content(
        f"Hi {first_name},\n\n"
        f"Welcome to the free {PRODUCT} trial.\n\n"
        f"Account email: {to}\n"
        f"Temporary password: {password}\n"
        f"License key: {license_key}\n\n"
        f"Included: {', '.join(PLUGINS)}\n"
        f"Your trial license is valid for {TRIAL_MONTHS} months.\n\n"
        f"Log in at /account.html and activate the key in each plugin.\n\n"
        f"— EASYBUNDLE\n"
    )
    return msg


def send_email(msg: EmailMessage) -> dict:
    OUTBOX_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    safe_to = re.sub(r"[^a-zA-Z0-9._@+-]+", "_", msg["To"] or "unknown")
    out_path = OUTBOX_DIR / f"{stamp}-{safe_to}.txt"
    out_path.write_text(
        f"To: {msg['To']}\nSubject: {msg['Subject']}\n\n{msg.get_content()}",
        encoding="utf-8",
    )

    host = os.environ.get("SMTP_HOST", "").strip()
    if host:
        port = int(os.environ.get("SMTP_PORT", "587"))
        user = os.environ.get("SMTP_USER", "")
        password = os.environ.get("SMTP_PASS", "")
        with smtplib.SMTP(host, port, timeout=30) as smtp:
            smtp.starttls()
            if user:
                smtp.login(user, password)
            smtp.send_message(msg)
        return {"method": "smtp", "outbox": str(out_path)}

    return {
        "method": "outbox",
        "outbox": str(out_path),
        "warning": "SMTP not configured; delivery saved to EASYBUNDLE_OS/key/Email",
    }


# ── validation ───────────────────────────────────────────────────────

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def parse_purchase(data: dict) -> tuple[dict | None, str | None]:
    """Validate free-trial registration fields."""
    first = (data.get("first_name") or "").strip()
    last = (data.get("last_name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    country = (data.get("country") or "").strip().upper()
    terms = bool(data.get("terms"))

    if not first or not last:
        return None, "Name is required"
    if not EMAIL_RE.match(email):
        return None, "Valid email is required"
    if not country:
        return None, "Country is required"
    if not terms:
        return None, "You must accept the license terms"

    return {
        "first_name": first,
        "last_name": last,
        "email": email,
        "country": country,
    }, None


# ── helpers ──────────────────────────────────────────────────────────

def row_to_user(row: sqlite3.Row) -> dict:
    expires_at = row["expires_at"]
    expires_ms = iso_to_epoch_ms(expires_at)
    device_id = decrypt_str(row["device_id_enc"]) if "device_id_enc" in row.keys() else None
    return {
        "id": row["id"],
        "email": decrypt_str(row["email_enc"]),
        "first_name": decrypt_str(row["first_name_enc"]),
        "last_name": decrypt_str(row["last_name_enc"]),
        "company": decrypt_str(row["company_enc"]),
        "country": decrypt_str(row["country_enc"]),
        "vat": decrypt_str(row["vat_enc"]),
        "license_key": decrypt_str(row["license_key_enc"]),
        "role": row["role"],
        "revoked": bool(row["revoked"]),
        "expires_at": expires_at,
        "expires_ms": expires_ms,
        "lifetime": expires_ms is None,
        "device_id": device_id,
        "device_bound_at": row["device_bound_at"] if "device_bound_at" in row.keys() else None,
        "created_at": row["created_at"],
    }


def current_email() -> str | None:
    email = session.get("user_email")
    return (email or "").strip().lower() or None


def is_admin() -> bool:
    email = current_email()
    if not email:
        return False
    with db() as conn:
        row = conn.execute(
            "SELECT role, totp_secret FROM users WHERE email_hash = ?",
            (email_hash(email),),
        ).fetchone()
    if not row or row["role"] != "admin":
        return False
    # Admin accounts with 2FA enabled must complete the TOTP step this session.
    if row["totp_secret"] and not session.get("2fa_verified"):
        return False
    return True


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not is_admin():
            return jsonify({"ok": False, "error": "Forbidden"}), 403
        return fn(*args, **kwargs)

    return wrapper


def log_admin(action: str, target_id: int | None, detail: dict | None = None) -> None:
    actor = current_email() or ""
    actor = actor or (session.get("pending_2fa_email") or "")
    detail = dict(detail or {})
    detail["actor"] = actor
    detail_enc = encrypt_str(json.dumps(detail, ensure_ascii=False))
    with db() as conn:
        conn.execute(
            "INSERT INTO admin_log (actor_hash, action, target_id, detail_enc, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                email_hash(actor),
                action,
                target_id,
                detail_enc,
                datetime.now(timezone.utc).isoformat(),
            ),
        )


def ensure_god_admin() -> None:
    """Idempotent: promote the god account to admin."""
    with db() as conn:
        row = conn.execute(
            "SELECT id FROM users WHERE email_hash = ?", (email_hash(GOD_EMAIL),)
        ).fetchone()
        if row:
            conn.execute(
                "UPDATE users SET role = 'admin' WHERE id = ?", (row["id"],)
            )


# ── routes ───────────────────────────────────────────────────────────

@app.get("/")
def index():
    return send_from_directory(ROOT, "index.html")


@app.get("/account.html")
def account_page():
    return send_from_directory(ROOT, "account.html")


@app.get("/admin.html")
def admin_page():
    if not is_admin():
        return (
            "<!DOCTYPE html><html><head><meta charset='utf-8'><title>403</title></head>"
            "<body style='background:#000;color:#f5f5f5;font-family:monospace;padding:40px'>"
            "<h1>403 — Forbidden</h1><p>Sign in as the admin account to view this page.</p>"
            "</body></html>",
            403,
        )
    return send_from_directory(ROOT, "admin.html")


@app.get("/api/health")
def health():
    ensure_signing_keys()
    return jsonify({"ok": True, "product": PRODUCT, "key_dir": str(KEY_DIR)})


@app.post("/api/register")
def register():
    """Free registration → instant 3-month trial license for all plugins."""
    data = request.get_json(silent=True) or request.form.to_dict()
    if "terms" in data and isinstance(data["terms"], str):
        data["terms"] = data["terms"] in ("1", "true", "on", "yes")

    parsed, err = parse_purchase(data)
    if err:
        return jsonify({"ok": False, "error": err}), 400

    with db() as conn:
        existing = conn.execute(
            "SELECT id FROM users WHERE email_hash = ?", (email_hash(parsed["email"]),)
        ).fetchone()
        if existing:
            return jsonify({"ok": False, "error": "An account with this email already exists. Log in instead."}), 409

    private = ensure_signing_keys()
    password = generate_password()
    expires_at = months_from_now(TRIAL_MONTHS)
    license_key, license_payload = generate_license(parsed["email"], private, expires_at)
    password_hash = hash_password(password)
    created_at = datetime.now(timezone.utc).isoformat()

    with db() as conn:
        conn.execute(
            """
            INSERT INTO users (
              email_hash, email_enc, password_hash,
              first_name_enc, last_name_enc, country_enc,
              license_key_hash, license_key_enc, license_payload_enc,
              role, revoked, expires_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'user', 0, ?, ?)
            """,
            (
                email_hash(parsed["email"]),
                encrypt_str(parsed["email"]),
                password_hash,
                encrypt_str(parsed["first_name"]),
                encrypt_str(parsed["last_name"]),
                encrypt_str(parsed["country"]),
                license_key_hash(license_key),
                encrypt_str(license_key),
                encrypt_str(license_payload),
                expires_at.isoformat(),
                created_at,
            ),
        )

    msg = build_email(parsed["email"], parsed["first_name"], password, license_key)
    delivery = send_email(msg)

    if parsed["email"] == GOD_EMAIL:
        ensure_god_admin()

    session["user_email"] = parsed["email"]

    return jsonify(
        {
            "ok": True,
            "email": parsed["email"],
            "license_key": license_key,
            "plugins": PLUGINS,
            "trial_months": TRIAL_MONTHS,
            "email_delivery": delivery,
            "account_url": "/account.html",
            # Password is emailed; also returned once so the UI can confirm in-dev.
            "password_emailed": True,
            "temp_password": password,
            "expires_at": expires_at.isoformat(),
            "lifetime": False,
        }
    )


def normalize_license_key(raw: str) -> str:
    """Accept EB-XXXX-… or bare hex; return canonical EB-XXXX-XXXX-XXXX-XXXX."""
    s = (raw or "").strip().upper().replace(" ", "")
    if s.startswith("EB-"):
        s = s[3:]
    s = s.replace("-", "")
    if len(s) != 16 or any(c not in string.hexdigits for c in s):
        return ""
    groups = [s[i : i + 4] for i in range(0, 16, 4)]
    return "EB-" + "-".join(groups)


@app.post("/api/activate")
def activate():
    """Exchange email + human license key for the signed sealed payload.

    Binds the license to the first machine (machine_id) that activates it.
    Re-signs the payload with a `device` claim so the offline plugin rejects
    the file elsewhere. A license can be unbound by an admin to allow a new
    machine.
    """
    data = request.get_json(silent=True) or {}
    key = normalize_license_key(data.get("license_key") or data.get("key") or "")
    email = (data.get("email") or "").strip().lower()
    machine_id = (data.get("machine_id") or "").strip()[:128]
    if not key:
        return jsonify({"ok": False, "error": "Invalid license key format"}), 400
    if not EMAIL_RE.match(email):
        return jsonify({"ok": False, "error": "Valid email is required"}), 400
    if not machine_id:
        return jsonify({"ok": False, "error": "Device identifier is required"}), 400

    private = ensure_signing_keys()
    with db() as conn:
        row = conn.execute(
            "SELECT license_key_enc, license_payload_enc, email_enc, revoked, expires_at, device_id_enc, device_bound_at "
            "FROM users WHERE license_key_hash = ?",
            (license_key_hash(key),),
        ).fetchone()

        if row is None:
            return jsonify({"ok": False, "error": "Unknown license key"}), 404

        stored_email = (decrypt_str(row["email_enc"]) or "").lower()
        if stored_email != email:
            return jsonify({"ok": False, "error": "Email does not match this license"}), 403

        valid, err = license_ok(row["expires_at"], row["revoked"])
        if not valid:
            return jsonify({"ok": False, "error": err}), 403

        bound = decrypt_str(row["device_id_enc"])
        if bound and bound != machine_id:
            return jsonify(
                {
                    "ok": False,
                    "error": "This license is already activated on another device.",
                }
            ), 409

        human_key = decrypt_str(row["license_key_enc"]) or key
        # (Re)sign a device-bound payload so the offline plugin enforces the device.
        payload = re_sign_for_device(
            stored_email, human_key, row["expires_at"], machine_id, private
        )
        conn.execute(
            "UPDATE users SET device_id_enc = ?, device_bound_at = ?, license_payload_enc = ? "
            "WHERE license_key_hash = ?",
            (
                encrypt_str(machine_id),
                datetime.now(timezone.utc).isoformat(),
                encrypt_str(payload),
                license_key_hash(key),
            ),
        )

    return jsonify(
        {
            "ok": True,
            "license_key": human_key,
            "license_payload": payload,
            "email": stored_email,
            "plugins": PLUGINS,
            "product": PRODUCT,
            "expires_at": row["expires_at"],
            "expires_ms": iso_to_epoch_ms(row["expires_at"]),
            "lifetime": row["expires_at"] is None,
            "server_now_ms": server_now_ms(),
        }
    )


@app.post("/api/verify")
def verify():
    """Periodic check: confirm email+key still exist and belong to this device."""
    data = request.get_json(silent=True) or {}
    key = normalize_license_key(data.get("license_key") or data.get("key") or "")
    email = (data.get("email") or "").strip().lower()
    machine_id = (data.get("machine_id") or "").strip()[:128]
    if not key:
        return jsonify({"ok": False, "valid": False, "error": "Invalid license key format"}), 400
    if not EMAIL_RE.match(email):
        return jsonify({"ok": False, "valid": False, "error": "Valid email is required"}), 400

    with db() as conn:
        row = conn.execute(
            "SELECT license_key_enc, email_enc, revoked, expires_at, device_id_enc "
            "FROM users WHERE license_key_hash = ? AND email_hash = ?",
            (license_key_hash(key), email_hash(email)),
        ).fetchone()

    if row is None:
        return jsonify({"ok": False, "valid": False, "error": "License not found"}), 404

    valid, err = license_ok(row["expires_at"], row["revoked"])
    if not valid:
        return jsonify({"ok": False, "valid": False, "error": err}), 403

    bound = decrypt_str(row["device_id_enc"])
    if machine_id and bound and bound != machine_id:
        return jsonify(
            {
                "ok": True,
                "valid": False,
                "error": "License is bound to another device",
                "server_now_ms": server_now_ms(),
            }
        )

    return jsonify(
        {
            "ok": True,
            "valid": True,
            "license_key": decrypt_str(row["license_key_enc"]),
            "email": decrypt_str(row["email_enc"]),
            "plugins": PLUGINS,
            "product": PRODUCT,
            "expires_at": row["expires_at"],
            "expires_ms": iso_to_epoch_ms(row["expires_at"]),
            "lifetime": row["expires_at"] is None,
            "server_now_ms": server_now_ms(),
        }
    )


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not email or not password:
        return jsonify({"ok": False, "error": "Email and password required"}), 400

    limited = check_rate_limit(email)
    if limited:
        return limited

    with db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE email_hash = ?", (email_hash(email),)
        ).fetchone()
    if not row or not verify_password(password, row["password_hash"]):
        _rate_failed(email)
        return jsonify({"ok": False, "error": "Invalid email or password"}), 401
    _rate_ok(email)

    if email == GOD_EMAIL:
        ensure_god_admin()
        with db() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE email_hash = ?", (email_hash(email),)
            ).fetchone()

    # Admins with 2FA enabled must complete a TOTP step before the session
    # becomes admin-capable.
    if row["role"] == "admin" and totp_enabled_for(row):
        session.clear()
        session["pending_2fa_email"] = email
        return jsonify({"ok": True, "needs_2fa": True})

    session.clear()
    session["user_email"] = email
    if row["role"] == "admin":
        session["2fa_verified"] = True
    return jsonify(
        {
            "ok": True,
            "user": {
                "email": decrypt_str(row["email_enc"]),
                "first_name": decrypt_str(row["first_name_enc"]),
                "last_name": decrypt_str(row["last_name_enc"]),
                "company": decrypt_str(row["company_enc"]),
                "country": decrypt_str(row["country_enc"]),
                "license_key": decrypt_str(row["license_key_enc"]),
                "role": row["role"],
                "admin": is_admin(),
                "revoked": bool(row["revoked"]),
                "expires_at": row["expires_at"],
                "expires_ms": iso_to_epoch_ms(row["expires_at"]),
                "lifetime": row["expires_at"] is None,
                "plugins": PLUGINS,
                "created_at": row["created_at"],
            },
        }
    )


@app.post("/api/login/2fa")
def login_2fa():
    """Second step: verify a TOTP code for a pending admin login."""
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    code = data.get("code") or ""
    pending = session.get("pending_2fa_email") or ""

    limited = check_rate_limit(email or pending)
    if limited:
        return limited

    if not pending or not email or pending != email:
        return jsonify({"ok": False, "error": "Complete the first login step first"}), 400
    if not code:
        return jsonify({"ok": False, "error": "Verification code is required"}), 400

    with db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE email_hash = ?", (email_hash(pending),)
        ).fetchone()
    if row is None or row["role"] != "admin":
        _rate_failed(pending)
        return jsonify({"ok": False, "error": "2FA is not enabled for this account"}), 403

    if not totp_verify(row["totp_secret"], code):
        _rate_failed(pending)
        return jsonify({"ok": False, "error": "Invalid verification code"}), 401

    _rate_ok(pending)
    session.clear()
    session["user_email"] = pending
    session["2fa_verified"] = True
    return jsonify(
        {
            "ok": True,
            "user": {
                "email": decrypt_str(row["email_enc"]),
                "first_name": decrypt_str(row["first_name_enc"]),
                "last_name": decrypt_str(row["last_name_enc"]),
                "company": decrypt_str(row["company_enc"]),
                "country": decrypt_str(row["country_enc"]),
                "license_key": decrypt_str(row["license_key_enc"]),
                "role": row["role"],
                "admin": is_admin(),
                "revoked": bool(row["revoked"]),
                "expires_at": row["expires_at"],
                "expires_ms": iso_to_epoch_ms(row["expires_at"]),
                "lifetime": row["expires_at"] is None,
                "plugins": PLUGINS,
                "created_at": row["created_at"],
            },
        }
    )


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.get("/api/me")
def me():
    email = current_email()
    if not email:
        return jsonify({"ok": False, "error": "Not logged in"}), 401
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE email_hash = ?", (email_hash(email),)
        ).fetchone()
    if not row:
        session.clear()
        return jsonify({"ok": False, "error": "Not logged in"}), 401
    return jsonify(
        {
            "ok": True,
            "user": {
                "email": decrypt_str(row["email_enc"]),
                "first_name": decrypt_str(row["first_name_enc"]),
                "last_name": decrypt_str(row["last_name_enc"]),
                "company": decrypt_str(row["company_enc"]),
                "country": decrypt_str(row["country_enc"]),
                "license_key": decrypt_str(row["license_key_enc"]),
                "role": row["role"],
                "admin": is_admin(),
                "revoked": bool(row["revoked"]),
                "expires_at": row["expires_at"],
                "expires_ms": iso_to_epoch_ms(row["expires_at"]),
                "lifetime": row["expires_at"] is None,
                "plugins": PLUGINS,
                "created_at": row["created_at"],
            },
        }
    )


# ── admin API (god mode) ─────────────────────────────────────────────

@app.get("/api/admin/users")
@admin_required
def admin_users_list():
    q = (request.args.get("q") or "").strip().lower()
    per_page = min(max(int(request.args.get("per_page") or 25), 1), 200)
    page = max(int(request.args.get("page") or 1), 1)

    with db() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
    users = [row_to_user(r) for r in rows]

    if q:
        users = [
            u
            for u in users
            if q in str(u["id"])
            or q in (u["email"] or "").lower()
            or q in (u["first_name"] or "").lower()
            or q in (u["last_name"] or "").lower()
            or q in (u["company"] or "").lower()
            or q in (u["country"] or "").lower()
            or q in (u["license_key"] or "").lower()
        ]

    total = len(users)
    pages = max((total + per_page - 1) // per_page, 1)
    page = min(page, pages)
    start = (page - 1) * per_page
    return jsonify(
        {
            "ok": True,
            "users": users[start:start + per_page],
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": pages,
        }
    )


@app.get("/api/admin/stats")
@admin_required
def admin_stats():
    now_ms = server_now_ms()
    with db() as conn:
        rows = conn.execute("SELECT id, role, revoked, expires_at FROM users").fetchall()

    total = len(rows)
    admins = 0
    active = 0
    expired = 0
    revoked = 0
    expiring_30 = 0
    for r in rows:
        if r["role"] == "admin":
            admins += 1
        if r["revoked"]:
            revoked += 1
            continue
        ms = iso_to_epoch_ms(r["expires_at"])
        if ms is None:
            active += 1
            continue
        if ms <= now_ms:
            expired += 1
        else:
            active += 1
            if ms <= now_ms + 30 * 86400000:
                expiring_30 += 1
    return jsonify(
        {
            "ok": True,
            "stats": {
                "total": total,
                "active": active,
                "expired": expired,
                "revoked": revoked,
                "expiring_30": expiring_30,
                "admins": admins,
            },
        }
    )


@app.get("/api/admin/users/export.csv")
@admin_required
def admin_users_csv():
    import csv
    import io

    with db() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
    users = [row_to_user(r) for r in rows]

    buf = io.StringIO()
    buf.write("\ufeff")
    writer = csv.writer(buf)
    writer.writerow(
        [
            "id", "email", "first_name", "last_name", "company", "country",
            "vat", "license_key", "role", "revoked", "expires_at",
            "device_id", "device_bound_at", "created_at",
        ]
    )
    for u in users:
        writer.writerow(
            [
                u["id"], u["email"], u["first_name"], u["last_name"],
                u["company"], u["country"], u["vat"], u["license_key"],
                u["role"], 1 if u["revoked"] else 0, u["expires_at"],
                u["device_id"], u["device_bound_at"], u["created_at"],
            ]
        )
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    resp = app.response_class(
        buf.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="easybundle-users-{stamp}.csv"'},
    )
    return resp


@app.post("/api/admin/users/<int:uid>/update")
@admin_required
def admin_users_update(uid: int):
    data = request.get_json(silent=True) or {}
    first = (data.get("first_name") or "").strip()
    last = (data.get("last_name") or "").strip()
    company = (data.get("company") or "").strip() or None
    country = (data.get("country") or "").strip().upper()
    vat = (data.get("vat") or "").strip() or None

    if not first or not last:
        return jsonify({"ok": False, "error": "Name is required"}), 400
    if not country:
        return jsonify({"ok": False, "error": "Country is required"}), 400

    with db() as conn:
        row = conn.execute("SELECT email_enc FROM users WHERE id = ?", (uid,)).fetchone()
        if row is None:
            return jsonify({"ok": False, "error": "User not found"}), 404
        conn.execute(
            """
            UPDATE users SET first_name_enc = ?, last_name_enc = ?,
              company_enc = ?, country_enc = ?, vat_enc = ?
            WHERE id = ?
            """,
            (
                encrypt_str(first),
                encrypt_str(last),
                encrypt_str(company),
                encrypt_str(country),
                encrypt_str(vat),
                uid,
            ),
        )

    log_admin("update_user", uid, {"email": decrypt_str(row["email_enc"])})
    return jsonify({"ok": True})


@app.post("/api/admin/users/<int:uid>/extend")
@admin_required
def admin_users_extend(uid: int):
    """Extend a license: months (1..120) or lifetime. Re-signs the payload."""
    data = request.get_json(silent=True) or {}
    months_raw = data.get("months")
    lifetime = bool(data.get("lifetime"))

    with db() as conn:
        row = conn.execute(
            "SELECT email_enc, license_key_enc, license_payload_enc, device_id_enc, expires_at "
            "FROM users WHERE id = ?",
            (uid,),
        ).fetchone()
        if row is None:
            return jsonify({"ok": False, "error": "User not found"}), 404

        if not lifetime:
            try:
                months = int(months_raw)
            except (TypeError, ValueError):
                return jsonify({"ok": False, "error": "Months must be a number"}), 400
            if months < 1 or months > 120:
                return jsonify({"ok": False, "error": "Months must be between 1 and 120"}), 400
            new_expires = months_from_now(months).isoformat()
        else:
            new_expires = None

        email = decrypt_str(row["email_enc"])
        human_key = decrypt_str(row["license_key_enc"])
        device_id = decrypt_str(row["device_id_enc"])
        private = ensure_signing_keys()
        payload = re_sign_for_device(email, human_key, new_expires, device_id, private)
        conn.execute(
            "UPDATE users SET expires_at = ?, license_payload_enc = ? WHERE id = ?",
            (new_expires, encrypt_str(payload), uid),
        )

    log_admin("extend_license", uid, {"email": email, "expires_at": new_expires})
    return jsonify({"ok": True, "expires_at": new_expires, "lifetime": new_expires is None})


@app.post("/api/admin/users/<int:uid>/reissue")
@admin_required
def admin_users_reissue(uid: int):
    """Generate a brand-new license key for the user, preserving expiry & device."""
    with db() as conn:
        row = conn.execute(
            "SELECT email_enc, expires_at, device_id_enc, first_name_enc "
            "FROM users WHERE id = ?",
            (uid,),
        ).fetchone()
        if row is None:
            return jsonify({"ok": False, "error": "User not found"}), 404
        email = decrypt_str(row["email_enc"])
        device_id = decrypt_str(row["device_id_enc"])
        first = decrypt_str(row["first_name_enc"]) or ""

        private = ensure_signing_keys()
        new_key, new_payload = generate_license(
            email, private, iso_to_dt(row["expires_at"]), device_id=device_id,
        )
        password = generate_password()
        conn.execute(
            """
            UPDATE users SET license_key_hash = ?, license_key_enc = ?, license_payload_enc = ?,
              password_hash = ?
            WHERE id = ?
            """,
            (
                license_key_hash(new_key),
                encrypt_str(new_key),
                encrypt_str(new_payload),
                hash_password(password),
                uid,
            ),
        )

    log_admin("reissue_license", uid, {"email": email})
    delivery = send_email(build_email(email, first, password, new_key))
    return jsonify(
        {
            "ok": True,
            "license_key": new_key,
            "temp_password": password,
            "email_delivery": delivery,
        }
    )


@app.post("/api/admin/users/<int:uid>/resend")
@admin_required
def admin_users_resend(uid: int):
    """Reset the password and email fresh credentials to the user."""
    password = generate_password()
    with db() as conn:
        row = conn.execute(
            "SELECT email_enc, first_name_enc, license_key_enc FROM users WHERE id = ?",
            (uid,),
        ).fetchone()
        if row is None:
            return jsonify({"ok": False, "error": "User not found"}), 404
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(password), uid),
        )
    email = decrypt_str(row["email_enc"])
    first = decrypt_str(row["first_name_enc"])
    license_key = decrypt_str(row["license_key_enc"])

    log_admin("resend_credentials", uid, {"email": email})
    delivery = send_email(build_email(email, first or "", password, license_key or ""))

    return jsonify(
        {
            "ok": True,
            "email": email,
            "temp_password": password,
            "email_delivery": delivery,
        }
    )


# ── admin 2FA ─────────────────────────────────────────────────────────

@app.get("/api/admin/2fa/status")
@admin_required
def admin_2fa_status():
    email = current_email()
    with db() as conn:
        row = conn.execute(
            "SELECT totp_secret FROM users WHERE email_hash = ?", (email_hash(email),)
        ).fetchone()
    return jsonify({"ok": True, "enabled": bool(row and row["totp_secret"])})


@app.post("/api/admin/2fa/setup")
@admin_required
def admin_2fa_setup():
    secret = generate_totp_secret()
    session["pending_totp"] = secret
    session["pending_totp_email"] = current_email()
    return jsonify(
        {
            "ok": True,
            "secret": secret,
            "otpauth_url": otpauth_uri(secret, current_email() or ""),
        }
    )


@app.post("/api/admin/2fa/enable")
@admin_required
def admin_2fa_enable():
    data = request.get_json(silent=True) or {}
    code = data.get("code") or ""
    secret = session.get("pending_totp")
    email = current_email()
    if not secret or not email or session.get("pending_totp_email") != email:
        return jsonify({"ok": False, "error": "Start 2FA setup first"}), 400
    if not totp_verify(secret, code):
        return jsonify({"ok": False, "error": "Invalid verification code"}), 401
    with db() as conn:
        conn.execute(
            "UPDATE users SET totp_secret = ? WHERE email_hash = ?",
            (secret, email_hash(email)),
        )
    session.pop("pending_totp", None)
    session.pop("pending_totp_email", None)
    log_admin("enable_2fa", None, {"email": email})
    return jsonify({"ok": True})


@app.post("/api/admin/2fa/disable")
@admin_required
def admin_2fa_disable():
    data = request.get_json(silent=True) or {}
    code = data.get("code") or ""
    email = current_email()
    with db() as conn:
        row = conn.execute(
            "SELECT totp_secret FROM users WHERE email_hash = ?", (email_hash(email),)
        ).fetchone()
    if not row or not row["totp_secret"]:
        return jsonify({"ok": False, "error": "2FA is not enabled"}), 400
    if not totp_verify(row["totp_secret"], code):
        return jsonify({"ok": False, "error": "Invalid verification code"}), 401
    with db() as conn:
        conn.execute(
            "UPDATE users SET totp_secret = NULL WHERE email_hash = ?",
            (email_hash(email),),
        )
    log_admin("disable_2fa", None, {"email": email})
    return jsonify({"ok": True})


@app.post("/api/admin/users")
@admin_required
def admin_users_create():
    data = request.get_json(silent=True) or {}
    first = (data.get("first_name") or "").strip()
    last = (data.get("last_name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    company = (data.get("company") or "").strip() or None
    country = (data.get("country") or "").strip().upper()
    vat = (data.get("vat") or "").strip() or None
    password = (data.get("password") or "").strip() or None
    send_mail = bool(data.get("send_email"))
    months_raw = data.get("months")

    if not first or not last:
        return jsonify({"ok": False, "error": "Name is required"}), 400
    if not EMAIL_RE.match(email):
        return jsonify({"ok": False, "error": "Valid email is required"}), 400
    if not country:
        return jsonify({"ok": False, "error": "Country is required"}), 400

    try:
        months = int(months_raw) if months_raw not in (None, "", "0") else 0
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "Months must be a number"}), 400
    if months < 0 or months > 120:
        return jsonify({"ok": False, "error": "Months must be between 0 and 120"}), 400

    expires_at = months_from_now(months) if months > 0 else None

    with db() as conn:
        existing = conn.execute(
            "SELECT id FROM users WHERE email_hash = ?", (email_hash(email),)
        ).fetchone()
        if existing:
            return jsonify({"ok": False, "error": "An account with this email already exists"}), 409

    private = ensure_signing_keys()
    license_key, license_payload = generate_license(email, private, expires_at)
    if not password:
        password = generate_password()
    password_hash = hash_password(password)
    created_at = datetime.now(timezone.utc).isoformat()

    with db() as conn:
        cur = conn.execute(
            """
            INSERT INTO users (
              email_hash, email_enc, password_hash,
              first_name_enc, last_name_enc, company_enc, country_enc, vat_enc,
              license_key_hash, license_key_enc, license_payload_enc,
              role, revoked, expires_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'user', 0, ?, ?)
            """,
            (
                email_hash(email),
                encrypt_str(email),
                password_hash,
                encrypt_str(first),
                encrypt_str(last),
                encrypt_str(company),
                encrypt_str(country),
                encrypt_str(vat),
                license_key_hash(license_key),
                encrypt_str(license_key),
                encrypt_str(license_payload),
                expires_at.isoformat() if expires_at else None,
                created_at,
            ),
        )
        new_id = cur.lastrowid
    if email == GOD_EMAIL:
        ensure_god_admin()
    log_admin("create_user", new_id, {"email": email, "license_key": license_key})

    delivery = None
    if send_mail:
        delivery = send_email(build_email(email, first, password, license_key))

    return jsonify(
        {
            "ok": True,
            "user": {
                "id": new_id,
                "email": email,
                "first_name": first,
                "last_name": last,
                "license_key": license_key,
                "role": "user",
                "revoked": False,
                "expires_at": expires_at.isoformat() if expires_at else None,
                "lifetime": expires_at is None,
            },
            "temp_password": password,
            "email_delivery": delivery,
        }
    ), 201


@app.post("/api/admin/users/<int:uid>/revoke")
@admin_required
def admin_users_revoke(uid: int):
    body = request.get_json(silent=True) or {}
    revoke = bool(body.get("revoke", True))

    with db() as conn:
        row = conn.execute(
            "SELECT email_enc, role FROM users WHERE id = ?", (uid,)
        ).fetchone()
        if row is None:
            return jsonify({"ok": False, "error": "User not found"}), 404
        if revoke and row["role"] == "admin":
            return jsonify({"ok": False, "error": "Cannot revoke an admin license"}), 403
        conn.execute("UPDATE users SET revoked = ? WHERE id = ?", (1 if revoke else 0, uid))

    log_admin("revoke" if revoke else "restore", uid, {"email": decrypt_str(row["email_enc"])})
    return jsonify({"ok": True, "revoked": revoke})


@app.post("/api/admin/revoke")
@admin_required
def admin_quick_revoke():
    """Revoke (or restore) a license by email or license key, without the user table."""
    body = request.get_json(silent=True) or {}
    revoke = bool(body.get("revoke", True))
    email = (body.get("email") or "").strip().lower()
    key = (body.get("license_key") or "").strip().upper()

    if not email and not key:
        return jsonify({"ok": False, "error": "Provide an email or license key"}), 400

    with db() as conn:
        if email:
            row = conn.execute(
                "SELECT id, email_enc, role FROM users WHERE email_hash = ?",
                (email_hash(email),),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT id, email_enc, role FROM users WHERE license_key_hash = ?",
                (license_key_hash(key),),
            ).fetchone()

        if row is None:
            return jsonify({"ok": False, "error": "No user found with that email or license key"}), 404
        if revoke and row["role"] == "admin":
            return jsonify({"ok": False, "error": "Cannot revoke an admin license"}), 403
        conn.execute("UPDATE users SET revoked = ? WHERE id = ?", (1 if revoke else 0, row["id"]))

    uid = row["id"]
    email_out = decrypt_str(row["email_enc"])
    log_admin("revoke" if revoke else "restore", uid, {"email": email_out, "by": "quick"})
    return jsonify({"ok": True, "revoked": revoke, "user_id": uid, "email": email_out})


@app.post("/api/admin/users/<int:uid>/unbind-device")
@admin_required
def admin_users_unbind_device(uid: int):
    """Clear device binding so the license can be activated on another machine."""
    with db() as conn:
        row = conn.execute(
            "SELECT email_enc FROM users WHERE id = ?", (uid,)
        ).fetchone()
        if row is None:
            return jsonify({"ok": False, "error": "User not found"}), 404
        conn.execute(
            "UPDATE users SET device_id_enc = NULL, device_bound_at = NULL WHERE id = ?",
            (uid,),
        )

    log_admin("unbind_device", uid, {"email": decrypt_str(row["email_enc"])})
    return jsonify({"ok": True})


@app.post("/api/admin/users/<int:uid>/reset-password")
@admin_required
def admin_users_reset_password(uid: int):
    password = generate_password()

    with db() as conn:
        row = conn.execute(
            "SELECT email_enc, first_name_enc, license_key_enc FROM users WHERE id = ?",
            (uid,),
        ).fetchone()
        if row is None:
            return jsonify({"ok": False, "error": "User not found"}), 404
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(password), uid),
        )
    email = decrypt_str(row["email_enc"])
    first = decrypt_str(row["first_name_enc"])
    license_key = decrypt_str(row["license_key_enc"])

    log_admin("reset_password", uid, {"email": email})
    delivery = send_email(build_email(email, first or "", password, license_key or ""))

    return jsonify(
        {
            "ok": True,
            "email": email,
            "temp_password": password,
            "email_delivery": delivery,
        }
    )


@app.delete("/api/admin/users/<int:uid>")
@admin_required
def admin_users_delete(uid: int):
    with db() as conn:
        row = conn.execute(
            "SELECT email_enc, role FROM users WHERE id = ?", (uid,)
        ).fetchone()
        if row is None:
            return jsonify({"ok": False, "error": "User not found"}), 404
        if row["role"] == "admin":
            return jsonify({"ok": False, "error": "Cannot delete an admin account"}), 403
        conn.execute("DELETE FROM users WHERE id = ?", (uid,))

    log_admin("delete_user", uid, {"email": decrypt_str(row["email_enc"])})
    return jsonify({"ok": True})


@app.get("/api/admin/log")
@admin_required
def admin_log():
    with db() as conn:
        rows = conn.execute(
            "SELECT actor_hash, action, target_id, detail_enc, created_at "
            "FROM admin_log ORDER BY id DESC LIMIT 200"
        ).fetchall()
    entries = []
    for r in rows:
        detail = None
        try:
            detail = json.loads(decrypt_str(r["detail_enc"]) or "null")
        except Exception:
            pass
        entries.append(
            {
                "actor": (detail or {}).get("actor") or (r["actor_hash"][:12] + "…"),
                "action": r["action"],
                "target_id": r["target_id"],
                "detail": detail,
                "created_at": r["created_at"],
            }
        )
    return jsonify({"ok": True, "entries": entries})


@app.get("/<path:path>")
def static_proxy(path: str):
    return send_from_directory(ROOT, path)


def main() -> None:
    init_db()
    ensure_signing_keys()
    ensure_god_admin()
    port = int(os.environ.get("PORT", "8787"))
    print(f"EASYBUNDLE server → http://127.0.0.1:{port}")
    print(f"Signing keys     → {KEY_DIR}")
    print(f"God mode admin   → {GOD_EMAIL}")
    debug = os.environ.get("DEBUG") in ("1", "true", "True")
    app.run(host="127.0.0.1", port=port, debug=debug, use_reloader=False)


if __name__ == "__main__":
    main()
