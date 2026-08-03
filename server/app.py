#!/usr/bin/env python3
"""EASYBUNDLE checkout + account API.

Typical plugin purchase fields collected:
  first/last name, email, company (opt), country, VAT/Tax ID (opt), terms.

On purchase:
  - create account (hashed password)
  - generate signed license key
  - ensure signing key exists in ~/Desktop/key
  - email password + license (SMTP or Mail.app / outbox fallback)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import sqlite3
import string
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from flask import Flask, jsonify, request, send_from_directory, session

ROOT = Path(__file__).resolve().parent.parent
SERVER_DIR = Path(__file__).resolve().parent
DATA_DIR = SERVER_DIR / "data"
DB_PATH = DATA_DIR / "easybundle.db"
KEY_DIR = Path.home() / "Desktop" / "Vibecoding" / "key"
PRIVATE_KEY_PATH = KEY_DIR / "easybundle_signing.key"
PUBLIC_KEY_PATH = KEY_DIR / "easybundle_signing.pub"
OUTBOX_DIR = KEY_DIR / "outbox"

PRODUCT = "EASYBUNDLE"
PLUGINS = ["CAESAR", "CAPSULE", "REFLECT", "SLOPE", "METROOM"]
BUNDLE_PRICE = os.environ.get("BUNDLE_PRICE", "149")

app = Flask(__name__, static_folder=str(ROOT), static_url_path="")
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)


# ── storage ──────────────────────────────────────────────────────────

def db() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              email TEXT NOT NULL UNIQUE,
              password_hash TEXT NOT NULL,
              first_name TEXT NOT NULL,
              last_name TEXT NOT NULL,
              company TEXT,
              country TEXT NOT NULL,
              vat TEXT,
              license_key TEXT NOT NULL,
              license_payload TEXT NOT NULL,
              created_at TEXT NOT NULL
            )
            """
        )


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
            "outbox/ — email deliveries when SMTP is not configured\n",
            encoding="utf-8",
        )
    return private


def generate_password(length: int = 14) -> str:
    alphabet = string.ascii_letters + string.digits
    # Avoid ambiguous characters
    alphabet = alphabet.replace("O", "").replace("0", "").replace("l", "").replace("I", "")
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_license(email: str, private: Ed25519PrivateKey) -> tuple[str, str]:
    """Return (human license key, signed payload b64)."""
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
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = private.sign(raw)
    sealed = base64.urlsafe_b64encode(raw + b"." + sig).decode("ascii")
    return human, sealed


# ── email ────────────────────────────────────────────────────────────

def build_email(to: str, first_name: str, password: str, license_key: str) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = f"Your {PRODUCT} license & account"
    msg["From"] = os.environ.get("SMTP_FROM", "licenses@easybundle.local")
    msg["To"] = to
    msg.set_content(
        f"Hi {first_name},\n\n"
        f"Thanks for purchasing {PRODUCT}.\n\n"
        f"Account email: {to}\n"
        f"Temporary password: {password}\n"
        f"License key: {license_key}\n\n"
        f"Included: {', '.join(PLUGINS)}\n\n"
        f"Log in at /account.html and activate the key in each plugin.\n\n"
        f"— repentov / EASYBUNDLE\n"
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
        "warning": "SMTP not configured; delivery saved to Desktop/key/outbox",
    }


# ── validation ───────────────────────────────────────────────────────

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def parse_purchase(data: dict) -> tuple[dict | None, str | None]:
    first = (data.get("first_name") or "").strip()
    last = (data.get("last_name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    company = (data.get("company") or "").strip() or None
    country = (data.get("country") or "").strip().upper()
    vat = (data.get("vat") or "").strip() or None
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
        "company": company,
        "country": country,
        "vat": vat,
    }, None


# ── routes ───────────────────────────────────────────────────────────

@app.get("/")
def index():
    return send_from_directory(ROOT, "index.html")


@app.get("/account.html")
def account_page():
    return send_from_directory(ROOT, "account.html")


@app.get("/api/health")
def health():
    ensure_signing_keys()
    return jsonify({"ok": True, "product": PRODUCT, "key_dir": str(KEY_DIR)})


@app.post("/api/purchase")
def purchase():
    data = request.get_json(silent=True) or request.form.to_dict()
    if "terms" in data and isinstance(data["terms"], str):
        data["terms"] = data["terms"] in ("1", "true", "on", "yes")

    parsed, err = parse_purchase(data)
    if err:
        return jsonify({"ok": False, "error": err}), 400

    with db() as conn:
        existing = conn.execute(
            "SELECT id FROM users WHERE email = ?", (parsed["email"],)
        ).fetchone()
        if existing:
            return jsonify({"ok": False, "error": "An account with this email already exists. Log in instead."}), 409

    private = ensure_signing_keys()
    password = generate_password()
    license_key, license_payload = generate_license(parsed["email"], private)
    password_hash = hash_password(password)
    created_at = datetime.now(timezone.utc).isoformat()

    with db() as conn:
        conn.execute(
            """
            INSERT INTO users (
              email, password_hash, first_name, last_name, company, country, vat,
              license_key, license_payload, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                parsed["email"],
                password_hash,
                parsed["first_name"],
                parsed["last_name"],
                parsed["company"],
                parsed["country"],
                parsed["vat"],
                license_key,
                license_payload,
                created_at,
            ),
        )

    msg = build_email(parsed["email"], parsed["first_name"], password, license_key)
    delivery = send_email(msg)

    session["user_email"] = parsed["email"]

    return jsonify(
        {
            "ok": True,
            "email": parsed["email"],
            "license_key": license_key,
            "plugins": PLUGINS,
            "price": BUNDLE_PRICE,
            "email_delivery": delivery,
            "account_url": "/account.html",
            # Password is emailed; also returned once so the UI can confirm in-dev.
            "password_emailed": True,
            "temp_password": password,
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
    """Exchange email + human license key for the signed sealed payload."""
    data = request.get_json(silent=True) or {}
    key = normalize_license_key(data.get("license_key") or data.get("key") or "")
    email = (data.get("email") or "").strip().lower()
    if not key:
        return jsonify({"ok": False, "error": "Invalid license key format"}), 400
    if not EMAIL_RE.match(email):
        return jsonify({"ok": False, "error": "Valid email is required"}), 400

    with db() as conn:
        row = conn.execute(
            "SELECT license_key, license_payload, email FROM users WHERE license_key = ?",
            (key,),
        ).fetchone()

    if row is None:
        return jsonify({"ok": False, "error": "Unknown license key"}), 404

    if (row["email"] or "").lower() != email:
        return jsonify({"ok": False, "error": "Email does not match this license"}), 403

    return jsonify(
        {
            "ok": True,
            "license_key": row["license_key"],
            "license_payload": row["license_payload"],
            "email": row["email"],
            "plugins": PLUGINS,
            "product": PRODUCT,
        }
    )


@app.post("/api/verify")
def verify():
    """Startup check: confirm email+key still exist on the server."""
    data = request.get_json(silent=True) or {}
    key = normalize_license_key(data.get("license_key") or data.get("key") or "")
    email = (data.get("email") or "").strip().lower()
    if not key:
        return jsonify({"ok": False, "valid": False, "error": "Invalid license key format"}), 400
    if not EMAIL_RE.match(email):
        return jsonify({"ok": False, "valid": False, "error": "Valid email is required"}), 400

    with db() as conn:
        row = conn.execute(
            "SELECT license_key, email FROM users WHERE license_key = ? AND lower(email) = ?",
            (key, email),
        ).fetchone()

    if row is None:
        return jsonify({"ok": False, "valid": False, "error": "License not found"}), 404

    return jsonify(
        {
            "ok": True,
            "valid": True,
            "license_key": row["license_key"],
            "email": row["email"],
            "plugins": PLUGINS,
            "product": PRODUCT,
        }
    )


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not email or not password:
        return jsonify({"ok": False, "error": "Email and password required"}), 400

    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not row or not verify_password(password, row["password_hash"]):
        return jsonify({"ok": False, "error": "Invalid email or password"}), 401

    session["user_email"] = email
    return jsonify(
        {
            "ok": True,
            "user": {
                "email": row["email"],
                "first_name": row["first_name"],
                "last_name": row["last_name"],
                "company": row["company"],
                "country": row["country"],
                "license_key": row["license_key"],
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
    email = session.get("user_email")
    if not email:
        return jsonify({"ok": False, "error": "Not logged in"}), 401
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not row:
        session.clear()
        return jsonify({"ok": False, "error": "Not logged in"}), 401
    return jsonify(
        {
            "ok": True,
            "user": {
                "email": row["email"],
                "first_name": row["first_name"],
                "last_name": row["last_name"],
                "company": row["company"],
                "country": row["country"],
                "license_key": row["license_key"],
                "plugins": PLUGINS,
                "created_at": row["created_at"],
            },
        }
    )


@app.get("/<path:path>")
def static_proxy(path: str):
    return send_from_directory(ROOT, path)


def main() -> None:
    init_db()
    ensure_signing_keys()
    port = int(os.environ.get("PORT", "8787"))
    print(f"EASYBUNDLE server → http://127.0.0.1:{port}")
    print(f"Signing keys     → {KEY_DIR}")
    app.run(host="127.0.0.1", port=port, debug=True)


if __name__ == "__main__":
    main()
