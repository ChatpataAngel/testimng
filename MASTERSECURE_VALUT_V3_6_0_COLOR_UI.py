#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""POPPY SECURE VAULT V3.5.5 — STARTUP + DEPENDENCY HARDENING"""
from __future__ import annotations
import ast, base64, datetime as dt, hashlib, hmac, html, io, json, logging, os, platform, re, secrets, shutil, sqlite3, stat, subprocess, sys, tarfile, threading, time, tokenize, urllib.request, uuid, zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Sequence, Tuple
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import metadata as importlib_metadata

try:
    from flask import Flask, request as flask_request, jsonify as flask_jsonify
    _FLASK_OK = True
except ImportError:
    Flask = None; flask_request = flask_jsonify = None; _FLASK_OK = False


def _load_env_file(path: Optional[Path] = None) -> None:
    if path is None:
        configured = os.getenv("POPPY_ENV_FILE", "").strip()
        path = Path(configured).expanduser() if configured else Path(__file__).resolve().with_name(".env")
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line: continue
            key, value = line.split("=", 1)
            key, value = key.strip(), value.strip().strip('"').strip("'")
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
                os.environ.setdefault(key, value)
    except FileNotFoundError:
        pass

_load_env_file()


CONFIG = {
    # Telegram
    "BOT_TOKEN": "",
    "OWNER_ID": "",
    "ADMIN_IDS": "",

    # Required security secrets
    "LICENSE_PEPPER": "",
    "PRIVATE_KEY_ENCRYPTION_KEY": "",
    "PRIVATE_KEY_ENCRYPTION_KEY_OLD": "",

    # Optional licensing / access
    "ACCESS_MODE": "authorized",
    "LICENSE_WRAPPER_URL": "",
    "POPPY_LICENSE_KEY": "",
    "LICENSE_SERVER_PORT": "8787",
    "LICENSE_SERVER_ENABLED": "1",
    "LICENSE_ADMIN_SECRET": "",

    # Optional Cloudflare Tunnel
    "CLOUDFLARED_TUNNEL_TOKEN": "",
    "CLOUDFLARED_PATH": "",
    "CLOUDFLARED_LOG": "cloudflared.log",
    "CLOUDFLARED_AUTO_START": "1",

    # Database and processing limits
    "DATABASE_PATH": "poppy_master_secure_vault.sqlite3",
    "MAX_DOWNLOAD_MB": "15",
    "MAX_PY_MB": "8",
    "MAX_ZIP_ENTRIES": "400",
    "MAX_ZIP_UNPACKED_MB": "60",
    "MAX_ZIP_RATIO": "250",
    "VAULT_MAX_FILE_MB": "20",
    "VAULT_MAX_PER_USER": "50",
    "JOB_TTL_SECONDS": "900",
    "MAX_CONCURRENT_JOBS_PER_USER": "2",
    "RATE_LIMIT_COUNT": "5",
    "RATE_LIMIT_SECONDS": "60",

    # Health / logging / workers
    "HEALTH_ENABLED": "1",
    "HEALTH_HOST": "127.0.0.1",
    "HEALTH_PORT": "8788",
    "BOT_WORKER_THREADS": "4",
    "LOG_LEVEL": "INFO",
}


for _k, _v in CONFIG.items():
    if _v is not None and str(_v) != "":
        os.environ.setdefault(_k, str(_v))


def _in_virtualenv() -> bool:
    return sys.prefix != getattr(sys, "base_prefix", sys.prefix) or hasattr(sys, "real_prefix")


def _version_tuple(value: str) -> Tuple[int, ...]:
    nums = re.findall(r"\d+", value or "")
    return tuple(int(x) for x in nums[:4]) or (0,)


def _dependency_ok(module: str, distribution: str, minimum: str) -> bool:
    try:
        imported = __import__(module)
        # A same-named but unrelated module must not pass the dependency check.
        if module == "telebot" and not hasattr(imported, "TeleBot"):
            return False
        if module == "flask" and not hasattr(imported, "Flask"):
            return False
        installed = importlib_metadata.version(distribution)
        return _version_tuple(installed) >= _version_tuple(minimum)
    except (ImportError, importlib_metadata.PackageNotFoundError, ValueError):
        return False


def _bootstrap_packages() -> None:
    # Module name, PyPI distribution name, minimum supported version.
    required = (
        ("cryptography", "cryptography", "41"),
        ("telebot", "pyTelegramBotAPI", "4.37.1"),
        ("flask", "Flask", "2.0"),
    )
    missing = [f"{dist}>={minimum}" for mod, dist, minimum in required
               if not _dependency_ok(mod, dist, minimum)]
    if not missing:
        return

    pip = [sys.executable, "-m", "pip"]
    probe = subprocess.run(pip + ["--version"], capture_output=True, text=True, timeout=30)
    if probe.returncode:
        boot = subprocess.run([sys.executable, "-m", "ensurepip", "--upgrade"],
                              capture_output=True, text=True, timeout=300)
        probe = subprocess.run(pip + ["--version"], capture_output=True, text=True, timeout=30)
        if probe.returncode:
            raise SystemExit("pip is unavailable; install/repair pip for this Python interpreter. "
                             + (boot.stderr or boot.stdout or "").strip()[-500:])

    base = pip + ["install", "--upgrade", "--disable-pip-version-check", "--no-input"]
    attempts = [base + missing]
    if not _in_virtualenv():
        attempts.append(base + ["--user"] + missing)
        if os.name != "nt":
            attempts.append(base + ["--break-system-packages"] + missing)

    last_error = ""
    for attempt in attempts:
        try:
            result = subprocess.run(attempt, capture_output=True, text=True, timeout=900)
        except subprocess.TimeoutExpired:
            last_error = "pip install timed out after 15 minutes"
            continue
        if result.returncode == 0:
            break
        last_error = (result.stderr or result.stdout or "pip install failed")[-1200:]

    failed = [f"{dist}>={minimum}" for mod, dist, minimum in required
              if not _dependency_ok(mod, dist, minimum)]
    # Flask is optional for the Telegram vault functions; it only disables the
    # embedded license HTTP server. Core crypto + Telegram packages are mandatory.
    core_failed = [x for x in failed if not x.lower().startswith("flask")]
    if core_failed:
        raise SystemExit("Could not install required dependencies: " + ", ".join(core_failed)
                         + ("\n" + last_error if last_error else ""))
    if failed:
        logging.getLogger("poppy-vault").warning("Flask is unavailable/outdated; embedded license server is disabled. %s", last_error)


def _try_import(mod: str) -> bool:
    try:
        __import__(mod); return True
    except ImportError:
        return False

_bootstrap_packages()

# Flask may have been installed by the bootstrap after the first import attempt.
try:
    from flask import Flask, request as flask_request, jsonify as flask_jsonify
    _FLASK_OK = True
except ImportError:
    Flask = None; flask_request = flask_jsonify = None; _FLASK_OK = False

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

APP_NAME = "POPPY SECURE VAULT"
APP_VERSION = "3.6.0"
UTC = dt.timezone.utc
DB_PATH = Path(os.getenv("DATABASE_PATH", "poppy_secure_vault.sqlite3")).expanduser()
MAX_DOWNLOAD_BYTES = int(os.getenv("MAX_DOWNLOAD_MB", "15")) * 1024 * 1024
MAX_PY_BYTES = int(os.getenv("MAX_PY_MB", "8")) * 1024 * 1024
MAX_ZIP_ENTRIES = int(os.getenv("MAX_ZIP_ENTRIES", "400"))
MAX_ZIP_UNPACKED = int(os.getenv("MAX_ZIP_UNPACKED_MB", "60")) * 1024 * 1024
MAX_ZIP_RATIO = int(os.getenv("MAX_ZIP_RATIO", "250"))
JOB_TTL_SECONDS = int(os.getenv("JOB_TTL_SECONDS", "900"))
MAX_CONCURRENT_JOBS_PER_USER = int(os.getenv("MAX_CONCURRENT_JOBS_PER_USER", "2"))
RATE_LIMIT_COUNT = int(os.getenv("RATE_LIMIT_COUNT", "5"))
RATE_LIMIT_SECONDS = int(os.getenv("RATE_LIMIT_SECONDS", "60"))
HEALTH_HOST = os.getenv("HEALTH_HOST", "127.0.0.1")
HEALTH_PORT = int(os.getenv("HEALTH_PORT", "8788"))
LICENSE_SERVER_PORT = int(os.getenv("LICENSE_SERVER_PORT", "8787"))
VAULT_MAX_FILE_BYTES = int(os.getenv("VAULT_MAX_FILE_MB", "20")) * 1024 * 1024
VAULT_MAX_PER_USER = int(os.getenv("VAULT_MAX_PER_USER", "50"))

VAULT_MAGIC = b"POPPYVAULT01"
VAULT_FILE_ID_LEN = 16
VAULT_NONCE_LEN = 12
VAULT_MAX_ATTEMPTS = 5
VAULT_ATTEMPT_WINDOW = 600
VAULT_PENDING_TTL = 600
VAULT_KEY_INPUT_TTL = 300
_SEP = "▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬"

RANK_DEFAULTS = [
    ("Member", 0, 20, 8 * 1024 * 1024, 1), ("Bronze", 10, 40, 12 * 1024 * 1024, 1),
    ("Silver", 30, 80, 16 * 1024 * 1024, 1), ("Gold", 75, 150, 20 * 1024 * 1024, 1),
    ("Diamond", 150, 300, 25 * 1024 * 1024, 1), ("Elite", 300, 500, 30 * 1024 * 1024, 1),
]
ROLE_PERMISSIONS = {
    "Owner": {"*"},
    "Super Admin": {"*", "!manage_admins"},
    "Admin": {"view_admin", "manage_users", "manage_access", "manage_rewards", "manage_ranks",
              "manage_archive", "manage_licenses", "view_monitoring", "export_reports",
              "use_sealed_mode", "manage_vault"},
    "Moderator": {"view_admin", "manage_users", "view_monitoring"},
}
MODULE_TO_PACKAGE = {
    "PIL": "Pillow", "cv2": "opencv-python", "yaml": "PyYAML", "bs4": "beautifulsoup4",
    "Crypto": "pycryptodome", "sklearn": "scikit-learn", "dotenv": "python-dotenv",
    "discord": "discord.py", "numpy": "numpy", "pandas": "pandas", "requests": "requests",
    "aiohttp": "aiohttp", "motor": "motor", "pymongo": "pymongo", "yt_dlp": "yt-dlp",
    "pytube": "pytube", "pydub": "pydub", "flask": "Flask", "django": "Django",
    "httpx": "httpx", "uvicorn": "uvicorn", "fastapi": "fastapi", "openai": "openai",
    "anthropic": "anthropic", "telebot": "pyTelegramBotAPI", "telegram": "python-telegram-bot",
}
ALL_MODES = {"portable", "balanced", "fortress", "vault", "sealed", "licensed"}
EMOJI_MODE = {"portable": "📦", "balanced": "⚖️", "fortress": "🛡️", "vault": "🔒", "sealed": "🔐", "licensed": "🎫"}

logging.basicConfig(level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("poppy-vault")


# ───── UI HELPERS ─────
DEV_FOOTER = "💗 Made with love by @drangeljangra (Dev) & @Priyanshuuuuu111 (Co-Dev)"

def _brand_text(value: Any) -> Any:
    if not isinstance(value, str) or DEV_FOOTER in value:
        return value
    return value.rstrip() + "\n\n" + DEV_FOOTER

def _button(types_module, text: str, **kwargs):
    """Create Telegram-native blue/green/red buttons (Bot API style field)."""
    callback = str(kwargs.get("callback_data", "")).lower()
    destructive = any(x in callback for x in ("revoke", "delete", "ban", "deny", "remove"))
    positive = any(x in callback for x in ("confirm", "setkey", "approve", "restore", "unban"))
    style = "danger" if destructive else ("success" if positive else "primary")
    try:
        return types_module.InlineKeyboardButton(text, style=style, **kwargs)
    except TypeError:
        return types_module.InlineKeyboardButton(text, **kwargs)

def _panel(title: str, body: str, footer: str = "", emoji: str = "") -> str:
    parts = [f"<b>{_SEP}</b>", f"<b>  {emoji} {title}</b>" if emoji else f"<b>  {title}</b>", f"<b>{_SEP}</b>", "", body]
    if footer: parts += ["", f"<i>{footer}</i>"]
    parts += ["", DEV_FOOTER]
    return "\n".join(parts)

def _kv(key: str, value: str) -> str: return f"<code>{key:<12}</code>  {value}"
def _b(text: str) -> str: return f"  ›  {text}"
def _marker(a: bool) -> str: return "●" if a else "○"
def _html(v: Any) -> str: return html.escape(str(v or ""), quote=False)


# ───── CORE ─────
def utc_ts() -> int: return int(time.time())
def utc_day(ts: Optional[int] = None) -> str: return dt.datetime.fromtimestamp(ts or utc_ts(), UTC).date().isoformat()
def month_key(ts: Optional[int] = None) -> str: return dt.datetime.fromtimestamp(ts or utc_ts(), UTC).strftime("%Y-%m")

def safe_filename(name: str, default: str = "file.bin") -> str:
    name = (name or default).replace("\\", "/").split("/")[-1]
    name = re.sub(r"[^A-Za-z0-9._() -]", "_", name).strip(" .")
    return (name or default)[:120]

def _env_bytes(name: str, minimum: int = 32) -> bytes:
    v = os.getenv(name, "").strip()
    if len(v.encode("utf-8")) < minimum: raise RuntimeError(f"{name} must be ≥{minimum} bytes.")
    return v.encode("utf-8")

def license_hash(key: str) -> str:
    return hmac.new(_env_bytes("LICENSE_PEPPER", 32), key.strip().encode("utf-8"), hashlib.sha256).hexdigest()

def private_key_cipher() -> Fernet:
    key = os.getenv("PRIVATE_KEY_ENCRYPTION_KEY", "").strip()
    if not key: raise RuntimeError("PRIVATE_KEY_ENCRYPTION_KEY not configured.")
    try: return Fernet(key.encode("ascii"))
    except Exception as exc: raise RuntimeError("Invalid Fernet key.") from exc

def as_bool(v: Optional[str]) -> bool: return str(v or "").strip().lower() in {"1", "true", "yes", "on"}


# ───── DATABASE ─────
@contextmanager
def db_conn(immediate: bool = False):
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
    try:
        yield conn; conn.commit()
    except Exception:
        conn.rollback(); raise
    finally:
        conn.close()


def init_db(owner_id: Optional[int] = None, admin_ids: Sequence[int] = ()) -> None:
    with db_conn(immediate=True) as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS users(user_id INTEGER PRIMARY KEY, username TEXT NOT NULL DEFAULT '',
            first_seen INTEGER NOT NULL, allowed INTEGER NOT NULL DEFAULT 0, banned INTEGER NOT NULL DEFAULT 0,
            suspended INTEGER NOT NULL DEFAULT 0, mode TEXT NOT NULL DEFAULT 'portable',
            credits INTEGER NOT NULL DEFAULT 0, reserved_credits INTEGER NOT NULL DEFAULT 0,
            lifetime_jobs INTEGER NOT NULL DEFAULT 0, streak INTEGER NOT NULL DEFAULT 0,
            last_daily TEXT, daily_cooldown_until INTEGER NOT NULL DEFAULT 0, rank_override TEXT,
            created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS admin_roles(user_id INTEGER PRIMARY KEY,
            role TEXT NOT NULL CHECK(role IN ('Owner','Super Admin','Admin','Moderator')),
            added_by INTEGER NOT NULL, added_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS config(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS credit_ledger(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            delta INTEGER NOT NULL, balance_after INTEGER NOT NULL, reason TEXT NOT NULL, ref_id TEXT,
            created_at INTEGER NOT NULL, FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS captcha_challenges(code TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
            answer_digest TEXT NOT NULL, expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
            consumed INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS daily_claims(user_id INTEGER NOT NULL, claim_date TEXT NOT NULL,
            amount INTEGER NOT NULL, streak INTEGER NOT NULL, created_at INTEGER NOT NULL,
            PRIMARY KEY(user_id, claim_date), FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS rank_config(rank_name TEXT PRIMARY KEY, threshold INTEGER NOT NULL,
            monthly_limit INTEGER NOT NULL, max_file_bytes INTEGER NOT NULL, processing_enabled INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS usage_monthly(user_id INTEGER NOT NULL, month TEXT NOT NULL,
            reserved_jobs INTEGER NOT NULL DEFAULT 0, completed_jobs INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(user_id, month), FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS licenses(key_hash TEXT PRIMARY KEY, key_last4 TEXT NOT NULL, plan TEXT NOT NULL,
            created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL DEFAULT 0, max_uses INTEGER NOT NULL,
            uses INTEGER NOT NULL DEFAULT 0, reserved_uses INTEGER NOT NULL DEFAULT 0,
            revoked INTEGER NOT NULL DEFAULT 0, bound_user_id INTEGER, metadata TEXT NOT NULL DEFAULT '{}',
            machines TEXT NOT NULL DEFAULT '[]', FOREIGN KEY(bound_user_id) REFERENCES users(user_id) ON DELETE SET NULL);
        CREATE TABLE IF NOT EXISTS jobs(job_id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, license_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, status TEXT NOT NULL,
            private_key_ciphertext BLOB, public_key_pem BLOB NOT NULL, original_filename TEXT,
            reserved_credits INTEGER NOT NULL DEFAULT 1, month TEXT NOT NULL, encrypted_sha256 TEXT,
            output_sha256 TEXT, completed_at INTEGER, refund_applied INTEGER NOT NULL DEFAULT 0,
            error_reason TEXT, max_output_bytes INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE,
            FOREIGN KEY(license_hash) REFERENCES licenses(key_hash));
        CREATE TABLE IF NOT EXISTS work_reservations(reservation_id TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
            credits INTEGER NOT NULL, month TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
            created_at INTEGER NOT NULL, completed_at INTEGER, refund_applied INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS audit_events(id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER,
            action TEXT NOT NULL, target_id INTEGER, details TEXT NOT NULL DEFAULT '{}',
            created_at INTEGER NOT NULL,
            FOREIGN KEY(actor_id) REFERENCES users(user_id) ON DELETE SET NULL,
            FOREIGN KEY(target_id) REFERENCES users(user_id) ON DELETE SET NULL);
        CREATE TABLE IF NOT EXISTS support_tickets(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            message TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', created_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS rate_limits(bucket TEXT PRIMARY KEY, hits INTEGER NOT NULL,
            window_start INTEGER NOT NULL, cooldown_until INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS vault_files(file_id TEXT PRIMARY KEY, owner_user_id INTEGER NOT NULL,
            original_filename TEXT NOT NULL, file_sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL,
            file_key_ciphertext BLOB NOT NULL, license_key_hash TEXT, license_key_last4 TEXT,
            created_at INTEGER NOT NULL, license_set_at INTEGER, revoked INTEGER NOT NULL DEFAULT 0,
            downloads INTEGER NOT NULL DEFAULT 0, last_download_at INTEGER,
            FOREIGN KEY(owner_user_id) REFERENCES users(user_id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS vault_attempts(id INTEGER PRIMARY KEY AUTOINCREMENT, file_id TEXT NOT NULL,
            user_id INTEGER NOT NULL, success INTEGER NOT NULL, created_at INTEGER NOT NULL);
        """)
        user_cols = {row[1] for row in c.execute("PRAGMA table_info(users)").fetchall()}
        for col, defn in {"suspended": "INTEGER NOT NULL DEFAULT 0", "credits": "INTEGER NOT NULL DEFAULT 0",
                          "reserved_credits": "INTEGER NOT NULL DEFAULT 0", "lifetime_jobs": "INTEGER NOT NULL DEFAULT 0",
                          "streak": "INTEGER NOT NULL DEFAULT 0", "last_daily": "TEXT",
                          "daily_cooldown_until": "INTEGER NOT NULL DEFAULT 0", "rank_override": "TEXT",
                          "created_at": "INTEGER NOT NULL DEFAULT 0"}.items():
            if col not in user_cols:
                c.execute(f"ALTER TABLE users ADD COLUMN {col} {defn}")
        job_cols = {row[1] for row in c.execute("PRAGMA table_info(jobs)").fetchall()}
        if "max_output_bytes" not in job_cols:
            c.execute("ALTER TABLE jobs ADD COLUMN max_output_bytes INTEGER NOT NULL DEFAULT 0")
        lic_cols = {row[1] for row in c.execute("PRAGMA table_info(licenses)").fetchall()}
        if "machines" not in lic_cols:
            c.execute("ALTER TABLE licenses ADD COLUMN machines TEXT NOT NULL DEFAULT '[]'")
        c.execute("UPDATE users SET created_at=first_seen WHERE created_at=0")
        for v in (1, 2, 3, 4, 5):
            c.execute("INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(?,?)", (v, utc_ts()))
        for name, threshold, limit, max_size, enabled in RANK_DEFAULTS:
            c.execute("INSERT OR IGNORE INTO rank_config VALUES(?,?,?,?,?)", (name, threshold, limit, max_size, enabled))
        defaults = {"access_mode": os.getenv("ACCESS_MODE", "authorized").strip().lower(),
                    "registration_enabled": "0", "maintenance_mode": "0", "daily_reward": "5",
                    "wallet_cap": "500", "credit_cost": "1", "challenge_ttl": "300",
                    "streak_rewards": json.dumps({"3": 2, "7": 5, "14": 10, "30": 25}),
                    "milestone_rewards": json.dumps({"3": 5, "7": 15, "14": 35, "30": 100}),
                    "archive_group_id": "", "archive_enabled": "0", "archive_original": "0",
                    "archive_protected": "1", "archive_reports": "1", "archive_metadata": "1",
                    "license_tunnel_url": "", "license_tunnel_token": "", "license_admin_secret": "",
                    "cloudflared_token_ciphertext": ""}
        for k, v in defaults.items():
            c.execute("INSERT OR IGNORE INTO config(key,value) VALUES(?,?)", (k, v))
        if defaults["access_mode"] not in {"authorized", "public"}:
            c.execute("UPDATE config SET value='authorized' WHERE key='access_mode'")
        if owner_id:
            c.execute("INSERT OR IGNORE INTO users(user_id,first_seen,allowed,created_at) VALUES(?,?,1,?)",
                      (owner_id, utc_ts(), utc_ts()))
            c.execute("INSERT INTO admin_roles(user_id,role,added_by,added_at) VALUES(?, 'Owner', ?, ?) "
                      "ON CONFLICT(user_id) DO UPDATE SET role='Owner'", (owner_id, owner_id, utc_ts()))
        for uid in admin_ids:
            if owner_id and uid == owner_id: continue
            c.execute("INSERT OR IGNORE INTO users(user_id,first_seen,allowed,created_at) VALUES(?,?,1,?)",
                      (uid, utc_ts(), utc_ts()))
            c.execute("INSERT OR IGNORE INTO admin_roles(user_id,role,added_by,added_at) VALUES(?, 'Admin', ?, ?)",
                      (uid, owner_id or uid, utc_ts()))


def setting(key: str, default: Optional[str] = None) -> Optional[str]:
    with db_conn() as c:
        row = c.execute("SELECT value FROM config WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default

def set_setting(key: str, value: Any) -> None:
    with db_conn(immediate=True) as c:
        c.execute("INSERT INTO config(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                  (key, str(value)))


def migrate_private_ciphertexts() -> int:
    old_raw = os.getenv("PRIVATE_KEY_ENCRYPTION_KEY_OLD", "").strip()
    if not old_raw: return 0
    marker = "private_cipher_rekey_v1"
    if setting(marker, "") == "done": return 0
    new_cipher = private_key_cipher()
    try: old_cipher = Fernet(old_raw.encode("ascii"))
    except Exception as exc: raise RuntimeError("PRIVATE_KEY_ENCRYPTION_KEY_OLD is invalid.") from exc
    if hmac.compare_digest(old_raw, os.getenv("PRIVATE_KEY_ENCRYPTION_KEY", "").strip()):
        set_setting(marker, "done"); return 0
    with db_conn(immediate=True) as conn:
        rows = conn.execute("SELECT job_id,private_key_ciphertext FROM jobs WHERE private_key_ciphertext IS NOT NULL").fetchall()
        updates = []
        for row in rows:
            plain = old_cipher.decrypt(bytes(row["private_key_ciphertext"]))
            updates.append((new_cipher.encrypt(plain), row["job_id"]))
        tok_row = conn.execute("SELECT value FROM config WHERE key='cloudflared_token_ciphertext'").fetchone()
        tok_update = None
        if tok_row and tok_row["value"]:
            old_ct = base64.b64decode(tok_row["value"], validate=True)
            tok_update = base64.b64encode(new_cipher.encrypt(old_cipher.decrypt(old_ct))).decode("ascii")
        for ct, jid in updates:
            conn.execute("UPDATE jobs SET private_key_ciphertext=? WHERE job_id=?", (ct, jid))
        if tok_update:
            conn.execute("UPDATE config SET value=? WHERE key='cloudflared_token_ciphertext'", (tok_update,))
        conn.execute("INSERT INTO config(key,value) VALUES(?, 'done') ON CONFLICT(key) DO UPDATE SET value='done'", (marker,))
    return len(updates) + (1 if tok_update else 0)


def touch_user(user_id: int, username: str = "") -> None:
    with db_conn(immediate=True) as c:
        c.execute("INSERT INTO users(user_id,username,first_seen,created_at) VALUES(?,?,?,?) "
                  "ON CONFLICT(user_id) DO UPDATE SET username=excluded.username",
                  (user_id, username or "", utc_ts(), utc_ts()))

def user_record(user_id: int) -> Optional[sqlite3.Row]:
    with db_conn() as c: return c.execute("SELECT * FROM users WHERE user_id=?", (user_id,)).fetchone()

def admin_role(user_id: int) -> Optional[str]:
    with db_conn() as c:
        row = c.execute("SELECT role FROM admin_roles WHERE user_id=?", (user_id,)).fetchone()
    return row["role"] if row else None

def is_owner(user_id: int, owner_id: Optional[int] = None) -> bool:
    cid = owner_id if owner_id is not None else int(os.getenv("OWNER_ID", "0") or 0)
    return bool(cid and user_id == cid) or admin_role(user_id) == "Owner"

def has_permission(user_id: int, permission: str) -> bool:
    role = admin_role(user_id)
    if not role: return False
    if role == "Owner": return True
    perms = ROLE_PERMISSIONS.get(role, set())
    return ("*" in perms and ("!" + permission) not in perms) or permission in perms

def user_allowed(user_id: int) -> bool:
    row = user_record(user_id)
    if not row or row["banned"] or row["suspended"]: return False
    if admin_role(user_id): return True
    if as_bool(setting("maintenance_mode", "0")): return False
    return bool(row["allowed"])

def audit(actor: Optional[int], action: str, target: Optional[int] = None, details: Optional[dict] = None) -> None:
    with db_conn(immediate=True) as c:
        c.execute("INSERT INTO audit_events(actor_id,action,target_id,details,created_at) VALUES(?,?,?,?,?)",
                  (actor, action, target, json.dumps(details or {}, ensure_ascii=True)[:4000], utc_ts()))


def rate_limit(bucket: str, limit: int = RATE_LIMIT_COUNT, window: int = RATE_LIMIT_SECONDS, cooldown: int = 0) -> bool:
    now = utc_ts()
    with db_conn(immediate=True) as c:
        row = c.execute("SELECT * FROM rate_limits WHERE bucket=?", (bucket,)).fetchone()
        if row and row["cooldown_until"] > now: return False
        if not row or now - row["window_start"] >= window:
            c.execute("INSERT INTO rate_limits(bucket,hits,window_start,cooldown_until) VALUES(?,?,?,0) "
                      "ON CONFLICT(bucket) DO UPDATE SET hits=1,window_start=excluded.window_start,cooldown_until=0",
                      (bucket, 1, now))
            return True
        hits = row["hits"] + 1
        until = now + cooldown if cooldown and hits > limit else 0
        c.execute("UPDATE rate_limits SET hits=?,cooldown_until=? WHERE bucket=?", (hits, until, bucket))
        return hits <= limit


def rank_for_user(user_id: int, conn: Optional[sqlite3.Connection] = None) -> dict:
    if conn is None:
        with db_conn() as local: return rank_for_user(user_id, local)
    user = conn.execute("SELECT lifetime_jobs,rank_override FROM users WHERE user_id=?", (user_id,)).fetchone()
    jobs = int(user["lifetime_jobs"]) if user else 0
    override = user["rank_override"] if user else None
    if override:
        row = conn.execute("SELECT * FROM rank_config WHERE rank_name=? COLLATE NOCASE", (override,)).fetchone()
        if row: return dict(row)
    row = conn.execute("SELECT * FROM rank_config WHERE threshold<=? ORDER BY threshold DESC LIMIT 1", (jobs,)).fetchone()
    return dict(row) if row else dict(conn.execute("SELECT * FROM rank_config ORDER BY threshold LIMIT 1").fetchone())

def usage_for(c: sqlite3.Connection, user_id: int, month: str) -> sqlite3.Row:
    c.execute("INSERT OR IGNORE INTO usage_monthly(user_id,month) VALUES(?,?)", (user_id, month))
    return c.execute("SELECT * FROM usage_monthly WHERE user_id=? AND month=?", (user_id, month)).fetchone()


# ───── LICENSES ─────
def create_license(days: int = 30, max_uses: int = 5, plan: str = "standard",
                   bind_user_id: Optional[int] = None) -> str:
    if days < 0 or days > 36500: raise ValueError("days must be 0 or 1..36500")
    if max_uses < 1 or max_uses > 100000: raise ValueError("max_uses must be 1..100000")
    if not re.fullmatch(r"[a-zA-Z0-9_-]{2,24}", plan): raise ValueError("Invalid plan.")
    if bind_user_id is not None: touch_user(bind_user_id)
    raw = "PV3-" + secrets.token_urlsafe(32)
    digest = license_hash(raw)
    now = utc_ts()
    expiry = now + days * 86400 if days else 0
    with db_conn(immediate=True) as c:
        c.execute("INSERT INTO licenses(key_hash,key_last4,plan,created_at,expires_at,max_uses,bound_user_id,machines) "
                  "VALUES(?,?,?,?,?,?,?,'[]')", (digest, raw[-4:], plan.lower(), now, expiry, max_uses, bind_user_id))
    return raw

def _license_state(row: sqlite3.Row, user_id: int, now: Optional[int] = None) -> Tuple[bool, str]:
    now = now or utc_ts()
    if row["revoked"]: return False, "revoked"
    if row["expires_at"] and row["expires_at"] < now: return False, "expired"
    if row["bound_user_id"] is not None and int(row["bound_user_id"]) != user_id: return False, "bound_to_another_account"
    if int(row["uses"]) >= int(row["max_uses"]): return False, "usage_limit_reached"
    return True, "ok"

def redeem_license(user_id: int, raw_key: str) -> Tuple[bool, str]:
    if len(raw_key.strip()) < 30: return False, "invalid_key"
    touch_user(user_id)
    digest = license_hash(raw_key)
    with db_conn(immediate=True) as c:
        row = c.execute("SELECT * FROM licenses WHERE key_hash=?", (digest,)).fetchone()
        if not row: return False, "unknown_key"
        ok, reason = _license_state(row, user_id)
        if not ok: return False, reason
        if row["bound_user_id"] is None:
            cur = c.execute("UPDATE licenses SET bound_user_id=? WHERE key_hash=? AND bound_user_id IS NULL", (user_id, digest))
            if cur.rowcount != 1: return False, "redemption_race_retry"
        elif row["bound_user_id"] != user_id:
            return False, "bound_to_another_account"
    audit(user_id, "license_redeemed", user_id, {"key_last4": raw_key[-4:]})
    return True, "redeemed"

def get_user_license(user_id: int) -> Optional[sqlite3.Row]:
    with db_conn() as c:
        rows = c.execute("SELECT * FROM licenses WHERE bound_user_id=? ORDER BY created_at DESC", (user_id,)).fetchall()
    for row in rows:
        ok, _ = _license_state(row, user_id)
        if ok and int(row["uses"]) + int(row["reserved_uses"]) < int(row["max_uses"]):
            return row
    return None

def revoke_license(raw_key: str) -> bool:
    digest = license_hash(raw_key)
    with db_conn(immediate=True) as c:
        cur = c.execute("UPDATE licenses SET revoked=1 WHERE key_hash=?", (digest,))
        return cur.rowcount == 1


# ───── CAPTCHA ─────
def create_captcha(user_id: int) -> Tuple[str, str]:
    a, b = secrets.randbelow(15) + 2, secrets.randbelow(15) + 2
    if secrets.randbelow(2): question, answer = f"{a} + {b}", a + b
    else:
        if a < b: a, b = b, a
        question, answer = f"{a} - {b}", a - b
    code = secrets.token_urlsafe(6).replace("-", "").replace("_", "")[:8].upper()
    expires = utc_ts() + int(setting("challenge_ttl", "300") or 300)
    salt = secrets.token_hex(16)
    digest = hashlib.sha256(f"{salt}:{answer}".encode()).hexdigest()
    with db_conn(immediate=True) as c:
        c.execute("UPDATE captcha_challenges SET consumed=1 WHERE user_id=? AND consumed=0", (user_id,))
        c.execute("INSERT INTO captcha_challenges(code,user_id,answer_digest,expires_at,created_at) VALUES(?,?,?,?,?)",
                  (code, user_id, salt + ":" + digest, expires, utc_ts()))
    return code, question


def answer_captcha(user_id: int, code: str, answer: str) -> Tuple[bool, str, int]:
    today = utc_day(); now = utc_ts()
    with db_conn(immediate=True) as c:
        user = c.execute("SELECT * FROM users WHERE user_id=?", (user_id,)).fetchone()
        if not user: return False, "user_not_found", 0
        if (setting("access_mode", "authorized") != "public" or not user["allowed"] or user["banned"]
                or user["suspended"] or as_bool(setting("maintenance_mode", "0"))):
            return False, "not_eligible", 0
        if user["daily_cooldown_until"] > now: return False, "cooldown", 0
        challenge = c.execute("SELECT * FROM captcha_challenges WHERE code=? AND user_id=?",
                              (code.upper(), user_id)).fetchone()
        if not challenge or challenge["consumed"]: return False, "invalid_challenge", 0
        if challenge["expires_at"] < now:
            c.execute("UPDATE captcha_challenges SET consumed=1 WHERE code=?", (code.upper(),))
            return False, "expired", 0
        salt, expected = challenge["answer_digest"].split(":", 1)
        actual = hashlib.sha256(f"{salt}:{answer.strip()}".encode()).hexdigest()
        if not hmac.compare_digest(actual, expected):
            attempts = int(challenge["attempts"]) + 1
            c.execute("UPDATE captcha_challenges SET attempts=?,consumed=? WHERE code=?",
                      (attempts, 1 if attempts >= 5 else 0, code.upper()))
            if attempts >= 5:
                c.execute("UPDATE users SET daily_cooldown_until=? WHERE user_id=?", (now + 600, user_id))
            return False, "wrong_answer", 0
        if c.execute("SELECT 1 FROM daily_claims WHERE user_id=? AND claim_date=?", (user_id, today)).fetchone():
            c.execute("UPDATE captcha_challenges SET consumed=1 WHERE code=?", (code.upper(),))
            return False, "already_claimed", 0
        previous = user["last_daily"]
        streak = 1
        if previous and previous != today:
            prev = dt.date.fromisoformat(previous); curr = dt.date.fromisoformat(today)
            streak = int(user["streak"]) + 1 if (curr - prev).days == 1 else 1
        base = int(setting("daily_reward", "5") or 5)
        streaks = json.loads(setting("streak_rewards", "{}") or "{}")
        milestones = json.loads(setting("milestone_rewards", "{}") or "{}")
        reward = base + int(streaks.get(str(streak), 0)) + int(milestones.get(str(streak), 0))
        cap = int(setting("wallet_cap", "500") or 500)
        available = max(0, cap - int(user["credits"]) - int(user["reserved_credits"]))
        credited = min(reward, available)
        new_balance = int(user["credits"]) + credited
        c.execute("UPDATE users SET credits=?,streak=?,last_daily=?,daily_cooldown_until=0 WHERE user_id=?",
                  (new_balance, streak, today, user_id))
        c.execute("INSERT INTO credit_ledger(user_id,delta,balance_after,reason,ref_id,created_at) VALUES(?,?,?,?,?,?)",
                  (user_id, credited, new_balance, "daily_reward", today, now))
        c.execute("INSERT INTO daily_claims(user_id,claim_date,amount,streak,created_at) VALUES(?,?,?,?,?)",
                  (user_id, today, credited, streak, now))
        c.execute("UPDATE captcha_challenges SET consumed=1 WHERE code=?", (code.upper(),))
    return True, "claimed", credited


# ───── PROCESSING RESERVATIONS ─────
def reserve_processing(user_id: int, credits_cost: int, file_size: int) -> str:
    rid = uuid.uuid4().hex
    month, now = month_key(), utc_ts()
    with db_conn(immediate=True) as c:
        user = c.execute("SELECT * FROM users WHERE user_id=?", (user_id,)).fetchone()
        role_row = c.execute("SELECT role FROM admin_roles WHERE user_id=?", (user_id,)).fetchone()
        if (not user or user["banned"] or user["suspended"]
                or (not role_row and (not user["allowed"] or as_bool(setting("maintenance_mode", "0"))))):
            raise ValueError("Account ineligible.")
        rank = rank_for_user(user_id, c)
        if not rank["processing_enabled"]: raise ValueError("Processing disabled.")
        if file_size > rank["max_file_bytes"]:
            raise ValueError(f"Exceeds {rank['rank_name']} limit ({rank['max_file_bytes']//(1024*1024)} MB).")
        usage = usage_for(c, user_id, month)
        if usage["reserved_jobs"] + usage["completed_jobs"] >= rank["monthly_limit"]:
            raise ValueError("Quota exhausted.")
        active = c.execute("SELECT COUNT(*) FROM jobs WHERE user_id=? AND status IN ('pending','processing')",
                           (user_id,)).fetchone()[0]
        active += c.execute("SELECT COUNT(*) FROM work_reservations WHERE user_id=? AND status='pending'",
                            (user_id,)).fetchone()[0]
        if active >= MAX_CONCURRENT_JOBS_PER_USER: raise ValueError("Max active jobs.")
        if user["credits"] < credits_cost: raise ValueError("Not enough credits.")
        c.execute("UPDATE users SET credits=credits-?,reserved_credits=reserved_credits+? WHERE user_id=?",
                  (credits_cost, credits_cost, user_id))
        c.execute("UPDATE usage_monthly SET reserved_jobs=reserved_jobs+1 WHERE user_id=? AND month=?", (user_id, month))
        c.execute("INSERT INTO work_reservations(reservation_id,user_id,credits,month,status,created_at) "
                  "VALUES(?,?,?,?,'pending',?)", (rid, user_id, credits_cost, month, now))
        c.execute("INSERT INTO credit_ledger(user_id,delta,balance_after,reason,ref_id,created_at) VALUES(?,?,?,?,?,?)",
                  (user_id, -credits_cost, int(user["credits"]) - credits_cost, "protection_job_reserved", rid, now))
    return rid


def finish_processing(rid: str, success: bool) -> bool:
    with db_conn(immediate=True) as c:
        row = c.execute("SELECT * FROM work_reservations WHERE reservation_id=?", (rid,)).fetchone()
        if not row or row["status"] != "pending": return False
        if success:
            c.execute("UPDATE users SET reserved_credits=MAX(0,reserved_credits-?),lifetime_jobs=lifetime_jobs+1 "
                      "WHERE user_id=?", (row["credits"], row["user_id"]))
            c.execute("UPDATE usage_monthly SET reserved_jobs=MAX(0,reserved_jobs-1),completed_jobs=completed_jobs+1 "
                      "WHERE user_id=? AND month=?", (row["user_id"], row["month"]))
            c.execute("UPDATE work_reservations SET status='completed',completed_at=? WHERE reservation_id=?",
                      (utc_ts(), rid))
        else:
            c.execute("UPDATE users SET credits=credits+?,reserved_credits=MAX(0,reserved_credits-?) WHERE user_id=?",
                      (row["credits"], row["credits"], row["user_id"]))
            c.execute("UPDATE usage_monthly SET reserved_jobs=MAX(0,reserved_jobs-1) WHERE user_id=? AND month=?",
                      (row["user_id"], row["month"]))
            user = c.execute("SELECT credits FROM users WHERE user_id=?", (row["user_id"],)).fetchone()
            c.execute("INSERT INTO credit_ledger(user_id,delta,balance_after,reason,ref_id,created_at) VALUES(?,?,?,?,?,?)",
                      (row["user_id"], row["credits"], user["credits"], "protection_job_refund", rid, utc_ts()))
            c.execute("UPDATE work_reservations SET status='failed',completed_at=?,refund_applied=1 WHERE reservation_id=?",
                      (utc_ts(), rid))
    return True


# ───── ANALYSIS + AST ─────
@dataclass
class Analysis:
    syntax_ok: bool
    imports: List[str]
    third_party: List[str]
    minimum_python: str
    warnings: List[str]
    errors: List[str]
    source_sha256: str
    credentials: List[str]
    environment_variables: List[str]
    environment_errors: List[str]


def _assignment_names(target: ast.AST) -> List[str]:
    if isinstance(target, ast.Name): return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        out = []
        for item in target.elts: out.extend(_assignment_names(item))
        return out
    return []

def _is_os_environ_expr(node: ast.AST, os_aliases: set, environ_aliases: set) -> bool:
    if isinstance(node, ast.Name): return isinstance(node.ctx, ast.Load) and node.id in environ_aliases
    return (isinstance(node, ast.Attribute) and node.attr == "environ"
            and isinstance(node.value, ast.Name) and node.value.id in os_aliases)

def decode_source(source: bytes) -> Tuple[str, str]:
    enc, _ = tokenize.detect_encoding(io.BytesIO(source).readline)
    return source.decode(enc), enc

def _minimum_python(text: str) -> str:
    for minor in range(10, sys.version_info.minor + 1):
        try:
            ast.parse(text, feature_version=(3, minor)); return f"3.{minor}+"
        except (SyntaxError, ValueError):
            continue
    return "Unknown"


def extract_environment_access(source: bytes) -> Tuple[bytes, List[str], bytes, List[str]]:
    text, _ = decode_source(source)
    tree = ast.parse(text)
    helper = "_poppy_master_env_" + secrets.token_hex(8)
    names: List[str] = []; errors: List[str] = []
    os_aliases = {"os"}; imported_getenv: set = set(); imported_environ: set = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "os": os_aliases.add(alias.asname or "os")
                elif alias.name.startswith("os.") and not alias.asname: os_aliases.add("os")
        elif isinstance(node, ast.ImportFrom) and node.module == "os":
            for alias in node.names:
                if alias.name == "*": errors.append("`from os import *` unsupported.")
                elif alias.name == "getenv": imported_getenv.add(alias.asname or alias.name)
                elif alias.name == "environ": imported_environ.add(alias.asname or alias.name)
    getenv_names = set(imported_getenv); environ_names = set(imported_environ)
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)): continue
            val = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            assigned = [n for t in targets for n in _assignment_names(t)]
            if not assigned or not isinstance(val, ast.Attribute) or not isinstance(val.value, ast.Name): continue
            if val.value.id in os_aliases and val.attr == "getenv":
                b = len(getenv_names); getenv_names.update(assigned); changed |= len(getenv_names) != b
            elif val.value.id in os_aliases and val.attr == "environ":
                b = len(environ_names); environ_names.update(assigned); changed |= len(environ_names) != b
            elif isinstance(val, ast.Name) and val.id in getenv_names:
                b = len(getenv_names); getenv_names.update(assigned); changed |= len(getenv_names) != b
            elif isinstance(val, ast.Name) and val.id in environ_names:
                b = len(environ_names); environ_names.update(assigned); changed |= len(environ_names) != b
    reassigned: set = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets: reassigned.update(_assignment_names(t))
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            reassigned.update(_assignment_names(node.target))
    dynamic_seen = False
    for node in ast.walk(tree):
        key_node = None
        if isinstance(node, ast.Subscript) and _is_os_environ_expr(node.value, os_aliases, environ_names):
            key_node = node.slice
        elif isinstance(node, ast.Call):
            is_env = ((isinstance(node.func, ast.Name) and node.func.id in getenv_names)
                      or (isinstance(node.func, ast.Attribute) and node.func.attr == "getenv"
                          and isinstance(node.func.value, ast.Name) and node.func.value.id in os_aliases))
            is_map = (isinstance(node.func, ast.Attribute) and node.func.attr == "get"
                      and _is_os_environ_expr(node.func.value, os_aliases, environ_names))
            if is_env or is_map:
                key_node = node.args[0] if node.args else next(
                    (kw.value for kw in node.keywords if kw.arg in {"key", None}), None)
        if key_node is not None:
            if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str) and key_node.value:
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key_node.value) and key_node.value not in names:
                    names.append(key_node.value)
            else: dynamic_seen = True

    class EnvRewriter(ast.NodeTransformer):
        def visit_Attribute(self, node: ast.Attribute) -> ast.AST:
            node = self.generic_visit(node)
            if not isinstance(node.ctx, ast.Load): return node
            if isinstance(node.value, ast.Name) and node.value.id in os_aliases:
                if node.attr == "environ":
                    return ast.copy_location(ast.Attribute(ast.Name(helper, ast.Load()), "environ", ast.Load()), node)
                if node.attr == "getenv":
                    return ast.copy_location(ast.Attribute(ast.Name(helper, ast.Load()), "getenv", ast.Load()), node)
            return node
        def visit_Name(self, node: ast.Name) -> ast.AST:
            if isinstance(node.ctx, ast.Load) and node.id not in reassigned:
                if node.id in imported_getenv:
                    return ast.copy_location(ast.Attribute(ast.Name(helper, ast.Load()), "getenv", ast.Load()), node)
                if node.id in imported_environ:
                    return ast.copy_location(ast.Attribute(ast.Name(helper, ast.Load()), "environ", ast.Load()), node)
            return node
        def visit_ImportFrom(self, node: ast.ImportFrom) -> Optional[ast.AST]:
            if node.module != "os": return node
            replacements, kept = [], []
            for alias in node.names:
                if alias.name in {"getenv", "environ"}:
                    local = alias.asname or alias.name
                    attr = "getenv" if alias.name == "getenv" else "environ"
                    replacements.append(ast.Assign(targets=[ast.Name(local, ast.Store())],
                        value=ast.Attribute(ast.Name(helper, ast.Load()), attr, ast.Load())))
                else: kept.append(alias)
            if kept:
                node.names = kept
                return [node, *[ast.copy_location(x, node) for x in replacements]]
            return [ast.copy_location(x, node) for x in replacements] or None

    transformed = EnvRewriter().visit(tree)
    ast.fix_missing_locations(transformed)
    transformed_src = (ast.unparse(transformed) + "\n").encode("utf-8")
    os_name = "_poppy_env_os_" + secrets.token_hex(5)
    cls_name = "_PoppyEnvProxy_" + secrets.token_hex(5)
    manifest = tuple(names) + (("<dynamic environment key>",) if dynamic_seen else ())
    preamble = (f"# === POPPY MASTER ENV ===\nimport os as {os_name}\nclass {cls_name}:\n"
                f"    NAMES = {manifest!r}\n    @property\n    def environ(self):\n        return {os_name}.environ\n"
                f"    def getenv(self, key, default=None):\n        return {os_name}.getenv(key, default)\n"
                f"{helper} = {cls_name}()\n# === END POPPY MASTER ENV ===\n\n").encode("utf-8")
    return transformed_src, sorted(names), preamble, errors


def _prepend_preamble_respecting_future_imports(user_source: bytes, preamble: bytes) -> bytes:
    try: tree = ast.parse(user_source.decode("utf-8"))
    except SyntaxError: return preamble + user_source
    body = list(tree.body); prefix_count = 0
    if (body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)): prefix_count = 1
    while (prefix_count < len(body) and isinstance(body[prefix_count], ast.ImportFrom)
           and body[prefix_count].module == "__future__"): prefix_count += 1
    if prefix_count == 0: return preamble + user_source
    prefix = "\n".join(ast.unparse(s) for s in body[:prefix_count]) + "\n"
    suffix = "\n".join(ast.unparse(s) for s in body[prefix_count:]) + "\n"
    return (prefix + preamble.decode("utf-8") + suffix).encode("utf-8")


_SCRUB_PATTERNS = [
    (re.compile(rb"\b\d{7,12}:[A-Za-z0-9_-]{30,}\b"), b"XXXXXXX", "Telegram bot token"),
    (re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{25,}\b"), b"XXXXXXX", "Git hosting token"),
    (re.compile(rb"\bAKIA[0-9A-Z]{16}\b"), b"XXXXXXX", "AWS access key"),
    (re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b"), b"XXXXXXX", "API secret"),
    (re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     b"XXXXXXX", "Private key"),
]

def scrub_source_secrets(source: bytes) -> Tuple[bytes, Dict[str, int]]:
    out = source; found: Dict[str, int] = {}
    for pat, repl, label in _SCRUB_PATTERNS:
        m = pat.findall(out)
        if m: found[label] = len(m); out = pat.sub(repl, out)
    return out, found


def _analyze_source_impl(source: bytes, filename: str = "uploaded.py") -> Tuple["Analysis", Optional[bytes]]:
    imports, warnings, third_party, credentials = set(), [], set(), []
    try:
        text, _ = decode_source(source); ast.parse(text, filename=filename)
    except Exception as exc:
        return Analysis(False, [], [], "Unknown", [], [str(exc)], hashlib.sha256(source).hexdigest(), [], [], []), None
    stdlib = set(getattr(sys, "stdlib_module_names", set()))
    tree = ast.parse(text, filename=filename)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names: imports.add(alias.name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level: warnings.append("Relative import — protect the whole ZIP.")
            elif node.module: imports.add(node.module.split(".", 1)[0])
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
            warnings.append(f"Dynamic {node.func.id}() detected.")
    for name in imports:
        if name not in stdlib and name not in sys.builtin_module_names and name != "__future__":
            third_party.add(MODULE_TO_PACKAGE.get(name, name))
    raw = source.decode("utf-8", errors="ignore")
    for pat, lbl in [(r"\b\d{7,12}:[A-Za-z0-9_-]{30,}\b", "Telegram token"),
                     (r"\bgh[pousr]_[A-Za-z0-9]{25,}\b", "Git hosting token"),
                     (r"\bAKIA[0-9A-Z]{16}\b", "AWS key"),
                     (r"\bsk-[A-Za-z0-9_-]{20,}\b", "API secret"),
                     (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private key")]:
        if re.search(pat, raw): credentials.append(lbl)
    try:
        transformed, env_vars, preamble, env_errors = extract_environment_access(source)
        payload = _prepend_preamble_respecting_future_imports(transformed, preamble)
    except Exception as exc:
        return Analysis(True, sorted(imports), sorted(third_party), _minimum_python(text),
                        sorted(set(warnings)) + [f"Env failed: {exc}"], [],
                        hashlib.sha256(source).hexdigest(), sorted(set(credentials)), [], [str(exc)]), None
    if env_vars: warnings.append("Master ENV vars: " + ", ".join(env_vars))
    if env_errors: warnings.append("Some env access not centralized.")
    if credentials: warnings.append("Potential credentials detected.")
    analysis = Analysis(True, sorted(imports), sorted(third_party), _minimum_python(text),
                        sorted(set(warnings)), [], hashlib.sha256(source).hexdigest(),
                        sorted(set(credentials)), env_vars, env_errors)
    return analysis, payload


def analyze_source(source: bytes, filename: str = "uploaded.py") -> Analysis:
    a, _ = _analyze_source_impl(source, filename)
    return a


# ───── WRAPPERS ─────
def _w_portable(encoded: bytes, digest: str) -> bytes:
    t = ('# POPPY VAULT — PORTABLE\n'
         'import base64 as _b, hashlib as _h, zlib as _z\n_data={data!r}\n'
         '_raw=_z.decompress(_b.b85decode(_data))\n'
         'if _h.sha256(_raw).hexdigest()!={digest!r}: raise RuntimeError("POPPY integrity failed")\n'
         'exec(compile(_raw, str(globals().get("__file__", "<protected>")), "exec"), globals(), globals())\n')
    return t.format(data=encoded, digest=digest).encode()

def _w_balanced(encoded: bytes, digest: str) -> bytes:
    chunks = [encoded[i:i+48] for i in range(0, len(encoded), 48)] or [b""]
    order = list(range(len(chunks))); secrets.SystemRandom().shuffle(order)
    sh = [chunks[i] for i in order]; rv = [order.index(i) for i in range(len(chunks))]
    t = ('# POPPY VAULT — BALANCED\nimport base64 as _b, hashlib as _h, zlib as _z\n'
         '_c={chunks!r}\n_order={order!r}\n_d=b"".join(_c[i] for i in _order)\n'
         '_raw=_z.decompress(_b.b85decode(_d))\n'
         'if _h.sha256(_raw).hexdigest()!={digest!r}: raise RuntimeError("POPPY integrity failed")\n'
         'exec(compile(_raw, str(globals().get("__file__", "<protected>")), "exec"), globals(), globals())\n')
    return t.format(chunks=sh, order=rv, digest=digest).encode()

def _w_fortress(encoded: bytes, digest: str) -> bytes:
    key = secrets.token_bytes(32)
    masked = bytes(v ^ key[i % len(key)] for i, v in enumerate(encoded))
    chunks = [masked[i:i+29] for i in range(0, len(masked), 29)] or [b""]
    order = list(range(len(chunks))); secrets.SystemRandom().shuffle(order)
    sh = [chunks[i] for i in order]; rv = [order.index(i) for i in range(len(chunks))]
    decoys = "\n".join(f"def _poppy_decoy_{i}(): return {secrets.token_hex(12)!r}" for i in range(3))
    t = ('# POPPY VAULT — FORTRESS\nimport base64 as _b, hashlib as _h, zlib as _z\n{decoys}\n'
         '_c={chunks!r}\n_order={order!r}\n_key=bytes.fromhex({key!r})\n'
         '_m=b"".join(_c[i] for i in _order)\n_e=bytes(v ^ _key[i%len(_key)] for i, v in enumerate(_m))\n'
         '_raw=_z.decompress(_b.b85decode(_e))\n'
         'if _h.sha256(_raw).hexdigest()!={digest!r}: raise RuntimeError("POPPY integrity failed")\n'
         'exec(compile(_raw, str(globals().get("__file__", "<protected>")), "exec"), globals(), globals())\n')
    return t.format(decoys=decoys, chunks=sh, order=rv, key=key.hex(), digest=digest).encode()


def _master_env_config_block(names: Sequence[str], sealed: bool = False, redact: bool = False) -> bytes:
    safe = sorted({n for n in names if isinstance(n, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", n)})
    if not safe: return b""
    os_alias = "_poppy_master_env_os_" + secrets.token_hex(5)
    lines: List[str] = []
    if redact:
        lines += ["# ============================================================",
                  "# POPPY VAULT — MASTER ENV (REDACTED)",
                  "# Fill in each value before running.", "# ============================================================"]
    elif sealed:
        lines += ["# ============================================================",
                  "# POPPY VAULT — MASTER ENV (SEALED)",
                  "# Values captured at protection time.", "# ============================================================"]
    else:
        lines += ["# ============================================================",
                  "# POPPY VAULT — MASTER ENV",
                  "# Blank values fall back to OS environment.", "# ============================================================"]
    lines.append("MASTER_ENV = {")
    for name in safe:
        if redact: lines.append(f"    {name!r}: 'XXXXXXX',")
        elif sealed:
            v = os.environ.get(name, "")
            lines.append(f"    {name!r}: {v!r}," if v else f"    {name!r}: '',  # not set at protection time")
        else: lines.append(f"    {name!r}: '',")
    lines += ["}", f"import os as {os_alias}",
              "for _poppy_master_env_key, _poppy_master_env_value in MASTER_ENV.items():",
              "    if _poppy_master_env_value is not None and str(_poppy_master_env_value).strip():",
              f"        {os_alias}.environ[_poppy_master_env_key] = str(_poppy_master_env_value)",
              "del _poppy_master_env_key, _poppy_master_env_value", "# POPPY MASTER ENV END", ""]
    return ("\n".join(lines) + "\n").encode("utf-8")



def _dependency_bootstrap_block(imports: Sequence[str]) -> bytes:
    """Generate a pip bootstrap for detected third-party imports."""
    stdlib = set(getattr(sys, "stdlib_module_names", set()))
    dependencies: List[Tuple[str, str]] = []
    seen = set()
    for module in imports:
        root = str(module).split(".", 1)[0]
        if not root or root in stdlib or root in sys.builtin_module_names or root == "__future__":
            continue
        package = MODULE_TO_PACKAGE.get(root, root)
        pair = (root, package)
        if pair not in seen:
            seen.add(pair)
            dependencies.append(pair)
    dependencies = [
        (m, p) for m, p in dependencies
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", m)
        and re.fullmatch(r"[A-Za-z0-9_.-]+", p)
    ]
    if not dependencies:
        return b""

    lines = [
        "# === POPPY AUTO DEPENDENCY BOOTSTRAP ===",
        "# Installs missing third-party Python packages before protected code runs.",
        "import importlib as _poppy_importlib",
        "import importlib.util as _poppy_import_util",
        "import subprocess as _poppy_subprocess",
        "import sys as _poppy_sys",
        f"_POPPY_REQUIRED = {dependencies!r}",
        "def _poppy_missing():",
        "    _poppy_importlib.invalidate_caches()",
        "    missing = []",
        "    for module, package in _POPPY_REQUIRED:",
        "        try:",
        "            found = _poppy_import_util.find_spec(module) is not None",
        "            if module == 'telegram' and found:",
        "                import telegram as _poppy_telegram_check",
        "                found = hasattr(_poppy_telegram_check, 'Update')",
        "        except (ImportError, ValueError, AttributeError):",
        "            found = False",
        "        if not found:",
        "            missing.append((module, package))",
        "    return missing",
        "_poppy_missing_items = _poppy_missing()",
        "if _poppy_missing_items:",
        "    try:",
        "        _poppy_pip = [_poppy_sys.executable, '-m', 'pip']",
        "        _poppy_probe = _poppy_subprocess.run(_poppy_pip + ['--version'],",
        "            capture_output=True, text=True, timeout=60)",
        "        if _poppy_probe.returncode != 0:",
        "            _poppy_subprocess.run([_poppy_sys.executable, '-m', 'ensurepip', '--upgrade'],",
        "                check=True, capture_output=True, text=True, timeout=300)",
        "        for _poppy_module, _poppy_package in _poppy_missing_items:",
        "            if _poppy_module == 'telegram':",
        "                _poppy_subprocess.run(_poppy_pip + ['uninstall', '-y', 'telegram'],",
        "                    capture_output=True, text=True, timeout=300)",
        "            print('[POPPY] Installing dependency:', _poppy_package, flush=True)",
        "            _poppy_result = _poppy_subprocess.run(_poppy_pip + ['install',",
        "                '--disable-pip-version-check', _poppy_package],",
        "                capture_output=True, text=True, timeout=900)",
        "            if _poppy_result.returncode != 0:",
        "                raise RuntimeError((_poppy_result.stderr or _poppy_result.stdout or",
        "                    'pip returned a non-zero exit status')[-2000:])",
        "        _poppy_missing_items = _poppy_missing()",
        "        if _poppy_missing_items:",
        "            raise RuntimeError('Imports still missing: ' + ', '.join(",
        "                module for module, package in _poppy_missing_items))",
        "    except Exception as _poppy_exc:",
        "        raise SystemExit('[POPPY] Dependency bootstrap failed: ' + str(_poppy_exc) +",
        "            '. Use a Python virtual environment and install dependencies manually if needed.')",
        "del _poppy_missing_items",
        "# === END POPPY AUTO DEPENDENCY BOOTSTRAP ===",
        "",
    ]
    return ('\n'.join(lines) + '\n').encode('utf-8')


def protect_python_source(source: bytes, mode: str = "portable", filename: str = "protected.py",
                         license_url: Optional[str] = None, redact_secrets: bool = False) -> Tuple[bytes, Analysis]:
    scrub_info: Dict[str, int] = {}
    if redact_secrets: source, scrub_info = scrub_source_secrets(source)
    analysis, payload = _analyze_source_impl(source, filename)
    if not analysis.syntax_ok: raise ValueError("Syntax error: " + "; ".join(analysis.errors))
    if payload is None or analysis.environment_errors:
        raise ValueError("Env extraction failed: " + ("; ".join(analysis.environment_errors) or "internal"))
    if scrub_info:
        analysis.warnings = list(analysis.warnings) + ["Scrubbed: " + ", ".join(f"{k} ×{v}" for k, v in scrub_info.items())]
    encoded = base64.b85encode(__import__("zlib").compress(payload, level=9))
    digest = hashlib.sha256(payload).hexdigest()
    if mode == "portable": result = _w_portable(encoded, digest)
    elif mode == "balanced": result = _w_balanced(encoded, digest)
    elif mode in {"fortress", "sealed", "vault"}: result = _w_fortress(encoded, digest)
    elif mode == "licensed":
        url = license_url or os.getenv("LICENSE_WRAPPER_URL", "").strip() or setting("license_tunnel_url", "") or ""
        if not url: raise ValueError("Licensed requires LICENSE_WRAPPER_URL.")
        if not url.startswith("https://"): raise ValueError("Licensed URL must be HTTPS.")
        fortress = _w_fortress(encoded, digest).decode()
        pre = (
            "import os as _os, json as _json, urllib.request as _ur, uuid as _uuid, hashlib as _hash\n"
            "import pathlib as _pl\n" f"_base={url!r}.rstrip('/')\n"
            "def _mid():\n    try: return _hash.sha256(str(_uuid.getnode()).encode()).hexdigest()[:32]\n"
            "    except Exception: return 'unknown'\n"
            "def _key():\n    k=_os.getenv('POPPY_LICENSE_KEY','').strip()\n    if k: return k\n"
            "    try: base=_pl.Path(__file__).parent\n    except NameError: base=_pl.Path.cwd()\n"
            "    for p in (base/'license.key', _pl.Path.cwd()/'license.key'):\n"
            "        try:\n            if p.exists(): return p.read_text(encoding='utf-8').strip()\n"
            "        except Exception: pass\n    return ''\n"
            "def _post(path, payload):\n"
            "    req=_ur.Request(_base+path, data=_json.dumps(payload).encode('utf-8'),\n"
            "                    headers={'Content-Type':'application/json','User-Agent':'PoppyLic/3'},\n"
            "                    method='POST')\n"
            "    with _ur.urlopen(req, timeout=15) as r:\n        return _json.loads(r.read(4096).decode('utf-8'))\n"
            "_k=_key()\nif not _k: raise SystemExit('[poppy] License key required.')\n_m=_mid()\n"
            "try:\n    _v=_post('/verify', {'key': _k, 'machine_id': _m})\n"
            "    if not _v.get('valid') and _v.get('reason') == 'not_activated':\n"
            "        _v=_post('/activate', {'key': _k, 'machine_id': _m})\n"
            "except Exception as _e:\n    raise SystemExit('[poppy] Server unreachable: %s' % _e)\n"
            "if not _v.get('valid'):\n    raise SystemExit('[poppy] Rejected: ' + str(_v.get('reason', 'invalid')))\n")
        result = (pre + fortress).encode()
    else: raise ValueError("Unsupported mode.")
    visible = list(analysis.environment_variables)
    if mode == "licensed": visible.append("POPPY_LICENSE_KEY")
    dependency_bootstrap = _dependency_bootstrap_block(analysis.imports)
    env_block = _master_env_config_block(visible, sealed=(mode == "sealed"), redact=redact_secrets)
    if mode == "licensed" and dependency_bootstrap:
        marker = "# POPPY VAULT — FORTRESS"
        result_text = result.decode("utf-8")
        if marker not in result_text:
            raise RuntimeError("Licensed wrapper structure check failed.")
        license_prefix, fortress_payload = result_text.split(marker, 1)
        full = env_block + license_prefix.encode("utf-8") + b"\n" + dependency_bootstrap + (marker + fortress_payload).encode("utf-8")
    else:
        full = env_block + dependency_bootstrap + result
    compile(full.decode("utf-8"), filename, "exec")
    recovered = __import__("zlib").decompress(base64.b85decode(encoded))
    if not hmac.compare_digest(hashlib.sha256(recovered).hexdigest(), digest):
        raise RuntimeError("Internal integrity failed.")
    return full, analysis


def _safe_zip_member(name: str) -> Optional[str]:
    norm = name.replace("\\", "/")
    path = PurePosixPath(norm)
    if path.is_absolute() or not path.parts or ".." in path.parts or re.match(r"^[A-Za-z]:", norm): return None
    if "\x00" in norm: return None
    cleaned = "/".join(p for p in path.parts if p not in {"", "."})
    return cleaned or None


def protect_zip(source: bytes, mode: str, license_url: Optional[str] = None,
                max_total_bytes: int = MAX_ZIP_UNPACKED, redact_secrets: bool = False) -> Tuple[bytes, int, List[Analysis]]:
    out = io.BytesIO(); analyses: List[Analysis] = []; protected = 0; removed_env: List[str] = []; seen = set()
    try: archive = zipfile.ZipFile(io.BytesIO(source), "r")
    except zipfile.BadZipFile as exc: raise ValueError("Corrupt ZIP.") from exc
    with archive, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as dst:
        infos = archive.infolist()
        if len(infos) > MAX_ZIP_ENTRIES: raise ValueError(f"Too many entries.")
        total = 0
        for info in infos:
            safe = _safe_zip_member(info.filename)
            if safe is None: raise ValueError("Unsafe path.")
            if safe in seen: raise ValueError("Duplicate entry.")
            seen.add(safe)
            base = PurePosixPath(safe).name.lower()
            if base == ".env" or base.startswith(".env."): removed_env.append(safe); continue
            if (info.external_attr >> 16) & 0o170000 == stat.S_IFLNK: raise ValueError("Symlinks not allowed.")
            if info.is_dir(): dst.writestr(safe.rstrip("/") + "/", b""); continue
            total += info.file_size
            if total > min(MAX_ZIP_UNPACKED, max_total_bytes): raise ValueError("ZIP too large.")
            if info.file_size > 0 and info.compress_size == 0: raise ValueError("Invalid metadata.")
            if info.compress_size and info.file_size / info.compress_size > MAX_ZIP_RATIO: raise ValueError("Ratio too high.")
            with archive.open(info, "r") as stream: content = stream.read(MAX_ZIP_UNPACKED + 1)
            if len(content) != info.file_size: raise ValueError("Size mismatch.")
            if safe.lower().endswith(".py"):
                if len(content) > MAX_PY_BYTES: raise ValueError(f"Too large: {safe}")
                content, rep = protect_python_source(content, mode, safe, license_url, redact_secrets)
                analyses.append(rep); protected += 1
            dst.writestr(safe, content)
        if not protected: raise ValueError("No Python files in ZIP.")
        dst.writestr("POPPY_DEPLOYMENT_REPORT.txt",
                     (f"POPPY VAULT ZIP\nMode: {mode}\nProtected: {protected}\n"
                      f"Dotenv removed: {', '.join(removed_env) if removed_env else 'none'}\n"
                      "Obfuscation is not encryption.\n").encode())
    return out.getvalue(), protected, analyses


# ───── VAULT FILES ─────
def create_vault_file(owner_id: int, source: bytes, filename: str) -> Tuple[bytes, str, Analysis]:
    analysis, payload = _analyze_source_impl(source, filename)
    if not analysis.syntax_ok: raise ValueError("Syntax error: " + "; ".join(analysis.errors))
    if payload is None: raise ValueError("Cannot prepare payload.")
    with db_conn() as c:
        count = c.execute("SELECT COUNT(*) FROM vault_files WHERE owner_user_id=?", (owner_id,)).fetchone()[0]
    if count >= VAULT_MAX_PER_USER: raise ValueError(f"Vault file limit reached ({VAULT_MAX_PER_USER}).")
    file_id = secrets.token_hex(8)
    file_key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(VAULT_NONCE_LEN)
    aad = file_id.encode("ascii")
    ciphertext = AESGCM(file_key).encrypt(nonce, source, aad)
    blob = VAULT_MAGIC + file_id.encode("ascii") + nonce + ciphertext
    if len(blob) > VAULT_MAX_FILE_BYTES: raise ValueError(f"Vault file exceeds {VAULT_MAX_FILE_BYTES // (1024*1024)} MB.")
    file_key_ct = private_key_cipher().encrypt(file_key)
    file_hash = hashlib.sha256(blob).hexdigest()
    with db_conn(immediate=True) as c:
        c.execute("INSERT INTO vault_files(file_id,owner_user_id,original_filename,file_sha256,"
                  "size_bytes,file_key_ciphertext,created_at) VALUES(?,?,?,?,?,?,?)",
                  (file_id, owner_id, safe_filename(filename), file_hash, len(blob), file_key_ct, utc_ts()))
    audit(owner_id, "vault_file_created", owner_id, {"file_id": file_id, "filename": filename, "size": len(blob)})
    return blob, file_id, analysis


def parse_vault_blob(blob: bytes) -> Tuple[str, bytes, bytes]:
    if len(blob) < len(VAULT_MAGIC) + VAULT_FILE_ID_LEN + VAULT_NONCE_LEN + 16: raise ValueError("File too short.")
    if not blob.startswith(VAULT_MAGIC): raise ValueError("Not a vault file.")
    offset = len(VAULT_MAGIC)
    try: file_id = blob[offset:offset + VAULT_FILE_ID_LEN].decode("ascii")
    except UnicodeDecodeError: raise ValueError("Invalid ID.")
    if not re.fullmatch(r"[0-9a-f]{16}", file_id): raise ValueError("Invalid ID format.")
    offset += VAULT_FILE_ID_LEN
    nonce = blob[offset:offset + VAULT_NONCE_LEN]; offset += VAULT_NONCE_LEN
    return file_id, nonce, blob[offset:]

def decrypt_vault_blob(blob: bytes, file_key: bytes) -> bytes:
    file_id, nonce, ct = parse_vault_blob(blob)
    try: return AESGCM(file_key).decrypt(nonce, ct, file_id.encode("ascii"))
    except Exception: raise ValueError("Decryption failed.")

def get_vault_file(file_id: str) -> Optional[sqlite3.Row]:
    with db_conn() as c: return c.execute("SELECT * FROM vault_files WHERE file_id=?", (file_id,)).fetchone()

def set_vault_license_key(file_id: str, owner_id: int, key: str) -> bool:
    digest = hmac.new(_env_bytes("LICENSE_PEPPER", 32), key.encode("utf-8"), hashlib.sha256).hexdigest()
    with db_conn(immediate=True) as c:
        cur = c.execute("UPDATE vault_files SET license_key_hash=?, license_key_last4=?, license_set_at=? "
                        "WHERE file_id=? AND owner_user_id=?",
                        (digest, key[-4:], utc_ts(), file_id, owner_id))
        return cur.rowcount > 0

def verify_vault_license(file_id: str, key: str) -> bool:
    row = get_vault_file(file_id)
    if not row or not row["license_key_hash"]: return False
    digest = hmac.new(_env_bytes("LICENSE_PEPPER", 32), key.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, row["license_key_hash"])

def record_vault_attempt(file_id: str, user_id: int, success: bool) -> None:
    with db_conn(immediate=True) as c:
        c.execute("INSERT INTO vault_attempts(file_id,user_id,success,created_at) VALUES(?,?,?,?)",
                  (file_id, user_id, 1 if success else 0, utc_ts()))

def count_recent_failed_attempts(file_id: str, user_id: int) -> int:
    with db_conn() as c:
        return c.execute("SELECT COUNT(*) FROM vault_attempts WHERE file_id=? AND user_id=? AND success=0 AND created_at>=?",
                         (file_id, user_id, utc_ts() - VAULT_ATTEMPT_WINDOW)).fetchone()[0]


_pending_vault_uploads: Dict[int, dict] = {}
_vault_key_input: Dict[int, dict] = {}


# ───── RSA DECRYPT ─────
EMBEDDED_ENCRYPT_UTILITY = '''#!/usr/bin/env python3
import argparse, base64, hashlib, json, os, re, sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
MAGIC = b"POPPYENC"
def canonical_header(h): return json.dumps(h, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
def encrypt_file(pk_path, inp, job_id, out=None, max_bytes=15*1024*1024):
    if not re.fullmatch(r"[0-9a-fA-F]{32}", job_id): raise ValueError("bad job")
    if not inp.is_file(): raise FileNotFoundError(str(inp))
    raw = inp.read_bytes()
    if len(raw) > max_bytes: raise ValueError("too large")
    pk = serialization.load_pem_public_key(pk_path.read_bytes())
    aes = os.urandom(32); nonce = os.urandom(12)
    wrapped = pk.encrypt(aes, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=job_id.encode("ascii")))
    hdr = {"v":1,"job_id":job_id,"filename":inp.name[:120],"file_size":len(raw),
           "sha256":hashlib.sha256(raw).hexdigest(),
           "wrapped_key":base64.b64encode(wrapped).decode(),"nonce":base64.b64encode(nonce).decode()}
    aad = canonical_header(hdr); ct = AESGCM(aes).encrypt(nonce, raw, aad)
    dest = out or inp.with_name(inp.name + ".poppy.enc")
    dest.write_bytes(MAGIC + len(aad).to_bytes(4,"big") + aad + ct); return dest
def main():
    p = argparse.ArgumentParser()
    p.add_argument("public_key", type=Path); p.add_argument("input_file", type=Path)
    p.add_argument("--job", required=True); p.add_argument("-o","--output", type=Path)
    a = p.parse_args()
    try: print(f"Encrypted: {encrypt_file(a.public_key, a.input_file, a.job, a.output)}"); return 0
    except Exception as e: print(f"Error: {e}", file=sys.stderr); return 2
if __name__ == "__main__": raise SystemExit(main())
'''


def generate_job_keys() -> Tuple[bytes, bytes]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    priv_pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pub_pem = priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return pub_pem, private_key_cipher().encrypt(priv_pem)


def reserve_job(user_id: int, license_row: sqlite3.Row, public_pem: bytes,
                encrypted_priv: bytes, credits_cost: int, max_file_bytes: int) -> str:
    job_id = uuid.uuid4().hex
    now, month = utc_ts(), month_key()
    with db_conn(immediate=True) as c:
        user = c.execute("SELECT * FROM users WHERE user_id=?", (user_id,)).fetchone()
        if not user or user["banned"] or user["suspended"]: raise ValueError("Account ineligible.")
        rank = rank_for_user(user_id, c); usage = usage_for(c, user_id, month)
        if usage["reserved_jobs"] + usage["completed_jobs"] >= rank["monthly_limit"]: raise ValueError("Quota exhausted.")
        if user["credits"] < credits_cost: raise ValueError("Not enough credits.")
        ok, reason = _license_state(license_row, user_id, now)
        if not ok: raise ValueError("License: " + reason)
        c.execute("UPDATE users SET credits=credits-?,reserved_credits=reserved_credits+? WHERE user_id=?",
                  (credits_cost, credits_cost, user_id))
        c.execute("UPDATE usage_monthly SET reserved_jobs=reserved_jobs+1 WHERE user_id=? AND month=?", (user_id, month))
        c.execute("UPDATE licenses SET reserved_uses=reserved_uses+1 WHERE key_hash=?", (license_row["key_hash"],))
        c.execute("INSERT INTO jobs(job_id,user_id,license_hash,created_at,expires_at,status,"
                  "private_key_ciphertext,public_key_pem,reserved_credits,month,max_output_bytes) "
                  "VALUES(?,?,?,?,?,'pending',?,?,?,?,?)",
                  (job_id, user_id, license_row["key_hash"], now, now + JOB_TTL_SECONDS,
                   encrypted_priv, public_pem, credits_cost, month, max_file_bytes))
    return job_id


def claim_job(job_id: str, user_id: int) -> sqlite3.Row:
    with db_conn(immediate=True) as c:
        job = c.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        if not job or job["user_id"] != user_id: raise ValueError("Job not found.")
        if job["expires_at"] < utc_ts(): raise ValueError("Job expired.")
        if job["status"] != "pending": raise ValueError("Job not pending.")
        cur = c.execute("UPDATE jobs SET status='processing' WHERE job_id=? AND status='pending'", (job_id,))
        if cur.rowcount != 1: raise ValueError("Already claimed.")
        return job


def _poppy_header_parse(blob: bytes) -> Tuple[dict, bytes]:
    magic = b"POPPYENC"
    if not blob.startswith(magic) or len(blob) < len(magic) + 4: raise ValueError("Not a POPPY file.")
    hlen = int.from_bytes(blob[len(magic):len(magic) + 4], "big")
    if hlen < 2 or hlen > 8192: raise ValueError("Bad header.")
    start = len(magic) + 4
    try: hdr = json.loads(blob[start:start + hlen].decode("utf-8"))
    except Exception: raise ValueError("Bad header.")
    return hdr, blob[start + hlen:]


def decrypt_poppy_payload(blob: bytes, job_id: str, priv_pem: bytes, max_out: int) -> Tuple[bytes, str]:
    hdr, ct = _poppy_header_parse(blob)
    if not hmac.compare_digest(hdr["job_id"], job_id): raise ValueError("Job mismatch.")
    wrapped = base64.b64decode(hdr["wrapped_key"], validate=True)
    nonce = base64.b64decode(hdr["nonce"], validate=True)
    pk = serialization.load_pem_private_key(priv_pem, password=None)
    aes = pk.decrypt(wrapped, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                           algorithm=hashes.SHA256(), label=job_id.encode("ascii")))
    aad = json.dumps(hdr, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    pt = AESGCM(aes).decrypt(nonce, ct, aad)
    if len(pt) > max_out: raise ValueError("Exceeds limit.")
    if int(hdr.get("file_size", -1)) != len(pt): raise ValueError("Size mismatch.")
    if not hmac.compare_digest(hashlib.sha256(pt).hexdigest(), hdr.get("sha256", "")): raise ValueError("Integrity failed.")
    return pt, safe_filename(hdr.get("filename", "decrypted.bin"))


def complete_job(job_id: str, enc_dig: str, out_dig: str) -> None:
    with db_conn(immediate=True) as c:
        job = c.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        if not job or job["status"] != "processing": raise ValueError("Job not processing.")
        c.execute("UPDATE licenses SET reserved_uses=MAX(0,reserved_uses-1),uses=uses+1 WHERE key_hash=?",
                  (job["license_hash"],))
        c.execute("UPDATE users SET reserved_credits=MAX(0,reserved_credits-?),lifetime_jobs=lifetime_jobs+1 WHERE user_id=?",
                  (job["reserved_credits"], job["user_id"]))
        c.execute("UPDATE usage_monthly SET reserved_jobs=MAX(0,reserved_jobs-1),completed_jobs=completed_jobs+1 "
                  "WHERE user_id=? AND month=?", (job["user_id"], job["month"]))
        c.execute("UPDATE jobs SET status='completed',private_key_ciphertext=NULL,encrypted_sha256=?,output_sha256=?,completed_at=? WHERE job_id=?",
                  (enc_dig, out_dig, utc_ts(), job_id))


def _fail_job(job_id: str, reason: str) -> bool:
    with db_conn(immediate=True) as c:
        job = c.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        if not job or job["status"] in {"completed", "failed"} or job["refund_applied"]: return False
        amount = job["reserved_credits"]
        c.execute("UPDATE users SET credits=credits+?,reserved_credits=MAX(0,reserved_credits-?) WHERE user_id=?",
                  (amount, amount, job["user_id"]))
        c.execute("UPDATE usage_monthly SET reserved_jobs=MAX(0,reserved_jobs-1) WHERE user_id=? AND month=?",
                  (job["user_id"], job["month"]))
        c.execute("UPDATE licenses SET reserved_uses=MAX(0,reserved_uses-1) WHERE key_hash=?", (job["license_hash"],))
        c.execute("UPDATE jobs SET status='failed',private_key_ciphertext=NULL,refund_applied=1,error_reason=? WHERE job_id=?",
                  (reason[:300], job_id))
    return True


def detect_poppy_file(blob: bytes) -> Optional[str]:
    if blob.startswith(VAULT_MAGIC): return "vault"
    if blob.startswith(b"POPPYENC"): return "decrypt"
    return None


# ───── LICENSE SERVER ─────
_LICENSE_APP: Optional["Flask"] = None  # type: ignore
_LICENSE_SERVER_STARTED = False
_LICENSE_SERVER_LOCK = threading.Lock()


def _lic_admin_secret() -> str:
    existing = os.getenv("LICENSE_ADMIN_SECRET", "").strip()
    if existing: return existing
    stored = setting("license_admin_secret", "")
    if stored: return stored
    new = secrets.token_hex(24); set_setting("license_admin_secret", new); return new

def _lic_machines(row: sqlite3.Row) -> List[str]:
    try: return json.loads((row["machines"] if "machines" in row.keys() else None) or "[]")
    except Exception: return []

def _lic_get_by_hash(raw: str) -> Optional[sqlite3.Row]:
    try: digest = license_hash(raw)
    except RuntimeError: return None
    with db_conn() as c: return c.execute("SELECT * FROM licenses WHERE key_hash=?", (digest,)).fetchone()

def _lic_save_machines(row: sqlite3.Row, machines: List[str]) -> None:
    with db_conn(immediate=True) as c:
        c.execute("UPDATE licenses SET machines=? WHERE key_hash=?", (json.dumps(machines), row["key_hash"]))


def _license_server() -> "Flask":  # type: ignore
    global _LICENSE_APP
    if _LICENSE_APP is not None: return _LICENSE_APP
    if not _FLASK_OK: raise RuntimeError("Flask missing.")
    app = Flask(f"poppy_{secrets.token_hex(3)}")
    app.config["JSON_SORT_KEYS"] = False

    def _admin(f):
        from functools import wraps
        @wraps(f)
        def wrap(*a, **kw):
            if flask_request.headers.get("X-Admin-Secret") != _lic_admin_secret():
                return flask_jsonify({"error": "forbidden"}), 403
            return f(*a, **kw)
        return wrap

    @app.get("/health")
    def _h(): return flask_jsonify({"ok": True, "service": "poppy-license", "version": APP_VERSION, "time": utc_ts()})

    @app.post("/verify")
    def _v():
        b = flask_request.get_json(silent=True) or {}
        raw = (b.get("key") or "").strip(); mid = (b.get("machine_id") or "").strip()
        if not raw: return flask_jsonify({"valid": False, "reason": "missing_key"}), 400
        row = _lic_get_by_hash(raw)
        if not row: return flask_jsonify({"valid": False, "reason": "unknown_key"})
        if row["revoked"]: return flask_jsonify({"valid": False, "reason": "revoked"})
        if row["expires_at"] and row["expires_at"] < utc_ts(): return flask_jsonify({"valid": False, "reason": "expired"})
        if not mid: return flask_jsonify({"valid": True, "plan": row["plan"], "expires_at": row["expires_at"]})
        if mid not in _lic_machines(row): return flask_jsonify({"valid": False, "reason": "not_activated"})
        return flask_jsonify({"valid": True, "plan": row["plan"], "expires_at": row["expires_at"]})

    @app.post("/activate")
    def _a():
        b = flask_request.get_json(silent=True) or {}
        raw = (b.get("key") or "").strip(); mid = (b.get("machine_id") or "").strip()
        if not raw or not mid: return flask_jsonify({"valid": False, "reason": "missing_fields"}), 400
        row = _lic_get_by_hash(raw)
        if not row: return flask_jsonify({"valid": False, "reason": "unknown_key"})
        if row["revoked"]: return flask_jsonify({"valid": False, "reason": "revoked"})
        if row["expires_at"] and row["expires_at"] < utc_ts(): return flask_jsonify({"valid": False, "reason": "expired"})
        machines = _lic_machines(row)
        if mid not in machines:
            cap = int(row["max_uses"] or 1)
            if len(machines) >= cap: return flask_jsonify({"valid": False, "reason": "max_machines"})
            machines.append(mid); _lic_save_machines(row, machines)
        return flask_jsonify({"valid": True, "plan": row["plan"], "expires_at": row["expires_at"]})

    @app.post("/admin/create")
    @_admin
    def _c():
        b = flask_request.get_json(silent=True) or {}
        raw = create_license(int(b.get("days", 30)), int(b.get("max_machines", 1)), str(b.get("plan", "standard")))
        return flask_jsonify({"ok": True, "key": raw})

    @app.get("/admin/list")
    @_admin
    def _l():
        with db_conn() as c:
            rows = c.execute("SELECT key_last4,plan,created_at,expires_at,max_uses,uses,revoked,bound_user_id,machines "
                             "FROM licenses ORDER BY created_at DESC LIMIT 200").fetchall()
        return flask_jsonify([dict(r) for r in rows])

    _LICENSE_APP = app
    return app


def _license_server_start() -> bool:
    global _LICENSE_SERVER_STARTED
    with _LICENSE_SERVER_LOCK:
        if _LICENSE_SERVER_STARTED: return True
        if not _FLASK_OK: log.warning("Flask not installed — licensed mode disabled"); return False
        if os.getenv("LICENSE_SERVER_ENABLED", "1").strip().lower() not in {"1", "true", "yes", "on"}: return False
        try: app = _license_server()
        except Exception: log.exception("Flask init failed"); return False
    def _run():
        try: app.run(host="127.0.0.1", port=LICENSE_SERVER_PORT, threaded=True, use_reloader=False, debug=False)
        except Exception: log.exception("License server crashed")
    threading.Thread(target=_run, daemon=True, name="poppy-lic").start()
    _LICENSE_SERVER_STARTED = True
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{LICENSE_SERVER_PORT}/health", timeout=2) as r:
                if r.status == 200: log.info("License server ready on :%s", LICENSE_SERVER_PORT); return True
        except Exception: time.sleep(0.3)
    return False


# ───── CLOUDFLARED ─────
_CF_PROCESS: Optional[subprocess.Popen] = None
_CF_LOCK = threading.RLock()
_CF_HOME = Path.home() / ".poppy_master_secure_vault"
_CF_BIN_DIR = _CF_HOME / "bin"
_CF_LOG_PATH = Path(os.getenv("CLOUDFLARED_LOG", str(_CF_HOME / "cloudflared.log"))).expanduser()
_CF_TOKEN_FILE_PATH: Optional[Path] = None
_CF_WATCHDOG_STARTED = False
_CF_WATCHDOG_STOP = threading.Event()
_CF_AUTOSTART_ENABLED = False
_CF_DOWNLOADS = {
    ("Windows", "amd64"): "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe",
    ("Windows", "x86_64"): "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe",
    ("Windows", "arm64"): "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-arm64.exe",
    ("Linux", "amd64"): "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64",
    ("Linux", "x86_64"): "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64",
    ("Linux", "aarch64"): "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64",
    ("Linux", "arm64"): "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64",
    ("Darwin", "x86_64"): "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-amd64.tgz",
    ("Darwin", "arm64"): "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-arm64.tgz",
}


def _cf_binary(prefer_managed: bool = False) -> Optional[Path]:
    configured = os.getenv("CLOUDFLARED_PATH", "").strip()
    if configured:
        custom = Path(configured).expanduser()
        if custom.is_file(): return custom
    bundled = _CF_BIN_DIR / ("cloudflared.exe" if os.name == "nt" else "cloudflared")
    if prefer_managed and bundled.is_file(): return bundled
    found = shutil.which("cloudflared")
    if found: return Path(found)
    return bundled if bundled.is_file() else None

def _cf_supports_token_file(binary: Path) -> bool:
    try:
        r = subprocess.run([str(binary), "tunnel", "run", "--help"], capture_output=True, text=True, timeout=15)
        return "--token-file" in ((r.stdout or "") + (r.stderr or ""))
    except Exception: return False

def _cf_write_token_file(token: str) -> Path:
    _CF_HOME.mkdir(parents=True, exist_ok=True)
    if os.name != "nt": _CF_HOME.chmod(0o700)
    path = _CF_HOME / ("cloudflared-token-" + secrets.token_hex(12) + ".txt")
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as s:
            s.write(token + "\n"); s.flush(); os.fsync(s.fileno())
    except Exception:
        path.unlink(missing_ok=True); raise
    if os.name != "nt": path.chmod(0o600)
    return path

def _cf_cleanup_token_file() -> None:
    global _CF_TOKEN_FILE_PATH
    path = _CF_TOKEN_FILE_PATH; _CF_TOKEN_FILE_PATH = None
    if path:
        try: path.unlink(missing_ok=True)
        except Exception: pass

def _cf_cleanup_stale_token_files() -> None:
    _CF_HOME.mkdir(parents=True, exist_ok=True)
    for path in _CF_HOME.glob("cloudflared-token-*.txt"):
        try: path.unlink(missing_ok=True)
        except Exception: pass


def _cf_install(force: bool = False) -> Tuple[bool, str]:
    current = _cf_binary()
    if current and not force: return True, f"already installed: {current}"
    url = _CF_DOWNLOADS.get((platform.system(), platform.machine().lower()))
    if not url: return False, f"Unsupported platform: {platform.system()} {platform.machine()}"
    temp = None
    try:
        _CF_BIN_DIR.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(url, headers={"User-Agent": f"POPPY-Vault/{APP_VERSION}"})
        with urllib.request.urlopen(req, timeout=180) as response: payload = response.read(100 * 1024 * 1024 + 1)
        if len(payload) > 100 * 1024 * 1024 or len(payload) < 500_000: raise RuntimeError("Unexpected file size.")
        target = _CF_BIN_DIR / ("cloudflared.exe" if os.name == "nt" else "cloudflared")
        temp = target.with_name(target.name + ".download")
        if platform.system() == "Darwin":
            archive = _CF_BIN_DIR / "cloudflared-macos.tgz"; archive.write_bytes(payload)
            try:
                with tarfile.open(archive, "r:gz") as tf:
                    member = next((m for m in tf.getmembers() if Path(m.name).name == "cloudflared" and m.isfile()), None)
                    if not member or not 500_000 <= member.size <= 100 * 1024 * 1024: raise RuntimeError("Bad archive.")
                    stream = tf.extractfile(member)
                    if not stream: raise RuntimeError("Bad archive.")
                    temp.write_bytes(stream.read())
            finally: archive.unlink(missing_ok=True)
        else: temp.write_bytes(payload)
        if os.name != "nt": temp.chmod(temp.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        check = subprocess.run([str(temp), "--version"], capture_output=True, text=True, timeout=20)
        if check.returncode or "cloudflared" not in ((check.stdout or "") + (check.stderr or "")).lower():
            raise RuntimeError("Version check failed.")
        temp.replace(target)
        return True, f"installed: {target}"
    except Exception as exc:
        if temp: temp.unlink(missing_ok=True)
        return False, f"Install failed: {type(exc).__name__}: {exc}"


def _cf_check_token(raw: str) -> Tuple[bool, str]:
    token = (raw or "").strip()
    parts = token.split(); lower = [x.lower() for x in parts]
    if "--token" in lower: token = " ".join(parts[lower.index("--token") + 1:]).strip()
    if not token: return False, "No token."
    try:
        padded = token + "=" * (-len(token) % 4)
        data = json.loads(base64.b64decode(padded, validate=True).decode("utf-8"))
        if not isinstance(data, dict) or not all(data.get(k) for k in ("a", "t", "s")):
            return False, "Missing fields."
    except Exception: return False, "Invalid token."
    return True, token


def _cf_save_token(token: str) -> None:
    enc = private_key_cipher().encrypt(token.encode("utf-8"))
    set_setting("cloudflared_token_ciphertext", base64.b64encode(enc).decode("ascii"))


def _cf_get_token() -> str:
    stored = setting("cloudflared_token_ciphertext", "") or ""
    if stored:
        try: return private_key_cipher().decrypt(base64.b64decode(stored, validate=True)).decode("utf-8")
        except Exception as exc: raise RuntimeError("Token cannot be decrypted.") from exc
    return os.getenv("CLOUDFLARED_TUNNEL_TOKEN", "").strip()


def _cf_spawn(token: str) -> str:
    global _CF_PROCESS, _CF_TOKEN_FILE_PATH
    binary = _cf_binary()
    if not binary:
        ok, message = _cf_install()
        if not ok: raise RuntimeError(message)
        binary = _cf_binary(prefer_managed=True)
    if not binary: raise RuntimeError("cloudflared binary not found.")
    if not _cf_supports_token_file(binary):
        if os.getenv("CLOUDFLARED_PATH", "").strip():
            raise RuntimeError("Configured cloudflared too old (needs 2025.4.0+).")
        ok, message = _cf_install(force=True)
        if not ok: raise RuntimeError(message)
        binary = _cf_binary(prefer_managed=True)
        if not binary or not _cf_supports_token_file(binary): raise RuntimeError("Cannot install modern cloudflared.")
    _CF_HOME.mkdir(parents=True, exist_ok=True)
    _CF_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    _cf_cleanup_token_file()
    token_file = _cf_write_token_file(token)
    _CF_TOKEN_FILE_PATH = token_file
    try:
        with _CF_LOG_PATH.open("ab") as log_file:
            flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
            proc = subprocess.Popen([str(binary), "tunnel", "--no-autoupdate", "run", "--token-file", str(token_file)],
                                    stdin=subprocess.DEVNULL, stdout=log_file, stderr=log_file,
                                    creationflags=flags, start_new_session=(os.name != "nt"))
    except Exception:
        _cf_cleanup_token_file(); raise
    with _CF_LOCK: _CF_PROCESS = proc
    time.sleep(2)
    if proc.poll() is not None:
        _cf_cleanup_token_file()
        raise RuntimeError(f"cloudflared exited rc={proc.returncode}.")
    return f"Tunnel started (PID {proc.pid})."


def _cf_watchdog() -> None:
    global _CF_PROCESS
    while not _CF_WATCHDOG_STOP.wait(30):
        try:
            with _CF_LOCK:
                enabled = _CF_AUTOSTART_ENABLED
                alive = bool(_CF_PROCESS and _CF_PROCESS.poll() is None)
            if enabled and not alive:
                token = _cf_get_token()
                if token: log.warning("cloudflared died; restarting"); _cf_spawn(token)
        except Exception: log.exception("Watchdog restart failed.")


def _cf_start_watchdog() -> None:
    global _CF_WATCHDOG_STARTED
    with _CF_LOCK:
        if _CF_WATCHDOG_STARTED: return
        _CF_WATCHDOG_STARTED = True
    threading.Thread(target=_cf_watchdog, daemon=True, name="poppy-cf-watchdog").start()


def cloudflared_configure(raw_token: str) -> str:
    valid, token = _cf_check_token(raw_token)
    if not valid: raise ValueError(token)
    _cf_save_token(token); return cloudflared_start()


def cloudflared_status() -> str:
    binary = _cf_binary(); version = "not installed"
    if binary:
        try:
            r = subprocess.run([str(binary), "--version"], capture_output=True, text=True, timeout=12)
            version = (r.stdout or r.stderr or "unknown").strip().splitlines()[0]
        except Exception as exc: version = f"check failed: {type(exc).__name__}"
    with _CF_LOCK:
        proc = _CF_PROCESS; alive = bool(proc and proc.poll() is None)
        pid = proc.pid if alive and proc else "—"; restart = _CF_AUTOSTART_ENABLED
    saved = bool(setting("cloudflared_token_ciphertext", "") or os.getenv("CLOUDFLARED_TUNNEL_TOKEN", ""))
    return (f"Binary: {binary or 'not installed'}\nVersion: {version}\n"
            f"Tunnel token: {'configured' if saved else 'not configured'}\n"
            f"Owned process: {'active' if alive else 'inactive'}\nPID: {pid}\n"
            f"Auto-restart: {restart}\nLog: {_CF_LOG_PATH}")


def cloudflared_start() -> str:
    global _CF_AUTOSTART_ENABLED
    token = _cf_get_token()
    if not token: raise RuntimeError("No tunnel token. Use /tunnel configure.")
    with _CF_LOCK:
        if _CF_PROCESS and _CF_PROCESS.poll() is None:
            _CF_AUTOSTART_ENABLED = True
            return f"Already running (PID {_CF_PROCESS.pid})."
    result = _cf_spawn(token)
    with _CF_LOCK: _CF_AUTOSTART_ENABLED = True
    _cf_start_watchdog(); return result


def cloudflared_stop() -> str:
    global _CF_PROCESS, _CF_AUTOSTART_ENABLED
    with _CF_LOCK:
        _CF_AUTOSTART_ENABLED = False; proc = _CF_PROCESS
    if not proc or proc.poll() is not None:
        with _CF_LOCK: _CF_PROCESS = None
        _cf_cleanup_token_file(); return "No active process."
    proc.terminate()
    try: proc.wait(timeout=10)
    except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)
    with _CF_LOCK:
        if _CF_PROCESS is proc: _CF_PROCESS = None
    _cf_cleanup_token_file(); return f"Stopped (PID {proc.pid})."


def cloudflared_reset() -> str:
    cloudflared_stop()
    with db_conn(immediate=True) as conn:
        conn.execute("DELETE FROM config WHERE key='cloudflared_token_ciphertext'")
    return "Token removed."


def cloudflared_startup() -> None:
    _cf_cleanup_stale_token_files()
    log.info("Checking cloudflared installation...")
    ok, detail = _cf_install(); log.info("%s", detail)
    if not ok: log.warning("cloudflared unavailable; use /tunnel install."); return
    if as_bool(os.getenv("CLOUDFLARED_AUTO_START", "1")):
        try:
            if _cf_get_token(): log.info("Restoring tunnel."); log.info("%s", cloudflared_start())
            else: log.info("No token configured. Use /tunnel configure.")
        except Exception: log.exception("Could not restore tunnel.")


# ───── HEALTH ─────
class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/health": self.send_error(404); return
        body = json.dumps({"ok": True, "service": "poppy-vault", "version": APP_VERSION, "time": utc_ts()}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a, **k): pass


def start_health() -> Optional[ThreadingHTTPServer]:
    if not as_bool(os.getenv("HEALTH_ENABLED", "1")): return None
    try:
        srv = ThreadingHTTPServer((HEALTH_HOST, HEALTH_PORT), _HealthHandler)
        threading.Thread(target=srv.serve_forever, daemon=True, name="health").start()
        return srv
    except Exception: log.exception("Health server failed"); return None


# ───── WORKERS ─────
def expire_pending_jobs() -> int:
    with db_conn() as c:
        ids = [r["job_id"] for r in c.execute("SELECT job_id FROM jobs WHERE status='pending' AND expires_at<?", (utc_ts(),))]
    return sum(1 for j in ids if _fail_job(j, "job_expired"))


def maintenance_worker(stop_event: threading.Event, interval: int = 30) -> None:
    while not stop_event.wait(max(5, interval)):
        try: expire_pending_jobs()
        except Exception: log.exception("Maintenance error")


def recover_jobs() -> int:
    with db_conn() as c:
        ids = [r["job_id"] for r in c.execute(
            "SELECT job_id FROM jobs WHERE status IN ('pending','processing') AND (status='processing' OR expires_at<?)",
            (utc_ts(),))]
    count = 0
    for jid in ids: count += 1 if _fail_job(jid, "server_restart") else 0
    with db_conn() as c:
        rids = [r["reservation_id"] for r in c.execute("SELECT reservation_id FROM work_reservations WHERE status='pending'")]
    for rid in rids: count += 1 if finish_processing(rid, False) else 0
    return count


# ───── VAULT CONSUMER ─────
def handle_vault_upload(message, blob: bytes, bot) -> None:
    uid = message.from_user.id
    try: file_id, _, _ = parse_vault_blob(blob)
    except ValueError as exc:
        bot.reply_to(message, _panel("Invalid File", _html(str(exc)), emoji="✗"), parse_mode="HTML"); return
    row = get_vault_file(file_id)
    if not row:
        bot.reply_to(message, _panel("File Not Recognized", "Not registered.", emoji="⚠️"), parse_mode="HTML"); return
    if row["revoked"]:
        bot.reply_to(message, _panel("File Revoked", "Access revoked.", f"ID: {file_id}", emoji="🚫"), parse_mode="HTML"); return
    if not row["license_key_hash"]:
        bot.reply_to(message, _panel("License Not Set", "Owner has not set a key.", emoji="⚠️"), parse_mode="HTML"); return
    fails = count_recent_failed_attempts(file_id, uid)
    if fails >= VAULT_MAX_ATTEMPTS:
        bot.reply_to(message, _panel("Locked", f"{fails} failed attempts.", "Try again later.", emoji="🔒"), parse_mode="HTML"); return
    _pending_vault_uploads[uid] = {"file_id": file_id, "blob": blob, "attempts": 0, "expires": utc_ts() + VAULT_PENDING_TTL}
    body = (f"{_kv('File', _html(row['original_filename']))}\n{_kv('ID', f'<code>{file_id}</code>')}\n\n"
            f"This file is license-protected.\nReply with the license key.")
    bot.send_message(message.chat.id, _panel("License Required", body,
                     f"Reply within 10 min  ·  {VAULT_MAX_ATTEMPTS} attempts max", emoji="🔑"), parse_mode="HTML")


def handle_vault_license_input(message, bot) -> bool:
    uid = message.from_user.id
    ctx = _pending_vault_uploads.get(uid)
    if not ctx: return False
    if ctx["expires"] < utc_ts():
        del _pending_vault_uploads[uid]
        bot.reply_to(message, _panel("Expired", "Try again.", emoji="⌛"), parse_mode="HTML"); return True
    key = (message.text or "").strip()
    if not key or len(key) < 6 or len(key) > 128:
        bot.reply_to(message, "Key must be 6-128 characters.", parse_mode="HTML"); return True
    file_id = ctx["file_id"]; row = get_vault_file(file_id)
    if not row or row["revoked"]:
        del _pending_vault_uploads[uid]
        bot.reply_to(message, "File unavailable.", parse_mode="HTML"); return True
    if not verify_vault_license(file_id, key):
        ctx["attempts"] += 1; record_vault_attempt(file_id, uid, False)
        remaining = VAULT_MAX_ATTEMPTS - count_recent_failed_attempts(file_id, uid)
        if remaining <= 0:
            del _pending_vault_uploads[uid]
            bot.reply_to(message, _panel("Locked", "Too many failures.", emoji="🔒"), parse_mode="HTML")
        else:
            bot.reply_to(message, _panel("Wrong Key", f"Incorrect.\n{remaining} attempts left.", emoji="✗"), parse_mode="HTML")
        return True
    del _pending_vault_uploads[uid]; record_vault_attempt(file_id, uid, True)
    try:
        file_key = private_key_cipher().decrypt(bytes(row["file_key_ciphertext"]))
        source = decrypt_vault_blob(ctx["blob"], file_key)
    except Exception:
        log.exception("Vault decrypt failed: %s", file_id)
        bot.reply_to(message, "Decryption failed.", parse_mode="HTML"); return True
    try:
        protected, _ = protect_python_source(source, mode="vault", filename=row["original_filename"], redact_secrets=True)
    except Exception as exc:
        log.exception("Vault protect failed: %s", file_id)
        bot.reply_to(message, f"Protection failed: <code>{_html(str(exc)[:300])}</code>", parse_mode="HTML"); return True
    out_name = Path(row["original_filename"]).stem + "_sealed.py"
    out = io.BytesIO(protected); out.name = safe_filename(out_name)
    caption = _panel("Sealed Build",
                     f"{_kv('File', _html(row['original_filename']))}\n"
                     f"{_kv('Mode', 'sealed (redacted)')}\n"
                     f"{_kv('SHA-256', f'<code>{hashlib.sha256(protected).hexdigest()[:24]}…</code>')}\n\n"
                     f"Fill in <code>MASTER_ENV</code> at the top before running.", emoji="✓")
    try: bot.send_document(message.chat.id, out, caption=caption, parse_mode="HTML", reply_to_message_id=message.message_id)
    except Exception: log.exception("Delivery failed"); bot.reply_to(message, "Delivery failed.", parse_mode="HTML"); return True
    with db_conn(immediate=True) as c:
        c.execute("UPDATE vault_files SET downloads=downloads+1, last_download_at=? WHERE file_id=?", (utc_ts(), file_id))
    audit(uid, "vault_file_delivered", row["owner_user_id"], {"file_id": file_id, "by_user": uid})
    return True


# ───── /files PORTAL ─────
def show_files_menu(message_or_call, bot):
    from telebot import types
    is_cb = hasattr(message_or_call, "data")
    source_message = message_or_call.message if is_cb else message_or_call
    uid = message_or_call.from_user.id
    chat_id = source_message.chat.id
    message_id = source_message.message_id
    with db_conn() as c:
        rows = c.execute("SELECT * FROM vault_files WHERE owner_user_id=? ORDER BY created_at DESC LIMIT 25", (uid,)).fetchall()
    if not rows:
        body = (f"You have no vault files yet.\n\n<b>To create one:</b>\n"
                f"{_b('Open /settings and pick Vault mode')}\n{_b('Upload a .py or .zip')}\n"
                f"{_b('Download the .poppy.enc the bot returns')}\n{_b('Come back here to set its license key')}")
        text = _panel("Vault Files", body, emoji="📁")
        kb = types.InlineKeyboardMarkup(row_width=1)
        kb.add(_button(types, "⚙️  Open Vault Mode", callback_data="mode:vault"))
        kb.add(_button(types, "‹  Back to Main Menu", callback_data="files:home"))
    else:
        total_dl = sum(r["downloads"] for r in rows)
        body = f"{len(rows)} file(s)  ·  {total_dl} total downloads\n\nTap a file to manage its license key."
        text = _panel("Vault Files", body, "Owner: you", emoji="📁")
        kb = types.InlineKeyboardMarkup(row_width=1)
        for r in rows:
            prefix = "✗" if r["revoked"] else ("✓" if r["license_key_hash"] else "○")
            name = r["original_filename"][:28]
            kb.add(_button(types, f"{prefix}  {name}   ·   {r['downloads']} dl",
                                              callback_data=f"vf:detail:{r['file_id']}"))
        kb.add(_button(types, "📊  Vault Stats", callback_data="vf:stats"))
        kb.add(_button(types, "‹  Back to Main Menu", callback_data="files:home"))
    if is_cb:
        bot.answer_callback_query(message_or_call.id)
        try: bot.edit_message_text(text, chat_id, message_id, parse_mode="HTML", reply_markup=kb)
        except Exception: bot.send_message(chat_id, text, parse_mode="HTML", reply_markup=kb)
    else: bot.reply_to(message_or_call, text, parse_mode="HTML", reply_markup=kb)


def show_file_detail(call, file_id: str, bot):
    from telebot import types
    uid = call.from_user.id
    with db_conn() as c:
        r = c.execute("SELECT * FROM vault_files WHERE file_id=? AND owner_user_id=?", (file_id, uid)).fetchone()
    if not r: bot.answer_callback_query(call.id, "Not found.", show_alert=True); return
    status = "Revoked" if r["revoked"] else "Active"
    key_status = f"Set (****{r['license_key_last4']})" if r["license_key_hash"] else "Not set"
    created = dt.datetime.fromtimestamp(r["created_at"], UTC).strftime("%Y-%m-%d %H:%M UTC")
    last_dl = "never" if not r["last_download_at"] else dt.datetime.fromtimestamp(r["last_download_at"], UTC).strftime("%Y-%m-%d %H:%M UTC")
    body = (f"{_kv('File', _html(r['original_filename']))}\n{_kv('ID', f'<code>{file_id}</code>')}\n"
            f"{_kv('Status', status)}\n{_kv('License', key_status)}\n"
            f"{_kv('Size', f'{r[chr(115)+chr(105)+chr(122)+chr(101)+chr(95)+chr(98)+chr(121)+chr(116)+chr(101)+chr(115)]/1024:.1f} KB')}\n"
            f"{_kv('Downloads', str(r['downloads']))}\n{_kv('Created', created)}\n{_kv('Last download', last_dl)}")
    kb = types.InlineKeyboardMarkup(row_width=2)
    if not r["revoked"]:
        set_label = "🔄 Rotate Key" if r["license_key_hash"] else "🔑 Set Key"
        kb.row(_button(types, set_label, callback_data=f"vf:setkey:{file_id}"),
               _button(types, "🚫 Revoke", callback_data=f"vf:revoke:{file_id}"))
    kb.row(_button(types, "🗑️ Delete", callback_data=f"vf:delete:{file_id}"),
           _button(types, "‹ Back", callback_data="vf:list"))
    bot.answer_callback_query(call.id)
    try: bot.edit_message_text(_panel("File Details", body, emoji="📄"), call.message.chat.id,
                               call.message.message_id, parse_mode="HTML", reply_markup=kb)
    except Exception: bot.send_message(call.message.chat.id, _panel("File Details", body, emoji="📄"),
                                        parse_mode="HTML", reply_markup=kb)


def show_vault_stats(call, bot):
    from telebot import types
    uid = call.from_user.id
    with db_conn() as c:
        total = c.execute("SELECT COUNT(*) FROM vault_files WHERE owner_user_id=?", (uid,)).fetchone()[0]
        active = c.execute("SELECT COUNT(*) FROM vault_files WHERE owner_user_id=? AND revoked=0", (uid,)).fetchone()[0]
        licensed = c.execute("SELECT COUNT(*) FROM vault_files WHERE owner_user_id=? AND license_key_hash IS NOT NULL", (uid,)).fetchone()[0]
        total_dl = c.execute("SELECT COALESCE(SUM(downloads),0) FROM vault_files WHERE owner_user_id=?", (uid,)).fetchone()[0]
        recent = c.execute("SELECT COUNT(*) FROM vault_attempts va JOIN vault_files vf ON va.file_id=vf.file_id "
                           "WHERE vf.owner_user_id=? AND va.created_at>=? AND va.success=1", (uid, utc_ts() - 86400)).fetchone()[0]
    body = (f"{_kv('Total files', str(total))}\n{_kv('Active', str(active))}\n"
            f"{_kv('With license', str(licensed))}\n{_kv('Total downloads', str(total_dl))}\n"
            f"{_kv('Downloads (24h)', str(recent))}")
    kb = types.InlineKeyboardMarkup(); kb.add(_button(types, "‹ Back", callback_data="vf:list"))
    bot.answer_callback_query(call.id)
    try: bot.edit_message_text(_panel("Vault Statistics", body, emoji="📊"), call.message.chat.id,
                               call.message.message_id, parse_mode="HTML", reply_markup=kb)
    except Exception: bot.send_message(call.message.chat.id, _panel("Vault Statistics", body, emoji="📊"),
                                        parse_mode="HTML", reply_markup=kb)


# ───── BOT HANDLERS ─────
def register_handlers(bot, owner_id: int) -> None:
    from telebot import types

    # Central outbound footer: covers ordinary text, edited menus and document captions.
    if not getattr(bot, "_poppy_brand_wrapped", False):
        _send_message = bot.send_message
        _reply_to = bot.reply_to
        _edit_message_text = bot.edit_message_text
        _send_document = bot.send_document

        def _wrap_text_method(method, text_index):
            def wrapped(*args, **kwargs):
                args = list(args)
                if len(args) > text_index:
                    args[text_index] = _brand_text(args[text_index])
                elif "text" in kwargs:
                    kwargs["text"] = _brand_text(kwargs["text"])
                return method(*args, **kwargs)
            return wrapped

        bot.send_message = _wrap_text_method(_send_message, 1)
        bot.reply_to = _wrap_text_method(_reply_to, 1)
        bot.edit_message_text = _wrap_text_method(_edit_message_text, 0)

        def _branded_send_document(*args, **kwargs):
            args = list(args)
            if len(args) > 2:
                args[2] = _brand_text(args[2] if args[2] is not None else DEV_FOOTER)
            elif "caption" in kwargs:
                kwargs["caption"] = _brand_text(kwargs["caption"] if kwargs["caption"] is not None else DEV_FOOTER)
            else:
                kwargs["caption"] = DEV_FOOTER
            return _send_document(*args, **kwargs)

        bot.send_document = _branded_send_document
        bot._poppy_brand_wrapped = True

    def reply(message, text, **kw): return bot.reply_to(message, text, parse_mode="HTML", **kw)
    def private_only(message) -> bool:
        if getattr(getattr(message, "chat", None), "type", "private") != "private":
            reply(message, "Private chat only."); return False
        return True

    def authorize(message, permission: Optional[str] = None) -> bool:
        uid = message.from_user.id
        touch_user(uid, getattr(message.from_user, "username", "") or "")
        account = user_record(uid)
        if not account or account["banned"] or account["suspended"]:
            reply(message, _panel("Access Disabled", "Contact the owner.", emoji="⛔")); return False
        if permission and not has_permission(uid, permission):
            reply(message, _panel("Permission Denied", "Your role does not allow this.", emoji="🚫")); return False
        if not permission and not user_allowed(uid):
            reply(message, _panel("Access Restricted", f"Your ID: <code>{uid}</code>\n\nAsk an admin to approve.", emoji="🔒"))
            return False
        return True

    def user_mode_keyboard(uid: int):
        cur = (user_record(uid) or {"mode": "portable"})["mode"]
        kb = types.InlineKeyboardMarkup(row_width=1)
        kb.add(_button(types, f"{_marker(cur=='portable')}  📦  Portable", callback_data="mode:portable"))
        kb.add(_button(types, f"{_marker(cur=='balanced')}  ⚖️  Balanced", callback_data="mode:balanced"))
        kb.add(_button(types, f"{_marker(cur=='fortress')}  🛡️  Fortress", callback_data="mode:fortress"))
        kb.add(_button(types, f"{_marker(cur=='vault')}  🔒  Vault (per-file license)", callback_data="mode:vault"))
        if has_permission(uid, "use_sealed_mode"):
            kb.add(_button(types, f"{_marker(cur=='sealed')}  🔐  Sealed (admin)", callback_data="mode:sealed"))
        if has_permission(uid, "manage_licenses") and (os.getenv("LICENSE_WRAPPER_URL", "").startswith("https://")
                                                       or (setting("license_tunnel_url", "") or "").startswith("https://")):
            kb.add(_button(types, f"{_marker(cur=='licensed')}  🎫  Licensed (verifier)", callback_data="mode:licensed"))
        kb.add(_button(types, "📁  Files", callback_data="files:open"))
        return kb

    def admin_keyboard():
        kb = types.InlineKeyboardMarkup(row_width=2)
        kb.row(_button(types, "🔐  Access", callback_data="adm:access"),
               _button(types, "👥  Admins", callback_data="adm:roles"))
        kb.row(_button(types, "🎁  Rewards", callback_data="adm:rewards"),
               _button(types, "🏆  Ranks", callback_data="adm:ranks"))
        kb.row(_button(types, "🗄️  Archive", callback_data="adm:archive"),
               _button(types, "🔑  Licensing", callback_data="adm:licenses"))
        kb.row(_button(types, "📊  Monitoring", callback_data="adm:monitor"),
               _button(types, "⚙️  Commands", callback_data="adm:commands"))
        return kb

    @bot.message_handler(commands=["start"])
    def cmd_start(message):
        uid = message.from_user.id
        touch_user(uid, getattr(message.from_user, "username", "") or "")
        if setting("access_mode", "authorized") == "public" and as_bool(setting("registration_enabled", "0")):
            with db_conn(immediate=True) as c:
                c.execute("UPDATE users SET allowed=1 WHERE user_id=? AND banned=0 AND suspended=0", (uid,))
        if not user_allowed(uid):
            return reply(message, _panel("Access Restricted",
                f"Your Telegram ID: <code>{uid}</code>\n\nAsk an administrator to approve.", emoji="🔒"))
        row = user_record(uid); rank = rank_for_user(uid)
        mode = row["mode"] if row else "portable"
        body = (f"{_kv('Rank', _html(rank['rank_name']))}\n"
                f"{_kv('Credits', str(row['credits'] if row else 0))}\n"
                f"{_kv('Mode', f'{EMOJI_MODE.get(mode, "•")}  {mode.title()}')}\n\n"
                f"<b>Actions</b>\n{_b('Send a .py or .zip to protect')}\n"
                f"{_b('/files — manage vault files')}\n{_b('/settings — choose a mode')}")
        reply(message, _panel(f"Poppy Vault · v{APP_VERSION}", body, emoji="🌹"),
              reply_markup=user_mode_keyboard(uid))

    @bot.message_handler(commands=["help"])
    def cmd_help(message):
        if not authorize(message): return
        body = (f"<b>Modes</b>\n{_b('📦  Portable — best compatibility')}\n"
                f"{_b('⚖️  Balanced — shuffled chunks')}\n{_b('🛡️  Fortress — layered obfuscation')}\n"
                f"{_b('🔒  Vault — per-file license')}\n{_b('🔐  Sealed — embed env (admin)')}\n"
                f"{_b('🎫  Licensed — runtime verifier (admin)')}\n\n"
                f"<b>Vault workflow</b>\n{_b('/settings → Vault')}\n"
                f"{_b('Upload .py or .zip → get .poppy.enc')}\n{_b('/files → set license key')}\n"
                f"{_b('Anyone with key can upload .poppy.enc')}\n\n"
                f"<b>Account</b>\n{_b('/profile  /daily  /redeem')}\n\n"
                f"<b>Admin</b>\n{_b('/admin  /stats  /newkey  /licenses')}\n"
                f"{_b('/license status|seturl|settoken')}")
        reply(message, _panel("Help", body, emoji="📖"))

    @bot.message_handler(commands=["myid"])
    def cmd_myid(message):
        touch_user(message.from_user.id, getattr(message.from_user, "username", "") or "")
        reply(message, _panel("Your Identity", f"<code>{message.from_user.id}</code>", emoji="👤"))

    @bot.message_handler(commands=["settings", "mode"])
    def cmd_settings(message):
        if not authorize(message): return
        cur = (user_record(message.from_user.id) or {"mode": "portable"})["mode"]
        body = f"Current: <b>{EMOJI_MODE.get(cur, '•')}  {cur.title()}</b>\n\nPick the mode used when you upload."
        reply(message, _panel("Mode Selection", body, emoji="⚙️"), reply_markup=user_mode_keyboard(message.from_user.id))

    @bot.callback_query_handler(func=lambda c: c.data.startswith("mode:"))
    def cb_mode(call):
        uid = call.from_user.id
        if not user_allowed(uid): bot.answer_callback_query(call.id, "Restricted.", show_alert=True); return
        mode = call.data.split(":", 1)[1]
        if mode not in ALL_MODES: bot.answer_callback_query(call.id, "Invalid mode."); return
        if mode == "sealed" and not has_permission(uid, "use_sealed_mode"):
            bot.answer_callback_query(call.id, "Admin only.", show_alert=True); return
        if mode == "licensed":
            url = os.getenv("LICENSE_WRAPPER_URL", "").strip() or (setting("license_tunnel_url", "") or "")
            if not has_permission(uid, "manage_licenses") or not url.startswith("https://"):
                bot.answer_callback_query(call.id, "Admin + HTTPS URL required.", show_alert=True); return
        with db_conn(immediate=True) as c:
            c.execute("UPDATE users SET mode=? WHERE user_id=?", (mode, uid))
        bot.answer_callback_query(call.id, f"Mode: {mode.title()}")
        try: bot.edit_message_text(_panel("Mode Saved", f"Mode: <b>{EMOJI_MODE.get(mode, '•')}  {mode.title()}</b>\n\nSend a .py or .zip.", emoji="✓"),
                                    call.message.chat.id, call.message.message_id, parse_mode="HTML",
                                    reply_markup=user_mode_keyboard(uid))
        except Exception: pass

    @bot.callback_query_handler(func=lambda c: c.data == "files:open")
    def cb_files_open(call):
        show_files_menu(call, bot)

    @bot.callback_query_handler(func=lambda c: c.data == "files:home")
    def cb_files_home(call):
        uid = call.from_user.id
        if not user_allowed(uid):
            bot.answer_callback_query(call.id, "Access restricted.", show_alert=True)
            return
        row = user_record(uid)
        rank = rank_for_user(uid)
        mode = row["mode"] if row else "portable"
        body = (f"{_kv('Rank', _html(rank['rank_name']))}\n"
                f"{_kv('Credits', str(row['credits'] if row else 0))}\n"
                f"{_kv('Mode', f'{EMOJI_MODE.get(mode, "•")}  {mode.title()}')}\n\n"
                f"<b>Actions</b>\n{_b('Send a .py or .zip to protect')}\n"
                f"{_b('/files — manage vault files')}\n{_b('/settings — choose a mode')}")
        bot.answer_callback_query(call.id)
        try:
            bot.edit_message_text(_panel(f"Poppy Vault · v{APP_VERSION}", body, emoji="🌹"),
                                  call.message.chat.id, call.message.message_id,
                                  parse_mode="HTML", reply_markup=user_mode_keyboard(uid))
        except Exception:
            bot.send_message(call.message.chat.id,
                             _panel(f"Poppy Vault · v{APP_VERSION}", body, emoji="🌹"),
                             reply_markup=user_mode_keyboard(uid))

    @bot.message_handler(commands=["files", "vault"])
    def cmd_files(message):
        if not private_only(message): return
        if not authorize(message): return
        show_files_menu(message, bot)

    @bot.callback_query_handler(func=lambda c: c.data.startswith("vf:"))
    def cb_vault(call):
        parts = call.data.split(":"); action = parts[1] if len(parts) > 1 else ""; uid = call.from_user.id
        if action == "list": show_files_menu(call, bot)
        elif action == "detail" and len(parts) >= 3: show_file_detail(call, parts[2], bot)
        elif action == "stats": show_vault_stats(call, bot)
        elif action == "setkey" and len(parts) >= 3:
            file_id = parts[2]
            with db_conn() as c:
                row = c.execute("SELECT 1 FROM vault_files WHERE file_id=? AND owner_user_id=?", (file_id, uid)).fetchone()
            if not row: bot.answer_callback_query(call.id, "Not found.", show_alert=True); return
            _vault_key_input[uid] = {"file_id": file_id, "expires": utc_ts() + VAULT_KEY_INPUT_TTL}
            bot.answer_callback_query(call.id)
            key_kb = types.InlineKeyboardMarkup()
            key_kb.add(_button(types, "‹  Back to File Details", callback_data="vf:detail:" + file_id))
            bot.send_message(call.message.chat.id, _panel("Set License Key",
                f"Send the license key for this file.\n\n<b>Requirements</b>\n"
                f"{_b('6-128 characters')}\n{_b('Stored as HMAC hash — cannot be retrieved')}\n"
                f"{_b('Required on every upload')}", "Reply within 5 minutes", emoji="🔑"),
                parse_mode="HTML", reply_markup=key_kb)
        elif action == "revoke" and len(parts) >= 3:
            file_id = parts[2]; kb = types.InlineKeyboardMarkup()
            kb.row(_button(types, "✓  Yes, revoke", callback_data=f"vf:doconfirm:{file_id}:revoke"),
                   _button(types, "‹ Cancel", callback_data=f"vf:detail:{file_id}"))
            bot.answer_callback_query(call.id)
            try: bot.edit_message_text(_panel("Confirm Revoke",
                "Revoking prevents anyone from decrypting this file.\n\nThis cannot be undone.",
                f"ID: {file_id}", emoji="🚫"), call.message.chat.id, call.message.message_id,
                parse_mode="HTML", reply_markup=kb)
            except Exception: pass
        elif action == "delete" and len(parts) >= 3:
            file_id = parts[2]; kb = types.InlineKeyboardMarkup()
            kb.row(_button(types, "✓  Yes, delete", callback_data=f"vf:doconfirm:{file_id}:delete"),
                   _button(types, "‹ Cancel", callback_data=f"vf:detail:{file_id}"))
            bot.answer_callback_query(call.id)
            try: bot.edit_message_text(_panel("Confirm Delete",
                "Permanently deletes the vault file and its license.\n\nThis cannot be undone.",
                f"ID: {file_id}", emoji="🗑️"), call.message.chat.id, call.message.message_id,
                parse_mode="HTML", reply_markup=kb)
            except Exception: pass
        elif action == "doconfirm" and len(parts) >= 4:
            file_id, op = parts[2], parts[3]
            if op == "revoke":
                with db_conn(immediate=True) as c:
                    c.execute("UPDATE vault_files SET revoked=1 WHERE file_id=? AND owner_user_id=?", (file_id, uid))
                audit(uid, "vault_file_revoked", uid, {"file_id": file_id}); bot.answer_callback_query(call.id, "Revoked.")
            elif op == "delete":
                with db_conn(immediate=True) as c:
                    c.execute("DELETE FROM vault_files WHERE file_id=? AND owner_user_id=?", (file_id, uid))
                audit(uid, "vault_file_deleted", uid, {"file_id": file_id}); bot.answer_callback_query(call.id, "Deleted.")
            show_files_menu(call, bot)
        else: bot.answer_callback_query(call.id)

    @bot.message_handler(func=lambda m: m.from_user.id in _vault_key_input, content_types=["text"])
    def _vault_key_input_handler(message):
        uid = message.from_user.id; ctx = _vault_key_input.get(uid)
        if not ctx: return
        if ctx["expires"] < utc_ts(): del _vault_key_input[uid]; reply(message, "Expired."); return
        key = (message.text or "").strip()
        if len(key) < 6 or len(key) > 128: reply(message, "Key must be 6-128 characters."); return
        file_id = ctx["file_id"]; del _vault_key_input[uid]
        if not set_vault_license_key(file_id, uid, key): reply(message, "File not found."); return
        audit(uid, "vault_key_set", uid, {"file_id": file_id})
        reply(message, _panel("License Key Set",
            f"{_kv('File', file_id)}\n{_kv('Key', f'****{key[-4:]}')}\n\n"
            f"<b>Important</b>\n{_b('Full key not shown again — save it now')}\n"
            f"{_b('Share only with intended recipients')}\n{_b('/files to manage more')}",
            "Keep this key safe", emoji="✓"))

    @bot.message_handler(commands=["profile"])
    def cmd_profile(message):
        if not private_only(message): return
        if not authorize(message): return
        uid = message.from_user.id; user = user_record(uid); rank = rank_for_user(uid)
        with db_conn() as c:
            usage = usage_for(c, uid, month_key())
            vault_count = c.execute("SELECT COUNT(*) FROM vault_files WHERE owner_user_id=?", (uid,)).fetchone()[0]
        body = (f"{_kv('Rank', _html(rank['rank_name']))}\n{_kv('Credits', str(user['credits']))}\n"
                f"{_kv('Lifetime jobs', str(user['lifetime_jobs']))}\n"
                f"{_kv('Monthly', f'{usage[chr(99)+chr(111)+chr(109)+chr(112)+chr(108)+chr(101)+chr(116)+chr(101)+chr(100)+chr(95)+chr(106)+chr(111)+chr(98)+chr(115)]} / {rank[chr(109)+chr(111)+chr(110)+chr(116)+chr(104)+chr(108)+chr(121)+chr(95)+chr(108)+chr(105)+chr(109)+chr(105)+chr(116)]}')}\n"
                f"{_kv('Streak', f'{user[chr(115)+chr(116)+chr(114)+chr(101)+chr(97)+chr(107)]} days')}\n"
                f"{_kv('Vault files', str(vault_count))}\n"
                f"{_kv('Mode', f'{EMOJI_MODE.get(user[chr(109)+chr(111)+chr(100)+chr(101)], chr(8226))}  {user[chr(109)+chr(111)+chr(100)+chr(101)].title()}')}")
        reply(message, _panel("Your Profile", body, emoji="👤"))

    @bot.message_handler(commands=["daily"])
    def cmd_daily(message):
        uid = message.from_user.id
        if setting("access_mode", "authorized") != "public":
            return reply(message, "Daily rewards available only in public mode.")
        if not authorize(message): return
        if not rate_limit(f"daily:{uid}", limit=3, window=3600): return reply(message, "Rate limited.")
        user = user_record(uid)
        if user["daily_cooldown_until"] > utc_ts(): return reply(message, "Cooldown active.")
        if user["last_daily"] == utc_day(): return reply(message, "Already claimed today.")
        code, q = create_captcha(uid)
        reply(message, _panel("Daily Reward", f"Solve: <code>{q} = ?</code>\n\nReply: <code>/captcha {code} ANSWER</code>",
                              "Expires in 5 minutes", emoji="🎁"))

    @bot.message_handler(commands=["captcha"])
    def cmd_captcha(message):
        parts = (message.text or "").split()
        if len(parts) != 3: return reply(message, "Usage: <code>/captcha CODE ANSWER</code>")
        ok, status, amount = answer_captcha(message.from_user.id, parts[1], parts[2])
        if ok:
            user = user_record(message.from_user.id)
            return reply(message, _panel("Reward Claimed", f"+{amount} credits\nBalance: {user['credits']}\nStreak: {user['streak']} days", emoji="✓"))
        reply(message, f"Failed: {status}")

    @bot.message_handler(commands=["redeem"])
    def cmd_redeem(message):
        if not private_only(message): return
        if not authorize(message): return
        parts = (message.text or "").split(maxsplit=1)
        if len(parts) != 2: return reply(message, "Usage: <code>/redeem LICENSE_KEY</code>")
        uid = message.from_user.id
        ok, reason = redeem_license(uid, parts[1].strip())
        if ok: reply(message, _panel("License Redeemed", "You can now use /decrypt.", emoji="✓"))
        else: reply(message, _panel("Rejected", f"<code>{_html(reason)}</code>", emoji="✗"))

    @bot.message_handler(commands=["decrypt"])
    def cmd_decrypt(message):
        if not private_only(message): return
        if not authorize(message): return
        uid = message.from_user.id
        lic = get_user_license(uid)
        if not lic: return reply(message, _panel("No Active License", "Use /redeem KEY first.", emoji="🔑"))
        try:
            pub, priv_ct = generate_job_keys()
            cost = int(setting("credit_cost", "1") or 1)
            rank = rank_for_user(uid)
            limit = min(int(rank["max_file_bytes"]), MAX_DOWNLOAD_BYTES - 65536)
            job_id = reserve_job(uid, lic, pub, priv_ct, cost, limit)
        except Exception as exc:
            return reply(message, f"Job creation failed: <code>{_html(str(exc))}</code>")
        try:
            reply(message, _panel("Decrypt Job",
                f"{_kv('Job ID', f'<code>{job_id}</code>')}\n{_kv('Expires', '15 minutes')}\n"
                f"{_kv('Max size', f'{limit/(1024*1024):.1f} MB')}\n\n<b>Steps</b>\n"
                f"{_b('Download public key + poppy_encrypt.py')}\n"
                f"{_b(f'Run: python poppy_encrypt.py {job_id}_public.pem YOUR_FILE --job {job_id}')}\n"
                f"{_b('Upload the .poppy.enc here')}", emoji="🔐"))
            pf = io.BytesIO(pub); pf.name = f"{job_id}_public.pem"
            bot.send_document(message.chat.id, pf, caption=f"Public key for {job_id}")
            uf = io.BytesIO(EMBEDDED_ENCRYPT_UTILITY.encode()); uf.name = "poppy_encrypt.py"
            bot.send_document(message.chat.id, uf, caption="Local encryption utility")
        except Exception:
            _fail_job(job_id, "delivery_failed"); reply(message, "Delivery failed — refunded.")

    # ── ADMIN ──
    @bot.message_handler(commands=["admin"])
    def cmd_admin(message):
        if not private_only(message): return
        if not authorize(message, "view_admin"): return
        body = (f"{_kv('Role', _html(admin_role(message.from_user.id) or 'Admin'))}\n"
                f"{_kv('Access', setting('access_mode', 'authorized'))}\n"
                f"{_kv('Maintenance', 'on' if as_bool(setting('maintenance_mode', '0')) else 'off')}")
        reply(message, _panel("Admin Panel", body, emoji="🛠️"), reply_markup=admin_keyboard())

    @bot.callback_query_handler(func=lambda c: c.data.startswith("adm:"))
    def cb_admin(call):
        uid = call.from_user.id
        action = call.data.split(":", 1)[1]
        perm_map = {"access": "manage_access", "roles": "manage_admins", "rewards": "manage_rewards",
                    "ranks": "manage_ranks", "archive": "manage_archive", "licenses": "manage_licenses",
                    "monitor": "view_monitoring", "commands": "view_admin", "back": "view_admin",
                    "toggle_access": "manage_access", "toggle_registration": "manage_access",
                    "toggle_maintenance": "manage_access", "toggle_archive": "manage_archive"}
        if not user_allowed(uid) or not has_permission(uid, perm_map.get(action, "view_admin")):
            bot.answer_callback_query(call.id, "Permission denied.", show_alert=True); return
        if action == "toggle_access":
            new = "public" if setting("access_mode", "authorized") == "authorized" else "authorized"
            set_setting("access_mode", new); bot.answer_callback_query(call.id, f"Access: {new}"); action = "access"
        elif action == "toggle_registration":
            new = "0" if as_bool(setting("registration_enabled", "0")) else "1"
            set_setting("registration_enabled", new); bot.answer_callback_query(call.id, "Toggled"); action = "access"
        elif action == "toggle_maintenance":
            new = "0" if as_bool(setting("maintenance_mode", "0")) else "1"
            set_setting("maintenance_mode", new); bot.answer_callback_query(call.id, "Toggled"); action = "access"
        elif action == "toggle_archive":
            new = "0" if as_bool(setting("archive_enabled", "0")) else "1"
            set_setting("archive_enabled", new); bot.answer_callback_query(call.id, "Toggled"); action = "archive"
        else: bot.answer_callback_query(call.id)

        if action == "back":
            body = (f"{_kv('Role', _html(admin_role(uid) or 'Admin'))}\n"
                    f"{_kv('Access', setting('access_mode', 'authorized'))}\n"
                    f"{_kv('Maintenance', 'on' if as_bool(setting('maintenance_mode', '0')) else 'off')}")
            text = _panel("Admin Panel", body, emoji="🛠️"); kb = admin_keyboard()
        elif action == "access":
            body = (f"{_kv('Access', setting('access_mode', 'authorized'))}\n"
                    f"{_kv('Registration', 'on' if as_bool(setting('registration_enabled','0')) else 'off')}\n"
                    f"{_kv('Maintenance', 'on' if as_bool(setting('maintenance_mode','0')) else 'off')}\n\n"
                    f"<b>Commands</b>\n{_b('/approve ID  ·  /deny ID confirm')}\n"
                    f"{_b('/ban ID confirm  ·  /unban ID')}\n{_b('/suspend ID confirm  ·  /restore ID')}")
            text = _panel("Access Management", body, emoji="🔐")
            kb = types.InlineKeyboardMarkup(row_width=1)
            kb.add(_button(types, "🔄  Toggle access", callback_data="adm:toggle_access"))
            kb.add(_button(types, "🔄  Toggle registration", callback_data="adm:toggle_registration"))
            kb.add(_button(types, "🔄  Toggle maintenance", callback_data="adm:toggle_maintenance"))
            kb.add(_button(types, "‹ Back", callback_data="adm:back"))
        elif action == "roles":
            with db_conn() as c:
                rows = c.execute("SELECT ar.user_id, ar.role, u.username FROM admin_roles ar "
                                 "LEFT JOIN users u ON u.user_id=ar.user_id "
                                 "ORDER BY ar.added_at DESC LIMIT 25").fetchall()
            lines = [f"{_kv('Total', str(len(rows)))}", ""]
            for r in rows:
                uname = f"@{r['username']}" if r["username"] else f"<code>{r['user_id']}</code>"
                lines.append(_b(f"{r['role']:<12}  {uname}"))
            lines += ["", "<b>Commands</b>", _b("/addadmin ID Super Admin|Admin|Moderator"), _b("/deladmin ID confirm")]
            text = _panel("Administrator Hierarchy", "\n".join(lines), emoji="👥")
            kb = types.InlineKeyboardMarkup(); kb.add(_button(types, "‹ Back", callback_data="adm:back"))
        elif action == "rewards":
            body = (f"{_kv('Daily', setting('daily_reward', '5'))}\n{_kv('Wallet cap', setting('wallet_cap', '500'))}\n"
                    f"{_kv('Credit cost', setting('credit_cost', '1'))}\n"
                    f"{_kv('Streak', _html(setting('streak_rewards', '{}'))[:60])}\n"
                    f"{_kv('Milestone', _html(setting('milestone_rewards', '{}'))[:60])}\n\n"
                    f"<b>Commands</b>\n{_b('/setreward DAILY CAP COST')}\n{_b('/setstreak DAYS BONUS')}\n"
                    f"{_b('/setmilestone DAYS BONUS')}\n{_b('/credits USER_ID AMOUNT')}")
            text = _panel("Reward Configuration", body, emoji="🎁")
            kb = types.InlineKeyboardMarkup(); kb.add(_button(types, "‹ Back", callback_data="adm:back"))
        elif action == "ranks":
            with db_conn() as c: ranks = c.execute("SELECT * FROM rank_config ORDER BY threshold").fetchall()
            lines = []
            for r in ranks:
                mb = r["max_file_bytes"] // (1024 * 1024)
                marker = "●" if r["processing_enabled"] else "○"
                lines.append(_b(f"{marker}  {r['rank_name']:<10}  {r['threshold']:>4} jobs  ·  {r['monthly_limit']}/mo  ·  {mb} MB"))
            lines += ["", "<b>Commands</b>", _b("/setrankconfig NAME THRESHOLD LIMIT MAX_MB 1|0"), _b("/setrank USER_ID RANK")]
            text = _panel("Rank Configuration", "\n".join(lines), emoji="🏆")
            kb = types.InlineKeyboardMarkup(); kb.add(_button(types, "‹ Back", callback_data="adm:back"))
        elif action == "archive":
            enabled = "on" if as_bool(setting("archive_enabled", "0")) else "off"
            group = setting("archive_group_id", "") or "not set"
            body = (f"{_kv('Enabled', enabled)}\n{_kv('Group', _html(group))}\n"
                    f"{_kv('Original', 'on' if as_bool(setting('archive_original','0')) else 'off')}\n"
                    f"{_kv('Protected', 'on' if as_bool(setting('archive_protected','1')) else 'off')}\n"
                    f"{_kv('Reports', 'on' if as_bool(setting('archive_reports','1')) else 'off')}\n"
                    f"{_kv('Metadata', 'on' if as_bool(setting('archive_metadata','1')) else 'off')}\n\n"
                    f"<b>Commands</b>\n{_b('/setarchive (in group) or /setarchive -100...')}\n"
                    f"{_b('/archivecategory original|protected|reports|metadata on|off')}\n{_b('/archive test')}")
            text = _panel("Archive Management", body, emoji="🗄️")
            kb = types.InlineKeyboardMarkup(row_width=1)
            kb.add(_button(types, "🔄  Toggle archive", callback_data="adm:toggle_archive"))
            kb.add(_button(types, "‹ Back", callback_data="adm:back"))
        elif action == "licenses":
            body = (f"<b>User Licenses</b>\n{_b('/newkey DAYS USES PLAN [ID]')}\n"
                    f"{_b('/licenses  ·  /revokekey KEY confirm')}\n{_b('/license status|seturl|settoken')}\n\n"
                    f"<b>Vault Files</b>\n{_b('Users create .poppy.enc via /settings → Vault')}\n"
                    f"{_b('Per-file keys set via /files')}")
            text = _panel("Licensing", body, emoji="🔑")
            kb = types.InlineKeyboardMarkup(); kb.add(_button(types, "‹ Back", callback_data="adm:back"))
        elif action == "monitor":
            with db_conn() as c:
                users = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
                vault = c.execute("SELECT COUNT(*) FROM vault_files").fetchone()[0]
                jobs = dict(c.execute("SELECT status, COUNT(*) FROM jobs GROUP BY status").fetchall())
                licenses = c.execute("SELECT COUNT(*) FROM licenses").fetchone()[0]
                audit_24h = c.execute("SELECT COUNT(*) FROM audit_events WHERE created_at>=?", (utc_ts() - 86400,)).fetchone()[0]
            body = (f"{_kv('Users', str(users))}\n{_kv('Licenses', str(licenses))}\n"
                    f"{_kv('Vault files', str(vault))}\n{_kv('Jobs pending', str(jobs.get('pending', 0)))}\n"
                    f"{_kv('Jobs completed', str(jobs.get('completed', 0)))}\n"
                    f"{_kv('Audit events (24h)', str(audit_24h))}")
            text = _panel("Monitoring", body, emoji="📊")
            kb = types.InlineKeyboardMarkup(); kb.add(_button(types, "‹ Back", callback_data="adm:back"))
        elif action == "commands":
            body = (f"<b>Access</b>\n{_b('/approve  ·  /deny  ·  /ban  ·  /unban')}\n"
                    f"{_b('/suspend  ·  /restore')}\n\n<b>Rewards</b>\n"
                    f"{_b('/setreward  ·  /setstreak  ·  /setmilestone  ·  /credits')}\n\n"
                    f"<b>Ranks</b>\n{_b('/setrankconfig  ·  /setrank')}\n\n<b>Archive</b>\n"
                    f"{_b('/setarchive  ·  /archive  ·  /archivecategory')}\n\n<b>Licensing</b>\n"
                    f"{_b('/newkey  ·  /licenses  ·  /revokekey  ·  /license')}\n\n<b>Monitoring</b>\n"
                    f"{_b('/stats  ·  /report  ·  /backup')}")
            text = _panel("All Commands", body, emoji="⚙️")
            kb = types.InlineKeyboardMarkup(); kb.add(_button(types, "‹ Back", callback_data="adm:back"))
        else:
            text = _panel("Admin Panel", "Unknown section.", emoji="🛠️"); kb = admin_keyboard()
        try:
            bot.edit_message_text(text, call.message.chat.id, call.message.message_id, parse_mode="HTML", reply_markup=kb)
        except Exception:
            try: bot.send_message(call.message.chat.id, text, parse_mode="HTML", reply_markup=kb)
            except Exception: log.exception("Admin panel render failed")

    @bot.message_handler(commands=["approve", "allow", "deny", "ban", "unban", "suspend", "restore"])
    def cmd_user_control(message):
        cmd = message.text.split()[0].split("@")[0][1:].lower()
        if not authorize(message, "manage_users"): return
        parts = (message.text or "").split(); destructive = cmd in {"deny", "ban", "suspend"}
        if len(parts) != (3 if destructive else 2) or not parts[1].isdigit():
            return reply(message, f"Usage: /{cmd} ID" + (" confirm" if destructive else ""))
        if destructive and parts[2].lower() != "confirm": return reply(message, "Add 'confirm' to run.")
        target = int(parts[1])
        if target == owner_id: return reply(message, "Cannot modify Owner.")
        touch_user(target)
        mapping = {"approve": ("allowed", 1), "allow": ("allowed", 1), "deny": ("allowed", 0),
                   "ban": ("banned", 1), "unban": ("banned", 0),
                   "suspend": ("suspended", 1), "restore": ("suspended", 0)}
        col, val = mapping[cmd]
        with db_conn(immediate=True) as c: c.execute(f"UPDATE users SET {col}=? WHERE user_id=?", (val, target))
        audit(message.from_user.id, f"user_{cmd}", target); reply(message, f"Updated <code>{target}</code>")

    @bot.message_handler(commands=["addadmin", "deladmin"])
    def cmd_admin_roles(message):
        cmd = message.text.split()[0].split("@")[0][1:].lower()
        if not is_owner(message.from_user.id): return reply(message, "Only Owner.")
        parts = (message.text or "").split(maxsplit=2)
        if cmd == "addadmin":
            if len(parts) != 3 or not parts[1].isdigit() or parts[2] not in {"Super Admin", "Admin", "Moderator"}:
                return reply(message, "Usage: /addadmin ID Super Admin|Admin|Moderator")
            target, role = int(parts[1]), parts[2]
            if target == owner_id: return reply(message, "Owner immutable.")
            touch_user(target)
            with db_conn(immediate=True) as c:
                c.execute("INSERT INTO admin_roles(user_id,role,added_by,added_at) VALUES(?,?,?,?) "
                          "ON CONFLICT(user_id) DO UPDATE SET role=excluded.role,added_by=excluded.added_by,added_at=excluded.added_at",
                          (target, role, message.from_user.id, utc_ts()))
                c.execute("UPDATE users SET allowed=1 WHERE user_id=?", (target,))
            reply(message, f"Assigned <b>{_html(role)}</b> to <code>{target}</code>.")
        else:
            if len(parts) != 3 or not parts[1].isdigit() or parts[2].lower() != "confirm":
                return reply(message, "Usage: /deladmin ID confirm")
            target = int(parts[1])
            if target == owner_id: return reply(message, "Owner immutable.")
            with db_conn(immediate=True) as c:
                cur = c.execute("DELETE FROM admin_roles WHERE user_id=?", (target,))
                c.execute("UPDATE users SET allowed=0 WHERE user_id=?", (target,))
            reply(message, "Removed." if cur.rowcount else "Not found.")

    @bot.message_handler(commands=["newkey"])
    def cmd_newkey(message):
        if not private_only(message): return
        if not authorize(message, "manage_licenses"): return
        parts = (message.text or "").split()
        try:
            days = int(parts[1]) if len(parts) >= 4 else 30
            uses = int(parts[2]) if len(parts) >= 4 else 5
            plan = parts[3] if len(parts) >= 4 else "standard"
            bind = int(parts[4]) if len(parts) == 5 else None
            key = create_license(days, uses, plan, bind)
        except Exception as exc: return reply(message, f"Error: {_html(str(exc))}")
        reply(message, _panel("License Created",
            f"<code>{key}</code>\n\n{_kv('Plan', _html(plan))}\n"
            f"{_kv('Duration', 'never' if not days else f'{days} days')}\n{_kv('Uses', str(uses))}",
            "Copy now — shown only once", emoji="🔑"))

    @bot.message_handler(commands=["licenses"])
    def cmd_licenses(message):
        if not private_only(message): return
        if not authorize(message, "manage_licenses"): return
        with db_conn() as c:
            rows = c.execute("SELECT key_last4,plan,expires_at,uses,max_uses,revoked "
                             "FROM licenses ORDER BY created_at DESC LIMIT 20").fetchall()
        if not rows: return reply(message, _panel("Licenses", "None yet.", emoji="🔑"))
        lines = []
        for r in rows:
            st = "✗" if r["revoked"] else "✓"
            exp = "never" if not r["expires_at"] else dt.datetime.fromtimestamp(r["expires_at"], UTC).strftime("%Y-%m-%d")
            lines.append(_b(f"{st}  ••••{r['key_last4']}  ·  {r['plan']}  ·  {r['uses']}/{r['max_uses']}  ·  {exp}"))
        reply(message, _panel("Licenses", "\n".join(lines), emoji="🔑"))

    @bot.message_handler(commands=["revokekey"])
    def cmd_revokekey(message):
        if not authorize(message, "manage_licenses"): return
        parts = (message.text or "").split(maxsplit=2)
        if len(parts) < 3 or parts[2].lower() != "confirm":
            return reply(message, "Usage: <code>/revokekey KEY confirm</code>")
        ok = revoke_license(parts[1].strip())
        reply(message, "Revoked." if ok else "Not found.")

    @bot.message_handler(commands=["license"])
    def cmd_license(message):
        if not private_only(message): return
        if not authorize(message, "manage_licenses"): return
        parts = (message.text or "").split()
        sub = parts[1].lower() if len(parts) > 1 else "status"
        if sub == "status":
            url = setting("license_tunnel_url", "") or "(not set)"; admin = _lic_admin_secret()
            body = (f"{_kv('Flask', f'127.0.0.1:{LICENSE_SERVER_PORT} ({"✓" if _LICENSE_SERVER_STARTED else "✗"})')}\n"
                    f"{_kv('Tunnel URL', _html(url))}\n{_kv('Admin secret', f'<code>{_html(admin)}</code>')}\n\n"
                    f"<b>Commands</b>\n{_b('/license settoken TOKEN')}\n"
                    f"{_b('/license seturl https://...')}\n{_b('/license start  ·  /license stop')}")
            reply(message, _panel("License Status", body, emoji="🔑"))
        elif sub == "seturl" and len(parts) == 3 and parts[2].startswith("https://"):
            set_setting("license_tunnel_url", parts[2].rstrip("/")); reply(message, "Saved.")
        elif sub == "settoken" and len(parts) == 3:
            set_setting("license_tunnel_token", parts[2].strip()); reply(message, "Saved.")
        elif sub == "start":
            try: reply(message, f"<code>{_html(cloudflared_start())[:300]}</code>")
            except Exception as exc: reply(message, f"Error: {_html(str(exc))}")
        elif sub == "stop": reply(message, _html(cloudflared_stop()))

    @bot.message_handler(commands=["tunnel"])
    def cmd_tunnel(message):
        if not authorize(message, "manage_access"): return
        parts = (message.text or "").split(); sub = parts[1].lower() if len(parts) > 1 else "status"
        try:
            if sub == "status": r = cloudflared_status()
            elif sub == "configure":
                rest = (message.text or "").split(maxsplit=2)
                if len(rest) < 3: return reply(message, "Usage: /tunnel configure TOKEN")
                r = cloudflared_configure(rest[2])
            elif sub == "install": r = "Installed: " + str((_cf_install(force=True))[1])
            elif sub == "start": r = cloudflared_start()
            elif sub == "stop": r = cloudflared_stop()
            elif sub == "reset": r = cloudflared_reset()
            else: return reply(message, "Usage: /tunnel status|configure|install|start|stop|reset")
            reply(message, f"<pre>{_html(r)[:2000]}</pre>")
        except Exception as exc: reply(message, f"Error: {_html(str(exc))}")

    @bot.message_handler(commands=["stats"])
    def cmd_stats(message):
        if not private_only(message): return
        if not authorize(message, "view_monitoring"): return
        with db_conn() as c:
            users = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            vault = c.execute("SELECT COUNT(*) FROM vault_files").fetchone()[0]
            jobs = dict(c.execute("SELECT status, COUNT(*) FROM jobs GROUP BY status").fetchall())
        body = (f"{_kv('Users', str(users))}\n{_kv('Vault files', str(vault))}\n"
                f"{_kv('Jobs pending', str(jobs.get('pending', 0)))}\n"
                f"{_kv('Jobs completed', str(jobs.get('completed', 0)))}")
        reply(message, _panel("Statistics", body, emoji="📊"))

    @bot.message_handler(commands=["setreward"])
    def cmd_setreward(message):
        if not authorize(message, "manage_rewards"): return
        parts = (message.text or "").split()
        if len(parts) != 4: return reply(message, "Usage: /setreward DAILY CAP COST")
        try:
            daily, cap, cost = map(int, parts[1:])
            if not (0 <= daily <= 10000 and 1 <= cap <= 1000000 and 1 <= cost <= 10000):
                raise ValueError()
        except Exception: return reply(message, "Values out of range.")
        for k, v in (("daily_reward", daily), ("wallet_cap", cap), ("credit_cost", cost)):
            set_setting(k, v)
        reply(message, "Updated.")

    @bot.message_handler(commands=["credits"])
    def cmd_credits(message):
        if not authorize(message, "manage_rewards"): return
        parts = (message.text or "").split()
        if len(parts) != 3 or not parts[1].isdigit() or not parts[2].lstrip("-").isdigit():
            return reply(message, "Usage: /credits USER_ID AMOUNT")
        target, amount = int(parts[1]), int(parts[2])
        touch_user(target)
        try:
            with db_conn(immediate=True) as c:
                row = c.execute("SELECT credits,reserved_credits FROM users WHERE user_id=?", (target,)).fetchone()
                if amount > 0:
                    cap = int(setting("wallet_cap", "500") or 500)
                    amount = min(amount, max(0, cap - row["credits"] - row["reserved_credits"]))
                balance = int(row["credits"]) + amount
                if balance < 0: raise ValueError("Insufficient.")
                c.execute("UPDATE users SET credits=? WHERE user_id=?", (balance, target))
                c.execute("INSERT INTO credit_ledger(user_id,delta,balance_after,reason,ref_id,created_at) VALUES(?,?,?,?,?,?)",
                          (target, amount, balance, "admin_adjustment", str(message.from_user.id), utc_ts()))
        except Exception as exc: return reply(message, f"Failed: {_html(str(exc))}")
        reply(message, f"Adjusted by {amount}. Balance: {balance}.")

    @bot.message_handler(commands=["setrank"])
    def cmd_setrank(message):
        if not authorize(message, "manage_ranks"): return
        parts = (message.text or "").split()
        if len(parts) != 3 or not parts[1].isdigit(): return reply(message, "Usage: /setrank USER_ID RANK")
        target, name = int(parts[1]), parts[2].title()
        with db_conn(immediate=True) as c:
            if not c.execute("SELECT 1 FROM rank_config WHERE rank_name=?", (name,)).fetchone():
                return reply(message, "Unknown rank.")
            cur = c.execute("UPDATE users SET rank_override=? WHERE user_id=?", (name, target))
        reply(message, "Saved." if cur.rowcount else "User not found.")

    @bot.message_handler(commands=["setrankconfig"])
    def cmd_setrankconfig(message):
        if not authorize(message, "manage_ranks"): return
        parts = (message.text or "").split()
        if len(parts) != 6: return reply(message, "Usage: /setrankconfig NAME THRESHOLD LIMIT MAX_MB 1|0")
        name = parts[1].title()
        try:
            threshold, limit, max_mb, enabled = int(parts[2]), int(parts[3]), int(parts[4]), int(parts[5])
            if threshold < 0 or limit < 0 or max_mb < 1 or enabled not in {0, 1}: raise ValueError()
        except ValueError: return reply(message, "Invalid values.")
        with db_conn(immediate=True) as c:
            cur = c.execute("UPDATE rank_config SET threshold=?,monthly_limit=?,max_file_bytes=?,processing_enabled=? WHERE rank_name=?",
                            (threshold, limit, max_mb * 1024 * 1024, enabled, name))
        reply(message, "Updated." if cur.rowcount else "Unknown rank.")

    # ── DOCUMENT HANDLER ──
    @bot.message_handler(content_types=["document"])
    def handle_document(message):
        uid = message.from_user.id
        if not authorize(message): return
        doc = message.document
        filename = safe_filename(getattr(doc, "file_name", "upload.bin"))
        ext = Path(filename).suffix.lower()
        size = int(getattr(doc, "file_size", 0) or 0)
        if size > MAX_DOWNLOAD_BYTES: return reply(message, f"Exceeds {MAX_DOWNLOAD_BYTES // (1024*1024)} MB.")
        try:
            info = bot.get_file(doc.file_id); payload = bot.download_file(info.file_path)
        except Exception as exc: return reply(message, f"Download failed: {_html(str(exc))}")
        if filename.lower().endswith(".poppy.enc") or ext == ".enc":
            kind = detect_poppy_file(payload)
            if kind == "vault":
                if not private_only(message): return
                return handle_vault_upload(message, payload, bot)
            elif kind == "decrypt":
                if not private_only(message): return
                return handle_decrypt_upload(message, payload, bot)
            else: return reply(message, "Unrecognized encrypted file.")
        if ext not in {".py", ".zip"}: return reply(message, "Send .py, .zip, or .poppy.enc")
        if not rate_limit(f"protect:{uid}"): return reply(message, "Rate limited.")
        mode = (user_record(uid) or {"mode": "portable"})["mode"]
        if mode not in ALL_MODES: mode = "portable"
        if mode == "sealed" and not has_permission(uid, "use_sealed_mode"): mode = "fortress"
        if mode == "licensed":
            url = os.getenv("LICENSE_WRAPPER_URL", "").strip() or (setting("license_tunnel_url", "") or "")
            if not has_permission(uid, "manage_licenses") or not url.startswith("https://"): mode = "fortress"
        try:
            cost = int(setting("credit_cost", "1") or 1)
            reservation = reserve_processing(uid, cost, len(payload))
        except Exception as exc: return reply(message, _panel("Blocked", _html(str(exc)), emoji="🚫"))
        try:
            if mode == "vault":
                _handle_vault_create(message, payload, filename, reservation, bot); return
            if ext == ".py":
                if len(payload) > MAX_PY_BYTES: raise ValueError("Python file too large.")
                result, analysis = protect_python_source(payload, mode, filename)
                out_name = Path(filename).stem + "_protected.py"
            else:
                rank = rank_for_user(uid)
                result, count, analyses = protect_zip(payload, mode, None, max_total_bytes=int(rank["max_file_bytes"]))
                out_name = Path(filename).stem + "_protected.zip"
            finish_processing(reservation, True)
            out = io.BytesIO(result); out.name = safe_filename(out_name)
            caption = _panel("Protected", f"{_kv('File', _html(out_name))}\n{_kv('Mode', f'{EMOJI_MODE.get(mode, "•")}  {mode.title()}')}", emoji="✓")
            bot.send_document(message.chat.id, out, caption=caption, parse_mode="HTML", reply_to_message_id=message.message_id)
        except Exception as exc:
            finish_processing(reservation, False)
            reply(message, _panel("Failed", f"<code>{_html(str(exc)[:400])}</code>", emoji="✗"))

    def _handle_vault_create(message, payload, filename, reservation, bot):
        uid = message.from_user.id
        try: blob, file_id, analysis = create_vault_file(uid, payload, filename)
        except Exception as exc:
            finish_processing(reservation, False)
            return reply(message, _panel("Vault Failed", f"<code>{_html(str(exc)[:300])}</code>", emoji="✗"))
        finish_processing(reservation, True)
        out = io.BytesIO(blob); out.name = safe_filename(Path(filename).stem + ".poppy.enc")
        body = (f"{_kv('File ID', f'<code>{file_id}</code>')}\n{_kv('Size', f'{len(blob)/(1024):.1f} KB')}\n\n"
                f"<b>Next step</b>\n{_b('Open /files and set a license key')}\n"
                f"{_b('Anyone with the key can upload it here')}\n{_b('They will receive a redacted-sealed build')}")
        bot.send_document(message.chat.id, out, caption=_panel("Vault File Created", body, "License key not set yet", emoji="🔒"),
                          parse_mode="HTML", reply_to_message_id=message.message_id)
        audit(uid, "vault_file_created", uid, {"file_id": file_id, "filename": filename})

    def handle_decrypt_upload(message, blob, bot):
        uid = message.from_user.id
        try:
            hdr, _ = _poppy_header_parse(blob); job_id = hdr["job_id"]
        except Exception: return reply(message, "Invalid encrypted file.")
        try: job = claim_job(job_id, uid)
        except Exception as exc: return reply(message, f"Claim failed: {_html(str(exc))}")
        try:
            priv_pem = private_key_cipher().decrypt(bytes(job["private_key_ciphertext"]))
            decrypted, out_name = decrypt_poppy_payload(blob, job_id, priv_pem, int(job["max_output_bytes"]))
            mode = (user_record(uid) or {"mode": "portable"})["mode"]
            if mode in {"vault", "sealed", "licensed"}: mode = "fortress"
            if out_name.lower().endswith(".py"):
                protected, _ = protect_python_source(decrypted, mode, out_name)
                final_name = Path(out_name).stem + "_protected.py"
            elif out_name.lower().endswith(".zip"):
                protected, _, _ = protect_zip(decrypted, mode)
                final_name = Path(out_name).stem + "_protected.zip"
            else: raise ValueError("Only .py or .zip.")
            complete_job(job_id, hashlib.sha256(blob).hexdigest(), hashlib.sha256(protected).hexdigest())
            out = io.BytesIO(protected); out.name = safe_filename(final_name)
            bot.send_document(message.chat.id, out, caption=_panel("Protected", _kv('File', _html(final_name)), emoji="✓"),
                              parse_mode="HTML", reply_to_message_id=message.message_id)
        except Exception as exc:
            _fail_job(job_id, str(exc)); reply(message, f"Failed: <code>{_html(str(exc)[:300])}</code>")

    @bot.message_handler(func=lambda m: m.from_user.id in _pending_vault_uploads, content_types=["text"])
    def _vault_pending_license_handler(message): handle_vault_license_input(message, bot)

    @bot.message_handler(func=lambda m: bool(m.text) and not m.text.startswith("/"), content_types=["text"])
    def plain_text(message):
        if not user_allowed(message.from_user.id): return
        reply(message, _panel("Send a File", "Upload a .py or .zip to protect, or /files to manage vault files.", emoji="📄"))


# ───── MAIN ─────
def main() -> int:
    if sys.version_info < (3, 10): raise SystemExit("Python 3.10+ required.")
    token = os.getenv("BOT_TOKEN", "").strip()
    owner_raw = os.getenv("OWNER_ID", "").strip()
    if not token: raise SystemExit("BOT_TOKEN required.")
    if not owner_raw.isdigit(): raise SystemExit("OWNER_ID must be numeric.")
    owner_id = int(owner_raw)
    admins = [int(x) for x in os.getenv("ADMIN_IDS", "").split(",") if x.strip().isdigit()]
    _env_bytes("LICENSE_PEPPER", 32)
    private_key_cipher()

    # Create/migrate the database before any setting()-based startup task.
    # Previously the tunnel and key migration ran before config tables existed.
    init_db(owner_id, admins)

    try:
        migrated = migrate_private_ciphertexts()
        if migrated: log.info("Migrated %s ciphertexts to new Fernet key.", migrated)
    except Exception:
        log.exception("Key migration failed")

    cloudflared_startup()

    try:
        import telebot
    except ImportError as exc: raise SystemExit("pyTelegramBotAPI not installed.") from exc

    recovered = recover_jobs()
    log.info("DB ready; recovered %s stale job(s).", recovered)
    _license_server_start()
    health = start_health()
    stop = threading.Event()
    threading.Thread(target=maintenance_worker, args=(stop,), daemon=True, name="maint").start()
    bot = telebot.TeleBot(token, parse_mode="HTML", threaded=True, num_threads=int(os.getenv("BOT_WORKER_THREADS", "4")))
    register_handlers(bot, owner_id)
    log.info("%s v%s starting in %s mode", APP_NAME, APP_VERSION, setting("access_mode", "authorized"))
    retry_delay = 5
    try:
        while not stop.is_set():
            try:
                bot.infinity_polling(skip_pending=True, timeout=30, long_polling_timeout=30)
                if not stop.is_set():
                    log.warning("Telegram polling stopped; reconnecting in %ss.", retry_delay)
            except KeyboardInterrupt:
                log.info("Shutdown requested.")
                break
            except Exception as exc:
                # Invalid/revoked bot tokens will never recover through retries.
                if getattr(exc, "error_code", None) == 401:
                    log.critical("Telegram rejected BOT_TOKEN (401); check the token in .env.")
                    raise
                log.exception("Telegram polling failed; retrying in %ss.", retry_delay)
            if stop.wait(retry_delay):
                break
            retry_delay = min(retry_delay * 2, 60)
    except KeyboardInterrupt:
        log.info("Shutdown.")
    finally:
        stop.set()
        _CF_WATCHDOG_STOP.set()
        if health: health.shutdown()
        cloudflared_stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())