import base64
import hashlib
import hmac
import io
import json
import os
import time
from functools import wraps

import pyotp
import qrcode
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from flask import request, jsonify, g

import config

# --- Rate limiting (in-memory) ---

_failed_attempts = {}  # ip -> {'count': int, 'blocked_until': float}


def _check_rate_limit(ip):
    entry = _failed_attempts.get(ip)
    if not entry:
        return True
    if entry['blocked_until'] and time.time() < entry['blocked_until']:
        return False
    if entry['blocked_until'] and time.time() >= entry['blocked_until']:
        del _failed_attempts[ip]
        return True
    return True


def _record_failure(ip):
    entry = _failed_attempts.setdefault(ip, {'count': 0, 'blocked_until': None})
    entry['count'] += 1
    if entry['count'] >= config.RATE_LIMIT_MAX_FAILURES:
        entry['blocked_until'] = time.time() + config.RATE_LIMIT_BLOCK_SECONDS


def _clear_failures(ip):
    _failed_attempts.pop(ip, None)


# --- Encryption helpers ---

def _derive_key():
    with open(config.MACHINE_ID_PATH, 'r') as f:
        machine_id = f.read().strip()
    salt = b'ssh-manager-totp-v1'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(machine_id.encode()))
    return Fernet(key)


def encrypt_totp_secret(secret):
    fernet = _derive_key()
    return fernet.encrypt(secret.encode())


def decrypt_totp_secret():
    fernet = _derive_key()
    with open(config.TOTP_SECRET_FILE, 'rb') as f:
        return fernet.decrypt(f.read()).decode()


# --- TOTP replay protection ---

_used_codes = {}  # code -> timestamp


def _cleanup_used_codes():
    cutoff = time.time() - 90  # 30s window * 3
    to_delete = [c for c, t in _used_codes.items() if t < cutoff]
    for c in to_delete:
        del _used_codes[c]


def verify_totp(code):
    try:
        secret = decrypt_totp_secret()
    except Exception:
        return False
    _cleanup_used_codes()
    if code in _used_codes:
        return False
    totp = pyotp.TOTP(secret)
    if totp.verify(code, valid_window=config.TOTP_VALID_WINDOW):
        _used_codes[code] = time.time()
        return True
    return False


def generate_totp_qr(secret, account='admin'):
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=account, issuer_name=config.TOTP_ISSUER)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return base64.b64encode(buf.getvalue()).decode()


# --- API key ---

def generate_api_key():
    return base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('=')


def hash_api_key(key):
    return hashlib.sha256(key.encode()).hexdigest()


def verify_api_key(key):
    try:
        with open(config.API_KEY_FILE, 'r') as f:
            stored_hash = f.read().strip()
    except FileNotFoundError:
        return False
    return hmac.compare_digest(hash_api_key(key), stored_hash)


# --- Setup ---

def is_setup_done():
    return os.path.exists(config.SETUP_DONE_FILE)


def perform_setup():
    os.makedirs(config.DATA_DIR, exist_ok=True)
    secret = pyotp.random_base32()
    encrypted = encrypt_totp_secret(secret)
    with open(config.TOTP_SECRET_FILE, 'wb') as f:
        f.write(encrypted)
    os.chmod(config.TOTP_SECRET_FILE, 0o600)

    api_key = generate_api_key()
    with open(config.API_KEY_FILE, 'w') as f:
        f.write(hash_api_key(api_key))
    os.chmod(config.API_KEY_FILE, 0o600)

    qr_b64 = generate_totp_qr(secret)

    with open(config.SETUP_DONE_FILE, 'w') as f:
        f.write(str(int(time.time())))
    os.chmod(config.SETUP_DONE_FILE, 0o600)

    return {'api_key': api_key, 'qr_code': qr_b64, 'totp_secret': secret}


# --- Decorators ---

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('X-API-Key', '')
        if not key or not verify_api_key(key):
            return jsonify({'error': 'Invalid API key'}), 401
        return f(*args, **kwargs)
    return decorated


def require_totp(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.remote_addr
        if not _check_rate_limit(ip):
            return jsonify({'error': 'Too many failed attempts. Try again later.'}), 429

        code = request.headers.get('X-TOTP-Code', '')
        if not code:
            body = request.get_json(silent=True) or {}
            code = body.get('totp_code', '')

        if not code:
            return jsonify({'error': 'TOTP code required'}), 403

        if not verify_totp(str(code).strip()):
            _record_failure(ip)
            return jsonify({'error': 'Invalid TOTP code'}), 403

        _clear_failures(ip)
        return f(*args, **kwargs)
    return decorated
