#!/usr/bin/env python3
import ssl
import os

from flask import Flask, jsonify, request, render_template, send_from_directory

import config
from auth import (
    is_setup_done, perform_setup, require_api_key, require_totp,
    verify_totp, generate_totp_qr, decrypt_totp_secret, verify_api_key,
    generate_api_key, hash_api_key, encrypt_totp_secret, _check_rate_limit,
    _record_failure, _clear_failures
)

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = os.urandom(32).hex()


# --- Security headers ---

@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'no-referrer'
    if request.path.startswith('/api/'):
        response.headers['Content-Security-Policy'] = "default-src 'none'"
    return response


# --- Page routes ---

@app.route('/')
def index():
    if not is_setup_done():
        return render_template('setup.html')
    return render_template('index.html')


@app.route('/manifest.json')
def manifest():
    return send_from_directory('static', 'manifest.json')


@app.route('/sw.js')
def service_worker():
    return send_from_directory('static', 'sw.js')


# --- Setup API ---

@app.route('/api/v1/setup/status', methods=['GET'])
def setup_status():
    return jsonify({'setup_done': is_setup_done()})


@app.route('/api/v1/setup/init', methods=['POST'])
def setup_init():
    if is_setup_done():
        return jsonify({'error': 'Setup already completed'}), 400
    result = perform_setup()
    return jsonify(result)


# --- Auth API ---

@app.route('/api/v1/auth/verify', methods=['POST'])
@require_api_key
def auth_verify():
    ip = request.remote_addr
    if not _check_rate_limit(ip):
        return jsonify({'error': 'Too many failed attempts. Try again later.'}), 429

    body = request.get_json(silent=True) or {}
    code = body.get('totp_code', '')
    if not code:
        return jsonify({'error': 'TOTP code required'}), 400

    if verify_totp(str(code).strip()):
        _clear_failures(ip)
        return jsonify({'valid': True})
    else:
        _record_failure(ip)
        return jsonify({'valid': False, 'error': 'Invalid TOTP code'}), 403


# --- Device (SSH Key) API ---

@app.route('/api/v1/devices', methods=['GET'])
@require_api_key
def list_devices():
    from ssh_manager import list_keys
    return jsonify({'devices': list_keys()})


@app.route('/api/v1/devices', methods=['POST'])
@require_api_key
@require_totp
def add_device():
    from ssh_manager import add_key
    body = request.get_json(silent=True) or {}
    name = body.get('name', '').strip()
    key_data = body.get('key', '').strip()
    if not name or not key_data:
        return jsonify({'error': 'Name and key are required'}), 400
    result = add_key(name, key_data)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify(result), 201


@app.route('/api/v1/devices/<device_id>', methods=['DELETE'])
@require_api_key
@require_totp
def delete_device(device_id):
    from ssh_manager import delete_key
    result = delete_key(device_id)
    if 'error' in result:
        return jsonify(result), 404
    return jsonify(result)


@app.route('/api/v1/devices/<device_id>', methods=['PATCH'])
@require_api_key
@require_totp
def toggle_device(device_id):
    from ssh_manager import toggle_key
    body = request.get_json(silent=True) or {}
    enabled = body.get('enabled')
    if enabled is None:
        return jsonify({'error': 'enabled field required'}), 400
    result = toggle_key(device_id, enabled)
    if 'error' in result:
        return jsonify(result), 404
    return jsonify(result)


# --- SSH Config API ---

@app.route('/api/v1/ssh/password-auth', methods=['GET'])
@require_api_key
def get_password_auth():
    from ssh_manager import get_password_auth_status
    return jsonify(get_password_auth_status())


@app.route('/api/v1/ssh/password-auth', methods=['POST'])
@require_api_key
@require_totp
def set_password_auth():
    from ssh_manager import toggle_password_auth
    body = request.get_json(silent=True) or {}
    enabled = body.get('enabled')
    if enabled is None:
        return jsonify({'error': 'enabled field required'}), 400
    result = toggle_password_auth(enabled)
    if 'error' in result:
        return jsonify(result), 500
    return jsonify(result)


# --- System Monitor API ---

@app.route('/api/v1/system/overview', methods=['GET'])
@require_api_key
def system_overview():
    from system_monitor import get_overview
    return jsonify(get_overview())


@app.route('/api/v1/system/fail2ban', methods=['GET'])
@require_api_key
def system_fail2ban():
    from system_monitor import get_fail2ban_status
    return jsonify(get_fail2ban_status())


@app.route('/api/v1/system/sessions', methods=['GET'])
@require_api_key
def system_sessions():
    from system_monitor import get_ssh_sessions
    return jsonify(get_ssh_sessions())


@app.route('/api/v1/system/firewall', methods=['GET'])
@require_api_key
def system_firewall():
    from system_monitor import get_firewall_status
    return jsonify(get_firewall_status())


# --- Settings API ---

@app.route('/api/v1/settings/totp-qr', methods=['GET'])
@require_api_key
@require_totp
def get_totp_qr():
    try:
        secret = decrypt_totp_secret()
        qr_b64 = generate_totp_qr(secret)
        return jsonify({'qr_code': qr_b64})
    except Exception as e:
        return jsonify({'error': 'Failed to generate QR code'}), 500


@app.route('/api/v1/settings/totp-regenerate', methods=['POST'])
@require_api_key
@require_totp
def regenerate_totp():
    import pyotp
    new_secret = pyotp.random_base32()
    encrypted = encrypt_totp_secret(new_secret)
    with open(config.TOTP_SECRET_FILE, 'wb') as f:
        f.write(encrypted)
    qr_b64 = generate_totp_qr(new_secret)
    return jsonify({'qr_code': qr_b64, 'totp_secret': new_secret})


if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(config.TLS_CERT, config.TLS_KEY)
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    app.run(
        host=config.LISTEN_HOST,
        port=config.LISTEN_PORT,
        ssl_context=context,
        debug=False
    )
