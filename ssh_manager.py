import fcntl
import hashlib
import os
import re
import subprocess

import config

DISABLED_PREFIX = '# DISABLED '

# Validate SSH key format: type base64 [comment]
SSH_KEY_PATTERN = re.compile(
    r'^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)'
    r'\s+'
    r'[A-Za-z0-9+/=]+'
    r'(\s+\S.*)?$'
)


def _key_id(line):
    """Generate a stable ID from a key line (ignoring disabled prefix)."""
    clean = line.replace(DISABLED_PREFIX, '', 1) if line.startswith(DISABLED_PREFIX) else line
    return hashlib.sha256(clean.strip().encode()).hexdigest()[:16]


def _parse_key_line(line):
    """Parse a single authorized_keys line into a device dict."""
    raw = line.strip()
    if not raw or (raw.startswith('#') and not raw.startswith(DISABLED_PREFIX)):
        return None

    disabled = raw.startswith(DISABLED_PREFIX)
    key_line = raw[len(DISABLED_PREFIX):] if disabled else raw

    parts = key_line.split(None, 2)
    if len(parts) < 2:
        return None

    key_type = parts[0]
    key_data = parts[1]
    comment = parts[2] if len(parts) > 2 else ''

    return {
        'id': _key_id(raw),
        'name': comment or key_type,
        'type': key_type,
        'fingerprint': key_data[:20] + '...' + key_data[-8:] if len(key_data) > 28 else key_data,
        'enabled': not disabled,
        'raw': key_line.strip(),
    }


def _read_authorized_keys():
    """Read and return all lines from authorized_keys via sudo."""
    path = config.AUTHORIZED_KEYS_PATH
    try:
        result = subprocess.run(
            ['sudo', 'cat', path],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return []
        return result.stdout.splitlines(keepends=True)
    except Exception:
        return []


def _write_authorized_keys(lines):
    """Write lines to authorized_keys via sudo."""
    path = config.AUTHORIZED_KEYS_PATH
    content = ''.join(lines)
    try:
        subprocess.run(
            ['sudo', 'tee', path],
            input=content, capture_output=True, text=True, timeout=5, check=True
        )
        subprocess.run(
            ['sudo', 'chmod', '600', path],
            capture_output=True, timeout=5
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f'Failed to write authorized_keys: {e.stderr}')


def list_keys():
    """List all SSH keys."""
    lines = _read_authorized_keys()
    devices = []
    for line in lines:
        parsed = _parse_key_line(line)
        if parsed:
            info = dict(parsed)
            del info['raw']
            devices.append(info)
    return devices


def add_key(name, key_data):
    """Add a new SSH key."""
    key_data = key_data.strip()

    if not SSH_KEY_PATTERN.match(key_data):
        return {'error': 'Invalid SSH key format. Expected: type base64-key [comment]'}

    # Check for duplicates
    lines = _read_authorized_keys()
    for line in lines:
        parsed = _parse_key_line(line)
        if parsed and parsed['raw'].split(None, 2)[:2] == key_data.split(None, 2)[:2]:
            return {'error': 'This key already exists'}

    # Replace or append comment with the device name
    parts = key_data.split(None, 2)
    new_line = f"{parts[0]} {parts[1]} {name}\n"

    lines.append(new_line)
    _write_authorized_keys(lines)

    parsed = _parse_key_line(new_line)
    info = dict(parsed)
    del info['raw']
    return {'device': info}


def delete_key(key_id):
    """Delete an SSH key by ID."""
    lines = _read_authorized_keys()
    new_lines = []
    found = False
    for line in lines:
        parsed = _parse_key_line(line)
        if parsed and parsed['id'] == key_id:
            found = True
            continue
        new_lines.append(line)

    if not found:
        return {'error': 'Key not found'}

    _write_authorized_keys(new_lines)
    return {'deleted': key_id}


def toggle_key(key_id, enabled):
    """Enable or disable an SSH key by ID."""
    lines = _read_authorized_keys()
    new_lines = []
    found = False
    for line in lines:
        parsed = _parse_key_line(line)
        if parsed and parsed['id'] == key_id:
            found = True
            if enabled and not parsed['enabled']:
                new_lines.append(parsed['raw'] + '\n')
            elif not enabled and parsed['enabled']:
                new_lines.append(DISABLED_PREFIX + parsed['raw'] + '\n')
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)

    if not found:
        return {'error': 'Key not found'}

    _write_authorized_keys(new_lines)
    return {'id': key_id, 'enabled': enabled}


def get_password_auth_status():
    """Check if password authentication is enabled in sshd_config."""
    try:
        result = subprocess.run(
            ['sudo', 'grep', '-E', r'^#?\s*PasswordAuthentication\s+(yes|no)', config.SSHD_CONFIG_PATH],
            capture_output=True, text=True, timeout=5
        )
        output = result.stdout.strip()
        if not output:
            return {'enabled': True, 'raw': 'not set (default yes)'}

        # Take the last uncommented line, or fallback to last line
        lines = [l.strip() for l in output.split('\n') if l.strip()]
        active_lines = [l for l in lines if not l.startswith('#')]
        last_line = active_lines[-1] if active_lines else lines[-1]
        if last_line.startswith('#'):
            return {'enabled': True, 'raw': last_line}
        enabled = 'yes' in last_line.lower()
        return {'enabled': enabled, 'raw': last_line}
    except Exception as e:
        return {'enabled': None, 'error': str(e)}


def toggle_password_auth(enabled):
    """Toggle PasswordAuthentication in sshd_config."""
    value = 'yes' if enabled else 'no'
    try:
        # Use sed to replace the line
        subprocess.run(
            ['sudo', 'sed', '-i',
             r's/^#\?\s*PasswordAuthentication\s\+\(yes\|no\)/PasswordAuthentication ' + value + '/',
             config.SSHD_CONFIG_PATH],
            check=True, capture_output=True, text=True, timeout=5
        )
        # Reload sshd
        subprocess.run(
            ['sudo', 'systemctl', 'reload', 'ssh'],
            check=True, capture_output=True, text=True, timeout=10
        )
        return {'enabled': enabled}
    except subprocess.CalledProcessError as e:
        return {'error': f'Failed to toggle password auth: {e.stderr}'}
    except Exception as e:
        return {'error': str(e)}
