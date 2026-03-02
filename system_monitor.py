import os
import subprocess
import time

import psutil


def get_overview():
    """Get CPU, memory, disk stats and uptime."""
    cpu_percent = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    boot_time = psutil.boot_time()
    uptime_seconds = int(time.time() - boot_time)

    days = uptime_seconds // 86400
    hours = (uptime_seconds % 86400) // 3600
    minutes = (uptime_seconds % 3600) // 60

    return {
        'cpu': {
            'percent': cpu_percent,
            'cores': psutil.cpu_count(),
        },
        'memory': {
            'percent': mem.percent,
            'used_gb': round(mem.used / (1024**3), 1),
            'total_gb': round(mem.total / (1024**3), 1),
        },
        'disk': {
            'percent': disk.percent,
            'used_gb': round(disk.used / (1024**3), 1),
            'total_gb': round(disk.total / (1024**3), 1),
        },
        'uptime': f'{days}d {hours}h {minutes}m',
        'uptime_seconds': uptime_seconds,
        'load_avg': list(os.getloadavg()) if hasattr(os, 'getloadavg') else [],
    }


def get_fail2ban_status():
    """Get fail2ban banned IPs for sshd jail."""
    try:
        result = subprocess.run(
            ['sudo', 'fail2ban-client', 'status', 'sshd'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return {'active': False, 'banned_ips': [], 'error': result.stderr.strip()}

        output = result.stdout
        banned_ips = []
        for line in output.split('\n'):
            if 'Banned IP list:' in line:
                ip_part = line.split(':', 1)[1].strip()
                if ip_part:
                    banned_ips = [ip.strip() for ip in ip_part.split()]
            elif 'Currently banned:' in line:
                banned_count = line.split(':', 1)[1].strip()

        return {
            'active': True,
            'banned_ips': banned_ips,
            'banned_count': len(banned_ips),
        }
    except FileNotFoundError:
        return {'active': False, 'banned_ips': [], 'error': 'fail2ban not installed'}
    except Exception as e:
        return {'active': False, 'banned_ips': [], 'error': str(e)}


def get_ssh_sessions():
    """Get active SSH sessions from who command."""
    try:
        result = subprocess.run(
            ['who'],
            capture_output=True, text=True, timeout=5
        )
        sessions = []
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 5:
                user = parts[0]
                terminal = parts[1]
                date_str = ' '.join(parts[2:4])
                ip = parts[4].strip('()') if len(parts) > 4 else 'local'
                sessions.append({
                    'user': user,
                    'terminal': terminal,
                    'login_time': date_str,
                    'ip': ip,
                })
            elif len(parts) >= 3:
                sessions.append({
                    'user': parts[0],
                    'terminal': parts[1],
                    'login_time': ' '.join(parts[2:]),
                    'ip': 'local',
                })
        return {'sessions': sessions, 'count': len(sessions)}
    except Exception as e:
        return {'sessions': [], 'count': 0, 'error': str(e)}


def get_firewall_status():
    """Get UFW firewall rules."""
    try:
        result = subprocess.run(
            ['sudo', 'ufw', 'status', 'numbered'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return {'active': False, 'rules': [], 'error': result.stderr.strip()}

        output = result.stdout
        active = 'Status: active' in output
        rules = []
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('['):
                # Parse numbered rule: [ 1] 22/tcp ALLOW IN Anywhere
                bracket_end = line.index(']')
                num = line[1:bracket_end].strip()
                rule_text = line[bracket_end + 1:].strip()
                rules.append({
                    'number': num,
                    'rule': rule_text,
                })

        return {'active': active, 'rules': rules}
    except Exception as e:
        return {'active': False, 'rules': [], 'error': str(e)}
