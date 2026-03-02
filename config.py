import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
CERTS_DIR = os.path.join(BASE_DIR, 'certs')

TLS_CERT = os.path.join(CERTS_DIR, 'cert.pem')
TLS_KEY = os.path.join(CERTS_DIR, 'key.pem')

TOTP_SECRET_FILE = os.path.join(DATA_DIR, 'totp_secret.enc')
API_KEY_FILE = os.path.join(DATA_DIR, 'api_key.hash')
SETUP_DONE_FILE = os.path.join(DATA_DIR, '.setup_done')

AUTHORIZED_KEYS_PATH = '/root/.ssh/authorized_keys'
SSHD_CONFIG_PATH = '/etc/ssh/sshd_config'

TOTP_ISSUER = 'SSH-Manager'
TOTP_VALID_WINDOW = 1

RATE_LIMIT_MAX_FAILURES = 5
RATE_LIMIT_BLOCK_SECONDS = 900  # 15 min

LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = 8443

MACHINE_ID_PATH = '/etc/machine-id'
