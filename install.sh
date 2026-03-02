#!/bin/bash
set -e

APP_DIR="/home/claude-dev/ssh-manager"
SERVICE_NAME="ssh-manager"
PORT=8443
USER="claude-dev"

echo "=== SSH Manager Installer ==="

# 1. Install dependencies
echo "[1/5] Installing Python dependencies..."
sudo apt update -qq
sudo apt install -y python3-flask python3-pyotp python3-qrcode python3-psutil python3-pil python3-cryptography

# 2. Ensure directory structure
echo "[2/5] Setting up directories..."
mkdir -p "$APP_DIR"/{static/{css,js,icons},templates,certs,data}
chmod 700 "$APP_DIR/data"

# 3. Generate TLS cert if missing
if [ ! -f "$APP_DIR/certs/cert.pem" ]; then
    echo "[3/5] Generating self-signed TLS certificate..."
    SERVER_IP=$(hostname -I | awk '{print $1}')
    openssl req -x509 -newkey rsa:4096 \
        -keyout "$APP_DIR/certs/key.pem" \
        -out "$APP_DIR/certs/cert.pem" \
        -days 365 -nodes \
        -subj "/CN=$SERVER_IP" \
        -addext "subjectAltName=IP:$SERVER_IP" 2>/dev/null
    chmod 600 "$APP_DIR/certs/key.pem"
    echo "    Certificate generated for IP: $SERVER_IP"
else
    echo "[3/5] TLS certificate already exists, skipping."
fi

# 4. Open firewall port
echo "[4/5] Configuring firewall..."
sudo ufw allow "$PORT/tcp" comment "SSH Manager" 2>/dev/null || true

# 5. Install systemd service
echo "[5/5] Installing systemd service..."
sudo tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null << EOF
[Unit]
Description=SSH Manager Web App
After=network.target

[Service]
Type=simple
User=${USER}
WorkingDirectory=${APP_DIR}
ExecStart=/usr/bin/python3 ${APP_DIR}/app.py
Restart=on-failure
RestartSec=5
Environment=PYTHONDONTWRITEBYTECODE=1

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable ${SERVICE_NAME}

echo ""
echo "=== Installation Complete ==="
echo "Start with: sudo systemctl start ${SERVICE_NAME}"
echo "Access at:  https://$(hostname -I | awk '{print $1}'):${PORT}"
echo ""
echo "First visit will show the setup page to generate"
echo "your API key and TOTP secret."
