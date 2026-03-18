#!/usr/bin/env bash
# setup-service.sh — Install argus-monitor as a systemd service
# Run as root or with sudo on the target Linux server.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration — adjust these if your layout differs
# ---------------------------------------------------------------------------
INSTALL_DIR="/opt/argus-agent"
SERVICE_NAME="argus-monitor"
SERVICE_USER="argus"
PYTHON="python3"

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "Error: run this script as root (sudo ./setup-service.sh)"
    exit 1
fi

if ! command -v "$PYTHON" &>/dev/null; then
    echo "Error: $PYTHON not found — install Python 3.11+ first"
    exit 1
fi

PY_VERSION=$($PYTHON -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
if [[ "$PY_MAJOR" -lt 3 || ("$PY_MAJOR" -eq 3 && "$PY_MINOR" -lt 11) ]]; then
    echo "Error: Python 3.11+ required (found $PY_VERSION)"
    exit 1
fi

# ---------------------------------------------------------------------------
# Create service user (no login shell, no home dir)
# ---------------------------------------------------------------------------
if ! id "$SERVICE_USER" &>/dev/null; then
    echo "Creating service user: $SERVICE_USER"
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

# ---------------------------------------------------------------------------
# Install application
# ---------------------------------------------------------------------------
echo "Installing to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

# Copy application files (not .env — that must exist already or be created)
for f in argus_monitor.py requirements.txt .env.example; do
    if [[ -f "$f" ]]; then
        cp "$f" "$INSTALL_DIR/"
    fi
done

# Create .env from example if it doesn't exist yet
if [[ ! -f "$INSTALL_DIR/.env" ]]; then
    cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
    echo ""
    echo "*** IMPORTANT: Edit $INSTALL_DIR/.env with your actual credentials ***"
    echo ""
fi

# Create venv and install dependencies
if [[ ! -d "$INSTALL_DIR/venv" ]]; then
    echo "Creating virtual environment..."
    $PYTHON -m venv "$INSTALL_DIR/venv"
fi

echo "Installing Python dependencies..."
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"

# Set ownership — service user needs read access, only root can write
chown -R root:$SERVICE_USER "$INSTALL_DIR"
chmod 750 "$INSTALL_DIR"
chmod 640 "$INSTALL_DIR/.env"
chmod 644 "$INSTALL_DIR/argus_monitor.py" "$INSTALL_DIR/requirements.txt"

# Log file needs to be writable by the service user
touch "$INSTALL_DIR/argus_monitor.log"
chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/argus_monitor.log"
chmod 644 "$INSTALL_DIR/argus_monitor.log"

# ---------------------------------------------------------------------------
# Create systemd unit
# ---------------------------------------------------------------------------
echo "Creating systemd service: $SERVICE_NAME"

cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=Argus Security Monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python argus_monitor.py
Restart=always
RestartSec=15

# python-dotenv loads .env from WorkingDirectory — no EnvironmentFile needed

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR/argus_monitor.log
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# ---------------------------------------------------------------------------
# Enable and start
# ---------------------------------------------------------------------------
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

echo ""
echo "============================================"
echo "  Setup complete"
echo "============================================"
echo ""
echo "  Config:  $INSTALL_DIR/.env"
echo "  Logs:    $INSTALL_DIR/argus_monitor.log"
echo "           journalctl -u $SERVICE_NAME -f"
echo ""
echo "  Commands:"
echo "    sudo systemctl start  $SERVICE_NAME"
echo "    sudo systemctl stop   $SERVICE_NAME"
echo "    sudo systemctl status $SERVICE_NAME"
echo "    sudo journalctl -u $SERVICE_NAME -f"
echo ""

if grep -q "your_username\|your_password\|your-key-here" "$INSTALL_DIR/.env" 2>/dev/null; then
    echo "  *** Edit $INSTALL_DIR/.env before starting! ***"
    echo ""
else
    echo "Starting service now..."
    systemctl start "$SERVICE_NAME"
    sleep 2
    systemctl status "$SERVICE_NAME" --no-pager || true
fi
