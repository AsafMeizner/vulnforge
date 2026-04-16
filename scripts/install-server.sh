#!/usr/bin/env bash
# VulnForge server bare-metal installer.
# Usage: sudo ./install-server.sh
# Produces: systemd unit + bootstrap token + start instructions.

set -euo pipefail

INSTALL_DIR="${VULNFORGE_INSTALL_DIR:-/opt/vulnforge}"
DATA_DIR="${VULNFORGE_DATA_DIR:-/var/lib/vulnforge}"
SERVICE_USER="${VULNFORGE_USER:-vulnforge}"

log()  { echo -e "\033[1;34m[install]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[ ok ]\033[0m $*"; }
warn() { echo -e "\033[1;33m[warn]\033[0m $*"; }
fail() { echo -e "\033[1;31m[fail]\033[0m $*" >&2; exit 1; }

# ── Preflight ──────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || fail "Must run as root (sudo)."

command -v node >/dev/null || fail "Node.js not installed. Install Node ≥ 20 first."
node_major=$(node -v | sed 's/v\([0-9]*\).*/\1/')
[[ $node_major -ge 20 ]] || fail "Node $node_major < 20. Upgrade required."

command -v python3 >/dev/null || warn "python3 missing — scanner tools will fail."
command -v git     >/dev/null || warn "git missing — project clones will fail."

log "Node: $(node -v)"
log "Target install dir: $INSTALL_DIR"
log "Target data dir:    $DATA_DIR"
log "Service user:       $SERVICE_USER"

# ── Prompt for config ──────────────────────────────────────────────────────
if [[ -z "${VULNFORGE_PUBLIC_URL:-}" ]]; then
  read -r -p "Public URL for this server (e.g. https://vf.company.com): " VULNFORGE_PUBLIC_URL
fi
[[ -n "$VULNFORGE_PUBLIC_URL" ]] || fail "Public URL is required."

PORT="${VULNFORGE_PORT:-3001}"

# ── User + dirs ────────────────────────────────────────────────────────────
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  log "Creating service user: $SERVICE_USER"
  useradd --system --home-dir "$DATA_DIR" --shell /bin/false "$SERVICE_USER"
fi

mkdir -p "$INSTALL_DIR" "$DATA_DIR"

# ── Copy payload (expects this script to live alongside dist-server/) ──────
PAYLOAD_DIR="$(cd "$(dirname "$0")" && pwd)"
[[ -d "$PAYLOAD_DIR/../dist-server" ]] || fail "dist-server/ not found next to installer; are you running from the extracted tarball?"

log "Copying payload …"
cp -r "$PAYLOAD_DIR/.."/{dist-server,package.json,plugins} "$INSTALL_DIR/"
cd "$INSTALL_DIR"
log "Installing production deps …"
npm ci --omit=dev --ignore-scripts

# ── Generate secrets ───────────────────────────────────────────────────────
JWT_SECRET=$(openssl rand -base64 48 | tr -d '\n')
BOOTSTRAP_TOKEN=$(openssl rand -hex 24)

cat > "$DATA_DIR/.env" <<EOF
VULNFORGE_MODE=server
VULNFORGE_HOST=0.0.0.0
VULNFORGE_PORT=$PORT
VULNFORGE_DB_PATH=$DATA_DIR/vulnforge.db
VULNFORGE_PUBLIC_URL=$VULNFORGE_PUBLIC_URL
VULNFORGE_JWT_SECRET=$JWT_SECRET
VULNFORGE_BOOTSTRAP_TOKEN=$BOOTSTRAP_TOKEN
EOF
chmod 600 "$DATA_DIR/.env"
chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR" "$INSTALL_DIR"

# ── systemd unit ───────────────────────────────────────────────────────────
cat > /etc/systemd/system/vulnforge-server.service <<EOF
[Unit]
Description=VulnForge Team Server
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$DATA_DIR/.env
ExecStart=$(command -v node) dist-server/server/index.js
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=$DATA_DIR $INSTALL_DIR/plugins

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable vulnforge-server.service
systemctl start vulnforge-server.service

ok "Installed and started."
echo ""
echo "  Service:        systemctl status vulnforge-server"
echo "  Logs:           journalctl -u vulnforge-server -f"
echo "  Data:           $DATA_DIR"
echo "  Config:         $DATA_DIR/.env"
echo ""
echo "  Bootstrap URL:  $VULNFORGE_PUBLIC_URL/api/session/bootstrap"
echo "  Bootstrap token (paste from desktop first-launch):"
echo ""
echo "      $BOOTSTRAP_TOKEN"
echo ""
echo "  After bootstrap, remove the VULNFORGE_BOOTSTRAP_TOKEN line from"
echo "  $DATA_DIR/.env and restart the service."
