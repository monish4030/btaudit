#!/usr/bin/env bash
# ============================================================
#  BTAudit — Kali Linux Installer
#  Made by Monish Paramasivam
#
#  Usage:
#    chmod +x install.sh
#    sudo ./install.sh
#
#  After install:
#    btaudit --help
#    sudo btaudit scan --duration 15
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

print_banner() {
cat << 'BANNER'

  ██████╗ ████████╗ █████╗ ██╗   ██╗██████╗ ██╗████████╗
  ██╔══██╗╚══██╔══╝██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
  ██████╔╝   ██║   ███████║██║   ██║██║  ██║██║   ██║
  ██╔══██╗   ██║   ██╔══██║██║   ██║██║  ██║██║   ██║
  ██████╔╝   ██║   ██║  ██║╚██████╔╝██████╔╝██║   ██║
  ╚═════╝    ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝

  Bluetooth Security Auditing Tool  v1.0.0
  Made by Monish Paramasivam
  For AUTHORIZED environments only

BANNER
}

info()    { echo -e "${CYAN}[*]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }

# ── Check root ───────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    error "Run as root: sudo ./install.sh"
fi

print_banner

# ── Detect Kali / Debian ─────────────────────────────────────
if ! grep -qi "kali\|debian\|ubuntu" /etc/os-release 2>/dev/null; then
    warn "This script targets Kali Linux / Debian. Continuing anyway..."
fi

# ── System packages ──────────────────────────────────────────
info "Updating package list..."
apt-get update -qq

info "Installing Bluetooth system dependencies..."
apt-get install -y --no-install-recommends \
    bluez \
    bluetooth \
    libbluetooth-dev \
    libglib2.0-dev \
    python3 \
    python3-pip \
    python3-venv \
    git \
    2>/dev/null || error "apt-get install failed"

success "System packages installed"

# ── Enable Bluetooth service ─────────────────────────────────
info "Enabling Bluetooth service..."
systemctl enable bluetooth 2>/dev/null || true
systemctl start bluetooth  2>/dev/null || warn "Could not start bluetooth service (may need hardware)"

# ── Python virtual environment ───────────────────────────────
INSTALL_DIR="/opt/btaudit"
VENV_DIR="$INSTALL_DIR/venv"

info "Creating install directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

# Copy project files
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
info "Copying project files from $SCRIPT_DIR..."
cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/" 2>/dev/null || true

info "Creating Python virtual environment..."
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

info "Installing Python dependencies..."
pip install --quiet --upgrade pip
pip install --quiet -e "$INSTALL_DIR[dashboard]" 2>/dev/null || \
pip install --quiet -r "$INSTALL_DIR/requirements.txt"

success "Python dependencies installed"

# ── Create system-wide launcher ──────────────────────────────
info "Creating /usr/local/bin/btaudit launcher..."
cat > /usr/local/bin/btaudit << LAUNCHER
#!/usr/bin/env bash
# BTAudit launcher — Made by Monish Paramasivam
source "$VENV_DIR/bin/activate"
exec python -m btaudit.cli "\$@"
LAUNCHER
chmod +x /usr/local/bin/btaudit

# ── Create reports directory ─────────────────────────────────
mkdir -p /opt/btaudit/reports
chmod 755 /opt/btaudit/reports

# ── Verify installation ───────────────────────────────────────
info "Verifying installation..."
if btaudit --version &>/dev/null; then
    success "BTAudit installed successfully!"
else
    # Fallback: try direct python invocation
    if source "$VENV_DIR/bin/activate" && python -m btaudit.cli --version &>/dev/null; then
        success "BTAudit installed (use: source $VENV_DIR/bin/activate && btaudit)"
    else
        warn "Launcher check inconclusive — try: btaudit --help"
    fi
fi

# ── Print usage ───────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Installation Complete!${NC}"
echo -e "${BOLD}════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${CYAN}Quick Start:${NC}"
echo ""
echo -e "  # Interactive scan (prompts for authorization)"
echo -e "  ${BOLD}sudo btaudit scan --duration 15${NC}"
echo ""
echo -e "  # Non-interactive (CI / scripting)"
echo -e "  ${BOLD}sudo BTAUDIT_AUTHORIZED=1 btaudit scan --non-interactive${NC}"
echo ""
echo -e "  # Web dashboard"
echo -e "  ${BOLD}sudo btaudit dashboard --port 8080${NC}"
echo -e "  # Then open: http://127.0.0.1:8080"
echo ""
echo -e "  # BLE only, save to /opt/btaudit/reports"
echo -e "  ${BOLD}sudo btaudit scan --no-classic -o /opt/btaudit/reports${NC}"
echo ""
echo -e "  ${YELLOW}⚠  Always use only on authorized environments!${NC}"
echo ""
