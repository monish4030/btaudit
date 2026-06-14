#!/usr/bin/env bash
# BTAudit Uninstaller — Made by Monish Paramasivam
# Usage: sudo ./uninstall.sh

set -e

if [[ $EUID -ne 0 ]]; then
    echo "[!] Run as root: sudo ./uninstall.sh"
    exit 1
fi

echo "[*] Removing BTAudit..."
rm -f  /usr/local/bin/btaudit
rm -rf /opt/btaudit

# Remove consent records (optional — comment out to keep audit trail)
# rm -rf ~/.btaudit

echo "[✓] BTAudit removed."
