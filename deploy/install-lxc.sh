#!/usr/bin/env bash
# Installation von NetS *innerhalb* eines Debian/Ubuntu-LXC-Containers.
# Vorher auf dem Host: siehe deploy/README-LXC.md (Netzwerkanbindung!).
set -euo pipefail

REPO_SRC="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
TARGET=/opt/nets

echo "==> Pakete installieren"
apt-get update -qq
apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip \
    snmp `# snmpbulkwalk fuer den generischen SNMP-Adapter` \
    nmap `# optionale Dienst-/OS-Erkennung` \
    iproute2 iputils-ping `# ICMP fuer geroutete Sweeps` \
    ca-certificates

echo "==> Code nach ${TARGET} kopieren"
mkdir -p "$TARGET"
cp -r "$REPO_SRC"/{nets,requirements.txt,pyproject.toml} "$TARGET"/

echo "==> Virtualenv anlegen"
python3 -m venv "$TARGET/.venv"
"$TARGET/.venv/bin/pip" install --quiet --upgrade pip
"$TARGET/.venv/bin/pip" install --quiet -r "$TARGET/requirements.txt"

echo "==> Dienstbenutzer und Datenverzeichnis"
id -u nets >/dev/null 2>&1 || useradd --system --home /var/lib/nets --shell /usr/sbin/nologin nets
mkdir -p /var/lib/nets
chown -R nets:nets /var/lib/nets "$TARGET"

echo "==> Herstellerdatenbank laden"
"$TARGET/.venv/bin/python" -m nets oui-update || echo "  (uebersprungen -- spaeter nachholen)"
chown -R nets:nets "$TARGET/nets/data" 2>/dev/null || true

echo "==> systemd-Unit installieren"
cp "$REPO_SRC/deploy/nets.service" /etc/systemd/system/nets.service
systemctl daemon-reload
systemctl enable --now nets.service

# Zusammenfassung nur, wenn direkt aufgerufen -- deploy/install.sh macht das
# sonst selbst und wartet dabei auf die WebUI.
if [ -z "${NETS_INSTALL_QUIET:-}" ]; then
    echo
    echo "Fertig. Pruefung:"
    "$TARGET/.venv/bin/python" -m nets check || true
    echo
    IP=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)
    echo "WebUI:  http://${IP:-<container-ip>}:8080"
    echo "Logs:   journalctl -u nets -f"
fi
