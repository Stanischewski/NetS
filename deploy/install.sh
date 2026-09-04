#!/usr/bin/env bash
# Installiert NetS auf diesem Rechner -- LXC, VM oder PC.
#
# Waehlt den Weg selbst:
#   Debian 13+ / Ubuntu 24.10+  ->  Debian-Paket aus den System-Abhaengigkeiten
#   aeltere Systeme             ->  virtuelle Umgebung unter /opt/nets
#
# Der Unterschied liegt an FastAPI: Der Code braucht `lifespan=` im
# Konstruktor (ab 0.93), Debian 12 liefert aber nur 0.92.
#
#   sudo bash deploy/install.sh
#   sudo bash deploy/install.sh --venv    # Paketweg ueberspringen
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

[ "$(id -u)" -eq 0 ] || { echo "Bitte mit sudo ausfuehren." >&2; exit 1; }

FORCE_VENV=0
[ "${1:-}" = "--venv" ] && FORCE_VENV=1

have_package() {   # have_package <name> <mindest-version>
    local version
    version="$(apt-cache policy "$1" 2>/dev/null | awk '/Candidate|Kandidat/ {print $2}' | head -1)"
    [ -n "$version" ] && [ "$version" != "(none)" ] || return 1
    dpkg --compare-versions "$version" ge "$2"
}

echo "==> Paketlisten aktualisieren"
apt-get update -qq

USE_DEB=0
if [ "$FORCE_VENV" -eq 0 ]; then
    if have_package python3-fastapi 0.93 \
       && have_package python3-scapy 2.6 \
       && have_package python3-httpx 0.27; then
        USE_DEB=1
    else
        echo "==> Systempakete sind zu alt fuer den Paketweg:"
        for p in python3-fastapi python3-scapy python3-httpx; do
            printf '      %-18s %s\n' "$p" \
                "$(apt-cache policy "$p" 2>/dev/null | awk '/Candidate|Kandidat/ {print $2}' | head -1)"
        done
        echo "    -> virtuelle Umgebung"
    fi
fi

if [ "$USE_DEB" -eq 1 ]; then
    echo "==> Baue und installiere das Debian-Paket"
    bash deploy/build-deb.sh
    VERSION="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' nets/__init__.py)"
    # Kein --no-install-recommends fuer die Abhaengigkeiten selbst, aber auch
    # nicht die schweren Empfehlungen von python3-scapy (ipython3 zieht
    # matplotlib und einen C++-Compiler mit: 1,1 GB statt 260 MB).
    apt-get install -y --no-install-recommends \
        "./dist/nets_${VERSION}-1_all.deb" snmp nmap
else
    echo "==> Installiere in eine virtuelle Umgebung"
    NETS_INSTALL_QUIET=1 bash deploy/install-lxc.sh "$ROOT"
fi

IP="$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)"

# Auf die WebUI warten statt nur auf "is-active". Der Dienst gilt systemd
# sofort als gestartet, uvicorn lauscht aber erst nach ein paar Sekunden --
# ein "laeuft" mit toter URL sieht wie ein Fehler aus.
echo
printf 'Warte auf die WebUI '
for _ in $(seq 30); do
    # In einer Subshell, weil bash die Fehlermeldung von /dev/tcp sonst an
    # der Umleitung vorbei auf stderr schreibt.
    if ( exec 3<>/dev/tcp/127.0.0.1/8080 ) 2>/dev/null; then
        echo " bereit."
        echo
        echo "WebUI:   http://${IP:-<host>}:8080"
        if [ "$USE_DEB" -eq 1 ]; then
            echo "Pruefen: nets check"
        else
            echo "Pruefen: /opt/nets/.venv/bin/python -m nets check"
        fi
        echo "Log:     journalctl -u nets -f"
        exit 0
    fi
    printf '.'
    sleep 1
done

echo " keine Antwort."
echo
echo "Der Dienst antwortet nicht auf Port 8080. Log:"
journalctl -u nets -n 20 --no-pager || true
exit 1
