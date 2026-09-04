#!/usr/bin/env bash
# Baut nets_<version>_all.deb.
#
# Reines Python, also architekturunabhaengig ("all"). Die Abhaengigkeiten
# kommen aus den Debian-Paketen statt aus einem mitgelieferten venv -- das
# setzt Debian 13 (trixie) oder neuer voraus, weil Debian 12 nur FastAPI 0.92
# hat und der Code `lifespan=` im Konstruktor braucht (ab 0.93).
#
#   bash deploy/build-deb.sh            # baut nach dist/
#   bash deploy/build-deb.sh --docker   # baut in einem trixie-Container
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ "${1:-}" = "--docker" ]; then
  exec docker run --rm -v "$ROOT:/src" -w /src debian:trixie-slim \
    sh -c 'apt-get update -qq && apt-get install -y -qq --no-install-recommends \
           dpkg-dev fakeroot python3 >/dev/null && bash deploy/build-deb.sh'
fi

VERSION="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' nets/__init__.py)"
[ -n "$VERSION" ] || { echo "Version nicht gefunden in nets/__init__.py" >&2; exit 1; }
PKG="nets_${VERSION}-1_all"
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT

echo "==> Baue $PKG"

install -d "$BUILD/DEBIAN" \
           "$BUILD/usr/lib/python3/dist-packages/nets" \
           "$BUILD/usr/bin" \
           "$BUILD/lib/systemd/system" \
           "$BUILD/etc/default" \
           "$BUILD/usr/share/doc/nets"

# Programmcode. __pycache__ bleibt draussen -- die .pyc gehoeren dem
# Zielsystem und werden dort beim ersten Import erzeugt.
find nets -name '__pycache__' -prune -o -type f -print | while read -r f; do
  install -Dm644 "$f" "$BUILD/usr/lib/python3/dist-packages/$f"
done

# Startbefehl. Kein Konsolen-Skript aus setuptools, damit das Paket ohne
# pip/entry-points auskommt.
cat > "$BUILD/usr/bin/nets" <<'WRAP'
#!/bin/sh
exec /usr/bin/python3 -m nets "$@"
WRAP
chmod 755 "$BUILD/usr/bin/nets"

install -Dm644 deploy/debian/nets.service "$BUILD/lib/systemd/system/nets.service"
install -Dm644 deploy/debian/default      "$BUILD/etc/default/nets"
install -Dm644 README.md                  "$BUILD/usr/share/doc/nets/README.md"
install -Dm644 deploy/README-LXC.md       "$BUILD/usr/share/doc/nets/README-LXC.md"

for script in postinst prerm postrm; do
  install -Dm755 "deploy/debian/$script" "$BUILD/DEBIAN/$script"
  # Der Platzhalter ist nur fuer debhelper gedacht, den wir hier nicht nutzen.
  sed -i '/#DEBHELPER#/d' "$BUILD/DEBIAN/$script"
done

sed "s/@VERSION@/${VERSION}-1/" deploy/debian/control.in > "$BUILD/DEBIAN/control"
# Installed-Size in KiB, wie dpkg es erwartet.
echo "Installed-Size: $(du -sk "$BUILD" | cut -f1)" >> "$BUILD/DEBIAN/control"

# Konfigurationsdatei, damit dpkg lokale Aenderungen respektiert.
echo "/etc/default/nets" > "$BUILD/DEBIAN/conffiles"

mkdir -p dist
if command -v fakeroot >/dev/null; then
  fakeroot dpkg-deb --build "$BUILD" "dist/$PKG.deb" >/dev/null
else
  dpkg-deb --build "$BUILD" "dist/$PKG.deb" >/dev/null
fi

echo "==> dist/$PKG.deb"
dpkg-deb --info "dist/$PKG.deb" | sed -n '2,12p'
echo "Inhalt:"
dpkg-deb --contents "dist/$PKG.deb" | awk '{print $6}' | grep -vE '/$' | head -12
echo "  ... $(dpkg-deb --contents "dist/$PKG.deb" | grep -vcE '/$') Dateien"
