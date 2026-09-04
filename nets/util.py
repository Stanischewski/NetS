"""Kleine Helfer: MAC-Normalisierung, OUI-Lookup, Zeit."""

from __future__ import annotations

import os
import re
import time
from functools import lru_cache
from pathlib import Path

_MAC_RE = re.compile(r"^[0-9a-f]{12}$")

# Vom IEEE bezogene OUI-Datei. Format je Zeile:  <prefix-hex>\t<vendor>
#
# Bei einer Paketinstallation liegen die Programmdateien unter /usr und duerfen
# nicht veraendert werden -- `nets oui-update` schreibt deshalb in den
# Datenpfad. Beim Lesen gewinnt die aktuellere, gepflegte Kopie dort; die im
# Paket mitgelieferte ist nur der Ausgangsstand.
_PACKAGED_OUI = Path(__file__).with_name("data") / "oui.tsv"
_STATE_OUI = Path(os.environ.get("NETS_STATE_DIR", "/var/lib/nets")) / "oui.tsv"


def oui_path(for_writing: bool = False) -> Path:
    if for_writing:
        # In den Datenpfad, sofern der beschreibbar ist -- sonst neben das
        # Programm, was bei einer Entwicklungskopie der Normalfall ist.
        try:
            _STATE_OUI.parent.mkdir(parents=True, exist_ok=True)
            probe = _STATE_OUI.parent / ".write-test"
            probe.touch()
            probe.unlink()
            return _STATE_OUI
        except OSError:
            return _PACKAGED_OUI
    return _STATE_OUI if _STATE_OUI.exists() else _PACKAGED_OUI


#: Rueckwaertskompatibel fuer Aufrufer, die nur lesen wollen.
OUI_FILE = oui_path()


def now() -> int:
    return int(time.time())


def norm_mac(mac: str | bytes) -> str | None:
    """Normalisiert auf 'aa:bb:cc:dd:ee:ff'. Gibt None bei Unsinn zurueck."""
    if isinstance(mac, bytes):
        if len(mac) != 6:
            return None
        return ":".join(f"{b:02x}" for b in mac)
    raw = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if not _MAC_RE.match(raw):
        return None
    return ":".join(raw[i : i + 2] for i in range(0, 12, 2))


def is_locally_administered(mac: str) -> bool:
    """True bei randomisierter / lokal vergebener MAC (U/L-Bit gesetzt).

    Betrifft iOS/Android/Win11-Privacy-MACs. Der Hersteller-Lookup ist dann
    wertlos -- solche Geraete muessen ueber andere Merkmale geclustert werden.
    """
    try:
        return bool(int(mac[:2], 16) & 0b10)
    except (ValueError, IndexError):
        return False


def is_multicast_mac(mac: str) -> bool:
    try:
        return bool(int(mac[:2], 16) & 0b1)
    except (ValueError, IndexError):
        return False


@lru_cache(maxsize=1)
def _oui_table() -> dict[str, str]:
    table: dict[str, str] = {}
    path = oui_path()
    if not path.exists():
        return table
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        prefix, _, vendor = line.partition("\t")
        prefix = prefix.strip().lower()
        if prefix and vendor:
            table[prefix] = vendor.strip()
    return table


def base_mac_of_bssid(mac: str) -> str | None:
    """Die Basis-MAC zu einer BSSID, sofern sie so gebildet wurde.

    Access Points leiten die BSSID ihrer Funkmodule fast immer aus der
    Geraete-MAC ab, indem sie das U/L-Bit setzen (0x02 im ersten Oktett).
    `36:19:4d:cd:91:9f` gehoert damit zum Geraet `34:19:4d:cd:91:9f`.

    Das ist keine Heuristik mit Grauzone: die Umkehrung ist eindeutig, und ein
    Treffer zaehlt nur, wenn die Basis-MAC auch wirklich als Geraet bekannt
    ist. Gibt None zurueck, wenn die MAC nicht lokal vergeben ist.
    """
    if not is_locally_administered(mac):
        return None
    try:
        first = int(mac[:2], 16) & ~0b10
    except ValueError:
        return None
    return f"{first:02x}{mac[2:]}"


def same_device_family(a: str, b: str, max_delta: int = 16) -> bool:
    """Schwacher Hinweis: zwei MACs koennten Funkmodule desselben Geraets sein.

    Mehrere Radios eines APs bekommen meist aufeinanderfolgende Adressen aus
    demselben Block. Das ist aber *kein* Beweis -- fortlaufende MACs werden
    auch an verschiedene Geraete einer Produktionscharge vergeben. Deshalb nur
    als Hinweis anzeigen, niemals zum Zusammenfuehren verwenden.
    """
    if a == b or a[:14] != b[:14]:   # gleiche ersten fuenf Oktette
        return False
    try:
        return abs(int(a[-2:], 16) - int(b[-2:], 16)) <= max_delta
    except ValueError:
        return False


def vendor_for_mac(mac: str) -> str | None:
    """Herstellerauflösung inkl. MA-M/MA-S (28/36 Bit) vor MA-L (24 Bit)."""
    if is_locally_administered(mac):
        return None
    flat = mac.replace(":", "")
    table = _oui_table()
    for nibbles in (9, 7, 6):  # laengstes Praefix gewinnt
        hit = table.get(flat[:nibbles])
        if hit:
            return hit
    return None
