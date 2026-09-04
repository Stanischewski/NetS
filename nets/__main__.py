"""Einstiegspunkt: `python -m nets`

Unterkommandos:
    serve       Dienst + WebUI starten (Standard)
    oui-update  IEEE-Herstellerdatenbank aktualisieren
    check       Umgebung pruefen (Rechte, Werkzeuge, Interfaces)
"""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import sys
from pathlib import Path

DEFAULT_DB = os.environ.get("NETS_DB", "/var/lib/nets/nets.db")


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .web.app import create_app

    app = create_app(args.db)
    uvicorn.run(app, host=args.host, port=args.port, log_level=args.log_level)
    return 0


#: Die IEEE-Server weisen den Default-User-Agent von urllib mit HTTP 418 ab.
_UA = {"User-Agent": "Mozilla/5.0 (compatible; NetS/0.1; +local network inventory)"}


def _fetch(url: str, timeout: int = 90) -> str:
    import urllib.request

    request = urllib.request.Request(url, headers=_UA)
    with urllib.request.urlopen(request, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def cmd_oui_update(args: argparse.Namespace) -> int:
    from .util import oui_path

    # --output erlaubt es, die Datei bewusst neben den Programmcode zu legen.
    # Genau das braucht der Paketbau: ohne mitgelieferte Datenbank waere eine
    # frische Installation auf Netzzugang angewiesen.
    target = Path(args.output) if getattr(args, "output", None) else oui_path(for_writing=True)
    target.parent.mkdir(parents=True, exist_ok=True)
    entries: dict[str, str] = {}

    # Primaerquelle IEEE. MA-M/MA-S sind die feiner granularen Bloecke und
    # muessen die groberen MA-L-Eintraege ueberschreiben duerfen.
    for name, url, nibbles in [
        ("MA-L", "https://standards-oui.ieee.org/oui/oui.csv", 6),
        ("MA-M", "https://standards-oui.ieee.org/oui28/mam.csv", 7),
        ("MA-S", "https://standards-oui.ieee.org/oui36/oui36.csv", 9),
    ]:
        try:
            text = _fetch(url)
        except Exception as exc:
            print(f"  {name}: fehlgeschlagen ({exc})", file=sys.stderr)
            continue
        count = 0
        for row in text.splitlines()[1:]:
            parts = _split_csv(row)
            if len(parts) < 3:
                continue
            prefix = parts[1].strip().lower()[:nibbles]
            vendor = parts[2].strip().strip('"')
            if prefix and vendor:
                entries[prefix] = vendor
                count += 1
        print(f"  {name}: {count} Eintraege")

    if not entries:
        print("  IEEE nicht erreichbar -- versuche Wireshark-'manuf'", file=sys.stderr)
        entries.update(_parse_manuf())

    if not entries:
        print("Keine Daten geladen -- alte Datei bleibt unveraendert.", file=sys.stderr)
        return 1

    target.write_text(
        "\n".join(f"{prefix}\t{vendor}" for prefix, vendor in sorted(entries.items())) + "\n",
        encoding="utf-8",
    )
    print(f"{len(entries)} Praefixe nach {target} geschrieben")
    return 0


def _parse_manuf() -> dict[str, str]:
    """Fallback: die 'manuf'-Datei von Wireshark.

    Format je Zeile:  00:00:0C[/28]<TAB>Cisco<TAB>Cisco Systems, Inc

    Wird tatsaechlich gebraucht: Die IEEE-Server lehnen Anfragen aus
    Rechenzentren ab (aus GitHub-Runnern kommt "Connection refused"), waehrend
    sie von einem Heimanschluss aus antworten. Ohne funktionierende
    Rueckfallquelle scheitert der Paketbau dort also immer.
    """
    url = "https://www.wireshark.org/download/automated/data/manuf"
    try:
        text = _fetch(url)
    except Exception as exc:
        print(f"  manuf: fehlgeschlagen ({exc})", file=sys.stderr)
        return {}

    entries: dict[str, str] = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        mask_spec, _, bits = parts[0].partition("/")
        prefix = mask_spec.replace(":", "").replace("-", "").lower()
        # Praefixlaenge in Nibbles; ohne /-Angabe sind es die ersten 24 Bit.
        nibbles = (int(bits) // 4) if bits.isdigit() else 6
        prefix = prefix[:nibbles]
        vendor = (parts[2] if len(parts) > 2 and parts[2].strip() else parts[1]).strip()
        # len(prefix) mitpruefen: eine verstuemmelte Zeile wie "AA:BB" haette
        # sonst ein zu kurzes Praefix in der Tabelle hinterlassen. Treffer
        # gaebe es damit zwar nie -- der Lookup fragt 6, 7 oder 9 Nibbles ab --
        # aber Muell gehoert gar nicht erst hinein.
        if vendor and nibbles in (6, 7, 9) and len(prefix) == nibbles:
            entries[prefix] = vendor
    print(f"  manuf: {len(entries)} Eintraege")
    return entries


def _split_csv(row: str) -> list[str]:
    """Minimaler CSV-Parser -- die IEEE-Dateien enthalten Kommas in Firmennamen."""
    out, current, in_quotes = [], [], False
    for char in row:
        if char == '"':
            in_quotes = not in_quotes
        elif char == "," and not in_quotes:
            out.append("".join(current))
            current = []
        else:
            current.append(char)
    out.append("".join(current))
    return out


def cmd_check(args: argparse.Namespace) -> int:
    ok = True
    print("Werkzeuge:")
    for tool, why in [
        ("snmpbulkwalk", "SNMP-Adapter (Paket net-snmp/snmp)"),
        ("nmap", "optionale Dienst-/OS-Erkennung"),
        ("ip", "Interface-Liste und Nachbarschaftscache"),
    ]:
        path = shutil.which(tool)
        print(f"  {'ok  ' if path else 'FEHLT'} {tool:<14} {path or why}")
        if not path and tool == "ip":
            ok = False

    print("\nPython-Module:")
    for module in ("scapy", "fastapi", "uvicorn", "httpx"):
        try:
            __import__(module)
            print(f"  ok    {module}")
        except ImportError:
            print(f"  FEHLT {module}")
            ok = False

    print("\nRechte:")
    try:
        import socket

        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 3)
        sock.close()
        print("  ok    AF_PACKET/SOCK_RAW (passives Mithoeren moeglich)")
    except PermissionError:
        print("  FEHLT CAP_NET_RAW -- als root starten oder Capability setzen")
        ok = False
    except Exception as exc:
        print(f"  ?     AF_PACKET-Test nicht moeglich: {exc}")

    from .util import _oui_table, oui_path

    table = _oui_table()
    print(f"\nOUI-Datenbank: {len(table)} Praefixe ({oui_path()})")
    if not table:
        print("  -> 'python -m nets oui-update' ausfuehren")

    db_path = Path(args.db)
    print(f"\nDatenbank: {db_path} ({'vorhanden' if db_path.exists() else 'wird beim Start angelegt'})")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nets", description="Netzwerk-Inventar und Topologie")
    parser.add_argument("--db", default=DEFAULT_DB, help=f"Pfad zur SQLite-DB (Standard: {DEFAULT_DB})")
    parser.add_argument("--log-level", default="info", choices=["debug", "info", "warning", "error"])
    sub = parser.add_subparsers(dest="command")

    serve = sub.add_parser("serve", help="Dienst und WebUI starten")
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", type=int, default=8080)
    serve.set_defaults(func=cmd_serve)

    oui = sub.add_parser("oui-update", help="IEEE-Herstellerdatenbank laden")
    oui.add_argument("--output", help="Zieldatei (Standard: der beschreibbare Datenpfad)")
    oui.set_defaults(func=cmd_oui_update)
    sub.add_parser("check", help="Umgebung pruefen").set_defaults(func=cmd_check)

    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s %(levelname)-7s %(name)s  %(message)s",
    )
    if not hasattr(args, "func"):
        args.host, args.port = "0.0.0.0", 8080
        args.func = cmd_serve
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
