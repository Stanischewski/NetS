"""Weboberflaechen-Suche.

Der Scanner selbst wird gegen einen echten HTTP-Server im Testprozess
geprueft -- gegen Mocks liesse sich nicht feststellen, ob Titel, Server-Header
und Weiterleitungen wirklich richtig gelesen werden.
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nets.collect.webscan import DEFAULT_PORTS, WebScanner, extract_title, parse_ports
from nets.store import Observation, Store


def test_port_list_is_forgiving_but_strict():
    assert parse_ports(None) == parse_ports(DEFAULT_PORTS)
    assert parse_ports("80, 443; 8006") == [80, 443, 8006]
    assert parse_ports("443,443,80") == [443, 80], "Doppelte fallen weg"
    # Unsinn wird verworfen statt zu einem Fehler zu führen.
    assert parse_ports("80, quatsch, 99999, -1, 0") == [80]
    assert parse_ports("") == parse_ports(None)


def test_title_extraction_handles_real_pages():
    assert extract_title(b"<title>Proxmox Virtual Environment</title>") == \
        "Proxmox Virtual Environment"
    # Titel aus Templates haben Umbrüche und Einrückung.
    assert extract_title(b"<html><head>\n<title>\n  Home\n  Assistant\n</title>") == "Home Assistant"
    assert extract_title(b'<TITLE class="x">UniFi</TITLE>') == "UniFi"
    assert extract_title(b"<title>Umlaut \xc3\xa4\xc3\xb6</title>") == "Umlaut äö"
    # Latin-1 als Rückfall, wenn UTF-8 nicht aufgeht.
    assert extract_title(b"<title>Gr\xfc\xdfe</title>") == "Grüße"
    assert extract_title(b"<html>kein Titel</html>") is None
    assert extract_title(b"") is None


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/weiter"):
            self.send_response(302)
            self.send_header("Location", "/ziel")
            self.end_headers()
            return
        if self.path.startswith("/geschuetzt"):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="x"')
            self.end_headers()
            return
        if self.path.startswith("/kaputt"):
            self.send_response(500)
            self.end_headers()
            return
        body = b"<html><head><title>Testoberflaeche</title></head><body>hi</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "TestServer/1.0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _server() -> tuple[ThreadingHTTPServer, int]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def test_probe_reads_title_and_server():
    srv, port = _server()
    try:
        scanner = WebScanner(ports=[port], timeout=3.0)
        found = asyncio.run(scanner.probe("127.0.0.1", port))
        assert found is not None
        assert found["title"] == "Testoberflaeche"
        # BaseHTTPRequestHandler stellt seinen eigenen Server-Header voran.
        assert "TestServer/1.0" in found["server"]
        assert found["status"] == 200
        assert found["scheme"] == "http"
        assert found["port"] == port
    finally:
        srv.shutdown()


def test_closed_port_yields_nothing_and_fast():
    """Der geschlossene Port ist der haeufigste Fall -- er muss billig sein.
    Ohne TCP-Vorpruefung zahlte jede Kombination den vollen HTTP-Timeout, und
    ein Lauf ueber 72 Adressen x 10 Ports lief in die Minuten."""
    import time

    scanner = WebScanner(ports=[1], timeout=5.0, connect_timeout=1.5)
    start = time.monotonic()
    assert asyncio.run(scanner.probe("127.0.0.1", 1)) is None
    # Eine Ablehnung kommt sofort -- nicht erst nach dem HTTP-Timeout.
    assert time.monotonic() - start < 2.0


def test_open_port_without_http_is_no_hit():
    """Ein offener Port muss nicht bedeuten, dass dort HTTP spricht."""
    import socket

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        scanner = WebScanner(ports=[port], timeout=2.0)
        assert asyncio.run(scanner.probe("127.0.0.1", port)) is None
    finally:
        srv.close()


def test_scan_only_touches_known_addresses():
    """Der Scanner bekommt seine Ziele vom Store -- er sucht nie selbst nach
    Adressen. Sonst waere es ein Netzscan, kein Nachschlagen."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    store = Store(tmp.name)

    store.observe(Observation(mac="aa:bb:cc:00:00:01", ip="192.0.2.10", source="arp"))
    store.observe(Observation(mac="aa:bb:cc:00:00:02", ip="192.0.2.11", source="arp"))
    # IPv6 und ignorierte Geräte gehören nicht dazu.
    store.observe(Observation(mac="aa:bb:cc:00:00:03", ip="fe80::1", source="ndp"))
    ignored = store.observe(Observation(mac="aa:bb:cc:00:00:04", ip="192.0.2.12", source="arp"))
    store.conn.execute("UPDATE devices SET ignored=1 WHERE id=?", (ignored,))

    assert store.scan_targets() == ["192.0.2.10", "192.0.2.11"]

    # Wer lange nicht gesehen wurde, fällt raus -- die IP gehört vielleicht
    # längst jemand anderem.
    store.conn.execute("UPDATE addresses SET last_seen = last_seen - 30*86400")
    assert store.scan_targets(max_age_days=7) == []


def test_results_are_upserted_and_keep_known_labels():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    store = Store(tmp.name)
    device = store.observe(Observation(mac="aa:bb:cc:00:00:01", ip="192.0.2.10", source="arp"))

    store.record_web_service({
        "ip": "192.0.2.10", "port": 8006, "scheme": "https", "status": 200,
        "title": "Proxmox Virtual Environment", "server": "nginx", "redirect": None,
    })
    rows = store.web_services()
    assert len(rows) == 1
    assert rows[0]["device_id"] == device, "über die IP dem Gerät zugeordnet"
    assert rows[0]["title"] == "Proxmox Virtual Environment"

    # Ein späterer Lauf ohne Titel (Timeout beim Body) darf ihn nicht löschen.
    store.record_web_service({
        "ip": "192.0.2.10", "port": 8006, "scheme": "https", "status": 200,
        "title": None, "server": None, "redirect": None,
    })
    rows = store.web_services()
    assert len(rows) == 1, "gleiche IP und Port -> eine Zeile"
    assert rows[0]["title"] == "Proxmox Virtual Environment"
    assert rows[0]["server"] == "nginx"

    # Anderer Port am selben Gerät ist ein eigener Eintrag.
    store.record_web_service({"ip": "192.0.2.10", "port": 22222, "scheme": "http",
                              "status": 401, "title": None, "server": None, "redirect": None})
    assert len(store.web_services()) == 2


def test_passive_sources_are_harvested_without_probing():
    """UPnP nennt seine URL von selbst -- die muss man nicht erfragen."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    store = Store(tmp.name)
    store.observe(Observation(
        mac="aa:bb:cc:00:00:01", ip="192.0.2.70", source="ssdp",
        facts={"upnp_location": "http://192.0.2.70:80/DevDesc.xml"},
    ))
    store.observe(Observation(
        mac="aa:bb:cc:00:00:02", ip="192.0.2.71", source="ssdp",
        facts={"upnp_location": "https://192.0.2.71:8443/desc"},
    ))
    store.observe(Observation(mac="aa:bb:cc:00:00:03", source="ssdp",
                              facts={"upnp_location": "kaputt"}))

    # mDNS nennt den Port im SRV-Record; die IP kennen wir vom Gerät.
    store.observe(Observation(
        mac="aa:bb:cc:00:00:05", ip="192.0.2.30", source="mdns",
        facts={"web_endpoint": "http:8123"},
    ))
    store.observe(Observation(
        mac="aa:bb:cc:00:00:06", ip="192.0.2.31", source="mdns",
        facts={"web_endpoint": "kaputt"},
    ))

    assert store.harvest_web_passive() == 3
    rows = {r["ip"]: r for r in store.web_services()}
    assert rows["192.0.2.70"]["port"] == 80 and rows["192.0.2.70"]["source"] == "ssdp"
    assert rows["192.0.2.71"]["port"] == 8443
    assert rows["192.0.2.71"]["scheme"] == "https"
    assert rows["192.0.2.30"]["port"] == 8123 and rows["192.0.2.30"]["source"] == "mdns"
    assert "192.0.2.31" not in rows, "unbrauchbare Angaben werden verworfen"

    # Ein zweiter Durchlauf legt nichts doppelt an.
    store.harvest_web_passive()
    assert len(store.web_services()) == 3


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  ok    {name}")
            except Exception as exc:
                failures += 1
                print(f"  FEHL  {name}: {type(exc).__name__}: {exc}")
                import traceback
                traceback.print_exc()
    print("\nalles gruen" if not failures else f"\n{failures} Test(s) fehlgeschlagen")
    sys.exit(1 if failures else 0)
