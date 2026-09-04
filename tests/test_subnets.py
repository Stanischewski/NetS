"""Mehrere Subnetze finden.

Der springende Punkt: ARP ist link-lokal. Fuer ein geroutetes Netz findet ein
ARP-Sweep *stillschweigend* nichts -- ohne Fehler, ohne Hinweis. Genau das war
der Fehler, den diese Tests absichern.
"""

from __future__ import annotations

import asyncio
import socket
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nets.collect import active
from nets.store import Observation, Store


def _store() -> Store:
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    return Store(tmp.name)


def test_local_and_routed_networks_are_distinguished():
    """Was auf einem eigenen Interface liegt, ist per ARP erreichbar --
    alles andere nur ueber einen Router."""
    local = asyncio.run(active.local_networks())
    routed = asyncio.run(active.routed_networks())

    assert all("/" in n for n in local + routed)
    # Kein Netz kann gleichzeitig lokal und geroutet sein.
    assert not (set(local) & set(routed))
    # Virtuelle Interfaces (docker, veth …) gehören in keine der Listen.
    assert "172.17.0.0/16" not in local + routed

    for net in local:
        assert asyncio.run(active.is_local_network(net)) is True
    for net in routed:
        assert asyncio.run(active.is_local_network(net)) is False

    # Ein Netz, in dem wir sicher nicht stehen.
    assert asyncio.run(active.is_local_network("203.0.113.0/24")) is False
    assert asyncio.run(active.is_local_network("kaputt")) is False


def test_routed_sweep_finds_open_tcp_without_icmp():
    """Viele Hosts verwerfen Ping. Ein offener Port beweist trotzdem, dass
    dort jemand ist."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        assert asyncio.run(active._tcp_alive("127.0.0.1", port, 1.0)) is True
        assert asyncio.run(active._tcp_alive("127.0.0.1", 1, 0.5)) is False
    finally:
        srv.close()
    # Nach dem Schliessen ist der Port zu.
    assert asyncio.run(active._tcp_alive("127.0.0.1", port, 0.5)) is False


def test_routed_sweep_records_hosts_without_inventing_macs():
    """Jenseits des eigenen Segments gibt es keine MAC. Eine zu erfinden wäre
    schlimmer als die Lücke zu zeigen -- solche Funde gehören deshalb nicht in
    die Geräteliste."""
    store = _store()
    store.record_subnet_host("203.0.113.5", "203.0.113.0/24", "icmp")
    store.record_subnet_host("203.0.113.9", "203.0.113.0/24", "tcp", "Port 443")

    assert store.conn.execute("SELECT COUNT(*) n FROM devices").fetchone()["n"] == 0
    rows = {r["ip"]: dict(r) for r in store.conn.execute("SELECT * FROM subnet_hosts")}
    assert rows["203.0.113.9"]["detail"] == "Port 443"
    assert rows["203.0.113.5"]["method"] == "icmp"

    # Ein zweiter Lauf legt nichts doppelt an, aktualisiert aber last_seen.
    store.record_subnet_host("203.0.113.5", "203.0.113.0/24", "tcp", "Port 22")
    assert store.conn.execute("SELECT COUNT(*) n FROM subnet_hosts").fetchone()["n"] == 2
    assert store.conn.execute(
        "SELECT method FROM subnet_hosts WHERE ip='203.0.113.5'"
    ).fetchone()["method"] == "tcp"


def test_overview_separates_real_inventory_from_mere_reachability():
    """Nur Adressen mit MAC sind echtes Inventar. Der Rest sagt bloss, dass
    dort etwas antwortet -- und genau das muss die Übersicht auseinanderhalten,
    sonst wiegt sie in falscher Sicherheit."""
    store = _store()
    # Eigenes Segment: über ARP mit MAC erfasst.
    store.observe(Observation(mac="aa:bb:cc:00:00:01", ip="198.51.100.5", source="arp"))
    store.observe(Observation(mac="aa:bb:cc:00:00:02", ip="198.51.100.6", source="arp"))
    # Geroutetes Netz: nur erreichbar, keine MAC.
    for i in range(3):
        store.record_subnet_host(f"203.0.113.{i + 1}", "203.0.113.0/24", "icmp")

    overview = {e["subnet"]: e for e in store.subnet_overview()}
    assert overview["198.51.100.0/24"]["with_mac"] == 2
    assert overview["198.51.100.0/24"]["responding"] == 0
    assert overview["203.0.113.0/24"]["with_mac"] == 0
    assert overview["203.0.113.0/24"]["responding"] == 3


def test_missing_ping_does_not_kill_the_sweep():
    """Schlanke Container-Images haben kein ping. Frueher riss die Ausnahme
    den ganzen Sweep mit und ein komplettes Subnetz fiel aus -- obwohl der
    TCP-Versuch danach allein getragen haette."""
    original = active._PING
    try:
        active._PING = None          # so, als waere ping nicht auffindbar
        assert asyncio.run(active._icmp_alive("127.0.0.1", 1.0)) is False
        # Der TCP-Weg funktioniert weiterhin.
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            store = _store()
            found = asyncio.run(active.routed_sweep(
                store, "127.0.0.1/32", ports=(port,), timeout=0.5))
            assert found == ["127.0.0.1"] or found == []
        finally:
            srv.close()
    finally:
        active._PING = original


def test_interface_comes_from_the_route():
    """Regression: der ARP-Sweep nahm immer das eine konfigurierte Interface.
    Steht der Rechner in zwei Segmenten, gingen die Anfragen am Ziel vorbei --
    gemessen: 0 Antworten über wlan0, 2 über enp0s31f6, dasselbe Subnetz."""
    for net in asyncio.run(active.local_networks()):
        iface = asyncio.run(active.interface_for(net))
        assert iface, f"für {net} muss ein Interface bestimmbar sein"
        assert not active.is_virtual_iface(iface)

    # Unsinn liefert None statt zu scheitern.
    assert asyncio.run(active.interface_for("kein-netz")) is None


def test_sniffer_accepts_several_interfaces():
    """Broadcast endet am Router: wer in mehreren Segmenten steht, muss auf
    jedem lauschen."""
    from nets.collect.passive import PassiveSniffer, parse_ifaces

    assert parse_ifaces("wlan0, eth0") == ["wlan0", "eth0"]
    assert parse_ifaces("eth0;eth1") == ["eth0", "eth1"]
    assert parse_ifaces("  ") == []
    assert parse_ifaces(None) == []

    store = _store()
    sniffer = PassiveSniffer(store, "wlan0, enp0s31f6")
    assert sniffer.ifaces == ["wlan0", "enp0s31f6"]
    assert sniffer.iface == "wlan0", "Einzel-Interface für Verfahren, die nur eines können"
    assert sniffer.status()["iface"] == "wlan0, enp0s31f6"

    # Pakete werden je Interface gezählt.
    class Fake:
        sniffed_on = "enp0s31f6"
    sniffer._handle(Fake())
    sniffer._handle(Fake())
    assert sniffer.status()["per_iface"] == {"enp0s31f6": 2}
    assert sniffer.status()["packets_seen"] == 2

    # Ohne Interface gibt es eine klare Meldung statt eines stillen Nichtstuns.
    empty = PassiveSniffer(store, "")
    try:
        empty.start()
    except RuntimeError as exc:
        assert "kein Interface" in str(exc)
    else:
        raise AssertionError("leere Interface-Liste muss auffallen")


def test_sweep_too_large_is_refused():
    store = _store()
    try:
        asyncio.run(active.routed_sweep(store, "198.51.100.0/8"))
    except ValueError as exc:
        assert "zu gross" in str(exc)
    else:
        raise AssertionError("ein /8 darf nicht durchgesweept werden")


def test_manuf_parser_handles_the_wireshark_format():
    """Die Rückfallquelle war lange tot, ohne dass es auffiel: IEEE antwortet
    von einem Heimanschluss aus, aus Rechenzentren aber nicht. Erst im CI
    schlug der Paketbau fehl -- und die Rückfall-URL lieferte 404.

    Der Parser wird hier ohne Netz gegen das echte Format geprüft."""
    import nets.__main__ as cli

    sample = "\n".join([
        "# Kommentarzeile",
        "",
        "DC:A6:32\tRaspberryPi\tRaspberry Pi Trading Ltd",
        "00:1B:A9\tBrother\tBrother industries, LTD.",
        "8C:1F:64:0D:0/36\tGeneSys\tGeneSys Elektronik GmbH",   # MA-S, 36 Bit
        "70:B3:D5:12:3/36\tKurzform",                            # ohne dritte Spalte
        "kaputt",
        "AA:BB\tZuKurz",                                          # kein gültiges Präfix
    ])
    original = cli._fetch
    cli._fetch = lambda url, timeout=90: sample
    try:
        entries = cli._parse_manuf()
    finally:
        cli._fetch = original

    assert entries["dca632"] == "Raspberry Pi Trading Ltd"
    assert entries["001ba9"] == "Brother industries, LTD."
    # Bei MA-S zählen neun Nibbles, und ohne dritte Spalte gilt die zweite.
    assert entries["8c1f640d0"] == "GeneSys Elektronik GmbH"
    assert entries["70b3d5123"] == "Kurzform"
    assert "aabb" not in entries and "kaputt" not in entries

    # Ein Netzfehler ergibt eine leere Menge, keinen Absturz.
    cli._fetch = lambda url, timeout=90: (_ for _ in ()).throw(OSError("kein Netz"))
    try:
        assert cli._parse_manuf() == {}
    finally:
        cli._fetch = original


def test_sniffer_falls_back_when_libpcap_is_missing():
    """Ohne libpcap laesst sich der BPF-Ausdruck nicht uebersetzen -- mitlesen
    kann der AF_PACKET-Socket aber weiterhin. Im LXC lief der Dienst deshalb
    scheinbar gesund, sammelte aber tagelang nichts."""
    import nets.collect.passive as passive

    store = _store()
    sniffer = passive.PassiveSniffer(store, iface="lo")

    attempts: list[str | None] = []
    original = passive.PassiveSniffer._start

    def fake(self, bpf):
        attempts.append(bpf)
        if bpf is not None:
            raise RuntimeError("Cannot set filter: libpcap is not available.")
        self._sniffer = object()

    passive.PassiveSniffer._start = fake
    try:
        sniffer.start()
    finally:
        passive.PassiveSniffer._start = original

    assert attempts == [sniffer.bpf, None], "erst mit Filter, dann ohne"
    assert sniffer.filtered is False
    assert sniffer.status()["filtered"] is False

    # Jeder andere Fehler bleibt ein Fehler -- ein fehlendes Interface darf
    # nicht heimlich zu einem ungefilterten Sniffer werden.
    def always_broken(self, bpf):
        raise RuntimeError("Interface 'gibtsnicht' nicht gefunden")

    passive.PassiveSniffer._start = always_broken
    try:
        try:
            passive.PassiveSniffer(store, iface="gibtsnicht").start()
            raise AssertionError("haette scheitern muessen")
        except RuntimeError as exc:
            assert "gibtsnicht" in str(exc)
    finally:
        passive.PassiveSniffer._start = original


def test_listen_address_comes_from_the_environment():
    """/etc/default/nets wurde zwar eingelesen, konnte aber nichts bewirken:
    Adresse und Port standen fest im ExecStart. Genau das braucht man aber,
    um die WebUI an Loopback zu binden und per SSH zu tunneln."""
    import importlib
    import os

    import nets.__main__ as cli

    def defaults(**env):
        """Laedt das Modul mit gesetzter Umgebung neu und liest die Vorgaben."""
        keep = {k: os.environ.get(k) for k in ("NETS_HOST", "NETS_PORT")}
        for key in keep:
            os.environ.pop(key, None)
        os.environ.update(env)
        try:
            module = importlib.reload(cli)
            return module.DEFAULT_HOST, module.DEFAULT_PORT
        finally:
            for key, value in keep.items():
                os.environ.pop(key, None)
                if value is not None:
                    os.environ[key] = value
            importlib.reload(cli)

    assert defaults() == ("0.0.0.0", 8080), "ohne Vorgabe von ueberall erreichbar"
    assert defaults(NETS_HOST="127.0.0.1", NETS_PORT="9999") == ("127.0.0.1", 9999)

    # Ein ausdrueckliches Argument muss die Umgebung schlagen. Geprueft wird
    # der echte Parser: cmd_serve wird ersetzt, statt uvicorn zu starten.
    seen = {}
    original = cli.cmd_serve
    cli.cmd_serve = lambda args: seen.update(host=args.host, port=args.port) or 0
    try:
        os.environ["NETS_HOST"] = "127.0.0.1"
        importlib.reload(cli).cmd_serve = cli.cmd_serve
        cli.main(["serve", "--host", "10.0.0.1"])
        assert seen["host"] == "10.0.0.1", seen
        # Auch ohne Unterkommando -- der Dienst startet dann ueber den
        # Standardpfad -- muss die Umgebung gelten, sonst lauschte er trotz
        # NETS_HOST=127.0.0.1 auf allen Adressen.
        seen.clear()
        cli.main([])
        assert seen["host"] == "127.0.0.1", seen
    finally:
        os.environ.pop("NETS_HOST", None)
        cli.cmd_serve = original
        importlib.reload(cli)


def test_service_unit_does_not_pin_the_address():
    """Sonst waere die EnvironmentFile-Zeile im Unit wirkungslos."""
    unit = (Path(__file__).resolve().parents[1] / "deploy/debian/nets.service").read_text()
    exec_line = next(l for l in unit.splitlines() if l.startswith("ExecStart="))
    assert "--port" not in exec_line and "--host" not in exec_line, exec_line
    assert "EnvironmentFile=-/etc/default/nets" in unit


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
