"""Replay-Test: realistischer Paketmix durch den kompletten passiven Pfad.

Deckt alles ab ausser dem Raw-Socket selbst -- Parser, Store, Ableitungen und
Topologie laufen genau so wie im Betrieb.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSRR, DNSRRSRV
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import ICMPv6ND_NS, IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from nets.collect.passive import PassiveSniffer
from nets.store import Store

# Echte OUIs, damit auch der Hersteller-Lookup mitgetestet wird.
MAC_PI = "dc:a6:32:aa:bb:cc"       # Raspberry Pi
MAC_APPLE = "8c:85:90:11:22:33"    # Apple
MAC_RANDOM = "a6:de:ad:be:ef:01"   # randomisierte MAC (U/L-Bit)
MAC_PRINTER = "00:1b:a9:44:55:66"  # Brother
MAC_SWITCH = "00:1b:0d:77:88:99"   # Cisco -- der einzige echte LLDP-Sender


def _tlv(tlv_type: int, payload: bytes) -> bytes:
    return ((tlv_type << 9) | len(payload)).to_bytes(2, "big") + payload


def lldp_frame() -> bytes:
    """Ein echtes LLDP-Frame, wie es ein managed Switch periodisch sendet."""
    body = (
        _tlv(1, b"\x04" + bytes.fromhex(MAC_SWITCH.replace(":", "")))  # Chassis ID (MAC)
        + _tlv(2, b"\x05" + b"GigabitEthernet0/3")                     # Port ID
        + _tlv(3, (120).to_bytes(2, "big"))                            # TTL
        + _tlv(5, b"sw-keller")                                        # SysName
        + _tlv(6, b"Cisco IOS Software, C2960X")                       # SysDescr
        + _tlv(0, b"")                                                 # Ende
    )
    return bytes(Ether(src=MAC_SWITCH, dst="01:80:c2:00:00:0e", type=0x88CC)) + body


def packets():
    # Ein stiller Host, der nur ARP spricht -- der klassische Fall, den ein
    # Ping-Sweep verpasst.
    yield Ether(src=MAC_PI, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc=MAC_PI, psrc="192.168.1.30", pdst="192.168.1.1"
    )

    # DHCP-Request eines Windows-Notebooks mit randomisierter MAC.
    yield (
        Ether(src=MAC_RANDOM, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=bytes.fromhex(MAC_RANDOM.replace(":", "")), xid=42)
        / DHCP(options=[
            ("message-type", 3),
            ("hostname", b"NB-BUERO-04"),
            ("vendor_class_id", b"MSFT 5.0"),
            ("param_req_list", [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]),
            ("requested_addr", "192.168.1.44"),
            "end",
        ])
    )

    # mDNS-Antwort eines Apple-Geraets mit Modell im TXT-Record.
    yield (
        Ether(src=MAC_APPLE, dst="01:00:5e:00:00:fb")
        / IP(src="192.168.1.61", dst="224.0.0.251")
        / UDP(sport=5353, dport=5353)
        / DNS(
            qr=1, aa=1,
            an=[
                DNSRR(rrname="macbook-anna.local.", type="A", rdata="192.168.1.61", ttl=120),
                DNSRR(rrname="macbook-anna._device-info._tcp.local.", type="TXT",
                      rdata=[b"md=MacBookPro18,3", b"osxvers=23"], ttl=120),
            ],
        )
    )

    # SSDP-NOTIFY eines Netzwerkdruckers.
    ssdp = (
        b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
        b"SERVER: Linux/3.10 UPnP/1.0 Brother/HL-L2350DW 1.24\r\n"
        b"NT: urn:schemas-upnp-org:device:Printer:1\r\n"
        b"LOCATION: http://192.168.1.70:80/DevDesc.xml\r\n\r\n"
    )
    yield (
        Ether(src=MAC_PRINTER, dst="01:00:5e:7f:ff:fa")
        / IP(src="192.168.1.70", dst="239.255.255.250")
        / UDP(sport=1900, dport=1900)
        / Raw(load=ssdp)
    )

    # IPv6 Neighbor Solicitation -- derselbe Pi, andere Adressfamilie.
    yield (
        Ether(src=MAC_PI, dst="33:33:ff:00:00:01")
        / IPv6(src="fe80::dea6:32ff:feaa:bbcc", dst="ff02::1:ff00:1")
        / ICMPv6ND_NS(tgt="fe80::1")
    )

    # Echtes LLDP-Frame eines Switches.
    yield Ether(lldp_frame())

    # Kaputtes Paket: darf den Sniffer nicht umbringen.
    yield Ether(src=MAC_PI) / Raw(load=b"\x00\xff" * 20)


def test_replay_full_pipeline():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    store = Store(tmp.name)
    sniffer = PassiveSniffer(store, iface="test0")

    for pkt in packets():
        # Serialisieren und neu parsen -- so kommen die Pakete auch vom Draht
        # an. Ohne diesen Zyklus testet man scapys Konstruktor, nicht den
        # Parser.
        sniffer._handle(Ether(bytes(pkt)))

    assert sniffer.packets_seen == 7
    assert sniffer.errors == 0, "kein Parser darf an diesen Paketen scheitern"

    devices = {r["mac"]: dict(r) for r in store.conn.execute("SELECT * FROM devices")}
    # Der Router aus dem ARP-Request wird nicht angelegt (nur pdst, keine MAC).
    assert set(devices) == {MAC_PI, MAC_RANDOM, MAC_APPLE, MAC_PRINTER, MAC_SWITCH}, devices.keys()

    # Hersteller aus der OUI-Datenbank -- schlaegt fehl, wenn oui-update fehlt.
    from nets.util import _oui_table
    if _oui_table():
        assert "Raspberry" in (devices[MAC_PI]["vendor"] or "")
        assert "Apple" in (devices[MAC_APPLE]["vendor"] or "")
        assert "Brother" in (devices[MAC_PRINTER]["vendor"] or "")
    assert devices[MAC_RANDOM]["vendor"] is None
    assert devices[MAC_RANDOM]["mac_random"] == 1

    # Hostnamen aus DHCP bzw. mDNS
    assert devices[MAC_RANDOM]["hostname"] == "NB-BUERO-04"
    assert devices[MAC_APPLE]["hostname"] == "macbook-anna"

    # DHCP-Nutzung erkannt -> darf nie als 'static' gelten
    assert devices[MAC_RANDOM]["addr_mode"] == "dhcp"

    facts = {}
    for row in store.conn.execute(
        "SELECT d.mac, f.key, f.value FROM facts f JOIN devices d ON d.id=f.device_id"
    ):
        facts[(row["mac"], row["key"])] = row["value"]

    # Regression: der LLDP-Parser sah frueher *jedes* Frame und markierte damit
    # das ganze Netz als Infrastruktur. Nur der echte LLDP-Sender darf das sein.
    infra = {mac for (mac, key), value in facts.items() if key == "role" and value == "infrastructure"}
    assert infra == {MAC_SWITCH}, f"nur der Switch ist Infrastruktur, nicht {infra}"
    assert facts[(MAC_SWITCH, "lldp_sysname")] == "sw-keller"
    assert facts[(MAC_SWITCH, "lldp_portid")] == "GigabitEthernet0/3"
    assert "C2960X" in facts[(MAC_SWITCH, "lldp_sysdescr")]
    assert devices[MAC_SWITCH]["hostname"] == "sw-keller"

    assert facts[(MAC_RANDOM, "dhcp_fingerprint")] == "1,3,6,15,31,33,43,44,46,47,119,121,249,252"
    assert facts[(MAC_RANDOM, "vendor_class")] == "MSFT 5.0"
    assert facts[(MAC_APPLE, "model")] == "MacBookPro18,3"
    assert "Brother" in facts[(MAC_PRINTER, "ssdp_server")]
    assert facts[(MAC_PRINTER, "upnp_type")] == "urn:schemas-upnp-org:device:Printer:1"

    # Der Pi wurde per IPv4 und IPv6 gesehen -- beides gehoert zu einem Geraet.
    pi_ips = sorted(
        r["ip"] for r in store.conn.execute(
            "SELECT a.ip FROM addresses a JOIN devices d ON d.id=a.device_id WHERE d.mac=?",
            (MAC_PI,),
        )
    )
    assert pi_ips == ["192.168.1.30", "fe80::dea6:32ff:feaa:bbcc"]

    # Statisch-Erkennung: nur wer nie DHCP gesprochen hat.
    store.infer_static_addressing(min_age_seconds=0)
    modes = {r["mac"]: r["addr_mode"] for r in store.conn.execute("SELECT mac, addr_mode FROM devices")}
    # Der Switch hat keine IPv4 gezeigt -> bleibt 'unknown', nicht 'static'.
    assert modes[MAC_SWITCH] == "unknown"
    assert modes[MAC_PI] == "static"
    assert modes[MAC_PRINTER] == "static"
    assert modes[MAC_RANDOM] == "dhcp"
    # Das Apple-Geraet hat nur mDNS gesprochen, aber eine IPv4 -> statisch.
    assert modes[MAC_APPLE] == "static"

    store.close()


def test_mdns_srv_reveals_web_interface_port():
    """Wer `_http._tcp` ankündigt, nennt im SRV-Record den Port. Das ist eine
    Weboberfläche, die man kennt, ohne irgendwo angeklopft zu haben."""
    import tempfile

    from nets.store import Store

    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    store = Store(tmp.name)
    sniffer = PassiveSniffer(store, iface="test0")

    mac = "dc:a6:32:11:22:33"
    announce = (
        Ether(src=mac, dst="01:00:5e:00:00:fb")
        / IP(src="192.0.2.30", dst="224.0.0.251")
        / UDP(sport=5353, dport=5353)
        / DNS(qr=1, aa=1, an=[
            DNSRR(rrname="homeassistant.local.", type="A", rdata="192.0.2.30", ttl=120),
            DNSRRSRV(rrname="Home._http._tcp.local.", type="SRV", port=8123,
                     target="homeassistant.local.", ttl=120),
        ])
    )
    sniffer._handle(Ether(bytes(announce)))
    assert sniffer.errors == 0

    endpoint = store.conn.execute(
        "SELECT value FROM facts WHERE key='web_endpoint'"
    ).fetchone()
    assert endpoint is not None and endpoint["value"] == "http:8123"

    # Und daraus wird ohne jeden Verbindungsversuch ein Eintrag.
    assert store.harvest_web_passive() == 1
    row = store.web_services()[0]
    assert (row["ip"], row["port"], row["scheme"], row["source"]) == \
        ("192.0.2.30", 8123, "http", "mdns")


def test_reflector_stays_recognised_without_an_address_record():
    """Aus dem echten Netz nachgestellt: der Router trug den Hostnamen eines
    PCs aus einem anderen VLAN, und auf der Weboberflaechen-Seite standen
    darum saemtliche VLAN-Gateways unter dessen Namen.

    Die alte Pruefung verlangte einen A-Record zum Gegenpruefen. Reine
    PTR/TXT-Ankuendigungen und solche, die nur AAAA fuehren, rutschten daran
    vorbei -- und genau die reicht ein Reflector auch weiter."""
    import tempfile

    from nets.collect import parsers
    from nets.store import Observation, Store

    parsers._REFLECTORS.clear()
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    store = Store(tmp.name)
    sniffer = PassiveSniffer(store, iface="test0")

    router = "6c:63:f8:00:00:03"
    pc = "a0:80:69:00:00:07"
    store.observe(Observation(mac=router, ip="192.0.2.2", source="arp"))
    store.observe(Observation(mac=pc, ip="10.10.10.24", source="arp"))

    def names():
        return {r["mac"]: r["hostname"] for r in
                store.conn.execute("SELECT mac, hostname FROM devices")}

    # 1) Erst wird der Reflector ueberfuehrt -- hier noch mit A-Record.
    sniffer._handle(Ether(bytes(
        Ether(src=router, dst="01:00:5e:00:00:fb")
        / IP(src="192.0.2.2", dst="224.0.0.251")
        / UDP(sport=5353, dport=5353)
        / DNS(qr=1, aa=1, an=[DNSRR(rrname="buero-pc.local.", type="A",
                                    rdata="10.10.10.24", ttl=120)]))))
    assert names()[pc] == "buero-pc", "der Name gehoert dem Geraet aus dem A-Record"
    assert not names()[router], "und keinesfalls dem Weiterleiter"

    # 2) Jetzt dasselbe ohne Adress-Record. Frueher landete der Hostname damit
    #    beim Router -- er ist ja der Absender.
    sniffer._handle(Ether(bytes(
        Ether(src=router, dst="01:00:5e:00:00:fb")
        / IP(src="192.0.2.2", dst="224.0.0.251")
        / UDP(sport=5353, dport=5353)
        / DNS(qr=1, aa=1, an=[
            DNSRR(rrname="fremder-pc.local.", type="AAAA",
                  rdata="fd00::24", ttl=120),
            DNSRR(rrname="fremder-pc._workstation._tcp.local.", type="TXT",
                  rdata=[b"md=OptiPlex 3070"], ttl=120)]))))
    assert not names()[router], "ein ueberfuehrter Weiterleiter erbt keinen Namen mehr"

    facts = {r["key"]: r["value"] for r in store.conn.execute(
        "SELECT f.key, f.value FROM facts f JOIN devices d ON d.id=f.device_id WHERE d.mac=?",
        (router,))}
    assert "model" not in facts, facts

    # 3) Ein AAAA-Record, dessen Adresse nicht zur IPv6-Quelle passt, entlarvt
    #    den Weiterleiter jetzt genauso wie ein A-Record.
    parsers._REFLECTORS.clear()
    store.observe(Observation(mac="2c:d8:ae:00:00:09", ip="fd00::55", source="ndp"))
    sniffer._handle(Ether(bytes(
        Ether(src=router, dst="33:33:00:00:00:fb")
        / IPv6(src="fd00::2", dst="ff02::fb")
        / UDP(sport=5353, dport=5353)
        / DNS(qr=1, aa=1, an=[DNSRR(rrname="tv.local.", type="AAAA",
                                    rdata="fd00::55", ttl=120)]))))
    assert names()["2c:d8:ae:00:00:09"] == "tv"
    assert not names()[router]


def test_ssdp_location_names_the_real_device():
    """SSDP traegt seine eigene Gegenprobe: LOCATION zeigt auf das
    Beschreibungsdokument des ankuendigenden Geraets. Bisher wurde die URL nur
    als Notiz abgelegt und die Merkmale dem Absender zugeschrieben."""
    import tempfile

    from nets.collect import parsers
    from nets.store import Observation, Store

    parsers._REFLECTORS.clear()
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    store = Store(tmp.name)
    sniffer = PassiveSniffer(store, iface="test0")

    router = "6c:63:f8:00:00:03"
    shelly = "b0:b2:1c:00:00:11"
    store.observe(Observation(mac=router, ip="192.0.2.2", source="arp"))
    store.observe(Observation(mac=shelly, ip="10.10.60.134", source="arp"))

    payload = (b"NOTIFY * HTTP/1.1\r\n"
               b"LOCATION: http://10.10.60.134:80/desc.xml\r\n"
               b"SERVER: ShellyHTTP/1.0.0\r\n"
               b"NT: urn:schemas-upnp-org:device:Basic:1\r\n\r\n")
    sniffer._handle(Ether(bytes(
        Ether(src=router, dst="01:00:5e:7f:ff:fa")
        / IP(src="192.0.2.2", dst="239.255.255.250")
        / UDP(sport=1900, dport=1900) / Raw(load=payload))))

    def facts_of(mac):
        return {r["key"]: r["value"] for r in store.conn.execute(
            "SELECT f.key, f.value FROM facts f JOIN devices d ON d.id=f.device_id "
            "WHERE d.mac=?", (mac,))}

    assert facts_of(shelly).get("ssdp_server") == "ShellyHTTP/1.0.0"
    assert "ssdp_server" not in facts_of(router)
    assert facts_of(router).get("role") == "ssdp_reflector"

    # Sendet das Geraet selbst, passt LOCATION zur Quelle -- normale Zuordnung.
    parsers._REFLECTORS.clear()
    sniffer._handle(Ether(bytes(
        Ether(src=shelly, dst="01:00:5e:7f:ff:fa")
        / IP(src="10.10.60.134", dst="239.255.255.250")
        / UDP(sport=1900, dport=1900) / Raw(load=payload))))
    assert facts_of(shelly).get("ssdp_server") == "ShellyHTTP/1.0.0"
    assert "role" not in facts_of(shelly)


def test_mdns_reflector_does_not_absorb_foreign_identities():
    """Regression aus dem echten Netz: ein UDM-Pro spiegelt mDNS über
    VLAN-Grenzen und setzt dabei seine eigene Absender-MAC ein. Dadurch sammelte
    er 25 fremde Hostnamen und Modelle ein -- Fernseher, Shellys, den Drucker.

    Die Wahrheit steht im Paket: der A-Record nennt die Adresse des gemeinten
    Geräts."""
    import tempfile

    from nets.store import Observation, Store

    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    store = Store(tmp.name)
    sniffer = PassiveSniffer(store, iface="test0")

    router = "6c:63:f8:00:00:03"      # UDM-Pro, spiegelt
    tv = "2c:d8:ae:00:00:01"          # der echte Fernseher in einem anderen VLAN
    store.observe(Observation(mac=router, ip="192.0.2.2", source="arp"))
    store.observe(Observation(mac=tv, ip="10.10.30.55", source="arp"))

    # Der Router sendet die Ankündigung des Fernsehers weiter: eigene MAC und
    # eigene Absender-IP, aber der A-Record nennt den Fernseher.
    reflected = (
        Ether(src=router, dst="01:00:5e:00:00:fb")
        / IP(src="192.0.2.2", dst="224.0.0.251")
        / UDP(sport=5353, dport=5353)
        / DNS(qr=1, aa=1, an=[
            DNSRR(rrname="wohnzimmer.local.", type="A", rdata="10.10.30.55", ttl=120),
            DNSRR(rrname="wohnzimmer._googlecast._tcp.local.", type="TXT",
                  rdata=[b"md=Streaming-Box", b"fn=Fernseher"], ttl=120),
        ])
    )
    sniffer._handle(Ether(bytes(reflected)))

    facts = {}
    for row in store.conn.execute(
        "SELECT d.mac, f.key, f.value FROM facts f JOIN devices d ON d.id=f.device_id"
    ):
        facts.setdefault(row["mac"], {})[row["key"]] = row["value"]

    assert facts.get(tv, {}).get("model") == "Streaming-Box", \
        "die Merkmale gehören dem Gerät aus dem A-Record"
    assert facts.get(tv, {}).get("friendly_name") == "Fernseher"
    assert "model" not in facts.get(router, {}), "der Weiterleiter darf nichts davon erben"
    assert facts.get(router, {}).get("role") == "mdns_reflector", \
        "stattdessen wird er als Weiterleiter markiert"

    # Der Fernseher hat nicht selbst gesendet -- keine Anwesenheit erfinden.
    tv_id = store.conn.execute("SELECT id FROM devices WHERE mac=?", (tv,)).fetchone()["id"]
    buckets_before = store.conn.execute(
        "SELECT COUNT(*) n FROM presence WHERE device_id=?", (tv_id,)
    ).fetchone()["n"]
    sniffer._handle(Ether(bytes(reflected)))
    assert store.conn.execute(
        "SELECT COUNT(*) n FROM presence WHERE device_id=?", (tv_id,)
    ).fetchone()["n"] == buckets_before

    # Ein unbekanntes Ziel legt kein Gerät an -- wir wissen nur, dass jemand
    # darüber geredet hat.
    before = store.conn.execute("SELECT COUNT(*) n FROM devices").fetchone()["n"]
    assert store.observe(Observation(mac=None, ip="10.10.99.99", source="mdns",
                                     facts={"model": "X"})) is None
    assert store.conn.execute("SELECT COUNT(*) n FROM devices").fetchone()["n"] == before

    # Falscher Alarm vermeiden: mDNS über IPv6 hat eine IPv6-Absenderadresse,
    # der A-Record ist aber immer IPv4. Ein Vergleich der beiden würde jedes
    # Gerät mit IPv6 zum Weiterleiter erklären.
    over_v6 = (
        Ether(src=tv, dst="33:33:00:00:00:fb")
        / IPv6(src="fe80::2ed8:aeff:fe3f:3ff7", dst="ff02::fb")
        / UDP(sport=5353, dport=5353)
        / DNS(qr=1, aa=1, an=[DNSRR(rrname="wohnzimmer.local.", type="A",
                                    rdata="10.10.30.55", ttl=120)])
    )
    sniffer._handle(Ether(bytes(over_v6)))
    assert store.conn.execute(
        "SELECT COUNT(*) n FROM facts WHERE device_id=? AND value='mdns_reflector'", (tv_id,)
    ).fetchone()["n"] == 0, "IPv6-Absender darf nicht als Weiterleiter gelten"

    # Sendet das Gerät selbst, bleibt alles wie bisher.
    direct = (
        Ether(src=tv, dst="01:00:5e:00:00:fb")
        / IP(src="10.10.30.55", dst="224.0.0.251")
        / UDP(sport=5353, dport=5353)
        / DNS(qr=1, aa=1, an=[DNSRR(rrname="wohnzimmer.local.", type="A",
                                    rdata="10.10.30.55", ttl=120)])
    )
    sniffer._handle(Ether(bytes(direct)))
    assert store.conn.execute(
        "SELECT COUNT(*) n FROM facts WHERE device_id=? AND key='role'", (tv_id,)
    ).fetchone()["n"] == 0
    assert sniffer.errors == 0


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
