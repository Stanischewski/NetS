"""Smoke-Tests ohne echtes Netz: synthetische Pakete durch die Parser, dann
Store, Topologie-Aufloesung und API pruefen.

Ausfuehren:  .venv/bin/python -m pytest tests/ -q
oder direkt: .venv/bin/python tests/test_smoke.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import ARP, Ether

from nets import topology, util
from nets.collect.parsers import ArpParser, DhcpParser
from nets.store import Observation, Store


def test_mac_helpers():
    assert util.norm_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert util.norm_mac("aabb.ccdd.eeff") == "aa:bb:cc:dd:ee:ff"
    assert util.norm_mac(b"\xaa\xbb\xcc\xdd\xee\xff") == "aa:bb:cc:dd:ee:ff"
    assert util.norm_mac("nonsense") is None
    # U/L-Bit: 0x02 gesetzt -> randomisiert
    assert util.is_locally_administered("a6:11:22:33:44:55")
    assert not util.is_locally_administered("a0:80:69:00:00:01")
    assert util.is_multicast_mac("01:00:5e:00:00:01")


def test_arp_parser():
    pkt = Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc="aa:bb:cc:dd:ee:01", psrc="192.168.1.50", pdst="192.168.1.1"
    )
    results = list(ArpParser().parse(pkt))
    assert len(results) == 1
    assert results[0].mac == "aa:bb:cc:dd:ee:01"
    assert results[0].ip == "192.168.1.50"

    reply = Ether() / ARP(
        op=2, hwsrc="aa:bb:cc:dd:ee:02", psrc="192.168.1.1",
        hwdst="aa:bb:cc:dd:ee:01", pdst="192.168.1.50",
    )
    assert len(list(ArpParser().parse(reply))) == 2  # Sender und Empfaenger


def test_dhcp_parser_extracts_fingerprint():
    pkt = (
        Ether(src="aa:bb:cc:dd:ee:03")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=bytes.fromhex("aabbccddee03"), xid=1)
        / DHCP(options=[
            ("message-type", 3),
            ("hostname", b"laptop-anna"),
            ("vendor_class_id", b"MSFT 5.0"),
            ("param_req_list", [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]),
            ("requested_addr", "192.168.1.77"),
            "end",
        ])
    )
    obs = list(DhcpParser().parse(pkt))
    assert len(obs) == 1
    o = obs[0]
    assert o.mac == "aa:bb:cc:dd:ee:03"
    assert o.hostname == "laptop-anna"
    assert o.dhcp_seen is True
    assert o.ip == "192.168.1.77"
    assert o.facts["dhcp_fingerprint"].startswith("1,3,6,15")
    assert o.facts["vendor_class"] == "MSFT 5.0"
    assert o.facts["dhcp_last_msg"] == "request"


def test_snmp_identity_parsing():
    """MACs kommen je nach SNMP-Typ in verschiedenen Schreibweisen."""
    from nets.adapters.snmp import _mac_from_snmp

    assert _mac_from_snmp("00 1B A9 44 55 66") == "00:1b:a9:44:55:66"   # Hex-STRING
    assert _mac_from_snmp("0:1b:a9:44:55:66") == "00:1b:a9:44:55:66"    # STRING
    # LLDP-Chassis-ID: erstes Byte ist der Subtyp und gehoert nicht zur MAC.
    assert _mac_from_snmp("4 00 1B A9 44 55 66") == "00:1b:a9:44:55:66"
    assert _mac_from_snmp("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    for junk in ("", "irgendwas", "00 1B A9", None):
        assert _mac_from_snmp(junk) is None


def test_switch_is_linked_to_its_own_device_entry():
    """Regression: der Switch stand zweimal im Inventar -- einmal als
    abgefragtes net_device, einmal als herrenloses Endgerät mit eigener MAC."""
    store = _store()
    switch_mac = "00:1b:a9:aa:bb:cc"
    switch_id = store.conn.execute(
        "INSERT INTO net_devices(name, adapter_type, config) VALUES('HP-2530','snmp','{}')"
    ).lastrowid

    # Der passive Sniffer sieht die Management-MAC des Switches im Netz.
    store.observe(Observation(mac=switch_mac, ip="192.0.2.208", source="arp"))
    store.record_fdb(switch_id, [("aa:bb:cc:00:00:01", "3", None)])
    topology.resolve(store)

    # Vor der Identitätsabfrage: der Switch gilt als Gerät ohne Zuordnung.
    before = topology.tree(store)
    assert before["stats"]["unattached"] == 1

    # Nach der Abfrage ist er mit seinem Infrastrukturknoten verschmolzen.
    store.record_identity(
        switch_id, [switch_mac, "00:1b:a9:aa:bb:cd"], ["192.0.2.208"],
        name="HP-2530-24G", description="ProCurve J9773A",
    )
    after = topology.tree(store)
    assert after["stats"]["unattached"] == 0, "der Switch darf kein herrenloses Gerät mehr sein"
    assert after["stats"]["self_linked"] == 1

    # Regression: ein 24-Port-Switch meldet 29 Interface-MACs. Daraus dürfen
    # keine Phantomgeräte entstehen -- nur die Bridge-Adresse zählt.
    before_count = store.conn.execute("SELECT COUNT(*) n FROM devices").fetchone()["n"]
    store.record_identity(
        switch_id, [switch_mac, *[f"00:1b:a9:aa:bb:{i:02x}" for i in range(0xD0, 0xE8)]],
        ["192.0.2.208"],
    )
    assert store.conn.execute("SELECT COUNT(*) n FROM devices").fetchone()["n"] == before_count, \
        "unbeobachtete Interface-MACs dürfen kein Gerät anlegen"
    # In net_identities stehen sie trotzdem -- zum Ausschließen als Client.
    # 24 neue plus die Bridge-MAC: die Liste wird ersetzt, nicht ergänzt.
    assert len(store.identity_macs(switch_id)) == 25

    node = after["roots"][0]
    assert node["label"] == "HP-2530"
    assert "192.0.2.208" in node["sublabel"]
    assert switch_mac in node["sublabel"]
    assert "+1 weitere" in node["sublabel"], "weitere Interface-MACs werden als Anzahl gezeigt"
    assert node["device_id"], "der Knoten muss auf den Geräteeintrag verlinken"

    # Die Identität landet auch als Merkmal am Gerät.
    facts = {
        r["key"]: r["value"] for r in store.conn.execute(
            "SELECT f.key, f.value FROM facts f JOIN devices d ON d.id=f.device_id WHERE d.mac=?",
            (switch_mac,),
        )
    }
    assert facts["role"] == "infrastructure"
    assert facts["model"] == "ProCurve J9773A"

    # Und die Eigen-MAC wird nicht mehr als Client an einen Port gehängt.
    store.record_fdb(switch_id, [(switch_mac, "3", None)])
    topology.resolve(store)
    assert not store.conn.execute(
        "SELECT 1 FROM attachments a JOIN devices d ON d.id=a.device_id WHERE d.mac=?",
        (switch_mac,),
    ).fetchone()


def test_unifi_prefers_classic_api_and_falls_back():
    """Ein API-Schlüssel öffnet bei aktuellen Controllern *beide* APIs. Nur die
    klassische liefert Switch-Port, SSID und Signal -- sie muss deshalb zuerst
    versucht werden. Erst wenn sie ablehnt, ist die schlankere
    Integrations-API die richtige Wahl."""
    import asyncio

    from nets.adapters import Capability
    from nets.adapters.unifi import UnifiAdapter

    with_key = UnifiAdapter({"base_url": "https://udm", "auth_method": "api_key", "api_key": "k"})

    # Der Zugangsweg begrenzt den Umfang nicht -- die *API* tut es.
    for cap in (Capability.WIRELESS, Capability.DHCP_LEASES, Capability.FDB,
                Capability.IDENTITY):
        assert with_key.has(cap)

    # Klassische API offen: der volle Datensatz, mit Port und SSID.
    classic = UnifiAdapter({"base_url": "https://udm", "auth_method": "api_key", "api_key": "k"})
    classic_pages = {
        "stat/device": [{"mac": "6c:63:f8:00:00:01", "name": "UDM Pro", "ip": "192.0.2.2",
                         "port_table": [{"port_idx": 1, "name": "WAN"}]}],
        "stat/sta": [{"mac": "a0:80:69:00:00:01", "sw_mac": "6c:63:f8:00:00:01", "sw_port": 2,
                      "vlan": 0, "is_wired": True, "hostname": "notebook"},
                     {"mac": "a6:11:22:33:44:55", "ap_mac": "6c:63:f8:00:00:02", "essid": "WLAN-Beispiel",
                      "signal": -52, "is_wired": False}],
        "list/user": [{"mac": "a0:80:69:00:00:01", "last_ip": "192.0.2.211", "hostname": "notebook"}],
    }

    async def fake_classic(path):
        return classic_pages[path]

    classic._get = fake_classic
    assert asyncio.run(classic._classic_available()) is True
    entries = asyncio.run(classic.fdb())
    assert ("6c:63:f8:00:00:01:2" in [e.port_key for e in entries]), \
        "die klassische API kennt den Switch-Port -- der muss durchkommen"
    wireless = asyncio.run(classic.wireless_clients())
    assert wireless[0].ssid == "WLAN-Beispiel" and wireless[0].signal == -52
    assert len(asyncio.run(classic.dhcp_leases())) == 1

    # Pflichtfelder hängen am gewählten Weg.
    assert UnifiAdapter.validate({"base_url": "https://udm", "auth_method": "api_key"})
    assert UnifiAdapter.validate({"base_url": "https://udm", "auth_method": "api_key",
                                  "api_key": "k"}) == []
    errors = UnifiAdapter.validate({"base_url": "https://udm", "auth_method": "password"})
    assert len(errors) == 2, errors

    # Antworten der echten Integrations-API, gekürzt.
    pages = {
        "/sites": {"data": [{"id": "site-1", "internalReference": "default", "name": "Default"}],
                   "totalCount": 1},
        "/sites/site-1/devices": {"data": [
            {"id": "dev-1", "name": "UDM Pro HSR24", "model": "UDM Pro",
             "macAddress": "6c:63:f8:00:00:01", "ipAddress": "unknown"}], "totalCount": 1},
        "/sites/site-1/devices/dev-1": {"interfaces": {"ports": [
            {"idx": 1, "state": "DOWN", "connector": "RJ45"},
            {"idx": 2, "state": "UP", "connector": "RJ45"}]}},
        "/sites/site-1/clients": {"data": [
            {"id": "c1", "macAddress": "a0:80:69:00:00:01", "name": "notebook",
             "type": "WIRED", "uplinkDeviceId": "dev-1"},
            # UniFi setzt die MAC als Namen, wenn keiner vergeben wurde.
            {"id": "c2", "macAddress": "34:19:4d:00:00:01", "name": "34:19:4d:00:00:01",
             "type": "WIRED", "uplinkDeviceId": "dev-1"}], "totalCount": 2},
    }

    async def fake_v1(path):
        return pages[path.split("?")[0]]

    async def classic_rejected(path):
        raise RuntimeError("403 Forbidden")

    with_key._v1 = fake_v1
    with_key._get = classic_rejected
    assert asyncio.run(with_key._classic_available()) is False, \
        "abgelehnte klassische API muss auf die Integrations-API führen"

    identity = asyncio.run(with_key.identity())
    assert identity.macs == ["6c:63:f8:00:00:01"]
    assert identity.ips == ["udm"], "ohne brauchbare Geräte-IP die Management-Adresse"

    entries = asyncio.run(with_key.fdb())
    assert len(entries) == 2
    # Der Port ist unbekannt -- und das muss dranstehen, statt einen zu erfinden.
    assert all("Port unbekannt" in e.port_key for e in entries)
    assert all("UDM Pro HSR24" in e.port_key for e in entries)

    hosts = asyncio.run(with_key.hosts())
    assert [h.name for h in hosts] == ["notebook"], \
        "eine MAC als Name ist kein Name"

    ports = asyncio.run(with_key.ports())
    assert [p.port_key for p in ports] == ["dev-1:1", "dev-1:2"]
    assert "RJ45" in ports[0].name

    # Was die API nicht hergibt, kommt leer zurück statt zu scheitern.
    assert asyncio.run(with_key.wireless_clients()) == []
    assert asyncio.run(with_key.dhcp_leases()) == []


def test_proxmox_config_parsing():
    """Die netN-Zeilen von QEMU und LXC haben unterschiedliche Formate --
    bei QEMU ist die MAC der *Wert des Modellschlüssels*, bei LXC hwaddr."""
    from nets.adapters.proxmox import _interfaces

    qemu = {
        "net0": "virtio=BC:24:11:00:00:01,bridge=vmbr0,tag=20,firewall=1",
        "net1": "e1000=BC:24:11:00:00:02,bridge=vmbr1",
        "name": "opnsense",          # kein Interface
        "scsi0": "local-lvm:vm-101-disk-0",
    }
    assert _interfaces(qemu) == [
        ("bc:24:11:00:00:01", "vmbr0", 20),
        ("bc:24:11:00:00:02", "vmbr1", None),
    ]

    lxc = {"net0": "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:AA:BB:CC,ip=dhcp,type=veth"}
    assert _interfaces(lxc) == [("bc:24:11:aa:bb:cc", "vmbr0", None)]

    # Kein Netz, kaputte Werte, fehlende Bridge
    assert _interfaces({"net0": "virtio=keine-mac,bridge=vmbr0"}) == []
    assert _interfaces({"net0": "virtio=BC:24:11:00:00:01"}) == [
        ("bc:24:11:00:00:01", "unbekannt", None)
    ]
    assert _interfaces({}) == []


def test_lldp_neighbor_matched_by_chassis_mac():
    """Regression: LLDP-Nachbarn wurden nur über den SysName aufgelöst. Wer
    den Adapter anders benannte als das Gerät sich selbst, bekam keine
    Verbindung -- obwohl die Chassis-MAC eindeutig ist."""
    store = _store()
    switch = store.conn.execute(
        "INSERT INTO net_devices(name, adapter_type, config) VALUES('HP-2530','snmp','{}')"
    ).lastrowid
    # Der Nutzer nennt den Host "Proxmox", LLDP meldet aber "pve.example".
    pve = store.conn.execute(
        "INSERT INTO net_devices(name, adapter_type, config) VALUES('Proxmox','proxmox','{}')"
    ).lastrowid

    pve_mac = "bc:24:11:aa:bb:cc"
    store.record_identity(pve, [pve_mac], ["192.0.2.2"], name="pve.example")
    store.record_fdb(switch, [("aa:bb:cc:00:00:01", "1", None)])
    store.record_fdb(pve, [("bc:24:11:00:00:99", "pve:vmbr0", 20)])
    store.record_links(switch, [("24", "pve.example", "eno1", pve_mac)], source="snmp")

    topology.resolve(store)
    tree = topology.tree(store)

    root = next(r for r in tree["roots"] if r["label"] == "HP-2530")
    child = next((c for c in root["children"] if c["label"] == "Proxmox"), None)
    assert child is not None, "der Host muss trotz abweichendem Namen unter dem Switch hängen"
    assert child["via_port"] == "24"
    assert child["kind"] == "infra", "kein 'unbekannter Nachbar' mehr"

    # Ohne Chassis-MAC greift weiterhin der Namensabgleich.
    store.conn.execute("UPDATE links SET b_mac=NULL")
    fallback = topology.tree(store)
    unknown = next(
        (c for r in fallback["roots"] for c in r["children"] if c["kind"] == "infra_unknown"), None
    )
    assert unknown and unknown["label"] == "pve.example"


def test_neighbor_resolved_via_management_ip():
    """Der Fall, der ohne diesen Weg scheitert: LLDP liefert eine Chassis-MAC,
    aber die API des Geräts gibt seine NIC-MACs nicht preis (Proxmox). Dann
    muss die passiv beobachtete IP die Brücke zur Adapterkonfiguration schlagen."""
    store = _store()
    switch = store.conn.execute(
        "INSERT INTO net_devices(name, adapter_type, config) VALUES('Switch','snmp','{\"host\":\"192.0.2.208\"}')"
    ).lastrowid
    pve = store.conn.execute(
        "INSERT INTO net_devices(name, adapter_type, config) "
        "VALUES('Virtualisierer','proxmox','{\"base_url\":\"https://192.0.2.20:8006\"}')"
    ).lastrowid

    chassis = "00:d8:61:00:00:01"
    # Der Sniffer hat die MAC mit ihrer IP gesehen -- das ist die einzige
    # Verbindung zwischen LLDP-Nachbar und Adapter.
    store.observe(Observation(mac=chassis, ip="192.0.2.20", source="arp"))
    store.record_fdb(switch, [("aa:bb:cc:00:00:01", "1", None)])
    store.record_fdb(pve, [("bc:24:11:00:00:99", "pve1:vmbr0", None)])
    # Weder Eigenadresse gemeldet noch Namensgleichheit: nur die Chassis-MAC.
    store.record_links(switch, [("24", "pve.example", "eno1", chassis)], source="snmp")
    assert store.identity_macs() == {}, "kein Adapter hat Eigenadressen gemeldet"

    topology.resolve(store)
    tree = topology.tree(store)
    root = next(r for r in tree["roots"] if r["label"] == "Switch")
    child = next((c for c in root["children"] if c["label"] == "Virtualisierer"), None)
    assert child is not None, "Auflösung über die Management-IP muss greifen"
    assert child["via_port"] == "24"

    # Ohne passenden Adapter bleibt der Nachbar unbekannt -- dann aber mit IP
    # und MAC beschriftet, damit man weiß, was man nachtragen müsste.
    store.conn.execute("UPDATE net_devices SET config='{}' WHERE id=?", (pve,))
    orphan = topology.tree(store)
    unknown = next(
        (c for r in orphan["roots"] for c in r["children"] if c["kind"] == "infra_unknown"), None
    )
    assert unknown is not None
    assert "pve.example" in unknown["label"]
    assert "192.0.2.20" in unknown["label"]
    assert chassis in unknown["label"]


def test_identity_falls_back_to_management_ip():
    """Proxmox gibt unter /nodes/<node>/network keine hwaddr heraus. Ohne
    Rückfallweg bliebe der Host als eigenes Endgerät im Inventar stehen."""
    store = _store()
    pve = store.conn.execute(
        "INSERT INTO net_devices(name, adapter_type, config) VALUES('pve','proxmox','{}')"
    ).lastrowid
    host_mac = "00:d8:61:00:00:01"
    store.observe(Observation(mac=host_mac, ip="192.0.2.20", source="arp"))

    # Der Adapter meldet keine MACs, nur seine Management-IP.
    assert store.record_identity(pve, [], ["192.0.2.20"]) == 1
    assert store.identity_macs() == {host_mac: pve}
    assert store.conn.execute(
        "SELECT source FROM net_identities WHERE mac=?", (host_mac,)
    ).fetchone()["source"] == "via-ip"

    # Unbekannte IP -> keine erfundene Zuordnung.
    other = store.conn.execute(
        "INSERT INTO net_devices(name, adapter_type, config) VALUES('x','proxmox','{}')"
    ).lastrowid
    assert store.record_identity(other, [], ["198.51.100.254"]) == 0


def test_infrastructure_nests_behind_infrastructure():
    """OPNsense ist eine VM auf einem Proxmox-Host, der an einem Switchport
    steckt. LLDP sagt dazu nichts -- die Verschachtelung muss aus den
    FDB-Tabellen kommen, sonst stehen drei lose Wurzeln nebeneinander."""
    store = _store()
    switch = store.conn.execute(
        "INSERT INTO net_devices(name, adapter_type, config) VALUES('Switch','snmp','{}')"
    ).lastrowid
    pve = store.conn.execute(
        "INSERT INTO net_devices(name, adapter_type, config) VALUES('pve','proxmox','{}')"
    ).lastrowid
    fw = store.conn.execute(
        "INSERT INTO net_devices(name, adapter_type, config) VALUES('OPNsense','snmp','{}')"
    ).lastrowid

    pve_mac, fw_mac = "00:d8:61:00:00:01", "bc:24:11:00:00:01"
    store.record_identity(pve, [pve_mac], ["192.0.2.20"])
    store.record_identity(fw, [fw_mac], ["192.0.2.2"])

    # Der Switch sieht an Port 24 alles, was hinter dem Host liegt ...
    store.record_fdb(switch, [(pve_mac, "24", None), (fw_mac, "24", None),
                              *[(f"aa:bb:cc:00:00:{i:02x}", "24", None) for i in range(6)]])
    # ... der Host selbst sieht die Firewall isoliert an seiner Bridge.
    store.record_fdb(pve, [(fw_mac, "pve:vmbr0", None)])
    store.record_ports(pve, [("pve:vmbr0", "pve / vmbr0", "access")])

    topology.resolve(store)
    tree = topology.tree(store)

    assert [r["label"] for r in tree["roots"]] == ["Switch"], "eine Wurzel, keine losen Knoten"
    switch_node = tree["roots"][0]
    pve_node = next(c for c in switch_node["children"] if c["label"] == "pve")
    assert pve_node["via_port"] == "24"

    fw_node = next((c for c in pve_node["children"] if c["label"] == "OPNsense"), None)
    assert fw_node is not None, "die VM muss unter ihrem Host hängen, nicht unter dem Switch"
    # Portname aus net_ports statt des rohen Schlüssels.
    assert fw_node["via_port"] == "pve / vmbr0"

    # Und beide tauchen nicht zusätzlich als Client an einem Port auf.
    for mac in (pve_mac, fw_mac):
        assert not store.conn.execute(
            "SELECT 1 FROM attachments a JOIN devices d ON d.id=a.device_id WHERE d.mac=?", (mac,)
        ).fetchone()


def test_links_are_not_duplicated_on_repeated_polls():
    """Regression: der UNIQUE-Index über links enthält b_name/b_port. In SQLite
    ist NULL nie gleich NULL -- ein Nachbar ohne SysName legte deshalb bei
    jedem Poll eine neue Zeile an, unbegrenzt."""
    store = _store()
    switch = store.conn.execute(
        "INSERT INTO net_devices(name, adapter_type, config) VALUES('Switch','snmp','{}')"
    ).lastrowid

    def count():
        return store.conn.execute("SELECT COUNT(*) n FROM links").fetchone()["n"]

    # Eine Abfrage liefert die vollständige Nachbartabelle -- beide Nachbarn
    # also gemeinsam. Der erste hat weder Namen noch Portnamen, nur eine
    # Chassis-MAC.
    neighbors = [
        ("12", None, None, "36:19:4d:00:00:01"),
        ("24", "pve.example", "eno1", "00:d8:61:00:00:01"),
    ]
    for _ in range(5):
        store.record_links(switch, neighbors, source="snmp")
    assert count() == 2, "wiederholte Polls dürfen keine Duplikate erzeugen"

    # Eine einmal gelernte MAC geht nicht verloren, wenn ein späterer Poll sie
    # nicht mitliefert.
    store.record_links(switch, [(*neighbors[0][:3], None), (*neighbors[1][:3], None)],
                       source="snmp")
    assert store.conn.execute(
        "SELECT b_mac FROM links WHERE a_port='24'"
    ).fetchone()["b_mac"] == "00:d8:61:00:00:01"
    assert count() == 2

    # Veraltete Nachbarschaften werden aufgeräumt.
    store.conn.execute("UPDATE links SET ts = ts - 8*86400 WHERE a_port='12'")
    store.prune()
    assert count() == 1


def test_lldp_neighbor_without_sysname_survives():
    """Regression: die Nachbarliste wurde über lldpRemSysName iteriert. Ein
    Gerät ohne SysName-TLV verschwand damit komplett -- obwohl seine
    Chassis-MAC vorhanden und zuordenbar war."""
    import asyncio

    from nets.adapters.snmp import SnmpAdapter

    adapter = SnmpAdapter({"host": "192.0.2.208"})
    walks = {
        "lldpRemSysName": {"0.24.1": "pve.example"},                  # nur ein Nachbar benannt
        "lldpRemPortId": {"0.24.1": "00 D8 61 00 00 01", "0.12.2": "Gi0/1"},
        "lldpRemChassisId": {"0.24.1": "00 D8 61 00 00 01", "0.12.2": "36 19 4D 00 00 01"},
    }

    async def fake_walk(oid, community_suffix=""):
        from nets.adapters.snmp import OID
        return walks[next(k for k, v in OID.items() if v == oid)]

    adapter._walk = fake_walk
    neighbors = asyncio.run(_collect(adapter.lldp()))

    assert len(neighbors) == 2, "auch der namenlose Nachbar muss erhalten bleiben"
    by_port = {n.local_port: n for n in neighbors}
    assert by_port["24"].remote_name == "pve.example"
    assert by_port["24"].remote_mac == "00:d8:61:00:00:01"
    # Rohe Hex-Port-IDs werden als MAC formatiert, Textnamen bleiben Text.
    assert by_port["24"].remote_port == "00:d8:61:00:00:01"
    assert by_port["12"].remote_name is None
    assert by_port["12"].remote_mac == "36:19:4d:00:00:01"
    assert by_port["12"].remote_port == "Gi0/1"


def test_inventory_names_hidden_vms():
    """Der eigentliche Gewinn: aus anonymen MACs hinter einem Uplink werden
    benannte VMs."""
    import asyncio

    from nets.adapters.proxmox import ProxmoxAdapter

    adapter = ProxmoxAdapter({"base_url": "https://pve:8006", "token_id": "x", "token_secret": "y"})
    adapter._cache = [{
        "node": "pve1", "kind": "vm",
        "guest": {"vmid": 101, "name": "opnsense", "status": "running"},
        "config": {"net0": "virtio=BC:24:11:00:00:01,bridge=vmbr0,tag=20"},
    }, {
        "node": "pve1", "kind": "container",
        "guest": {"vmid": 200, "name": "nextcloud", "status": "running"},
        "config": {"net0": "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:AA:00:01,ip=dhcp"},
    }]

    hosts = asyncio.run(_collect(adapter.hosts()))
    assert [h.name for h in hosts] == ["opnsense", "nextcloud"]
    assert hosts[0].mac == "bc:24:11:00:00:01"
    assert hosts[0].kind == "vm"
    assert "VM 101 auf pve1" in hosts[0].note and "VLAN 20" in hosts[0].note
    assert "CT 200 auf pve1" in hosts[1].note

    entries = asyncio.run(_collect(adapter.fdb()))
    assert {(e.mac, e.port_key, e.vlan) for e in entries} == {
        ("bc:24:11:00:00:01", "pve1:vmbr0", 20),
        ("bc:24:11:aa:00:01", "pve1:vmbr0", None),
    }


async def _collect(awaitable):
    return list(await awaitable)


def test_virtual_iface_filter():
    """Regression: Docker-Bridges lieferten ueber 'ip neigh' Adressen wie
    172.18.0.x, die dann als echte Netzwerkgeraete im Inventar landeten."""
    from nets.collect.active import is_virtual_iface

    for name in ("docker0", "br-1a2b3c", "veth7f21a1", "virbr0", "lo", "wg0", "tailscale0"):
        assert is_virtual_iface(name), name
    for name in ("eth0", "wlan0", "enp0s31f6", "eno1", "ens18", "bond0"):
        assert not is_virtual_iface(name), name


def _store() -> Store:
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    return Store(tmp.name)


def test_store_dedupe_and_history():
    store = _store()
    a = store.observe(Observation(mac="aa:bb:cc:00:00:01", ip="198.51.100.5", source="arp"))
    b = store.observe(Observation(mac="AA:BB:CC:00:00:01", ip="198.51.100.6", source="arp"))
    assert a == b, "gleiche MAC in anderer Schreibweise muss dasselbe Geraet sein"

    ips = [r["ip"] for r in store.conn.execute("SELECT ip FROM addresses WHERE device_id=?", (a,))]
    assert sorted(ips) == ["198.51.100.5", "198.51.100.6"], "IP-Historie muss beide behalten"

    # Multicast- und Nulladressen werden verworfen
    assert store.observe(Observation(mac="01:00:5e:00:00:fb", source="mdns")) is None
    assert store.observe(Observation(mac="00:00:00:00:00:00", source="arp")) is None

    # Fakten werden dedupliziert
    for _ in range(3):
        store.observe(Observation(mac="aa:bb:cc:00:00:01", source="mdns", facts={"model": "iPhone14,2"}))
    count = store.conn.execute(
        "SELECT COUNT(*) c FROM facts WHERE device_id=? AND key='model'", (a,)
    ).fetchone()["c"]
    assert count == 1

    # Rotierende Werte (Avahi im Namenskonflikt zaehlt hoch) duerfen die
    # Tabelle nicht unbegrenzt fluten -- nur die juengsten bleiben.
    from nets.store import MAX_FACT_VALUES

    for i in range(MAX_FACT_VALUES * 3):
        store.observe(Observation(mac="aa:bb:cc:00:00:01", source="mdns", hostname=f"host-{i}"))
    hostnames = [
        r["value"] for r in store.conn.execute(
            "SELECT value FROM facts WHERE device_id=? AND source='mdns' AND key='hostname' "
            "ORDER BY ts DESC, id DESC", (a,)
        )
    ]
    assert len(hostnames) == MAX_FACT_VALUES
    assert hostnames[0] == f"host-{MAX_FACT_VALUES * 3 - 1}", "der neueste Wert muss erhalten bleiben"


def test_addr_mode_inference():
    store = _store()
    dhcp_dev = store.observe(Observation(mac="aa:bb:cc:00:00:10", ip="198.51.100.10", source="dhcp", dhcp_seen=True))
    static_dev = store.observe(Observation(mac="aa:bb:cc:00:00:11", ip="198.51.100.11", source="arp"))

    # Erst mit genuegend Beobachtungsdauer darf 'static' gesetzt werden.
    assert store.infer_static_addressing(min_age_seconds=86400) == 0
    assert store.infer_static_addressing(min_age_seconds=0) == 1

    modes = {
        r["id"]: r["addr_mode"] for r in store.conn.execute("SELECT id, addr_mode FROM devices")
    }
    assert modes[dhcp_dev] == "dhcp"
    assert modes[static_dev] == "static"


def test_topology_picks_access_port_over_uplink():
    """Der Kern der Topologie-Heuristik.

    Switch 'core' sieht die MAC ueber seinen Uplink zusammen mit 20 anderen,
    Switch 'edge' sieht sie allein an Port 3. Das Geraet haengt an edge/3.
    """
    store = _store()
    core = store.conn.execute(
        "INSERT INTO net_devices(name, adapter_type, config) VALUES('core','snmp','{}')"
    ).lastrowid
    edge = store.conn.execute(
        "INSERT INTO net_devices(name, adapter_type, config) VALUES('edge','snmp','{}')"
    ).lastrowid

    target = "aa:bb:cc:00:00:99"
    noise = [(f"aa:bb:cc:00:01:{i:02x}", "1", None) for i in range(20)]

    store.record_fdb(core, [(target, "1", None), *noise])           # alles am Uplink Port 1
    store.record_fdb(edge, [(target, "3", None), ("aa:bb:cc:00:00:98", "4", None)])

    assert topology.resolve(store) >= 1
    row = store.conn.execute(
        "SELECT a.net_device_id, a.port_key, a.confidence FROM attachments a "
        "JOIN devices d ON d.id=a.device_id WHERE d.mac=?", (target,)
    ).fetchone()
    assert row["net_device_id"] == edge, "Port mit den wenigsten MACs muss gewinnen"
    assert row["port_key"] == "3"
    assert row["confidence"] == 1.0


def test_topology_tree_structure():
    """Der Baum muss die Struktur zeigen, die der Graph verschluckt hat:
    Geräte je Port gruppiert, Uplinks markiert, Nicht-Zugeordnete sichtbar."""
    store = _store()
    core = store.conn.execute(
        "INSERT INTO net_devices(name, adapter_type, config) VALUES('core','snmp','{}')"
    ).lastrowid
    edge = store.conn.execute(
        "INSERT INTO net_devices(name, adapter_type, config) VALUES('edge','snmp','{}')"
    ).lastrowid
    store.record_ports(edge, [("3", "GigabitEthernet0/3", "access"), ("12", None, None)])

    # core kennt alles über seinen Uplink; edge hat einen Einzelport und einen
    # Port, an dem 8 MACs hängen (dort steckt unmanaged Hardware).
    crowd = [f"aa:bb:cc:00:02:{i:02x}" for i in range(8)]
    store.record_fdb(core, [(m, "1", None) for m in (*crowd, "aa:bb:cc:00:00:99")])
    store.record_fdb(edge, [("aa:bb:cc:00:00:99", "3", None), *[(m, "12", None) for m in crowd]])
    # LLDP: core und edge sind Nachbarn, dazu ein unbekannter Nachbar.
    store.record_links(core, [("1", "edge", "24")], source="snmp")
    store.record_links(edge, [("24", "core", "1"), ("23", "pve-host", "eth0")], source="snmp")

    # Ein Gerät, das kein Switch kennt -- darf nicht unsichtbar werden.
    store.observe(Observation(mac="aa:bb:cc:00:0f:ff", ip="10.9.9.9", source="arp"))
    topology.resolve(store)

    tree = topology.tree(store)
    assert tree["stats"]["unattached"] == 1

    def find(nodes, label):
        for node in nodes:
            if node["label"] == label:
                return node
            hit = find(node["children"], label)
            if hit:
                return hit
        return None

    # core hat die meisten MACs -> Wurzel, edge hängt darunter.
    labels = [r["label"] for r in tree["roots"]]
    assert "core" in labels, labels
    core_node = find(tree["roots"], "core")
    assert find(core_node["children"], "edge"), "edge muss unter core hängen"
    assert find(tree["roots"], "edge") is not tree["roots"][0]

    # Der unbekannte LLDP-Nachbar taucht als Hinweis auf.
    unknown = find(tree["roots"], "pve-host")
    assert unknown and unknown["kind"] == "infra_unknown"

    # Port 3 trägt den Namen aus net_ports, Port 12 ist als Uplink markiert.
    named = find(tree["roots"], "GigabitEthernet0/3")
    assert named and named["count"] == 1 and not named["hidden_infrastructure"]
    crowded = find(tree["roots"], "Port 12")
    assert crowded["count"] == 8
    assert crowded["hidden_infrastructure"], "8 MACs an einem Port = verdeckte Hardware"
    # Kein LLDP an Port 12 -> nicht abfragbare Hardware, der Hinweis muss das sagen.
    assert "unmanaged" in crowded["hint"]
    assert "Adapter" not in crowded["hint"], "ohne LLDP gibt es nichts hinzuzufügen"

    # Nicht zugeordnete Geräte stehen sichtbar in einer eigenen Gruppe,
    # nach Subnetz sortiert.
    group = find(tree["roots"], "Ohne Port-Zuordnung")
    assert group and group["count"] == 1
    assert find(group["children"], "10.9.9.0/24")

    # Zählwerte müssen sich nach oben summieren.
    assert core_node["count"] == sum(c["count"] for c in core_node["children"])


def test_port_hint_distinguishes_lldp_from_silence():
    """LLDP reicht genau einen Hop weit. Meldet sich dort ein Nachbar, weiß man
    *wer* davorsteht und kann ihn abfragen; schweigt der Port, steckt dort
    Hardware ohne LLDP, an der nichts zu machen ist. Zwei sehr verschiedene
    Lagen -- vorher bekamen beide denselben Hinweis."""
    store = _store()
    switch = store.conn.execute(
        "INSERT INTO net_devices(name, adapter_type, config) VALUES('Switch','snmp','{}')"
    ).lastrowid

    crowd_a = [(f"aa:bb:cc:00:01:{i:02x}", "12", None) for i in range(9)]
    crowd_b = [(f"aa:bb:cc:00:02:{i:02x}", "20", None) for i in range(6)]
    store.record_fdb(switch, [*crowd_a, *crowd_b, ("aa:bb:cc:00:03:01", "5", None)])
    # Nur Port 12 hat einen LLDP-Nachbarn.
    store.record_links(switch, [("12", "router.fritz.box", "lan1", "36:19:4d:00:00:01")], source="snmp")

    topology.resolve(store)
    tree = topology.tree(store)
    ports = {c["label"]: c for c in tree["roots"][0]["children"] if c["kind"] == "port"}

    with_lldp = ports["Port 12"]
    assert "router.fritz.box" in with_lldp["hint"]
    assert "einen Hop" in with_lldp["hint"], "die Reichweite von LLDP muss benannt werden"
    assert "Als Adapter hinzufügen" in with_lldp["hint"], "hier gibt es eine Handlungsoption"
    assert any("hinter router.fritz.box" in b["text"] for b in with_lldp["badges"])

    without = ports["Port 20"]
    assert "Kein LLDP-Nachbar" in without["hint"]
    assert "unmanaged" in without["hint"]
    assert not any("hinter" in b["text"] for b in without["badges"])

    # Ein normaler Endgeräteport bekommt gar keinen Hinweis.
    assert ports["Port 5"]["hint"] is None
    assert not ports["Port 5"]["hidden_infrastructure"]


def test_adapter_registry_and_validation():
    from nets import adapters

    types = {t["type_id"] for t in adapters.all_types()}
    assert {"snmp", "unifi", "openwrt", "mikrotik", "fritzbox"} <= types

    for described in adapters.all_types():
        assert described["display_name"], "Adapter braucht einen Anzeigenamen"
        for field in described["config_fields"]:
            assert {"key", "label", "type"} <= set(field), field
            if field["type"] == "select":
                assert field.get("choices"), f"select ohne choices: {field['key']}"

    snmp = adapters.Adapter.registry["snmp"]
    assert snmp.validate({}) , "fehlender Host muss einen Fehler ergeben"
    assert snmp.validate({"host": "192.168.1.2"}) == []
    assert "Zahl" in " ".join(snmp.validate({"host": "x", "port": "keine-zahl"}))


def test_sniffer_watchdog():
    """Regression: der scapy-Thread starb bei einem WLAN-Reconnect lautlos weg
    und niemand hat es gemerkt -- das Tool sammelte danach tagelang nichts."""
    import asyncio

    from nets.daemon import Daemon

    class FakeSniffer:
        def __init__(self, running=True, packets=0):
            self._running, self.packets_seen = running, packets

        def status(self):
            return {"running": self._running, "error": None}

    store = _store()
    daemon = Daemon(store)
    for key, value in {"passive_enabled": "1", "sniffer_stall_seconds": "900"}.items():
        store.set_setting(key, value)

    restarts = []
    daemon.start_sniffer = lambda: restarts.append(daemon.sniffer)

    # 1) Gar kein Sniffer -> Neustart
    daemon.sniffer = None
    asyncio.run(daemon.check_sniffer())
    assert len(restarts) == 1
    assert "nicht gestartet" in daemon.sniffer_last_reason

    # 2) Thread beendet -> Neustart
    daemon.sniffer = FakeSniffer(running=False)
    asyncio.run(daemon.check_sniffer())
    assert len(restarts) == 2

    # 3) Laeuft und zaehlt hoch -> kein Neustart
    daemon.sniffer = FakeSniffer(running=True, packets=10)
    asyncio.run(daemon.check_sniffer())
    daemon.sniffer.packets_seen = 25
    asyncio.run(daemon.check_sniffer())
    assert len(restarts) == 2, "ein gesunder Sniffer darf nicht neu gestartet werden"

    # 4) Laeuft, aber Zaehler steht seit ueber der Grenze -> Neustart
    daemon._last_packet_change = util.now() - 1000
    asyncio.run(daemon.check_sniffer())
    assert len(restarts) == 3
    assert "keine Pakete" in daemon.sniffer_last_reason

    # 5) Passives Mithoeren abgeschaltet -> Watchdog haelt still
    store.set_setting("passive_enabled", "0")
    daemon.sniffer = None
    asyncio.run(daemon.check_sniffer())
    assert len(restarts) == 3

    # 6) Abschaltbar ueber die Einstellung
    store.set_setting("passive_enabled", "1")
    store.set_setting("sniffer_stall_seconds", "0")
    daemon.sniffer = FakeSniffer(running=True, packets=25)
    daemon._last_packet_count = 25
    daemon._last_packet_change = util.now() - 100000
    asyncio.run(daemon.check_sniffer())
    assert len(restarts) == 3, "Stillstandserkennung muss abschaltbar sein"

    assert daemon.status()["sniffer"]["restarts"] == 3


def test_api_end_to_end():
    from fastapi.testclient import TestClient

    from nets.web.app import create_app

    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    app = create_app(tmp.name)

    with TestClient(app) as client:
        assert client.get("/api/status").status_code == 200
        assert client.get("/").status_code == 200

        types = client.get("/api/adapter-types").json()
        assert len(types) >= 5

        # Anlegen mit fehlendem Pflichtfeld -> 400
        bad = client.post("/api/net-devices", json={"name": "x", "adapter_type": "snmp", "config": {}})
        assert bad.status_code == 400

        created = client.post("/api/net-devices", json={
            "name": "Switch Keller", "adapter_type": "snmp",
            "config": {"host": "192.168.1.2", "community": "geheim"},
        })
        assert created.status_code == 200
        net_id = created.json()["id"]

        # Passwortfelder duerfen nie im Klartext aus der API kommen.
        listed = client.get("/api/net-devices").json()
        assert listed[0]["config"]["community"] == "********"
        assert listed[0]["config"]["host"] == "192.168.1.2"

        # Maskierter Wert beim Speichern = unveraendert lassen
        client.put(f"/api/net-devices/{net_id}", json={
            "name": "Switch Keller", "config": {"community": "********", "host": "192.168.1.3"},
        })
        stored = json.loads(
            app.state.store.conn.execute(
                "SELECT config FROM net_devices WHERE id=?", (net_id,)
            ).fetchone()["config"]
        )
        assert stored["community"] == "geheim"
        assert stored["host"] == "192.168.1.3"

        # Geraet anlegen und Detailansicht abrufen
        device_id = app.state.store.observe(
            Observation(mac="aa:bb:cc:11:22:33", ip="192.168.1.50", hostname="nas",
                        source="mdns", facts={"model": "DS920+"})
        )
        devices = client.get("/api/devices?q=nas").json()
        assert len(devices) == 1 and devices[0]["ip"] == "192.168.1.50"

        detail = client.get(f"/api/devices/{device_id}").json()
        assert detail["device"]["hostname"] == "nas"
        assert any(f["key"] == "model" for f in detail["facts"])

        client.patch(f"/api/devices/{device_id}", json={"label": "Synology NAS"})
        assert client.get("/api/devices").json()[0]["label"] == "Synology NAS"

        # Nicht erlaubte Felder werden abgewiesen
        assert client.patch(f"/api/devices/{device_id}", json={"mac": "x"}).status_code == 400

        settings = client.get("/api/settings").json()
        assert "iface" in settings and "subnets" in settings
        assert client.put("/api/settings", json={"subnets": "192.168.1.0/24"}).status_code == 200
        assert client.get("/api/settings").json()["subnets"] == "192.168.1.0/24"

        assert client.get("/api/topology").status_code == 200


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(list(globals().items())):
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
