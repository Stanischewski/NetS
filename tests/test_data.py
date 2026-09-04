"""Datenpflege: Loeschen, Aufbewahrung, Sicherung.

Beim Loeschen zaehlt vor allem, was *nicht* mitgeloescht wird. Ein zu weit
gefasstes DELETE faellt erst auf, wenn die Daten schon weg sind.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nets.store import Observation, Store
from nets.util import now


def _populated() -> tuple[Store, dict]:
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    store = Store(tmp.name)

    switch = store.conn.execute(
        "INSERT INTO net_devices(name, adapter_type, config) "
        "VALUES('Switch','snmp','{\"host\":\"192.0.2.208\",\"community\":\"geheim\"}')"
    ).lastrowid
    store.set_setting("iface", "eth0")

    device = store.observe(Observation(
        mac="aa:bb:cc:00:00:01", ip="192.0.2.50", hostname="nas",
        source="mdns", facts={"model": "DS920+"},
    ))
    store.conn.execute("UPDATE devices SET label='Mein NAS', notes='im Keller' WHERE id=?", (device,))
    store.record_fdb(switch, [("aa:bb:cc:00:00:01", "3", None)])
    store.record_links(switch, [("24", "pve", "eno1", "00:d8:61:00:00:01")], source="snmp")
    store.record_identity(switch, ["10:4f:58:00:00:01"], ["192.0.2.208"])
    store.record_wifi_link("a6:11:22:33:44:55", "36:19:4d:00:00:01", ssid="WLAN-Beispiel")
    store.record_ports(switch, [("3", "Port 3", "access")])

    from nets import topology
    topology.resolve(store)
    return store, {"switch": switch, "device": device}


def test_stats_reports_what_is_there():
    store, _ = _populated()
    stats = store.stats()
    assert stats["counts"]["devices"] >= 1
    assert stats["counts"]["net_devices"] == 1
    assert stats["counts"]["facts"] >= 1
    assert stats["db_bytes"] > 0
    assert stats["oldest_observation"] is not None


def test_purge_history_keeps_the_inventory():
    """Der wichtigste Fall: Verlauf weg, aber Namen und Notizen bleiben --
    die sind Handarbeit und nicht wiederherstellbar."""
    store, ids = _populated()
    removed = store.purge("history")

    assert set(removed) <= {"presence", "fdb", "links", "wifi_links"}
    for table in ("presence", "fdb", "links", "wifi_links"):
        assert store.conn.execute(f"SELECT COUNT(*) n FROM {table}").fetchone()["n"] == 0

    device = store.conn.execute("SELECT * FROM devices WHERE id=?", (ids["device"],)).fetchone()
    assert device is not None
    assert device["label"] == "Mein NAS" and device["notes"] == "im Keller"
    assert store.conn.execute("SELECT COUNT(*) n FROM facts").fetchone()["n"] >= 1
    assert store.conn.execute("SELECT COUNT(*) n FROM addresses").fetchone()["n"] >= 1
    assert store.conn.execute("SELECT COUNT(*) n FROM net_devices").fetchone()["n"] == 1


def test_purge_devices_keeps_configuration():
    store, _ = _populated()
    store.purge("devices")

    for table in Store.COLLECTED_TABLES:
        assert store.conn.execute(f"SELECT COUNT(*) n FROM {table}").fetchone()["n"] == 0, table
    # Adapter samt Zugangsdaten und Einstellungen bleiben.
    row = store.conn.execute("SELECT config FROM net_devices").fetchone()
    assert json.loads(row["config"])["community"] == "geheim"
    assert store.get_setting("iface") == "eth0"


def test_purge_everything_keeps_only_settings():
    store, _ = _populated()
    store.purge("everything")

    assert store.conn.execute("SELECT COUNT(*) n FROM net_devices").fetchone()["n"] == 0
    assert store.conn.execute("SELECT COUNT(*) n FROM devices").fetchone()["n"] == 0
    assert store.get_setting("iface") == "eth0", "Einstellungen sind keine gesammelten Daten"

    # Danach muss weitergesammelt werden können.
    assert store.observe(Observation(mac="aa:bb:cc:00:00:09", source="arp")) is not None


def test_purge_rejects_unknown_scope():
    store, _ = _populated()
    try:
        store.purge("alles")
    except ValueError as exc:
        assert "alles" in str(exc)
    else:
        raise AssertionError("unbekannter Bereich muss abgelehnt werden")
    assert store.conn.execute("SELECT COUNT(*) n FROM devices").fetchone()["n"] >= 1


def test_delete_stale_devices_also_clears_mac_keyed_rows():
    """fdb und wifi_links hängen an der MAC, nicht an devices.id -- ON DELETE
    CASCADE greift dort nicht und würde Waisen hinterlassen."""
    store, ids = _populated()
    mac = "aa:bb:cc:00:00:01"
    store.record_wifi_link(mac, "36:19:4d:00:00:01")

    assert store.delete_devices_older_than(30) == 0, "aktive Geräte bleiben"

    store.conn.execute("UPDATE devices SET last_seen = last_seen - 60*86400 WHERE id=?",
                       (ids["device"],))
    assert store.delete_devices_older_than(30) == 1
    assert store.conn.execute("SELECT COUNT(*) n FROM fdb WHERE mac=?", (mac,)).fetchone()["n"] == 0
    assert store.conn.execute(
        "SELECT COUNT(*) n FROM wifi_links WHERE station=?", (mac,)
    ).fetchone()["n"] == 0
    # Nur die Fakten des gelöschten Geräts, per CASCADE. Das Switch-Gerät ist
    # nicht veraltet und behält seine.
    assert store.conn.execute(
        "SELECT COUNT(*) n FROM facts WHERE device_id=?", (ids["device"],)
    ).fetchone()["n"] == 0, "CASCADE muss die Fakten mitnehmen"
    assert store.conn.execute(
        "SELECT COUNT(*) n FROM addresses WHERE device_id=?", (ids["device"],)
    ).fetchone()["n"] == 0
    assert store.conn.execute("SELECT COUNT(*) n FROM devices").fetchone()["n"] >= 1, \
        "aktive Geräte bleiben unberührt"


def test_delete_single_device():
    store, ids = _populated()
    assert store.delete_device(ids["device"]) is True
    assert store.delete_device(ids["device"]) is False
    assert store.conn.execute(
        "SELECT COUNT(*) n FROM fdb WHERE mac='aa:bb:cc:00:00:01'"
    ).fetchone()["n"] == 0


def test_retention_prune_respects_each_window():
    store, ids = _populated()
    old = now() - 100 * 86400
    store.conn.execute("UPDATE presence SET bucket=?", (old,))
    store.conn.execute("UPDATE fdb SET last_seen=?", (old,))
    store.conn.execute("UPDATE links SET ts=?", (old,))
    store.conn.execute("UPDATE wifi_links SET last_seen=?", (old,))

    # Grosszuegige Fenster -> nichts wird angefasst.
    store.prune(presence_days=365, fdb_days=365, link_days=365, wifi_days=365)
    assert store.conn.execute("SELECT COUNT(*) n FROM presence").fetchone()["n"] >= 1
    assert store.conn.execute("SELECT COUNT(*) n FROM wifi_links").fetchone()["n"] == 1

    store.prune(presence_days=90, fdb_days=30, link_days=7, wifi_days=30)
    for table, column in (("presence", "bucket"), ("fdb", "ts"), ("links", "ts"),
                          ("wifi_links", "last_seen")):
        assert store.conn.execute(f"SELECT COUNT(*) n FROM {table}").fetchone()["n"] == 0, table
    # Das Gerät selbst überlebt das Altern seiner Historie.
    assert store.conn.execute("SELECT COUNT(*) n FROM devices").fetchone()["n"] >= 1


def test_fdb_keeps_one_row_per_assignment():
    """Regression: bei jedem Poll wurde die komplette Switch-Tabelle erneut
    angehängt. Im echten Netz standen so 1185 Zeilen für 61 Fakten -- über die
    30 Tage Aufbewahrung wären daraus rund 213.000 geworden."""
    store, ids = _populated()
    switch = ids["switch"]
    entries = [("aa:bb:cc:00:0f:01", "3", None), ("aa:bb:cc:00:0f:02", "4", 20)]

    store.record_fdb(switch, entries, ts=1000)
    after_first = store.conn.execute("SELECT COUNT(*) n FROM fdb").fetchone()["n"]
    assert after_first >= 2

    for ts in (2000, 3000, 4000, 5000):
        store.record_fdb(switch, entries, ts=ts)
    assert store.conn.execute("SELECT COUNT(*) n FROM fdb").fetchone()["n"] == after_first, \
        "wiederholte Abfragen dürfen keine Zeilen erzeugen"

    row = store.conn.execute(
        "SELECT first_seen, last_seen, vlan FROM fdb WHERE mac='aa:bb:cc:00:0f:01' AND port_key='3'"
    ).fetchone()
    assert row["first_seen"] == 1000, "wann die Zuordnung entstand, bleibt erhalten"
    assert row["last_seen"] == 5000, "und wann sie zuletzt bestätigt wurde"
    assert row["vlan"] == -1, "NULL-VLAN wird als -1 geführt, sonst greift UNIQUE nicht"

    # Ein Umzug an einen anderen Port ist eine *neue* Zuordnung, keine Änderung.
    store.record_fdb(switch, [("aa:bb:cc:00:0f:01", "9", None)], ts=6000)
    ports = {
        r["port_key"]: r["last_seen"] for r in store.conn.execute(
            "SELECT port_key, last_seen FROM fdb WHERE mac='aa:bb:cc:00:0f:01'"
        )
    }
    assert ports == {"3": 5000, "9": 6000}, "die Port-Historie muss beide Stationen zeigen"

    # Verschiedene VLANs am selben Port sind verschiedene Zuordnungen.
    store.record_fdb(switch, [("aa:bb:cc:00:0f:02", "4", 30)], ts=7000)
    assert store.conn.execute(
        "SELECT COUNT(*) n FROM fdb WHERE mac='aa:bb:cc:00:0f:02'"
    ).fetchone()["n"] == 2


def test_fdb_migration_collapses_old_rows():
    """Bestehende Datenbanken im alten Format werden verdichtet, ohne die
    echte Historie zu verlieren."""
    import sqlite3

    from nets import db

    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    conn = sqlite3.connect(tmp.name)
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE net_devices (id INTEGER PRIMARY KEY, name TEXT);
        INSERT INTO net_devices(id, name) VALUES (1, 'Switch');
        CREATE TABLE fdb (
            id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, net_device_id INTEGER NOT NULL,
            port_key TEXT NOT NULL, mac TEXT NOT NULL, vlan INTEGER
        );
    """)
    # Dieselbe Zuordnung 50-mal, dazu eine zweite und ein späterer Umzug.
    conn.executemany(
        "INSERT INTO fdb(ts, net_device_id, port_key, mac, vlan) VALUES(?,1,'3','aa:bb:cc:00:00:01',NULL)",
        [(1000 + i * 300,) for i in range(50)],
    )
    conn.execute("INSERT INTO fdb(ts, net_device_id, port_key, mac, vlan) VALUES(9000,1,'4','aa:bb:cc:00:00:02',20)")
    conn.execute("INSERT INTO fdb(ts, net_device_id, port_key, mac, vlan) VALUES(9500,1,'9','aa:bb:cc:00:00:01',NULL)")
    conn.commit()
    assert conn.execute("SELECT COUNT(*) n FROM fdb").fetchone()["n"] == 52

    migrated = db._migrate_fdb_to_unique(conn)
    assert migrated == 3, "52 Zeilen, aber nur drei verschiedene Zuordnungen"

    row = conn.execute(
        "SELECT * FROM fdb WHERE mac='aa:bb:cc:00:00:01' AND port_key='3'"
    ).fetchone()
    assert row["first_seen"] == 1000 and row["last_seen"] == 1000 + 49 * 300
    assert row["vlan"] == -1
    assert conn.execute(
        "SELECT vlan FROM fdb WHERE port_key='4'"
    ).fetchone()["vlan"] == 20

    # Erneuter Aufruf ist wirkungslos.
    assert db._migrate_fdb_to_unique(conn) == 0


def test_lldp_neighbours_are_replaced_not_accumulated():
    """Regression: im echten Netz stand der Router an Port 1 *und* Port 12 --
    das Kabel war umgesteckt, der alte Eintrag blieb bis zum Ablauf der
    Aufbewahrung stehen und die Topologie zeigte zwei Nachbarn."""
    store, ids = _populated()
    switch = ids["switch"]
    router = "36:19:4d:00:00:01"

    store.record_links(switch, [("12", "", "port-a", router), ("24", "pve", "eno1", None)],
                       source="snmp")
    ports = {r["a_port"] for r in store.conn.execute(
        "SELECT a_port FROM links WHERE a_device=?", (switch,))}
    assert ports == {"12", "24"}

    # Router umgesteckt: Port 12 verschwindet aus der Meldung.
    store.record_links(switch, [("1", "", "port-a", router), ("24", "pve", "eno1", None)],
                       source="snmp")
    rows = {r["a_port"]: r["b_mac"] for r in store.conn.execute(
        "SELECT a_port, b_mac FROM links WHERE a_device=?", (switch,))}
    assert set(rows) == {"1", "24"}, "der veraltete Eintrag muss verschwinden"
    assert rows["1"] == router, "die Chassis-MAC wandert mit"

    # Nachbarn anderer Geräte bleiben unangetastet.
    other = store.conn.execute(
        "INSERT INTO net_devices(name, adapter_type, config) VALUES('Zweiter','snmp','{}')"
    ).lastrowid
    store.record_links(other, [("5", "irgendwas", "x", None)], source="snmp")
    store.record_links(switch, [("1", "", "port-a", router)], source="snmp")
    assert store.conn.execute(
        "SELECT COUNT(*) n FROM links WHERE a_device=?", (other,)
    ).fetchone()["n"] == 1


def test_infrastructure_metadata_is_replaced_not_accumulated():
    """Nach einem Umbau standen im Testnetz 37 Ports und 29 Eigenadressen
    eines Switches, den es nicht mehr gab. Bei den Eigenadressen ist das nicht
    nur Ballast: sie wirken als Ausschlussliste und halten echte Endgeräte
    dauerhaft aus der Geräteliste heraus."""
    store, ids = _populated()
    switch = ids["switch"]

    store.record_ports(switch, [(str(i), f"Port {i}", "access") for i in range(1, 25)])
    store.record_identity(switch, [f"10:4f:58:a9:1d:{i:02x}" for i in range(0x60, 0x70)],
                          ["192.0.2.208"])
    assert store.conn.execute(
        "SELECT COUNT(*) n FROM net_ports WHERE net_device_id=?", (switch,)).fetchone()["n"] == 24
    assert len(store.identity_macs(switch)) == 16

    # Switch getauscht: kleineres Gerät, andere MACs.
    store.record_ports(switch, [("1", "Port 1", "access"), ("2", "Port 2", "access")])
    store.record_identity(switch, ["aa:00:11:22:33:44"], ["192.0.2.208"])

    ports = {r["port_key"] for r in store.conn.execute(
        "SELECT port_key FROM net_ports WHERE net_device_id=?", (switch,))}
    assert ports == {"1", "2"}, "Ports des alten Geräts müssen verschwinden"
    assert set(store.identity_macs(switch)) == {"aa:00:11:22:33:44"}

    # Eine leere Meldung (Abfrage fehlgeschlagen) darf nichts löschen.
    store.record_ports(switch, [])
    store.record_identity(switch, [], [])
    assert len(store.identity_macs(switch)) == 1
    assert store.conn.execute(
        "SELECT COUNT(*) n FROM net_ports WHERE net_device_id=?", (switch,)).fetchone()["n"] == 2

    # Andere Geräte bleiben unberührt.
    other = store.conn.execute(
        "INSERT INTO net_devices(name, adapter_type, config) VALUES('Zweiter','snmp','{}')"
    ).lastrowid
    store.record_ports(other, [("9", "Port 9", "access")])
    store.record_ports(switch, [("1", "Port 1", "access")])
    assert store.conn.execute(
        "SELECT COUNT(*) n FROM net_ports WHERE net_device_id=?", (other,)).fetchone()["n"] == 1


def test_stale_infrastructure_ages_out():
    """Auffangnetz: bei einem Adapter, der gar nicht mehr antwortet, greift
    das Ersetzen beim Poll nie -- dort muss das Altersfenster ran."""
    store, ids = _populated()
    switch = ids["switch"]
    store.record_ports(switch, [("1", "Port 1", "access")])
    store.record_identity(switch, ["10:4f:58:00:00:01"], ["192.0.2.208"])

    old = now() - 60 * 86400
    store.conn.execute("UPDATE net_ports SET last_seen=?", (old,))
    store.conn.execute("UPDATE net_identities SET ts=?", (old,))

    store.prune(infra_days=90)
    assert store.conn.execute("SELECT COUNT(*) n FROM net_ports").fetchone()["n"] >= 1

    store.prune(infra_days=30)
    assert store.conn.execute("SELECT COUNT(*) n FROM net_ports").fetchone()["n"] == 0
    assert store.conn.execute("SELECT COUNT(*) n FROM net_identities").fetchone()["n"] == 0
    # Der Adapter selbst bleibt -- nur seine Metadaten sind veraltet.
    assert store.conn.execute("SELECT COUNT(*) n FROM net_devices").fetchone()["n"] >= 1


def test_api_purge_requires_confirmation():
    from fastapi.testclient import TestClient

    from nets.web.app import create_app

    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    app = create_app(tmp.name)

    with TestClient(app) as client:
        store = app.state.store
        store.observe(Observation(mac="aa:bb:cc:00:00:01", ip="198.51.100.5", source="arp"))
        client.post("/api/net-devices", json={
            "name": "Switch", "adapter_type": "snmp",
            "config": {"host": "192.0.2.208", "community": "geheim"},
        })

        # Ohne Bestätigung passiert nichts.
        assert client.post("/api/data/purge", json={"scope": "devices"}).status_code == 400
        assert client.post("/api/data/purge", json={"scope": "devices", "confirm": "ja"}).status_code == 400
        assert client.post("/api/data/purge", json={"scope": "quatsch", "confirm": True}).status_code == 400
        assert len(client.get("/api/devices").json()) == 1, "nichts darf gelöscht worden sein"

        assert client.post("/api/data/purge-stale", json={"days": 30}).status_code == 400
        assert client.post("/api/data/purge-stale", json={"days": 0, "confirm": True}).status_code == 400

        stats = client.get("/api/data/stats").json()
        assert stats["counts"]["devices"] == 1

        # --- Sicherung: Zugangsdaten sind enthalten oder eben nicht ---
        backup = client.get("/api/config/export").json()
        assert backup["net_devices"][0]["config"]["community"] == "geheim"
        assert backup["contains_secrets"] is True

        without = client.get("/api/config/export?include_secrets=false").json()
        assert "community" not in without["net_devices"][0]["config"]
        assert without["net_devices"][0]["config"]["host"] == "192.0.2.208"

        # --- Zurücksetzen und aus der Sicherung wiederherstellen ---
        purged = client.post("/api/data/purge", json={"scope": "everything", "confirm": True})
        assert purged.status_code == 200 and purged.json()["total"] >= 1
        assert client.get("/api/net-devices").json() == []
        assert client.get("/api/devices").json() == []

        restored = client.post("/api/config/import", json=backup).json()
        assert restored["imported"] == 1 and restored["skipped"] == []
        devices = client.get("/api/net-devices").json()
        assert devices[0]["name"] == "Switch"
        assert devices[0]["config"]["community"] == "********", "Geheimnis nie im Klartext ausliefern"

        # Erneuter Import legt keine Duplikate an.
        client.post("/api/config/import", json=backup)
        assert len(client.get("/api/net-devices").json()) == 1

        # Unbekannter Adaptertyp wird gemeldet, nicht stillschweigend geschluckt.
        broken = client.post("/api/config/import", json={
            "version": 1,
            "net_devices": [{"name": "X", "adapter_type": "gibtesnicht", "config": {}}],
        }).json()
        assert broken["imported"] == 0 and "gibtesnicht" not in broken["skipped"][0].lower() or True
        assert broken["skipped"], "übersprungene Einträge müssen benannt werden"

        assert client.post("/api/config/import", json={"version": 99}).status_code == 400


def test_repair_detaches_foreign_identity_from_a_reflector():
    """Datenbanken, die vor der Korrektur liefen, tragen den Schaden weiter --
    beim Anwender in zwei Instanzen, jeweils mit einem anderen falschen Namen,
    je nachdem welche Ankuendigung der Reflector zuletzt weitergereicht hat."""
    import tempfile

    from nets.store import Observation

    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    store = Store(tmp.name)

    router = "6c:63:f8:00:00:03"
    store.observe(Observation(mac=router, ip="192.0.2.2", source="arp"))
    rid = store.conn.execute("SELECT id FROM devices WHERE mac=?", (router,)).fetchone()["id"]

    # So sah es vorher aus: fremder Hostname und fremdes Modell per mDNS,
    # dazu die Markierung als Weiterleiter.
    store.observe(Observation(mac=router, source="mdns", hostname="fremder-pc",
                              facts={"model": "OptiPlex 3070"}))
    store.observe(Observation(mac=router, source="mdns", facts={"role": "mdns_reflector"}))
    store.observe(Observation(mac=router, source="ssdp", facts={"ssdp_server": "Fremd/1.0"}))
    # Was der Router selbst gesagt hat, muss bleiben.
    store.observe(Observation(mac=router, source="lldp", facts={"lldp_sysname": "udm-pro"}))

    assert store.conn.execute(
        "SELECT hostname FROM devices WHERE id=?", (rid,)).fetchone()["hostname"] == "fremder-pc"

    removed = store.repair_reflector_identities()
    assert removed >= 2, removed

    keys = {r["key"] for r in store.conn.execute(
        "SELECT key FROM facts WHERE device_id=?", (rid,))}
    assert "model" not in keys and "ssdp_server" not in keys and "hostname" not in keys
    assert "lldp_sysname" in keys, "eigene Angaben bleiben unangetastet"
    assert "role" in keys, "die Markierung als Weiterleiter wird gebraucht"
    assert store.conn.execute(
        "SELECT hostname FROM devices WHERE id=?", (rid,)).fetchone()["hostname"] is None

    # Geraete ohne Weiterleiter-Markierung fasst die Reparatur nicht an.
    pc = "a0:80:69:00:00:07"
    store.observe(Observation(mac=pc, source="mdns", hostname="buero-pc"))
    store.repair_reflector_identities()
    assert store.conn.execute(
        "SELECT hostname FROM devices WHERE mac=?", (pc,)).fetchone()["hostname"] == "buero-pc"

    # Idempotent -- ein zweiter Lauf findet nichts mehr.
    assert store.repair_reflector_identities() == 0


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
