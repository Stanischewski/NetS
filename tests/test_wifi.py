"""802.11-Auswertung ohne Funkkarte: konstruierte Frames durch den Parser.

Deckt alles ausser dem Monitor-Mode-Socket selbst ab. Der interessante Teil
sind die Adressfelder -- ihre Bedeutung haengt an ToDS/FromDS, und ein
Vertauscher waere im Betrieb kaum zu bemerken: die Zuordnung waere dann
schlicht falschherum.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap

from nets.collect.wifi import WifiSniffer, _station_and_bssid, channel_to_band
from nets.store import Store
from nets.util import base_mac_of_bssid, same_device_family

# Aus dem echten Netz: Speedport-Basis-MAC und die daraus abgeleitete BSSID.
ROUTER = "34:19:4d:00:00:01"
BSSID_24 = "36:19:4d:00:00:01"
BSSID_REPEATER = "24:41:fe:00:00:10"
PHONE = "a6:11:22:33:44:55"
LAPTOP = "a0:80:69:00:00:01"


def _store() -> Store:
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    return Store(tmp.name)


def test_bssid_derives_from_base_mac():
    """Access Points bilden BSSIDs, indem sie das U/L-Bit setzen. Die
    Umkehrung ist eindeutig -- damit ist 36:19:… als Funkmodul des Routers
    34:19:… identifizierbar, ohne irgendetwas abzufragen."""
    assert base_mac_of_bssid(BSSID_24) == ROUTER
    # Eine global vergebene MAC ist selbst keine abgeleitete BSSID.
    assert base_mac_of_bssid(ROUTER) is None
    # Umkehrung ist involutiv auf dem U/L-Bit.
    assert base_mac_of_bssid("a6:11:22:33:44:55") == "a4:11:22:33:44:55"

    # Schwacher Hinweis auf mehrere Radios desselben Geraets.
    assert same_device_family("24:41:fe:00:00:10", "24:41:fe:00:00:1a")
    assert not same_device_family("24:41:fe:00:00:10", "24:41:fe:00:01:10")  # anderes Oktett
    assert not same_device_family("24:41:fe:00:00:10", "24:41:fe:00:00:80")  # zu weit weg
    assert not same_device_family(ROUTER, ROUTER)


def test_address_fields_follow_tods_fromds():
    """Der Kern: wer ist Station, wer ist AP."""
    # Station -> AP: addr1=BSSID, addr2=Station
    up = Dot11(FCfield=0x01, addr1=BSSID_24, addr2=PHONE, addr3=ROUTER)
    assert _station_and_bssid(up) == (PHONE, BSSID_24)

    # AP -> Station: addr1=Station, addr2=BSSID
    down = Dot11(FCfield=0x02, addr1=PHONE, addr2=BSSID_24, addr3=ROUTER)
    assert _station_and_bssid(down) == (PHONE, BSSID_24)

    # Management ohne DS-Flags: addr3 ist die BSSID, addr2 der Absender.
    mgmt = Dot11(FCfield=0x00, addr1="ff:ff:ff:ff:ff:ff", addr2=PHONE, addr3=BSSID_24)
    assert _station_and_bssid(mgmt) == (PHONE, BSSID_24)

    # WDS (beide Flags): nicht eindeutig -> nichts behaupten.
    wds = Dot11(FCfield=0x03, addr1=BSSID_24, addr2=BSSID_REPEATER, addr3=PHONE)
    assert _station_and_bssid(wds) == (None, None)

    # Broadcast-BSSID (Probe Request an alle) darf nichts erzeugen.
    probe = Dot11(FCfield=0x00, addr1="ff:ff:ff:ff:ff:ff", addr2=PHONE,
                  addr3="ff:ff:ff:ff:ff:ff")
    assert _station_and_bssid(probe) == (None, None)


def test_beacon_learns_ssid_and_channel():
    store = _store()
    sniffer = WifiSniffer(store, iface="mon0")

    beacon = (
        RadioTap()
        / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=BSSID_24, addr3=BSSID_24)
        / Dot11Beacon()
        / Dot11Elt(ID=0, info=b"WLAN-Beispiel")
        / Dot11Elt(ID=3, info=bytes([11]))
    )
    sniffer._handle(RadioTap(bytes(beacon)))
    assert sniffer.networks[BSSID_24] == ("WLAN-Beispiel", 11)
    # Ein Beacon allein ist keine Assoziation.
    assert sniffer.associations == 0

    # Danach erbt ein Datenframe SSID und Kanal aus dem Beacon.
    data = RadioTap() / Dot11(FCfield=0x01, addr1=BSSID_24, addr2=PHONE, addr3=BSSID_24)
    sniffer._handle(RadioTap(bytes(data)))
    assert sniffer.associations == 1

    link = store.wifi_links()[PHONE]
    assert link["bssid"] == BSSID_24
    assert link["ssid"] == "WLAN-Beispiel"
    assert link["channel"] == 11
    assert sniffer.errors == 0


def test_roaming_keeps_only_latest_access_point():
    """Ein Handy wandert zwischen Router und Repeater -- gezeigt wird, wo es
    zuletzt war, nicht beides gleichzeitig."""
    from nets.util import now

    store = _store()
    store.record_wifi_link(PHONE, BSSID_24, ssid="WLAN-Beispiel", channel=11, ts=now() - 600)
    store.record_wifi_link(PHONE, BSSID_REPEATER, ssid="WLAN-Beispiel", channel=36, ts=now() - 60)

    links = store.wifi_links()
    assert links[PHONE]["bssid"] == BSSID_REPEATER, "die jüngste Assoziation gewinnt"
    # Die Historie bleibt trotzdem erhalten.
    assert store.conn.execute(
        "SELECT COUNT(*) n FROM wifi_links WHERE station=?", (PHONE,)
    ).fetchone()["n"] == 2

    # Zählwerte laufen hoch, statt Zeilen zu duplizieren.
    for _ in range(4):
        store.record_wifi_link(PHONE, BSSID_REPEATER)
    assert store.conn.execute(
        "SELECT frames FROM wifi_links WHERE station=? AND bssid=?", (PHONE, BSSID_REPEATER)
    ).fetchone()["frames"] == 5

    # Unsinn wird abgewiesen.
    assert not store.record_wifi_link(PHONE, PHONE)              # Station == AP
    assert not store.record_wifi_link("01:00:5e:00:00:fb", BSSID_24)   # Multicast
    assert not store.record_wifi_link("quatsch", BSSID_24)

    # Veraltete Assoziationen gelten nicht mehr als aktuell -- ein Gerät, das
    # vor Tagen an einem AP hing, hängt dort heute nicht zwingend noch.
    store.conn.execute("UPDATE wifi_links SET last_seen = last_seen - 3*86400")
    assert store.wifi_links() == {}


def test_topology_groups_clients_under_access_point():
    """Der eigentliche Zweck: hinter dem Uplink-Port stehen die Geräte nicht
    mehr flach nebeneinander, sondern unter ihrem Funkmodul."""
    from nets import topology
    from nets.store import Observation

    store = _store()
    switch = store.conn.execute(
        "INSERT INTO net_devices(name, adapter_type, config) VALUES('Switch','snmp','{}')"
    ).lastrowid

    wired = "00:1b:a9:00:00:01"
    at_router = [PHONE, LAPTOP, "a2:00:00:00:00:01"]
    at_repeater = ["a2:00:00:00:00:02", "a2:00:00:00:00:03"]
    for mac in (*at_router, *at_repeater, wired, ROUTER):
        store.observe(Observation(mac=mac, source="arp"))

    # Der Switch sieht alles gesammelt an Port 12 -- ohne 802.11 wäre hier Schluss.
    store.record_fdb(switch, [(m, "12", None) for m in (*at_router, *at_repeater, wired, ROUTER)])
    topology.resolve(store)

    for mac in at_router:
        store.record_wifi_link(mac, BSSID_24, ssid="WLAN-Beispiel", channel=11, signal=-52)
    for mac in at_repeater:
        store.record_wifi_link(mac, BSSID_REPEATER, ssid="WLAN-Beispiel", channel=36)

    port = next(
        c for c in topology.tree(store)["roots"][0]["children"]
        if c["kind"] == "port" and c["label"] == "Port 12"
    )
    aps = [c for c in port["children"] if c["kind"] == "ap"]
    assert len(aps) == 2, "beide Funkmodule müssen als Gruppe erscheinen"

    biggest = aps[0]
    assert biggest["label"] == "WLAN-Beispiel"
    assert biggest["count"] == 3
    assert BSSID_24 in biggest["sublabel"] and "Kanal 11" in biggest["sublabel"]
    assert "2,4 GHz" in biggest["sublabel"]
    assert any("-52 dBm" in b["text"] for b in biggest["children"][0]["badges"])

    # Kabelgebundene Geräte bleiben direkt am Port.
    direct = [c["mac"] for c in port["children"] if c["kind"] == "device"]
    assert wired in direct
    assert PHONE not in direct

    # Der Hinweis darf nicht mehr behaupten, man wisse nichts.
    assert "802.11" in port["hint"]
    assert any("Funkmodule erkannt" in b["text"] for b in port["badges"])


def test_band_from_channel():
    assert channel_to_band(1) == "2.4 GHz"
    assert channel_to_band(13) == "2.4 GHz"
    assert channel_to_band(36) == "5 GHz"
    assert channel_to_band(140) == "5 GHz"
    assert channel_to_band(None) is None


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
