"""Identitaetsableitung bei randomisierten MACs.

Alle Testdaten stammen aus einem echten Netz -- erfundene Fingerprints wuerden
genau das nicht pruefen, worauf es ankommt.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nets import identify
from nets.store import Observation, Store
from nets.util import now

IPHONE_FP = "1,121,3,6,15,108,114,119,162,252"
ANDROID_FP = "1,3,6,15,26,28,51,58,59,43,114,108"


def _store() -> Store:
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    return Store(tmp.name)


def test_fingerprints_of_real_devices():
    assert identify.os_from_fingerprint(IPHONE_FP) == ("iOS / iPadOS", 1.0)
    assert identify.os_from_fingerprint(ANDROID_FP) == ("Android", 1.0)
    assert identify.os_from_fingerprint("1,3,6,15,31,33,43,44,46,47,119,121,249,252")[0] == "Windows"
    assert identify.os_from_fingerprint("1,3,28,6")[0] == "ESP32 / ESP8266"

    # Leichte Abweichungen (andere Client-Version) werden noch erkannt ...
    variant, score = identify.os_from_fingerprint("1,121,3,6,15,108,114,119,252,162,44")
    assert variant == "iOS / iPadOS" and 0.75 <= score < 1.0

    # ... Unsinn dagegen nicht. Lieber nichts sagen als etwas Falsches.
    assert identify.os_from_fingerprint("7,7,7") == (None, 0.0)
    assert identify.os_from_fingerprint(None) == (None, 0.0)
    assert identify.os_from_fingerprint("")[0] is None


def test_vendor_class_beats_fingerprint():
    """Option 60 nennt oft die Version, Option 55 nur die Familie."""
    assert identify.os_from_vendor_class("android-dhcp-16") == "Android 16"
    assert identify.os_from_vendor_class("MSFT 5.0") == "Windows"
    assert identify.os_from_vendor_class("udhcp 1.36.1") == "BusyBox / Embedded"
    assert identify.os_from_vendor_class("irgendwas") is None
    assert identify.os_from_vendor_class(None) is None

    result = identify.guess(
        {"dhcp_fingerprint": ANDROID_FP, "vendor_class": "android-dhcp-16"}, "Android-Telefon"
    )
    assert result["os_guess"] == "Android 16", "die genauere Quelle muss gewinnen"
    assert any("Vendor-Class" in e for e in result["evidence"])


def test_mac_kinds_are_distinguished():
    """Nicht jede lokal vergebene MAC ist ein Privacy-Handy."""
    known = {"34:19:4d:00:00:01"}

    # BSSID: unterscheidet sich nur im U/L-Bit von einem bekannten Gerät.
    kind, base = identify.classify_mac("36:19:4d:00:00:01", known)
    assert kind == identify.MAC_BSSID and base == "34:19:4d:00:00:01"

    # Dieselbe MAC ohne das zugehörige Gerät bleibt eine Vermutung -> privacy.
    assert identify.classify_mac("36:19:4d:00:00:01", set())[0] == identify.MAC_PRIVACY

    # Virtualisierer erkennt man am Präfix oder am Fakt aus der API.
    assert identify.classify_mac("52:54:00:12:34:56", known)[1] == "QEMU/KVM"
    assert identify.classify_mac("02:42:ac:11:00:02", known)[1] == "Docker"
    assert identify.classify_mac("02:fd:ac:00:00:01", known, has_guest_fact=True)[0] == identify.MAC_VIRTUAL

    # Regulär vergeben.
    assert identify.classify_mac("a0:80:69:00:00:01", known)[0] == identify.MAC_GLOBAL


def test_hard_facts_beat_guessed_service():
    """Regression: eine Home-Assistant-VM bot _shelly._tcp an und wurde
    dadurch als Smart-Home-Gerät eingestuft statt als VM. Was der
    Virtualisierer meldet, ist harte Auskunft und schlägt die Vermutung."""
    result = identify.guess({
        "guest_kind": "vm",
        "guest_note": "VM 101 auf pve · vmbr0 · running",
        "mdns_services": "_shelly._tcp,_http._tcp",
    })
    assert result["device_type"] == "VM"
    assert any("VM 101" in e for e in result["evidence"])

    # Ohne den harten Fakt greift die Dienst-Heuristik wieder.
    assert identify.guess({"mdns_services": "_shelly._tcp"})["device_type"] == "Smart Home"
    assert identify.guess({"mdns_services": "_googlecast._tcp"})["device_type"] == "Streaming / TV"
    assert identify.guess({"mdns_services": "_ipp._tcp"})["device_type"] == "Drucker"


def test_model_from_mdns_is_the_most_concrete():
    """Ein Fernseher nennt sein Modell im Klartext -- das schlägt alles."""
    result = identify.guess({
        "model": "XY-1234", "friendly_name": "Fernseher", "mdns_services": "_googlecast._tcp",
    }, hostname="b61a9e5b-e0c8-3cda-52e1-111a7d0fbc06")
    assert result["label"] == "XY-1234", "der UUID-Hostname darf das Modell nicht verdrängen"
    assert result["device_type"] == "Streaming / TV"

    # Ohne jedes Merkmal wird nichts behauptet.
    empty = identify.guess({}, hostname=None)
    assert empty["os_guess"] is None and empty["label"] is None and empty["evidence"] == []


def test_refresh_identities_writes_to_devices():
    store = _store()
    phone = store.observe(Observation(
        mac="86:48:b3:00:00:01", ip="192.0.2.47", hostname="iPhone", source="dhcp",
        facts={"dhcp_fingerprint": IPHONE_FP}, dhcp_seen=True,
    ))
    store.observe(Observation(mac="a0:80:69:00:00:01", ip="192.0.2.211", source="arp"))

    assert store.refresh_identities() >= 1
    row = store.conn.execute("SELECT os_guess, device_type FROM devices WHERE id=?", (phone,)).fetchone()
    assert row["os_guess"] == "iOS / iPadOS"
    assert row["device_type"] == "Smartphone / Tablet"


def test_transient_macs_are_marked_as_such():
    """Vier MACs im echten Netz tauchten genau einmal in der Switch-Tabelle
    auf, ohne je eine IP zu haben. Solche Erscheinungen neben ein seit Stunden
    aktives Gerät zu stellen, macht die Liste unbrauchbar."""
    assert identify.transience(1, 0, 0).startswith("flüchtig")
    assert identify.transience(0, 0, 0).startswith("flüchtig")
    assert identify.transience(4, 0, 13).startswith("flüchtig")
    # Mit IP oder über eine Stunde aktiv -> kein Geist mehr.
    assert identify.transience(1, 1, 0) is None
    assert identify.transience(23, 1, 757) is None
    assert identify.transience(5, 0, 900) is None


def test_similar_devices_requires_no_time_overlap():
    """Der entscheidende Punkt: zwei MACs, die gleichzeitig im Netz waren,
    können nicht dasselbe Gerät sein -- egal wie ähnlich sie aussehen.

    Genau dieser Fall trat im echten Netz auf: drei „iPhone" mit identischem
    Fingerprint, aber überlappender Anwesenheit. Ein automatisches
    Zusammenführen hätte drei Geräte zu einem gemacht."""
    store = _store()
    bucket = (now() // 300) * 300

    def phone(mac: str, buckets: list[int]) -> int:
        device_id = store.observe(Observation(
            mac=mac, hostname="iPhone", source="dhcp",
            facts={"dhcp_fingerprint": IPHONE_FP}, dhcp_seen=True,
        ))
        # observe() legt selbst einen Bucket zur aktuellen Zeit an; für diesen
        # Test soll allein die unten gesetzte Anwesenheit zählen.
        store.conn.execute("DELETE FROM presence WHERE device_id=?", (device_id,))
        for offset in buckets:
            store.conn.execute(
                "INSERT INTO presence(device_id, bucket, hits, sources) VALUES(?,?,1,'dhcp') "
                "ON CONFLICT(device_id, bucket) DO NOTHING",
                (device_id, bucket - offset * 300),
            )
        return device_id

    a = phone("86:48:b3:00:00:01", [0, 1, 2])        # jetzt
    overlapping = phone("c6:61:2a:00:00:01", [1, 2, 3])  # gleichzeitig -> anderes Gerät
    rotated = phone("9a:f4:90:00:00:01", [10, 11, 12])   # davor -> könnte dasselbe sein

    similar = {s["id"] for s in store.similar_devices(a)}
    assert rotated in similar, "zeitlich getrennte MAC mit gleichem Fingerprint ist ein Kandidat"
    assert overlapping not in similar, "gleichzeitig gesehen schließt Identität aus"

    # Geräte mit regulärer MAC rotieren nicht -- für sie gibt es keine Vorschläge.
    wired = store.observe(Observation(mac="a0:80:69:00:00:01", source="arp"))
    assert store.similar_devices(wired) == []


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
