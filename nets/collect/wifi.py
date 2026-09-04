"""802.11-Mitschnitt im Monitor-Mode -- wer haengt an welchem Access Point.

Das ist der einzige Weg, der *ohne* Mitwirkung des WLAN-Geraets funktioniert.
Ein Speedport oder ein Mesh-Repeater muss dafuer weder eine API haben noch
LLDP sprechen: Die Zuordnung steht in jedem einzelnen 802.11-Frame, das durch
die Luft geht.

Der Trick sind die Adressfelder. Anders als bei Ethernet hat ein 802.11-Frame
bis zu vier davon, und ihre Bedeutung haengt an den Flags ToDS/FromDS:

    ToDS=1, FromDS=0   Station -> AP     addr1=BSSID   addr2=Station
    ToDS=0, FromDS=1   AP -> Station     addr1=Station addr2=BSSID
    ToDS=0, FromDS=0   Management/IBSS   addr3=BSSID

Damit faellt aus jedem Datenframe direkt ab, welche Station mit welchem
Funkmodul spricht. Beacons liefern zusaetzlich BSSID -> SSID und Kanal.

Voraussetzung: eine WLAN-Karte im Monitor-Mode. Die darf *nicht* gleichzeitig
als normale Verbindung dienen -- in der Praxis also ein zweiter (USB-)Adapter.
"""

from __future__ import annotations

import logging
import subprocess
import threading
import time

from ..store import Observation, Store
from ..util import norm_mac

log = logging.getLogger("nets.wifi")

#: 2,4 GHz vollstaendig, 5 GHz nur die in DE ueblichen Kanaele. Mehr Kanaele
#: bedeuten laengere Rundenzeit und damit mehr verpasste Frames je AP.
CHANNELS_24 = [1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 5, 10]
CHANNELS_5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 132, 136, 140]


def channel_to_band(channel: int | None) -> str | None:
    if channel is None:
        return None
    if 1 <= channel <= 14:
        return "2.4 GHz"
    if 32 <= channel <= 177:
        return "5 GHz"
    return "6 GHz"


class WifiSniffer:
    """Laeuft dauerhaft, springt Kanaele durch und schreibt Assoziationen."""

    def __init__(self, store: Store, iface: str, dwell_seconds: float = 3.0,
                 channels: list[int] | None = None):
        self.store = store
        self.iface = iface
        self.dwell = dwell_seconds
        self.channels = channels or (CHANNELS_24 + CHANNELS_5)
        self._sniffer = None
        self._hopper: threading.Thread | None = None
        self._stop = threading.Event()
        self.frames_seen = 0
        self.associations = 0
        self.errors = 0
        self.error: str | None = None
        self.current_channel: int | None = None
        #: BSSID -> (ssid, channel), aus Beacons gelernt.
        self.networks: dict[str, tuple[str | None, int | None]] = {}

    # ------------------------------------------------------------- Kanalwechsel

    def _set_channel(self, channel: int) -> bool:
        try:
            subprocess.run(
                ["iw", "dev", self.iface, "set", "channel", str(channel)],
                check=True, capture_output=True, timeout=5,
            )
            self.current_channel = channel
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            # Nicht jede Karte unterstuetzt jeden Kanal (DFS, 5 GHz, Regulatory
            # Domain). Ein Fehlschlag ist normal -- Kanal einfach ueberspringen.
            return False

    def _hop(self) -> None:
        usable = list(self.channels)
        while not self._stop.is_set():
            for channel in list(usable):
                if self._stop.is_set():
                    return
                if not self._set_channel(channel):
                    usable.remove(channel)
                    log.debug("Kanal %d nicht nutzbar, wird ausgelassen", channel)
                    continue
                self._stop.wait(self.dwell)
            if not usable:
                self.error = "keiner der konfigurierten Kanaele ist nutzbar"
                log.error(self.error)
                return

    # ---------------------------------------------------------------- Auswertung

    def _handle(self, pkt) -> None:
        self.frames_seen += 1
        try:
            self._parse(pkt)
        except Exception:
            self.errors += 1
            log.debug("802.11-Frame konnte nicht ausgewertet werden", exc_info=True)

    def _parse(self, pkt) -> None:
        from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp

        if Dot11 not in pkt:
            return
        dot11 = pkt[Dot11]

        # Beacons und Probe Responses: BSSID -> SSID und Kanal lernen.
        if Dot11Beacon in pkt or Dot11ProbeResp in pkt:
            bssid = norm_mac(dot11.addr3 or "")
            if bssid:
                self.networks[bssid] = (_ssid_of(pkt, Dot11Elt), _channel_of(pkt, Dot11Elt))
            return

        station, bssid = _station_and_bssid(dot11)
        if not station or not bssid or station == bssid:
            return

        ssid, channel = self.networks.get(bssid, (None, None))
        self.store.record_wifi_link(
            station=station,
            bssid=bssid,
            ssid=ssid,
            channel=channel or self.current_channel,
            signal=_signal_of(pkt),
        )
        # Zaehlt zugleich als Anwesenheitsbeleg -- ein Geraet, das funkt, ist da.
        self.store.observe(Observation(mac=station, source="wifi"))
        self.associations += 1

    # -------------------------------------------------------------- Lebenszyklus

    def start(self) -> None:
        from scapy.sendrecv import AsyncSniffer

        self.error = None
        self._stop.clear()
        log.info("Starte WLAN-Mitschnitt auf %s (%d Kanaele)", self.iface, len(self.channels))

        self._sniffer = AsyncSniffer(iface=self.iface, prn=self._handle, store=False, monitor=True)
        self._sniffer.start()
        time.sleep(0.5)
        failure = getattr(self._sniffer, "exception", None)
        if failure is not None or not getattr(self._sniffer, "running", False):
            self.error = str(failure) if failure else (
                f"'{self.iface}' liefert keine Frames -- ist die Karte im Monitor-Mode?"
            )
            self._sniffer = None
            raise RuntimeError(self.error)

        self._hopper = threading.Thread(target=self._hop, daemon=True, name="wifi-hopper")
        self._hopper.start()

    def stop(self) -> None:
        self._stop.set()
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                log.debug("WLAN-Sniffer-Stop fehlgeschlagen", exc_info=True)
            self._sniffer = None

    def status(self) -> dict:
        running = bool(self._sniffer and getattr(self._sniffer, "running", False))
        return {
            "iface": self.iface,
            "running": running,
            "frames_seen": self.frames_seen,
            "associations": self.associations,
            "parse_errors": self.errors,
            "channel": self.current_channel,
            "networks": [
                {"bssid": b, "ssid": s, "channel": c} for b, (s, c) in sorted(self.networks.items())
            ],
            "error": self.error,
        }


# --------------------------------------------------------------------- Parser


def _station_and_bssid(dot11) -> tuple[str | None, str | None]:
    """Loest die Adressfelder eines 802.11-Frames auf.

    Gibt (Station, BSSID) zurueck. Bei Frames ohne eindeutige Zuordnung --
    WDS (ToDS=1/FromDS=1) oder reine Broadcast-Management-Frames -- (None, None).
    """
    to_ds = bool(dot11.FCfield & 0x1)
    from_ds = bool(dot11.FCfield & 0x2)

    if to_ds and not from_ds:
        return norm_mac(dot11.addr2 or ""), norm_mac(dot11.addr1 or "")
    if from_ds and not to_ds:
        return norm_mac(dot11.addr1 or ""), norm_mac(dot11.addr2 or "")
    if not to_ds and not from_ds:
        # Management-Frames: addr3 ist die BSSID, addr2 der Absender. Nur
        # verwerten, wenn der Absender nicht selbst der AP ist.
        bssid = norm_mac(dot11.addr3 or "")
        sender = norm_mac(dot11.addr2 or "")
        if bssid and sender and sender != bssid and bssid != "ff:ff:ff:ff:ff:ff":
            return sender, bssid
    return None, None


def _ssid_of(pkt, Dot11Elt) -> str | None:
    element = pkt.getlayer(Dot11Elt, ID=0)
    if element is None or not element.info:
        return None
    ssid = element.info.decode("utf-8", errors="replace").strip("\x00")
    return ssid or None  # leerer SSID = verstecktes Netz


def _channel_of(pkt, Dot11Elt) -> int | None:
    element = pkt.getlayer(Dot11Elt, ID=3)  # DS Parameter Set
    if element is not None and element.info:
        return int(element.info[0])
    return None


def _signal_of(pkt) -> int | None:
    """Empfangspegel aus dem RadioTap-Header, falls die Karte ihn liefert."""
    try:
        value = pkt.getfield_and_val("dBm_AntSignal")
        return int(value[1]) if value else None
    except Exception:
        signal = getattr(pkt, "dBm_AntSignal", None)
        return int(signal) if isinstance(signal, int) else None
