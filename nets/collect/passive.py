"""Der passive Sniffer -- Herzstueck des Tools.

Laeuft dauerhaft und schreibt jede Beobachtung in die Historie. Genau das
loest das Problem "Geraet ist meistens offline": man muss nicht zufaellig zum
richtigen Zeitpunkt scannen, sondern hat durchgehend zugehoert.
"""

from __future__ import annotations

import logging
import threading
import time

from ..store import Store
from .parsers import ALL_PARSERS

log = logging.getLogger("nets.passive")


def parse_ifaces(value: str | None) -> list[str]:
    """"wlan0, eth0" -> ["wlan0", "eth0"]."""
    return [p.strip() for p in (value or "").replace(";", ",").split(",") if p.strip()]


class PassiveSniffer:
    """Hoert auf einem oder mehreren Interfaces gleichzeitig.

    Mehrere sind der Normalfall, sobald der Rechner in mehr als einem Segment
    steht: Broadcast endet am Router, also sieht jedes Interface nur sein
    eigenes Netz. Gemessen an einem Rechner mit WLAN und Kabel: 60 ARP-Pakete
    in zwoelf Sekunden auf der Kabelseite, 4 im WLAN -- wer nur auf einem
    lauscht, verpasst das meiste.
    """

    def __init__(self, store: Store, iface: str | list[str], parsers=None):
        self.store = store
        self.ifaces = parse_ifaces(iface) if isinstance(iface, str) else list(iface)
        #: Erstes Interface -- fuer Verfahren, die nur eines annehmen koennen.
        self.iface = self.ifaces[0] if self.ifaces else ""
        self.parsers = list(parsers if parsers is not None else ALL_PARSERS)
        self._sniffer = None
        self._stop = threading.Event()
        self.packets_seen = 0
        self.per_iface: dict[str, int] = {}
        self.errors = 0
        self.error: str | None = None
        #: Faellt der Kernel-Filter aus, laeuft der Sniffer ungefiltert weiter.
        self.filtered = True

    @property
    def bpf(self) -> str:
        """Ein gemeinsamer Kernel-Filter statt N Sniffer."""
        return " or ".join(f"({p.bpf})" for p in self.parsers)

    def _handle(self, pkt) -> None:
        self.packets_seen += 1
        source = getattr(pkt, "sniffed_on", None)
        if source:
            self.per_iface[source] = self.per_iface.get(source, 0) + 1
        for parser in self.parsers:
            try:
                for obs in parser.parse(pkt):
                    self.store.observe(obs)
            except Exception:  # ein kaputtes Paket darf den Sniffer nie killen
                self.errors += 1
                log.debug("Parser %s ist an einem Paket gescheitert", parser.name, exc_info=True)

    def start(self) -> None:
        if not self.ifaces:
            self.error = "kein Interface konfiguriert"
            raise RuntimeError(self.error)
        self.error = None
        try:
            self._start(self.bpf)
            self.filtered = True
        except RuntimeError as exc:
            # Den BPF-Ausdruck uebersetzt libpcap, nicht scapy. Fehlt die
            # Bibliothek, scheitert nur das Uebersetzen -- mitlesen kann der
            # AF_PACKET-Socket weiterhin. Ungefiltert weiterzumachen ist
            # deutlich besser als gar nichts zu sammeln: die Parser verwerfen
            # uninteressante Pakete ohnehin, es kostet nur CPU, weil jedes
            # Paket dafuer bis nach Python durchgereicht wird.
            if "libpcap" not in str(exc):
                raise
            log.warning("Kein Kernel-Filter moeglich (%s) -- der Sniffer laeuft "
                        "ungefiltert weiter und filtert in Python. Behebbar mit: "
                        "apt install libpcap0.8t64", exc)
            self._start(None)
            self.filtered = False

    def _start(self, bpf: str | None) -> None:
        from scapy.sendrecv import AsyncSniffer

        log.info("Starte passiven Sniffer auf %s (filter: %s)",
                 ", ".join(self.ifaces), bpf or "keiner")
        kwargs = {"filter": bpf} if bpf else {}
        self._sniffer = AsyncSniffer(
            # scapy nimmt eine Liste entgegen und markiert jedes Paket mit
            # sniffed_on -- ein Sniffer je Interface waere nur mehr Threads.
            iface=self.ifaces if len(self.ifaces) > 1 else self.ifaces[0],
            prn=self._handle,
            store=False,
            **kwargs,
        )
        self._sniffer.start()

        # AsyncSniffer.start() kehrt sofort zurueck; ein fehlendes Interface
        # oder fehlendes CAP_NET_RAW faellt erst im Thread auf und landet in
        # .exception. Ohne diese Pruefung meldet die UI faelschlich "laeuft".
        time.sleep(0.5)
        failure = getattr(self._sniffer, "exception", None)
        if failure is not None or not getattr(self._sniffer, "running", False):
            self.error = str(failure) if failure else (
                f"Sniffer auf '{', '.join(self.ifaces)}' nicht gestartet")
            self._sniffer = None
            raise RuntimeError(self.error)

    def stop(self) -> None:
        self._stop.set()
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                log.debug("Sniffer-Stop fehlgeschlagen", exc_info=True)

    def status(self) -> dict:
        running = bool(self._sniffer and getattr(self._sniffer, "running", False))
        failure = getattr(self._sniffer, "exception", None) if self._sniffer else None
        return {
            "iface": ", ".join(self.ifaces),
            "ifaces": list(self.ifaces),
            "per_iface": dict(self.per_iface),
            "running": running and failure is None,
            "packets_seen": self.packets_seen,
            "parse_errors": self.errors,
            "parsers": [p.name for p in self.parsers],
            "filtered": self.filtered,
            "error": str(failure) if failure else self.error,
        }
