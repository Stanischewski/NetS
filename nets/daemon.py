"""Der Dauerlaeufer: passiver Sniffer + geplante Adapter-Polls + Sweeps.

Der Sniffer laeuft in einem eigenen Thread (scapy ist blockierend), alles
andere als asyncio-Tasks. Fehler eines Adapters landen in net_devices.last_error
und werden in der UI angezeigt, statt den Dienst zu beenden.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

from . import adapters, topology
from .adapters.base import Capability
from .collect.active import (
    arp_sweep,
    icmpv6_sweep,
    interface_for,
    is_local_network,
    read_local_neighbours,
    routed_networks,
    routed_sweep,
)
from .collect.passive import PassiveSniffer, parse_ifaces
from .collect.webscan import WebScanner, parse_ports
from .collect.wifi import WifiSniffer
from .store import Observation, Store, json_config
from .util import now

log = logging.getLogger("nets.daemon")

DEFAULTS = {
    "iface": "eth0",
    "subnets": "",                    # kommagetrennt, leer = kein Sweep
    "sweep_interval": "3600",
    "adapter_interval": "300",
    "topology_interval": "600",
    "maintenance_interval": "21600",
    "passive_enabled": "1",
    "sweep_enabled": "1",
    "static_infer_days": "3",
    "watchdog_interval": "60",
    # Ein Netz ohne jeden Broadcast in 15 Minuten gibt es nicht. Bleibt der
    # Paketzaehler so lange stehen, ist der Socket tot, auch wenn der Thread
    # noch laeuft -- dann neu starten. 0 schaltet diese Pruefung ab.
    "sniffer_stall_seconds": "900",
    # WLAN-Mitschnitt: braucht eine *zweite* Karte im Monitor-Mode. Die
    # Karte, die die normale Verbindung traegt, kann das nicht nebenbei.
    "wifi_enabled": "0",
    "wifi_iface": "",
    "wifi_dwell_seconds": "3",
    # Aufbewahrung der gesammelten Daten, in Tagen. 0 = nie automatisch löschen.
    "retention_presence_days": "90",
    "retention_fdb_days": "30",
    "retention_link_days": "7",
    "retention_wifi_days": "30",
    "retention_infra_days": "30",
    # Weboberflaechen-Suche: aktiv, deshalb aus. Sucht nur auf Adressen, die
    # ohnehin schon im Inventar stehen -- kein zusaetzlicher Adressraum-Scan.
    "web_scan_enabled": "0",
    "web_scan_ports": "",
    "web_scan_interval": "21600",
}


class Daemon:
    def __init__(self, store: Store):
        self.store = store
        self.sniffer: PassiveSniffer | None = None
        self.wifi: WifiSniffer | None = None
        self._tasks: list[asyncio.Task] = []
        self._stopping = asyncio.Event()
        self.last_runs: dict[str, int] = {}
        self.sniffer_restarts = 0
        self.sniffer_last_restart: int | None = None
        self.sniffer_last_reason: str | None = None
        self._last_packet_count = 0
        self._last_packet_change = now()

    def setting(self, key: str) -> str:
        return self.store.get_setting(key, DEFAULTS.get(key, "")) or ""

    def setting_int(self, key: str) -> int:
        try:
            return int(self.setting(key))
        except ValueError:
            return int(DEFAULTS.get(key, "0") or 0)

    # --------------------------------------------------------------- Lebenszyklus

    async def start(self) -> None:
        for key, value in DEFAULTS.items():
            if self.store.get_setting(key) is None:
                self.store.set_setting(key, value)

        if self.setting("passive_enabled") == "1":
            self.start_sniffer()
        if self.setting("wifi_enabled") == "1" and self.setting("wifi_iface"):
            self.start_wifi()

        self._tasks = [
            asyncio.create_task(self._loop("adapters", self.poll_adapters, "adapter_interval")),
            asyncio.create_task(self._loop("topology", self.run_topology, "topology_interval")),
            asyncio.create_task(self._loop("sweep", self.run_sweeps, "sweep_interval")),
            asyncio.create_task(self._loop("maintenance", self.run_maintenance, "maintenance_interval")),
            asyncio.create_task(self._loop("watchdog", self.check_sniffer, "watchdog_interval")),
            asyncio.create_task(self._loop("webscan", self.run_web_scan, "web_scan_interval")),
        ]
        log.info("Daemon gestartet")

    async def check_sniffer(self) -> None:
        """Haelt den passiven Sniffer am Leben.

        Der scapy-Thread stirbt bei einem Interface-Wechsel (WLAN-Reconnect,
        Link-Down) ohne Exception einfach weg. Ohne diese Ueberwachung sammelt
        das Tool danach still nichts mehr -- und genau das faellt erst Tage
        spaeter auf, wenn die Historie Luecken hat.
        """
        if self.setting("passive_enabled") != "1":
            return

        reason = None
        if self.sniffer is None:
            reason = "Sniffer war nicht gestartet"
        elif not self.sniffer.status()["running"]:
            reason = self.sniffer.status().get("error") or "Sniffer-Thread beendet"
        else:
            reason = self._stall_reason()

        if reason is None:
            return

        self.sniffer_restarts += 1
        self.sniffer_last_restart = now()
        self.sniffer_last_reason = reason
        log.warning("Starte Sniffer neu (%s) -- Neustart Nr. %d", reason, self.sniffer_restarts)
        await asyncio.to_thread(self.start_sniffer)

    def _stall_reason(self) -> str | None:
        """Erkennt einen laufenden, aber tauben Sniffer am Paketzaehler."""
        limit = self.setting_int("sniffer_stall_seconds")
        seen = self.sniffer.packets_seen if self.sniffer else 0
        if seen != self._last_packet_count:
            self._last_packet_count = seen
            self._last_packet_change = now()
            return None
        idle = now() - self._last_packet_change
        if limit > 0 and idle >= limit:
            return f"seit {idle // 60} Minuten keine Pakete mehr"
        return None

    def start_sniffer(self) -> None:
        if self.sniffer is not None:
            self.sniffer.stop()
        iface = self.setting("iface")
        # Die Instanz bleibt auch bei Fehlschlag bestehen -- nur so kann die UI
        # sagen, *warum* nichts mitgehoert wird.
        self.sniffer = PassiveSniffer(self.store, iface)
        # Der Zaehler startet bei 0; ohne Reset wuerde der Watchdog die
        # Stille direkt nach dem Neustart als neuen Stillstand werten.
        self._last_packet_count = 0
        self._last_packet_change = now()
        try:
            self.sniffer.start()
        except Exception as exc:
            log.error("Sniffer konnte nicht starten (Rechte? Interface '%s'?): %s", iface, exc)

    async def stop(self) -> None:
        self._stopping.set()
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        if self.sniffer:
            self.sniffer.stop()
        if self.wifi:
            self.wifi.stop()
        log.info("Daemon gestoppt")

    async def _loop(self, name: str, fn, interval_key: str) -> None:
        # Beim Start etwas versetzen, damit nicht alles gleichzeitig losrennt.
        await asyncio.sleep(5 + 3 * len(self.last_runs))
        while not self._stopping.is_set():
            try:
                await fn()
                self.last_runs[name] = now()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("Task '%s' fehlgeschlagen", name)
            interval = max(30, self.setting_int(interval_key))
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._stopping.wait(), timeout=interval)

    # ------------------------------------------------------------------ Arbeit

    async def poll_adapters(self) -> None:
        rows = self.store.net_devices(only_enabled=True)
        if rows:
            await asyncio.gather(*(self.poll_one(row) for row in rows), return_exceptions=True)

    async def poll_one(self, row) -> None:
        try:
            adapter = adapters.build(row["adapter_type"], json_config(row))
        except KeyError as exc:
            self.store.set_adapter_status(row["id"], False, str(exc))
            return

        try:
            if adapter.has(Capability.IDENTITY):
                identity = await adapter.identity()
                if identity.macs or identity.ips:
                    self.store.record_identity(
                        row["id"], identity.macs, identity.ips,
                        identity.name, identity.description,
                    )

            if adapter.has(Capability.PORT_STATUS):
                ports = list(await adapter.ports())
                if ports:
                    self.store.record_ports(row["id"], [(p.port_key, p.name, p.kind) for p in ports])

            if adapter.has(Capability.FDB):
                entries = list(await adapter.fdb())
                if entries:
                    self.store.record_fdb(row["id"], [(e.mac, e.port_key, e.vlan) for e in entries])

            if adapter.has(Capability.LLDP):
                neighbors = list(await adapter.lldp())
                if neighbors:
                    self.store.record_links(
                        row["id"],
                        [(n.local_port, n.remote_name, n.remote_port, n.remote_mac) for n in neighbors],
                        source=row["adapter_type"],
                    )

            if adapter.has(Capability.INVENTORY):
                for host in await adapter.hosts():
                    # Namen von VMs/Containern sind oft die einzige Chance,
                    # eine MAC hinter einem Uplink-Port zu benennen.
                    self.store.observe(
                        Observation(
                            mac=host.mac,
                            ip=host.ip,
                            hostname=host.name,
                            source=f"inventory:{row['id']}",
                            facts={k: v for k, v in (("guest_kind", host.kind),
                                                     ("guest_note", host.note)) if v},
                        )
                    )

            if adapter.has(Capability.WIRELESS):
                clients = list(await adapter.wireless_clients())
                # WLAN-Clients zaehlen als Anwesenheit *und* als Topologie-Kante.
                for client in clients:
                    self.store.observe(
                        Observation(
                            mac=client.mac,
                            source=f"wifi:{row['id']}",
                            facts={
                                k: v
                                for k, v in (
                                    ("wifi_ap", client.ap_name),
                                    ("wifi_ssid", client.ssid),
                                    ("wifi_band", client.band),
                                    ("wifi_signal", str(client.signal) if client.signal is not None else None),
                                )
                                if v
                            },
                        )
                    )
                if clients and not adapter.has(Capability.FDB):
                    self.store.record_fdb(
                        row["id"], [(c.mac, f"wlan:{c.ap_name or ''}", None) for c in clients]
                    )

            if adapter.has(Capability.DHCP_LEASES):
                for lease in await adapter.dhcp_leases():
                    self.store.observe(
                        Observation(
                            mac=lease.mac,
                            ip=lease.ip,
                            hostname=lease.hostname,
                            source=f"lease:{row['id']}",
                            facts={"dhcp_reservation": "1"} if lease.static else {},
                            # Eine Lease belegt DHCP-Nutzung; eine feste
                            # Reservierung ist ebenfalls DHCP (nur mit fester IP).
                            dhcp_seen=True,
                        )
                    )

            if adapter.has(Capability.ARP_TABLE):
                for mac, ip in await adapter.arp_table():
                    self.store.observe(Observation(mac=mac, ip=ip, source=f"arp:{row['id']}"))

            self.store.set_adapter_status(row["id"], True, None)
        except Exception as exc:
            log.warning("Adapter '%s' fehlgeschlagen: %s", row["name"], exc)
            self.store.set_adapter_status(row["id"], False, f"{type(exc).__name__}: {exc}")
        finally:
            await adapter.close()

    async def run_topology(self) -> None:
        await asyncio.to_thread(topology.resolve, self.store)

    async def sweep_subnets(self, cidrs: list[str]) -> dict:
        """Sweept die angegebenen Netze mit dem jeweils passenden Verfahren.

        ARP ist link-lokal und ueberquert keinen Router. Fuer ein geroutetes
        Netz faende ein ARP-Sweep stillschweigend nichts -- deshalb wird nach
        Erreichbarkeit unterschieden statt blind zu arpen.
        """
        result = {"found": 0, "hosts": 0, "per_subnet": {}, "errors": {}}
        for cidr in cidrs:
            try:
                if await is_local_network(cidr):
                    # Nicht das konfigurierte Interface nehmen, sondern das,
                    # ueber das die Route wirklich laeuft -- sonst geht die
                    # ARP-Anfrage am Ziel-Segment vorbei.
                    iface = (await interface_for(cidr)
                             or (parse_ifaces(self.setting("iface")) or [""])[0])
                    n = await arp_sweep(self.store, iface, cidr)
                    result["found"] += n
                    result["per_subnet"][cidr] = {"method": f"arp über {iface}", "found": n}
                else:
                    ips = await routed_sweep(self.store, cidr)
                    result["hosts"] += len(ips)
                    result["per_subnet"][cidr] = {"method": "geroutet", "found": len(ips)}
            except Exception as exc:
                log.warning("Sweep %s fehlgeschlagen: %s", cidr, exc)
                result["errors"][cidr] = str(exc)
        return result

    async def run_sweeps(self) -> None:
        if self.setting("sweep_enabled") != "1":
            return
        await read_local_neighbours(self.store)
        cidrs = [s.strip() for s in self.setting("subnets").split(",") if s.strip()]
        if cidrs:
            await self.sweep_subnets(cidrs)
        try:
            for iface in parse_ifaces(self.setting("iface")):
                await icmpv6_sweep(self.store, iface)
        except Exception as exc:
            log.debug("ICMPv6-Sweep fehlgeschlagen: %s", exc)

    async def run_web_scan(self, force: bool = False) -> int:
        """Sucht Weboberflaechen auf bekannten Adressen.

        Die passive Ernte laeuft *immer* -- UPnP und mDNS nennen ihre Adressen
        von selbst, das kostet keinen einzigen Verbindungsversuch. Nur das
        aktive Anklopfen haengt am Schalter.
        """
        passive = self.store.harvest_web_passive()
        if not force and self.setting("web_scan_enabled") != "1":
            return passive
        targets = self.store.scan_targets()
        if not targets:
            return passive
        scanner = WebScanner(parse_ports(self.setting("web_scan_ports")))
        found = await scanner.scan(targets)
        for entry in found:
            self.store.record_web_service(entry)
        return len(found) + passive

    async def run_maintenance(self) -> None:
        days = max(1, self.setting_int("static_infer_days"))
        marked = await asyncio.to_thread(self.store.infer_static_addressing, days * 86400)
        if marked:
            log.info("%d Geraete als statisch adressiert markiert", marked)
        # Erst reparieren, dann ableiten: eine fremde Identitaet am
        # Weiterleiter wuerde sonst gleich wieder in einen Geraetetyp
        # uebersetzt.
        await asyncio.to_thread(self.store.repair_reflector_identities)
        identified = await asyncio.to_thread(self.store.refresh_identities)
        log.info("%d Geraete mit abgeleiteter Identitaet", identified)
        retention = {
            key: self.setting_int(f"retention_{key}")
            for key in ("presence_days", "fdb_days", "link_days", "wifi_days", "infra_days")
        }
        # 0 bedeutet "nie loeschen" -- dann einen Wert einsetzen, der nie greift.
        retention = {k: (v if v > 0 else 36500) for k, v in retention.items()}
        await asyncio.to_thread(lambda: self.store.prune(**retention))

    # ------------------------------------------------------------------ Status

    def status(self) -> dict:
        sniffer = self.sniffer.status() if self.sniffer else {"running": False}
        sniffer.update(
            restarts=self.sniffer_restarts,
            last_restart=self.sniffer_last_restart,
            last_restart_reason=self.sniffer_last_reason,
        )
        return {
            "sniffer": sniffer,
            "wifi": self.wifi.status() if self.wifi else {"running": False, "iface": self.setting("wifi_iface")},
            "last_runs": self.last_runs,
            "settings": {k: self.setting(k) for k in DEFAULTS},
        }
