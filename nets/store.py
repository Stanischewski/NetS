"""Schreib-/Lesepfad auf die DB.

Alle Collector schreiben ueber genau eine Funktion -- `Store.observe()`. Damit
gibt es einen einzigen Ort, an dem Geraete angelegt, Fakten dedupliziert und
Anwesenheit aggregiert wird.
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from . import db, util

PRESENCE_BUCKET = 300  # Sekunden

#: Wie viele verschiedene Werte je (Geraet, Quelle, Merkmal) aufgehoben werden.
MAX_FACT_VALUES = 10


@dataclass
class Observation:
    """Was ein Collector gesehen hat. Alles ausser `mac` ist optional."""

    #: Wer gesendet hat. Darf None sein, wenn stattdessen `ip` gesetzt ist --
    #: dann werden die Merkmale dem Geraet zugeordnet, dem diese IP gehoert.
    #: Noetig fuer weitergereichte Ankuendigungen (mDNS-Reflector), bei denen
    #: die Absender-MAC dem Weiterleiter gehoert, nicht dem gemeinten Geraet.
    mac: str | None
    source: str
    ip: str | None = None
    hostname: str | None = None
    facts: dict[str, str] = field(default_factory=dict)
    ts: int | None = None
    #: Setzt addr_mode auf 'dhcp' -- nur wenn echter DHCP-Verkehr gesehen wurde.
    dhcp_seen: bool = False


class Store:
    """Thread-sicher ueber thread-lokale Verbindungen.

    Der Sniffer laeuft in einem eigenen Thread, `asyncio.to_thread` in weiteren
    und uvicorn in noch anderen -- eine SQLite-Verbindung darf aber nur in dem
    Thread benutzt werden, in dem sie entstanden ist. WAL erlaubt parallele
    Leser; konkurrierende Schreiber serialisiert SQLite selbst (busy_timeout).
    """

    def __init__(self, path: str):
        self._path = path
        self._local = threading.local()
        self._all_conns: list[sqlite3.Connection] = []
        db.init(self.conn)
        self._lock = threading.Lock()

    @property
    def conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = db.connect(self._path)
            self._local.conn = conn
            self._all_conns.append(conn)
        return conn

    # ---------------------------------------------------------------- Schreiben

    def observe(self, obs: Observation) -> int | None:
        """Verarbeitet eine Beobachtung und gibt die device_id zurueck."""
        ts = obs.ts or util.now()
        mac = util.norm_mac(obs.mac) if obs.mac else None

        if mac is None:
            # Ohne Absender-MAC: das Geraet ueber die IP suchen. Neu anlegen
            # waere falsch -- wir wissen nur, *worueber* jemand geredet hat,
            # nicht dass dieses Geraet selbst gesendet hat.
            device_id = self._device_by_ip(obs.ip)
            if device_id is None:
                return None
            return self._apply_facts(device_id, obs, ts)

        if util.is_multicast_mac(mac) or mac == "00:00:00:00:00:00":
            return None

        with self._lock:
            cur = self.conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                device_id = self._upsert_device(cur, mac, ts)
                if obs.ip:
                    self._touch_address(cur, device_id, obs.ip, obs.source, ts)
                if obs.hostname:
                    self._record_fact(cur, device_id, ts, obs.source, "hostname", obs.hostname)
                    cur.execute(
                        "UPDATE devices SET hostname=? WHERE id=? AND (hostname IS NULL OR hostname='')",
                        (obs.hostname, device_id),
                    )
                for key, value in obs.facts.items():
                    if value:
                        self._record_fact(cur, device_id, ts, obs.source, key, str(value))
                if obs.dhcp_seen:
                    cur.execute(
                        "UPDATE devices SET addr_mode='dhcp', addr_mode_since=COALESCE(addr_mode_since, ?) "
                        "WHERE id=? AND addr_mode!='dhcp'",
                        (ts, device_id),
                    )
                self._touch_presence(cur, device_id, ts, obs.source)
                cur.execute("COMMIT")
            except Exception:
                cur.execute("ROLLBACK")
                raise
        return device_id

    def _device_by_ip(self, ip: str | None) -> int | None:
        if not ip:
            return None
        row = self.conn.execute(
            "SELECT device_id FROM addresses WHERE ip=? ORDER BY last_seen DESC LIMIT 1", (ip,)
        ).fetchone()
        return int(row["device_id"]) if row else None

    def _apply_facts(self, device_id: int, obs: Observation, ts: int) -> int:
        """Merkmale einem bereits bekannten Geraet zuschreiben, ohne dessen
        Anwesenheit zu behaupten -- gesendet hat schliesslich jemand anders."""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                if obs.hostname:
                    self._record_fact(cur, device_id, ts, obs.source, "hostname", obs.hostname)
                    cur.execute(
                        "UPDATE devices SET hostname=? WHERE id=? AND (hostname IS NULL OR hostname='')",
                        (obs.hostname, device_id),
                    )
                for key, value in obs.facts.items():
                    if value:
                        self._record_fact(cur, device_id, ts, obs.source, key, str(value))
                cur.execute("COMMIT")
            except Exception:
                cur.execute("ROLLBACK")
                raise
        return device_id

    def _upsert_device(self, cur: sqlite3.Cursor, mac: str, ts: int) -> int:
        row = cur.execute("SELECT id FROM devices WHERE mac=?", (mac,)).fetchone()
        if row:
            cur.execute("UPDATE devices SET last_seen=? WHERE id=?", (ts, row["id"]))
            return int(row["id"])
        cur.execute(
            "INSERT INTO devices(mac, mac_random, vendor, first_seen, last_seen) VALUES(?,?,?,?,?)",
            (mac, int(util.is_locally_administered(mac)), util.vendor_for_mac(mac), ts, ts),
        )
        return int(cur.lastrowid)

    def _touch_address(self, cur: sqlite3.Cursor, device_id: int, ip: str, source: str, ts: int) -> None:
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            return
        if parsed.is_unspecified or parsed.is_multicast:
            return
        cur.execute(
            "INSERT INTO addresses(device_id, ip, family, source, first_seen, last_seen) "
            "VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(device_id, ip) DO UPDATE SET last_seen=excluded.last_seen",
            (device_id, str(parsed), parsed.version, source, ts, ts),
        )

    def _record_fact(self, cur: sqlite3.Cursor, device_id: int, ts: int, source: str, key: str, value: str) -> None:
        cur.execute(
            "INSERT INTO facts(device_id, ts, source, key, value) VALUES(?,?,?,?,?) "
            "ON CONFLICT(device_id, source, key, value) DO NOTHING",
            (device_id, ts, source, key, value[:512]),
        )
        if cur.rowcount:
            self._cap_fact_values(cur, device_id, source, key)

    def _cap_fact_values(self, cur: sqlite3.Cursor, device_id: int, source: str, key: str) -> None:
        """Haelt die Zahl verschiedener Werte je Merkmal begrenzt.

        Manche Geraete rotieren Werte staendig -- ein Avahi im Namenskonflikt
        zaehlt seinen Hostnamen hoch (host-1443, host-1444, ...), andere
        wechseln bei jedem Start ihre Kennung. Ohne Deckel waechst die Tabelle
        unbegrenzt und die Detailansicht wird unlesbar. Die juengsten Werte
        sind die interessanten.
        """
        cur.execute(
            "DELETE FROM facts WHERE id IN ("
            "  SELECT id FROM facts WHERE device_id=? AND source=? AND key=?"
            "  ORDER BY ts DESC, id DESC LIMIT -1 OFFSET ?)",
            (device_id, source, key, MAX_FACT_VALUES),
        )

    def _touch_presence(self, cur: sqlite3.Cursor, device_id: int, ts: int, source: str) -> None:
        bucket = ts - (ts % PRESENCE_BUCKET)
        cur.execute(
            "INSERT INTO presence(device_id, bucket, hits, sources) VALUES(?,?,1,?) "
            "ON CONFLICT(device_id, bucket) DO UPDATE SET "
            "  hits = hits + 1, "
            "  sources = CASE WHEN instr(sources, excluded.sources) > 0 "
            "                 THEN sources ELSE sources || ',' || excluded.sources END",
            (device_id, bucket, source),
        )

    # ------------------------------------------------------ Infrastruktur/FDB

    def record_fdb(self, net_device_id: int, entries: list[tuple[str, str, int | None]], ts: int | None = None) -> int:
        """entries: Liste von (mac, port_key, vlan)."""
        ts = ts or util.now()
        rows = []
        for mac, port_key, vlan in entries:
            norm = util.norm_mac(mac)
            if norm and not util.is_multicast_mac(norm):
                # -1 statt NULL: NULL ist in SQLite nie gleich NULL, der
                # UNIQUE-Index wuerde sonst nicht greifen.
                rows.append((net_device_id, str(port_key), norm, -1 if vlan is None else vlan, ts, ts))
        if not rows:
            return 0
        with self._lock:
            # Eine Zeile je Zuordnung. Der Switch meldet bei jedem Poll
            # dieselbe Tabelle -- die unveraendert wegzuschreiben ergaebe
            # sechsstellige Zeilenzahlen fuer ein paar Dutzend Fakten.
            self.conn.executemany(
                "INSERT INTO fdb(net_device_id, port_key, mac, vlan, first_seen, last_seen) "
                "VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(net_device_id, port_key, mac, vlan) DO UPDATE SET "
                "  last_seen = excluded.last_seen",
                rows,
            )
        # Die MACs aus der FDB sind zugleich ein Anwesenheitsbeleg.
        for _, port_key, mac, _, _, _ in rows:
            self.observe(Observation(mac=mac, source=f"fdb:{net_device_id}", ts=ts))
        return len(rows)

    def record_ports(self, net_device_id: int, ports: list[tuple[str, str | None, str | None]], ts: int | None = None) -> None:
        """Portliste eines Geraets. Ersetzt die bisherige, ergaenzt sie nicht.

        Ein Adapter meldet bei jeder Abfrage seine *vollstaendige* Portliste.
        Wird ein Switch getauscht oder umkonfiguriert, blieben die alten Ports
        sonst fuer immer stehen -- nach einem Umbau standen im Testnetz 37
        Ports eines Geraets, das es nicht mehr gab.
        """
        if not ports:
            return
        ts = ts or util.now()
        keys = [str(k) for k, _, _ in ports]
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                cur.executemany(
                    "INSERT INTO net_ports(net_device_id, port_key, name, kind, last_seen) VALUES(?,?,?,?,?) "
                    "ON CONFLICT(net_device_id, port_key) DO UPDATE SET "
                    "  name=COALESCE(excluded.name, name), kind=COALESCE(excluded.kind, kind), "
                    "  last_seen=excluded.last_seen",
                    [(net_device_id, str(k), n, kind, ts) for k, n, kind in ports],
                )
                placeholders = ",".join("?" * len(keys))
                cur.execute(
                    f"DELETE FROM net_ports WHERE net_device_id=? AND port_key NOT IN ({placeholders})",
                    [net_device_id, *keys],
                )
                cur.execute("COMMIT")
            except Exception:
                cur.execute("ROLLBACK")
                raise

    def record_links(self, net_device_id: int, neighbors, source: str, ts: int | None = None) -> None:
        """neighbors: (lokaler port_key, remote sysname, remote portname[, remote mac])."""
        ts = ts or util.now()
        rows = []
        for entry in neighbors:
            port, remote_name, remote_port = entry[0], entry[1], entry[2]
            remote_mac = util.norm_mac(entry[3]) if len(entry) > 3 and entry[3] else None
            # Leerstring statt NULL: in SQLite ist NULL nie gleich NULL, ein
            # UNIQUE-Index greift dort also nicht. Ein Nachbar ohne SysName
            # wuerde sonst bei jedem Poll eine neue Zeile anlegen.
            rows.append((ts, net_device_id, str(port), remote_name or "",
                         remote_port or "", remote_mac or "", source))
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                cur.executemany(
                    "INSERT INTO links(ts, a_device, a_port, b_name, b_port, b_mac, source) "
                    "VALUES(?,?,?,?,?,?,?) "
                    "ON CONFLICT(a_device, a_port, b_name, b_port) DO UPDATE SET "
                    # NULLIF, weil hier Leerstrings statt NULL gespeichert werden:
                    # eine einmal gelernte Chassis-MAC darf nicht verloren gehen,
                    # nur weil ein spaeterer Poll sie nicht mitliefert.
                    "  ts=excluded.ts, b_mac=COALESCE(NULLIF(excluded.b_mac, ''), b_mac)",
                    rows,
                )
                # Eine Abfrage liefert die *vollstaendige* Nachbartabelle des
                # Geraets. Alles, was diesmal nicht dabei war, existiert nicht
                # mehr -- sonst bleibt ein umgestecktes Kabel als Geisterkante
                # stehen, bis die Aufbewahrungsfrist greift, und die Topologie
                # zeigt denselben Nachbarn an zwei Ports.
                keep = [(r[1], r[2], r[3], r[4]) for r in rows]
                placeholders = ",".join("(?,?,?,?)" for _ in keep)
                cur.execute(
                    f"DELETE FROM links WHERE a_device=? AND source=? "
                    f"AND (a_port, b_name, b_port) NOT IN "
                    f"(SELECT column2, column3, column4 FROM (VALUES {placeholders}))",
                    [net_device_id, source, *[v for row in keep for v in row]],
                )
                cur.execute("COMMIT")
            except Exception:
                cur.execute("ROLLBACK")
                raise

    def record_identity(self, net_device_id: int, macs, ips, name=None, description=None) -> int:
        """Verknuepft ein abgefragtes Infrastrukturgeraet mit seinen eigenen
        Adressen -- und damit mit dem Endgeraet-Eintrag, den die passiven
        Collector fuer dieselbe Hardware angelegt haben."""
        ts = util.now()
        clean = [m for m in (util.norm_mac(x) for x in macs) if m and m != "00:00:00:00:00:00"]
        source = "adapter"

        # Nicht jede API gibt ihre NIC-MACs preis -- Proxmox etwa liefert unter
        # /nodes/<node>/network keine hwaddr. Dann ueber die Management-IP
        # nachschlagen: die hat der passive Sniffer laengst einer MAC zugeordnet.
        if not clean and ips:
            placeholders = ",".join("?" * len(ips))
            clean = [
                r["mac"] for r in self.conn.execute(
                    f"SELECT DISTINCT d.mac FROM devices d JOIN addresses a ON a.device_id=d.id "
                    f"WHERE a.ip IN ({placeholders})",
                    list(ips),
                )
            ]
            source = "via-ip"

        if clean:
            with self._lock:
                cur = self.conn.cursor()
                cur.execute("BEGIN IMMEDIATE")
                try:
                    cur.executemany(
                        "INSERT INTO net_identities(net_device_id, mac, source, ts) VALUES(?,?,?,?) "
                        "ON CONFLICT(net_device_id, mac) DO UPDATE SET ts=excluded.ts, source=excluded.source",
                        [(net_device_id, mac, source, ts) for mac in clean],
                    )
                    # Ersetzen statt ergaenzen: die Eigenadressen sind eine
                    # Ausschlussliste. Bleiben MACs getauschter Hardware darin
                    # stehen, werden echte Endgeraete mit diesen Adressen
                    # dauerhaft aus der Geraeteliste herausgehalten.
                    placeholders = ",".join("?" * len(clean))
                    cur.execute(
                        f"DELETE FROM net_identities WHERE net_device_id=? AND mac NOT IN ({placeholders})",
                        [net_device_id, *clean],
                    )
                    cur.execute("COMMIT")
                except Exception:
                    cur.execute("ROLLBACK")
                    raise

        # Wichtig: NICHT fuer jede dieser MACs ein Geraet anlegen. Ein
        # 24-Port-Switch meldet 29 Interface-MACs, von denen im normalen
        # Verkehr nur die Bridge-Adresse je auftaucht -- der Rest waeren
        # reine Phantomgeraete im Inventar.
        #
        # Angelegt wird nur die erste MAC (Bridge-/Chassis-Adresse, die auch
        # die Management-IP traegt); alle uebrigen werden nur dann ergaenzt,
        # wenn sie ohnehin schon als Geraet bekannt sind.
        known = {
            r["mac"] for r in self.conn.execute(
                "SELECT mac FROM devices WHERE mac IN (%s)" % ",".join("?" * len(clean)), clean
            )
        } if clean else set()

        facts = {"role": "infrastructure"}
        if description:
            facts["model"] = description

        for index, mac in enumerate(clean):
            if index > 0 and mac not in known:
                continue
            self.observe(
                Observation(
                    mac=mac,
                    ip=ips[0] if ips and index == 0 else None,
                    hostname=name,
                    source=f"identity:{net_device_id}",
                    facts=facts,
                    ts=ts,
                )
            )
        return len(clean)

    def identity_macs(self, net_device_id: int | None = None) -> dict[str, int]:
        """{mac: net_device_id} aller bekannten Infrastruktur-Adressen.

        Eine MAC kann mehreren Eintraegen gehoeren -- etwa wenn dieselbe Box
        zweimal konfiguriert ist (SNMPv2c und v3) oder eine VM auf einem Host
        laeuft. Der niedrigste Eintrag gewinnt, damit die Anzeige stabil ist
        und nicht zwischen zwei Knoten springt.
        """
        sql = "SELECT mac, net_device_id FROM net_identities"
        params: tuple = ()
        if net_device_id is not None:
            sql += " WHERE net_device_id=?"
            params = (net_device_id,)
        result: dict[str, int] = {}
        for row in self.conn.execute(sql + " ORDER BY net_device_id", params):
            result.setdefault(row["mac"], row["net_device_id"])
        return result

    def record_wifi_link(self, station: str, bssid: str, ssid: str | None = None,
                         channel: int | None = None, signal: int | None = None,
                         ts: int | None = None) -> bool:
        """Eine aus 802.11 gelesene Assoziation Station <-> Funkmodul."""
        station_mac, bssid_mac = util.norm_mac(station), util.norm_mac(bssid)
        if not station_mac or not bssid_mac or station_mac == bssid_mac:
            return False
        if util.is_multicast_mac(station_mac) or util.is_multicast_mac(bssid_mac):
            return False
        ts = ts or util.now()
        with self._lock:
            self.conn.execute(
                "INSERT INTO wifi_links(station, bssid, ssid, channel, signal, frames, first_seen, last_seen) "
                "VALUES(?,?,?,?,?,1,?,?) "
                "ON CONFLICT(station, bssid) DO UPDATE SET "
                "  frames = frames + 1, last_seen = excluded.last_seen, "
                # SSID und Kanal lernen wir aus Beacons, die nicht bei jedem
                # Datenframe vorliegen -- einmal Gelerntes nicht ueberschreiben.
                "  ssid = COALESCE(excluded.ssid, ssid), "
                "  channel = COALESCE(excluded.channel, channel), "
                "  signal = COALESCE(excluded.signal, signal)",
                (station_mac, bssid_mac, ssid, channel, signal, ts, ts),
            )
        return True

    def wifi_links(self, max_age: int = 86400) -> dict[str, sqlite3.Row]:
        """Aktuellste Assoziation je Station.

        Ein Geraet wandert zwischen Access Points; nur die juengste zaehlt.
        """
        cutoff = util.now() - max_age
        result: dict[str, sqlite3.Row] = {}
        for row in self.conn.execute(
            "SELECT * FROM wifi_links WHERE last_seen >= ? ORDER BY last_seen ASC", (cutoff,)
        ):
            result[row["station"]] = row
        return result

    def record_web_service(self, entry: dict, source: str = "scan", ts: int | None = None) -> None:
        """Eine gefundene Weboberflaeche festhalten."""
        ts = ts or util.now()
        device_id = self._device_by_ip(entry["ip"])
        with self._lock:
            self.conn.execute(
                "INSERT INTO web_services(device_id, ip, port, scheme, title, server, status, "
                "                         redirect, source, first_seen, last_seen) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(ip, port) DO UPDATE SET "
                "  device_id=COALESCE(excluded.device_id, device_id), scheme=excluded.scheme, "
                # Titel und Server nur ueberschreiben, wenn diesmal etwas kam --
                # ein Timeout soll eine bekannte Beschriftung nicht loeschen.
                "  title=COALESCE(excluded.title, title), server=COALESCE(excluded.server, server), "
                "  status=excluded.status, redirect=excluded.redirect, last_seen=excluded.last_seen",
                (device_id, entry["ip"], int(entry["port"]), entry["scheme"], entry.get("title"),
                 entry.get("server"), entry.get("status"), entry.get("redirect"), source, ts, ts),
            )

    def web_services(self) -> list[dict]:
        """Alle bekannten Oberflaechen, mit dem Geraet dahinter."""
        return [dict(r) for r in self.conn.execute(
            """
            SELECT w.*, d.mac, d.label, d.hostname, d.vendor, d.os_guess, d.device_type
            FROM web_services w
            LEFT JOIN devices d ON d.id = w.device_id
            ORDER BY w.ip, w.port
            """
        )]

    def harvest_web_passive(self) -> int:
        """Weboberflaechen aus den passiven Quellen uebernehmen.

        UPnP nennt eine LOCATION-URL, mDNS einen SRV-Record mit Port -- beides
        liegt laengst im Inventar und muss nicht erfragt werden. Deshalb laeuft
        das auch, wenn die aktive Suche abgeschaltet ist.
        """
        import re as _re

        found = 0
        for row in self.conn.execute(
            "SELECT DISTINCT value FROM facts WHERE key='upnp_location'"
        ):
            match = _re.match(r"^(https?)://([0-9.]+)(?::(\d+))?", row["value"] or "")
            if not match:
                continue
            scheme, ip, port = match.groups()
            self.record_web_service(
                {"ip": ip, "port": int(port or (443 if scheme == "https" else 80)),
                 "scheme": scheme, "status": None, "server": None, "title": None,
                 "redirect": None},
                source="ssdp",
            )
            found += 1

        # mDNS: der SRV-Record nennt den Port, die IP kennen wir vom Geraet.
        for row in self.conn.execute(
            """
            SELECT f.value, a.ip FROM facts f
            JOIN addresses a ON a.device_id = f.device_id AND a.family = 4
            WHERE f.key = 'web_endpoint'
            GROUP BY f.device_id, f.value
            HAVING a.last_seen = MAX(a.last_seen)
            """
        ):
            scheme, _, port = (row["value"] or "").partition(":")
            if scheme in ("http", "https") and port.isdigit():
                self.record_web_service(
                    {"ip": row["ip"], "port": int(port), "scheme": scheme,
                     "status": None, "server": None, "title": None, "redirect": None},
                    source="mdns",
                )
                found += 1
        return found

    def record_subnet_host(self, ip: str, subnet: str, method: str,
                           detail: str | None = None, ts: int | None = None) -> None:
        ts = ts or util.now()
        with self._lock:
            self.conn.execute(
                "INSERT INTO subnet_hosts(ip, subnet, method, detail, first_seen, last_seen) "
                "VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(ip) DO UPDATE SET subnet=excluded.subnet, method=excluded.method, "
                "  detail=COALESCE(excluded.detail, detail), last_seen=excluded.last_seen",
                (ip, subnet, method, detail, ts, ts),
            )

    def subnet_overview(self) -> list[dict]:
        """Was wissen wir je Subnetz -- und was fehlt noch?

        Der entscheidende Wert ist `with_mac`: nur Adressen, zu denen wir auch
        eine MAC haben, sind echtes Inventar. Der Rest sagt bloss, dass dort
        etwas antwortet.
        """
        seen: dict[str, dict] = {}

        for row in self.conn.execute(
            "SELECT ip FROM addresses WHERE family=4"
        ):
            key = ".".join(row["ip"].split(".")[:3]) + ".0/24"
            entry = seen.setdefault(key, {"subnet": key, "with_mac": 0, "responding": 0})
            entry["with_mac"] += 1

        for row in self.conn.execute("SELECT subnet, COUNT(*) n FROM subnet_hosts GROUP BY subnet"):
            entry = seen.setdefault(
                row["subnet"], {"subnet": row["subnet"], "with_mac": 0, "responding": 0}
            )
            entry["responding"] = row["n"]

        return sorted(seen.values(), key=lambda e: e["subnet"])

    def scan_targets(self, max_age_days: int = 7) -> list[str]:
        """IPv4-Adressen, die einen Versuch wert sind.

        Nur Geraete, die kuerzlich gesehen wurden -- eine Adresse, die seit
        Wochen niemand benutzt, ist entweder frei oder gehoert inzwischen
        jemand anderem.
        """
        cutoff = util.now() - max_age_days * 86400
        return [r["ip"] for r in self.conn.execute(
            "SELECT DISTINCT a.ip FROM addresses a JOIN devices d ON d.id=a.device_id "
            "WHERE a.family=4 AND d.ignored=0 AND a.last_seen >= ? ORDER BY a.ip",
            (cutoff,),
        )]

    def set_adapter_status(self, net_device_id: int, ok: bool, error: str | None) -> None:
        with self._lock:
            if ok:
                self.conn.execute(
                    "UPDATE net_devices SET last_ok=?, last_error=NULL WHERE id=?", (util.now(), net_device_id)
                )
            else:
                self.conn.execute(
                    "UPDATE net_devices SET last_error=? WHERE id=?", ((error or "unbekannter Fehler")[:500], net_device_id)
                )

    # -------------------------------------------------------------------- Lesen

    def net_devices(self, only_enabled: bool = False) -> list[sqlite3.Row]:
        sql = "SELECT * FROM net_devices"
        if only_enabled:
            sql += " WHERE enabled=1"
        return list(self.conn.execute(sql + " ORDER BY name"))

    def settings(self) -> dict[str, str]:
        return {r["key"]: r["value"] for r in self.conn.execute("SELECT key, value FROM settings")}

    def get_setting(self, key: str, default: str | None = None) -> str | None:
        row = self.conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO settings(key, value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    # ------------------------------------------------------------- Ableitungen

    def refresh_identities(self) -> int:
        """Leitet Betriebssystem und Geraetetyp aus den gesammelten Merkmalen ab.

        Laeuft als Wartungsschritt statt bei jeder Beobachtung: die Merkmale
        sammeln sich ueber Stunden an, und eine Ableitung auf halber Strecke
        waere nur schlechter.
        """
        from . import identify

        facts_by_device: dict[int, dict[str, str]] = defaultdict(dict)
        for row in self.conn.execute(
            "SELECT device_id, key, value, ts FROM facts ORDER BY ts ASC"
        ):
            facts_by_device[row["device_id"]][row["key"]] = row["value"]

        known_macs = {r["mac"] for r in self.conn.execute("SELECT mac FROM devices")}
        updates = []
        for row in self.conn.execute(
            """
            SELECT d.id, d.mac, d.hostname, d.first_seen, d.last_seen,
                   (SELECT COUNT(*) FROM presence p WHERE p.device_id=d.id)  AS buckets,
                   (SELECT COUNT(*) FROM addresses a WHERE a.device_id=d.id) AS ips
            FROM devices d
            """
        ):
            facts = facts_by_device.get(row["id"], {})
            mac_kind, _detail = identify.classify_mac(
                row["mac"], known_macs, has_guest_fact=bool(facts.get("guest_kind"))
            )
            result = identify.guess(facts, row["hostname"], mac_kind)
            device_type = result["device_type"]
            if device_type is None:
                # Nichts erkannt? Dann wenigstens sagen, ob das Geraet
                # ueberhaupt substanziell da war.
                device_type = identify.transience(
                    row["buckets"], row["ips"], (row["last_seen"] - row["first_seen"]) // 60
                )
            updates.append((result["os_guess"], device_type, row["id"]))

        with self._lock:
            self.conn.executemany(
                "UPDATE devices SET os_guess=?, device_type=? WHERE id=?", updates
            )
        return sum(1 for os_guess, kind, _ in updates if os_guess or kind)

    def similar_devices(self, device_id: int, max_results: int = 5) -> list[dict]:
        """Andere MACs, die dasselbe Geraet sein koennten.

        Zwei Bedingungen muessen zusammenkommen: gleicher DHCP-Fingerprint bzw.
        Hostname *und* keine zeitliche Ueberschneidung. Der zweite Teil ist der
        entscheidende -- zwei MACs, die gleichzeitig im Netz waren, koennen
        nicht dasselbe Geraet sein, egal wie aehnlich sie sonst aussehen.
        Deshalb wird hier nur vorgeschlagen, nie automatisch zusammengefuehrt.
        """
        row = self.conn.execute(
            "SELECT mac, hostname, mac_random FROM devices WHERE id=?", (device_id,)
        ).fetchone()
        if row is None or not row["mac_random"]:
            return []

        fingerprint = self.conn.execute(
            "SELECT value FROM facts WHERE device_id=? AND key='dhcp_fingerprint' "
            "ORDER BY ts DESC LIMIT 1", (device_id,)
        ).fetchone()
        fingerprint = fingerprint["value"] if fingerprint else None
        if not fingerprint and not row["hostname"]:
            return []

        candidates = self.conn.execute(
            """
            SELECT DISTINCT d.id, d.mac, d.hostname, d.first_seen, d.last_seen
            FROM devices d
            LEFT JOIN facts f ON f.device_id = d.id AND f.key = 'dhcp_fingerprint'
            WHERE d.id != ? AND d.mac_random = 1 AND d.ignored = 0
              AND (f.value = ? OR (? IS NOT NULL AND d.hostname = ?))
            """,
            (device_id, fingerprint, row["hostname"], row["hostname"]),
        ).fetchall()

        own_buckets = {
            r["bucket"] for r in self.conn.execute(
                "SELECT bucket FROM presence WHERE device_id=?", (device_id,)
            )
        }
        out = []
        for candidate in candidates:
            other = {
                r["bucket"] for r in self.conn.execute(
                    "SELECT bucket FROM presence WHERE device_id=?", (candidate["id"],)
                )
            }
            overlap = own_buckets & other
            if overlap:
                continue  # gleichzeitig gesehen -> definitiv ein anderes Gerät
            out.append({
                "id": candidate["id"],
                "mac": candidate["mac"],
                "hostname": candidate["hostname"],
                "first_seen": candidate["first_seen"],
                "last_seen": candidate["last_seen"],
                "reason": "gleicher DHCP-Fingerprint" if fingerprint else "gleicher Hostname",
            })
        return sorted(out, key=lambda d: -d["last_seen"])[:max_results]

    def infer_static_addressing(self, min_age_seconds: int = 3 * 86400) -> int:
        """Markiert Geraete als 'static'.

        Kriterium: lange genug beobachtet, hat eine IPv4, aber in der ganzen
        Zeit nie DHCP-Verkehr gezeigt. Braucht Beobachtungsdauer -- deshalb
        der Default von drei Tagen.
        """
        cutoff = util.now() - min_age_seconds
        with self._lock:
            cur = self.conn.execute(
                """
                UPDATE devices SET addr_mode='static', addr_mode_since=?
                WHERE addr_mode='unknown'
                  AND first_seen <= ?
                  AND EXISTS (SELECT 1 FROM addresses a WHERE a.device_id=devices.id AND a.family=4)
                  AND NOT EXISTS (SELECT 1 FROM facts f WHERE f.device_id=devices.id AND f.source='dhcp')
                """,
                (util.now(), cutoff),
            )
        return cur.rowcount

    # ------------------------------------------------------------ Datenpflege

    #: Was zu den *gesammelten* Daten zaehlt -- im Gegensatz zur Konfiguration
    #: (net_devices, settings), die ein Loeschen ueberleben soll.
    COLLECTED_TABLES = (
        "attachments", "web_services", "subnet_hosts", "wifi_links", "fdb", "links", "net_identities",
        "net_ports", "presence", "facts", "addresses", "devices",
    )
    HISTORY_TABLES = ("presence", "fdb", "links", "wifi_links")

    def stats(self) -> dict:
        """Zeilenzahlen und Dateigroesse -- damit sichtbar ist, was ein
        Loeschen ueberhaupt betrifft."""
        counts = {}
        for table in (*self.COLLECTED_TABLES, "net_devices", "settings"):
            counts[table] = self.conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]

        size = 0
        for suffix in ("", "-wal", "-shm"):
            try:
                size += Path(self._path + suffix).stat().st_size
            except OSError:
                pass

        oldest = self.conn.execute("SELECT MIN(bucket) AS b FROM presence").fetchone()["b"]
        return {
            "counts": counts,
            "db_bytes": size,
            "db_path": self._path,
            "oldest_observation": oldest,
        }

    def purge(self, scope: str) -> dict[str, int]:
        """Loescht gesammelte Daten.

        scope:
          history    -- nur Verlauf (Anwesenheit, FDB, LLDP, WLAN); Inventar bleibt
          devices    -- alle gesammelten Daten, Adapter-Konfiguration bleibt
          everything -- zusaetzlich die Adapter; Einstellungen bleiben
        """
        if scope == "history":
            tables = self.HISTORY_TABLES
        elif scope == "devices":
            tables = self.COLLECTED_TABLES
        elif scope == "everything":
            tables = (*self.COLLECTED_TABLES, "net_devices")
        else:
            raise ValueError(f"Unbekannter Bereich: {scope}")

        removed: dict[str, int] = {}
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                for table in tables:
                    before = cur.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]
                    cur.execute(f"DELETE FROM {table}")
                    if before:
                        removed[table] = before
                cur.execute("COMMIT")
            except Exception:
                cur.execute("ROLLBACK")
                raise
        self.vacuum()
        return removed

    def delete_devices_older_than(self, days: int) -> int:
        """Geraete entfernen, die seit `days` Tagen nicht gesehen wurden.

        Haengende Zeilen raeumt ON DELETE CASCADE weg; fdb und wifi_links
        haengen an der MAC statt an der id und brauchen einen eigenen Schnitt.
        """
        cutoff = util.now() - days * 86400
        with self._lock:
            macs = [
                r["mac"] for r in self.conn.execute(
                    "SELECT mac FROM devices WHERE last_seen < ?", (cutoff,)
                )
            ]
            if not macs:
                return 0
            placeholders = ",".join("?" * len(macs))
            self.conn.execute(f"DELETE FROM fdb WHERE mac IN ({placeholders})", macs)
            self.conn.execute(f"DELETE FROM wifi_links WHERE station IN ({placeholders})", macs)
            cur = self.conn.execute("DELETE FROM devices WHERE last_seen < ?", (cutoff,))
        return cur.rowcount

    def delete_device(self, device_id: int) -> bool:
        row = self.conn.execute("SELECT mac FROM devices WHERE id=?", (device_id,)).fetchone()
        if row is None:
            return False
        with self._lock:
            self.conn.execute("DELETE FROM fdb WHERE mac=?", (row["mac"],))
            self.conn.execute("DELETE FROM wifi_links WHERE station=?", (row["mac"],))
            self.conn.execute("DELETE FROM devices WHERE id=?", (device_id,))
        return True

    def vacuum(self) -> None:
        """Gibt den Plattenplatz nach einem Loeschen wirklich frei."""
        with self._lock:
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.conn.execute("VACUUM")

    def prune(self, presence_days: int = 90, fdb_days: int = 30, link_days: int = 7,
              wifi_days: int = 30, infra_days: int = 30) -> None:
        now = util.now()
        with self._lock:
            self.conn.execute("DELETE FROM presence WHERE bucket < ?", (now - presence_days * 86400,))
            self.conn.execute("DELETE FROM fdb WHERE last_seen < ?", (now - fdb_days * 86400,))
            # Links werden bei jedem Poll neu geschrieben; alte Zeilen sind
            # entweder verschwundene Nachbarn oder Reste aus einer Zeit mit
            # anderer Formatierung.
            self.conn.execute("DELETE FROM links WHERE ts < ?", (now - link_days * 86400,))
            self.conn.execute(
                "DELETE FROM wifi_links WHERE last_seen < ?", (now - wifi_days * 86400,)
            )
            # Auffangnetz fuer Adapter, die gar nicht mehr antworten: dort
            # greift das Ersetzen beim Poll nie, weil kein Poll mehr gelingt.
            cutoff = now - infra_days * 86400
            self.conn.execute("DELETE FROM net_ports WHERE last_seen < ?", (cutoff,))
            self.conn.execute("DELETE FROM net_identities WHERE ts < ?", (cutoff,))

    def close(self) -> None:
        for conn in self._all_conns:
            try:
                conn.close()
            except sqlite3.Error:
                pass
        self._all_conns.clear()
        self._local = threading.local()


def json_config(row: sqlite3.Row) -> dict:
    try:
        return json.loads(row["config"])
    except (json.JSONDecodeError, TypeError):
        return {}
