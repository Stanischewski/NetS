"""Topologie-Aufloesung: an welchem Port haengt welches Geraet?

Kernproblem: eine MAC taucht in der FDB *mehrerer* Switches auf -- auf dem
Switch, an dem sie wirklich haengt, und auf jedem Switch davor (dort ueber
den Uplink). Der klassische Loesungsansatz:

    Der Port, an dem ein Geraet wirklich haengt, ist der Port mit den
    *wenigsten* gelernten MACs.

Uplinks tragen die MACs des ganzen dahinterliegenden Netzes, Access-Ports
typischerweise genau eine. Zusaetzlich markieren wir Ports als Uplink, wenn
LLDP dort einen Nachbarn meldet -- das ist die harte Evidenz und schlaegt die
Heuristik.
"""

from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict

from .store import Store
from .util import now

log = logging.getLogger("nets.topology")

#: FDB-Eintraege aelter als das hier werden ignoriert.
FRESHNESS = 3600

#: LLDP-Nachbarschaften altern langsamer -- ein Switch meldet sie nur
#: periodisch, und die Verkabelung aendert sich selten.
LINK_FRESHNESS = 86400


def resolve(store: Store, freshness: int = FRESHNESS) -> int:
    """Berechnet attachments neu. Gibt die Zahl der aufgeloesten Geraete zurueck."""
    cutoff = now() - freshness
    conn = store.conn

    # Nur der jeweils juengste FDB-Eintrag je (net_device, port, mac) zaehlt.
    rows = list(
        conn.execute(
            """
            SELECT net_device_id, port_key, mac, last_seen
            FROM fdb WHERE last_seen >= ?
            """,
            (cutoff,),
        )
    )
    if not rows:
        log.info("Keine frischen FDB-Daten -- Topologie unveraendert")
        return 0

    # Wie viele MACs haengen an jedem Port? -> Uplink-Erkennung
    port_macs: dict[tuple[int, str], set[str]] = defaultdict(set)
    for row in rows:
        port_macs[(row["net_device_id"], row["port_key"])].add(row["mac"])

    # LLDP-Nachbarschaften altern langsamer als FDB-Eintraege, daher ein
    # eigenes, grosszuegigeres Fenster.
    lldp_ports = {
        (r["a_device"], r["a_port"])
        for r in conn.execute("SELECT a_device, a_port FROM links WHERE ts >= ?", (now() - 86400,))
    }

    wireless_ports = {
        (r["net_device_id"], r["port_key"])
        for r in conn.execute("SELECT net_device_id, port_key FROM net_ports WHERE kind='wireless'")
    }

    # Kandidaten je MAC sammeln und den besten Port waehlen.
    candidates: dict[str, list[tuple[int, str, int]]] = defaultdict(list)
    for row in rows:
        key = (row["net_device_id"], row["port_key"])
        candidates[row["mac"]].append((row["net_device_id"], row["port_key"], len(port_macs[key])))

    mac_to_device = {
        r["mac"]: r["id"] for r in conn.execute("SELECT id, mac FROM devices")
    }
    # Infrastruktur-MACs (die Switches selbst) nicht als Client anhaengen.
    # Frueher stand hier ein SELECT auf facts.value -- das lieferte den String
    # 'infrastructure' statt der MAC, die Pruefung lief also immer ins Leere.
    infra_macs = set(store.identity_macs())
    infra_macs |= {
        r["mac"].lower()
        for r in conn.execute(
            "SELECT d.mac FROM devices d JOIN facts f ON f.device_id=d.id "
            "WHERE f.key='role' AND f.value='infrastructure'"
        )
    }

    resolved = 0
    ts = now()
    with store._lock:
        cur = conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        try:
            cur.execute("DELETE FROM attachments")
            for mac, options in candidates.items():
                device_id = mac_to_device.get(mac)
                if device_id is None or mac in infra_macs:
                    continue

                # LLDP-Ports sind nachweislich Uplinks -> ausschliessen,
                # solange es eine Alternative gibt.
                filtered = [o for o in options if (o[0], o[1]) not in lldp_ports] or options
                # Kleinste MAC-Zahl gewinnt; bei Gleichstand der erste Treffer.
                net_device_id, port_key, mac_count = min(filtered, key=lambda o: o[2])

                is_wireless = (net_device_id, port_key) in wireless_ports or "wlan" in port_key.lower()
                confidence = _confidence(mac_count, len(options), len(filtered) < len(options))

                cur.execute(
                    "INSERT INTO attachments(device_id, net_device_id, port_key, medium, confidence, ts) "
                    "VALUES(?,?,?,?,?,?)",
                    (device_id, net_device_id, port_key, "wireless" if is_wireless else "wired", confidence, ts),
                )
                resolved += 1
            cur.execute("COMMIT")
        except Exception:
            cur.execute("ROLLBACK")
            raise

    log.info("Topologie aufgeloest: %d Geraete an %d Ports", resolved, len(port_macs))
    return resolved


def _confidence(mac_count: int, option_count: int, lldp_helped: bool) -> float:
    """1.0 = ein einziges Geraet am Port. Sinkt, je mehr MACs dort haengen
    (Hub, unmanaged Switch dazwischen, oder wir sehen nur den Uplink)."""
    score = 1.0 / max(mac_count, 1)
    if option_count == 1:
        score = max(score, 0.6)  # nur ein Switch kennt die MAC ueberhaupt
    if lldp_helped:
        score = min(1.0, score + 0.15)
    return round(score, 3)


#: Ab so vielen Geraeten an einem Port ist das kein Endgeraeteport mehr,
#: sondern fast sicher ein Uplink zu Hardware, die wir nicht abfragen
#: (unmanaged Switch, Access Point, Virtualisierungs-Host).
UPLINK_HINT = 4

_DEVICE_QUERY = """
    SELECT d.id, d.mac, d.label, d.hostname, d.vendor, d.mac_random, d.last_seen,
           d.addr_mode,
           a.net_device_id, a.port_key, a.medium, a.confidence,
           (SELECT ip FROM addresses ad WHERE ad.device_id=d.id AND ad.family=4
            ORDER BY ad.last_seen DESC LIMIT 1) AS ip
    FROM devices d
    LEFT JOIN attachments a ON a.device_id = d.id
    WHERE d.ignored = 0
"""


def tree(store: Store) -> dict:
    """Hierarchischer Baum fuer die WebUI.

    Ein kraeftebasierter Graph wird bei dieser Datenform unlesbar: In einem
    typischen Netz haengen fast alle Geraete an einer Handvoll Ports, und ein
    einziger Uplink-Port traegt schnell zwei Dutzend MACs. Als Ring um einen
    Punkt ist das nicht zu entziffern.

    Deshalb: Router/Switch -> Port -> Geraet, mit den Geraeten je Port
    gruppiert und zusammenklappbar. Die Struktur des Netzes ist damit sichtbar,
    statt sie aus einem Knaeuel erraten zu muessen.
    """
    conn = store.conn

    net_devices = {
        r["id"]: dict(r)
        for r in conn.execute(
            "SELECT id, name, adapter_type, config, last_ok, last_error FROM net_devices"
        )
    }
    port_meta = {
        (r["net_device_id"], r["port_key"]): dict(r)
        for r in conn.execute("SELECT net_device_id, port_key, name, kind FROM net_ports")
    }

    # Die Switches kennen ihre eigenen MACs. Diese Geraete gehoeren nicht in
    # die Liste der Endgeraete, sondern *sind* der Infrastrukturknoten --
    # sonst steht ein Switch zweimal im Baum.
    identity_macs = store.identity_macs()
    # Aus 802.11 gelesene Assoziationen: Station -> Funkmodul.
    wifi = store.wifi_links()
    identity_totals: dict[int, int] = Counter(identity_macs.values())
    self_info: dict[int, dict] = {}

    attached: dict[int, list[dict]] = defaultdict(list)   # (net_id, port) -> Geraete
    unattached: list[dict] = []
    for row in conn.execute(_DEVICE_QUERY):
        owner = identity_macs.get(row["mac"])
        if owner is not None:
            # Nur die erste (meist die Bridge-MAC) traegt die Anzeigedaten.
            entry = self_info.setdefault(owner, {"macs": [], "ip": None, "device_id": None})
            entry["macs"].append(row["mac"])
            entry["ip"] = entry["ip"] or row["ip"]
            entry["device_id"] = entry["device_id"] or row["id"]
            continue

        device = _device_node(row)
        if row["net_device_id"] is None:
            unattached.append(device)
        else:
            attached[(row["net_device_id"], row["port_key"])].append(device)

    parents, uplink_ports, unknown_neighbors = _infra_hierarchy(conn, net_devices, store)

    def build_infra(net_id: int) -> dict:
        info = net_devices[net_id]
        children: list[dict] = []

        # Erst die nachgelagerte Infrastruktur -- sie strukturiert den Baum.
        for child_id, via_port in sorted(
            ((c, p) for c, (par, p) in parents.items() if par == net_id),
            key=lambda x: net_devices[x[0]]["name"].lower(),
        ):
            node = build_infra(child_id)
            meta = port_meta.get((net_id, via_port), {}) if via_port else {}
            node["via_port"] = meta.get("name") or via_port
            children.append(node)

        for name, via_port in sorted(unknown_neighbors.get(net_id, [])):
            children.append({
                "id": f"ext:{net_id}:{name}",
                "kind": "infra_unknown",
                "label": name,
                "sublabel": "über LLDP gemeldet, aber nicht konfiguriert",
                "via_port": via_port,
                "badges": [{"text": "nicht abgefragt", "tone": "warn"}],
                "count": 0,
                "children": [],
            })

        # Dann die Ports mit Endgeraeten.
        ports = [
            (port_key, devices)
            for (owner, port_key), devices in attached.items()
            if owner == net_id
        ]
        for port_key, devices in sorted(ports, key=lambda x: _port_sort_key(x[0])):
            children.append(
                _port_node(net_id, port_key, devices, port_meta, uplink_ports, wifi)
            )

        # Ein Knoten ohne jeden Zweig sagt sonst nicht, ob er nichts liefert
        # oder ob wirklich nichts dranhaengt. Router haben typischerweise gar
        # keine Bridge-FDB -- das ist normal und kein Fehler.
        # Eigene Adressen mit anzeigen -- damit ist auf einen Blick klar, dass
        # dieser Knoten und das frueher separat gelistete Geraet dasselbe sind.
        own = self_info.get(net_id, {})
        parts = [info["adapter_type"]]
        if own.get("ip"):
            parts.append(own["ip"])
        if own.get("macs"):
            # Angezeigt wird die im Netz gesehene Adresse; die Anzahl bezieht
            # sich auf alle bekannten Eigenadressen (ein 24-Port-Switch meldet
            # eine MAC je Port, die nie Verkehr erzeugt).
            parts.append(own["macs"][0])
            others = identity_totals.get(net_id, 0) - 1
            if others > 0:
                parts[-1] += f" (+{others} weitere Interface-MACs)"

        badges = _infra_badges(info)
        if not children:
            parts.append("keine MAC-Tabelle geliefert")
            badges.append({"text": "keine Port-Daten", "tone": "info"})

        return {
            "id": f"net:{net_id}",
            "kind": "infra",
            "label": info["name"],
            "sublabel": " · ".join(parts),
            "badges": badges,
            "device_id": own.get("device_id"),
            "self_macs": own.get("macs", []),
            "count": sum(c["count"] for c in children),
            "children": children,
        }

    roots = [build_infra(net_id) for net_id in _roots(net_devices, parents)]
    roots.sort(key=lambda n: (-n["count"], n["label"].lower()))

    if unattached:
        roots.append(_unattached_group(unattached))

    return {
        "roots": roots,
        "stats": {
            "infra": len(net_devices),
            "attached": sum(len(v) for v in attached.values()),
            "unattached": len(unattached),
            "ports": len(attached),
            "self_linked": sum(len(v["macs"]) for v in self_info.values()),
        },
    }


def _device_node(row) -> dict:
    badges = []
    if row["mac_random"]:
        badges.append({"text": "zufällige MAC", "tone": "warn"})
    if row["medium"] == "wireless":
        badges.append({"text": "WLAN", "tone": "wireless"})
    if row["addr_mode"] == "static":
        badges.append({"text": "statisch", "tone": "info"})
    label = row["label"] or row["hostname"] or row["ip"] or row["mac"]
    # Ohne diese Pruefung steht bei namenlosen Geraeten zweimal dasselbe da:
    # "192.0.2.1 — 192.0.2.1 · Arcadyan".
    details = [part for part in (row["ip"], row["vendor"] or row["mac"]) if part and part != label]
    return {
        "id": f"dev:{row['id']}",
        "device_id": row["id"],
        "kind": "device",
        "label": label,
        "sublabel": " · ".join(details),
        "badges": badges,
        "mac": row["mac"],
        "ip": row["ip"],
        "last_seen": row["last_seen"],
        "confidence": row["confidence"],
        "count": 1,
        "children": [],
    }


def _group_by_access_point(devices: list[dict], wifi: dict) -> list[dict]:
    """Faltet die per 802.11 erkannten Clients unter ihr Funkmodul.

    Genau das ist der Gewinn des Monitor-Mode: Hinter einem Uplink-Port liegen
    sonst nur zwei Dutzend gleichrangige MACs. Mit den Assoziationen wird
    daraus "diese acht haengen am Speedport-Funk, jene sechs am Repeater".
    """
    by_bssid: dict[str, list[dict]] = defaultdict(list)
    wired: list[dict] = []
    for device in devices:
        link = wifi.get(device.get("mac"))
        if link is None:
            wired.append(device)
            continue
        device = dict(device, badges=[*device["badges"]])
        if link["signal"] is not None:
            device["badges"].append({"text": f"{link['signal']} dBm", "tone": "wireless"})
        by_bssid[link["bssid"]].append(device)

    groups: list[dict] = []
    for bssid, clients in sorted(by_bssid.items(), key=lambda x: -len(x[1])):
        sample = wifi[clients[0]["mac"]]
        ssid, channel = sample["ssid"], sample["channel"]
        label = ssid or bssid
        details = [bssid] if ssid else []
        if channel:
            details.append(f"Kanal {channel} · {_band(channel)}")
        clients.sort(key=lambda d: d["label"].lower())
        groups.append({
            "id": f"bssid:{bssid}",
            "kind": "ap",
            "label": label,
            "sublabel": " · ".join([*details, f"{len(clients)} Client{'s' if len(clients) != 1 else ''}"]),
            "badges": [{"text": "per 802.11 erkannt", "tone": "wireless"}],
            "mac": bssid,
            "count": len(clients),
            "children": clients,
        })

    wired.sort(key=lambda d: d["label"].lower())
    return groups + wired


def _band(channel: int) -> str:
    if 1 <= channel <= 14:
        return "2,4 GHz"
    return "5 GHz" if channel <= 177 else "6 GHz"


def _port_node(net_id, port_key, devices, port_meta, uplink_ports, wifi=None) -> dict:
    meta = port_meta.get((net_id, port_key), {})
    # HP/ProCurve & Co. melden als ifName schlicht "12" -- als Baumeintrag
    # allein waere das nichtssagend.
    name = meta.get("name") or str(port_key)
    if name.isdigit():
        name = f"Port {name}"
    devices.sort(key=lambda d: d["label"].lower())
    children = _group_by_access_point(devices, wifi or {})
    access_points = [c for c in children if c["kind"] == "ap"]

    badges = []
    wireless = meta.get("kind") == "wireless" or "wlan" in str(port_key).lower()
    if wireless:
        badges.append({"text": "WLAN", "tone": "wireless"})

    # Hier steht Hardware dazwischen, die wir nicht sehen. Ohne diesen Hinweis
    # wirkt es so, als haengten zwei Dutzend Geraete direkt am Switchport.
    hidden = len(devices) >= UPLINK_HINT and not wireless
    neighbors = [n for n in uplink_ports.get((net_id, port_key), []) if n]
    hint = None

    if access_points:
        badges.append({
            "text": f"{len(access_points)} Funkmodul{'e' if len(access_points) != 1 else ''} erkannt",
            "tone": "wireless",
        })

    if hidden and access_points:
        # Kein Ratespiel mehr: die Clients stehen unter ihrem Funkmodul.
        badges.append({"text": f"{len(devices)} MACs", "tone": "info"})
        hint = (
            f"Die Zuordnung stammt aus mitgeschnittenen 802.11-Frames, nicht aus einer "
            f"Abfrage des Geraets — sie funktioniert deshalb auch bei Routern und Repeatern "
            f"ohne jede API."
        )
    elif hidden:
        badges.append({"text": f"{len(devices)} MACs", "tone": "warn"})
        # Entscheidend fuer die Frage "was kann ich tun?": LLDP reicht genau
        # einen Hop weit. Meldet sich dort ein Nachbar, ist bekannt *wer*
        # davorsteht und man kann ihn abfragen. Schweigt der Port, steckt dort
        # Hardware ohne LLDP -- meist ein unmanaged Switch, der sich gar nicht
        # abfragen laesst.
        if neighbors:
            badges.append({"text": f"hinter {neighbors[0]}", "tone": "info"})
            hint = (
                f"LLDP nennt als direkten Nachbarn „{neighbors[0]}“ — mehr sagt LLDP nicht, "
                f"es reicht nur einen Hop weit. Die {len(devices)} MACs hier sind alles, was "
                f"über diesen Nachbarn erreichbar ist, nicht was an ihm steckt. "
                f"Als Adapter hinzufügen, um sie ihren echten Ports zuzuordnen."
            )
        else:
            hint = (
                f"Kein LLDP-Nachbar an diesem Port, aber {len(devices)} MACs — dort hängt "
                f"vermutlich ein unmanaged Switch oder Access Point. Solche Geräte melden sich "
                f"nicht und lassen sich nicht abfragen; die Geräte dahinter bleiben ohne "
                f"genauen Port."
            )
    elif neighbors:
        badges.append({"text": f"LLDP: {neighbors[0]}", "tone": "info"})

    return {
        "id": f"port:{net_id}:{port_key}",
        "kind": "port",
        "label": name,
        "sublabel": f"{len(devices)} Gerät{'e' if len(devices) != 1 else ''}",
        "badges": badges,
        "hidden_infrastructure": hidden,
        "hint": hint,
        "count": len(devices),
        "children": children,
    }


def _unattached_group(devices: list[dict]) -> dict:
    """Geraete ohne Port-Zuordnung nach Subnetz gruppiert.

    Frueher stand hier nur eine Zahl. Damit verschwanden genau die
    interessanten Faelle -- Geraete, die kein Switch kennt -- aus dem Bild.
    """
    by_subnet: dict[str, list[dict]] = defaultdict(list)
    for device in devices:
        by_subnet[_subnet_label(device.get("ip"))].append(device)

    children = []
    for subnet, group in sorted(by_subnet.items()):
        group.sort(key=lambda d: d["label"].lower())
        children.append({
            "id": f"subnet:{subnet}",
            "kind": "group",
            "label": subnet,
            "sublabel": f"{len(group)} Gerät{'e' if len(group) != 1 else ''}",
            "badges": [],
            "count": len(group),
            "children": group,
        })

    return {
        "id": "unattached",
        "kind": "group",
        "label": "Ohne Port-Zuordnung",
        "sublabel": "kein Switch meldet diese MACs",
        "badges": [{"text": str(len(devices)), "tone": "warn"}],
        "count": len(devices),
        "children": children,
    }


def _subnet_label(ip: str | None) -> str:
    if not ip:
        return "ohne IPv4"
    parts = ip.split(".")
    return f"{'.'.join(parts[:3])}.0/24" if len(parts) == 4 else ip


def _infra_badges(info: dict) -> list[dict]:
    if info["last_error"]:
        return [{"text": "Fehler", "tone": "err"}]
    if not info["last_ok"]:
        return [{"text": "noch nie abgefragt", "tone": "warn"}]
    return [{"text": "ok", "tone": "ok"}]


def _port_sort_key(port_key: str):
    """Ports natuerlich sortieren: Port 2 vor Port 10."""
    text = str(port_key)
    return (0, int(text), "") if text.isdigit() else (1, 0, text)


def _infra_hierarchy(conn, net_devices: dict, store: Store):
    """Baut aus den LLDP-Nachbarschaften eine Eltern-Kind-Struktur.

    LLDP sagt nur "A und B sind verbunden", nicht wer oben steht. Als Wurzel
    waehlen wir den Switch mit den meisten gelernten MACs -- der steht dem
    Kern am naechsten, weil ueber ihn der Verkehr des ganzen dahinter
    liegenden Netzes laeuft.
    """
    resolver = _NeighborResolver(conn, net_devices, store)
    adjacency: dict[int, set[int]] = defaultdict(set)
    via: dict[tuple[int, int], str] = {}
    uplink_ports: dict[tuple[int, str], list[str]] = defaultdict(list)
    unknown: dict[int, set[tuple[str, str]]] = defaultdict(set)

    # Nur frische Nachbarschaften: veraltete Zeilen wuerden sonst eine
    # Hierarchie aufspannen, die es laengst nicht mehr gibt.
    for row in conn.execute(
        "SELECT a_device, a_port, b_name, b_mac FROM links WHERE ts >= ? ORDER BY ts DESC",
        (now() - LINK_FRESHNESS,),
    ):
        source, port, remote = row["a_device"], row["a_port"], (row["b_name"] or "").strip()
        if source not in net_devices or not (remote or row["b_mac"]):
            continue
        target = resolver.resolve(row["b_mac"], remote)
        uplink_ports[(source, port)].append(
            net_devices[target]["name"] if target else (remote or row["b_mac"])
        )
        if target is None:
            unknown[source].add((resolver.describe(row["b_mac"], remote), port))
        elif target != source:
            adjacency[source].add(target)
            adjacency[target].add(source)
            via[(source, target)] = port

    # Infrastruktur kann selbst hinter Infrastruktur haengen: OPNsense ist eine
    # VM auf einem Proxmox-Host, der wiederum an einem Switchport steckt. LLDP
    # sagt dazu nichts -- aber die eigene MAC des Geraets steht in der FDB
    # dessen, was davor haengt. Der Port mit den wenigsten MACs ist der
    # naechstgelegene, also der richtige Elternteil.
    for child, (parent, port) in _fdb_parents(conn, net_devices, store).items():
        adjacency[child].add(parent)
        adjacency[parent].add(child)
        via[(parent, child)] = port

    mac_counts = {
        r["net_device_id"]: r["n"]
        for r in conn.execute(
            "SELECT net_device_id, COUNT(DISTINCT mac) AS n FROM fdb GROUP BY net_device_id"
        )
    }

    parents: dict[int, tuple[int, str | None]] = {}
    visited: set[int] = set()
    for root in _roots_by_weight(net_devices, adjacency, mac_counts):
        if root in visited:
            continue
        visited.add(root)
        queue = [root]
        while queue:
            current = queue.pop(0)
            for neighbor in sorted(adjacency[current]):
                if neighbor in visited:
                    continue
                visited.add(neighbor)
                parents[neighbor] = (current, via.get((current, neighbor)) or via.get((neighbor, current)))
                queue.append(neighbor)

    return parents, uplink_ports, {k: sorted(v) for k, v in unknown.items()}


def _fdb_parents(conn, net_devices: dict, store: Store) -> dict[int, tuple[int, str]]:
    """Findet je Infrastrukturgeraet den Port, an dem es selbst haengt.

    Nur der *beste* Kandidat wird zurueckgegeben. Ein Geraet taucht naemlich in
    der FDB jedes Switches auf dem Weg auf; wuerde man alle Kanten aufnehmen,
    haengte eine VM genauso am Kernswitch wie an ihrem Host. Der Port mit den
    wenigsten MACs ist der naechstgelegene.
    """
    owner_of: dict[str, int] = store.identity_macs()
    if not owner_of:
        return {}

    cutoff = now() - LINK_FRESHNESS
    port_sizes: dict[tuple[int, str], int] = {
        (r["net_device_id"], r["port_key"]): r["n"]
        for r in conn.execute(
            "SELECT net_device_id, port_key, COUNT(DISTINCT mac) AS n FROM fdb "
            "WHERE last_seen >= ? GROUP BY net_device_id, port_key",
            (cutoff,),
        )
    }

    best: dict[int, tuple[int, str, int]] = {}
    for row in conn.execute(
        "SELECT DISTINCT net_device_id, port_key, mac FROM fdb WHERE last_seen >= ?", (cutoff,)
    ):
        child = owner_of.get(row["mac"])
        host = row["net_device_id"]
        if child is None or child == host or host not in net_devices:
            continue
        size = port_sizes.get((host, row["port_key"]), 1)
        if child not in best or size < best[child][2]:
            best[child] = (host, row["port_key"], size)

    return {child: (host, port) for child, (host, port, _) in best.items()}


class _NeighborResolver:
    """Ordnet einen LLDP-Nachbarn einem konfigurierten Adapter zu.

    LLDP liefert je nach Gegenstelle Unterschiedliches: mal nur eine
    Chassis-MAC, mal nur einen SysName, mal beides. Und der Nutzer benennt
    seinen Adapter selten exakt wie der SysName lautet. Deshalb mehrere
    Schluessel, vom Sichersten zum Schwaechsten:

      1. Chassis-MAC gegen die vom Adapter gemeldeten Eigenadressen
      2. Chassis-MAC -> passiv beobachtete IP -> Management-IP eines Adapters
         (traegt auch dann, wenn die API des Geraets keine NIC-MACs preisgibt --
         bei Proxmox etwa ist das nicht garantiert)
      3. SysName gegen den Adapternamen
      4. erster Teil eines FQDN gegen den Adapternamen ("pve.example" -> "pve")
    """

    def __init__(self, conn, net_devices: dict, store: Store):
        self.by_mac = store.identity_macs()
        self.names = {info["name"].lower(): net_id for net_id, info in net_devices.items()}

        # Management-Adressen der Adapter aus deren Konfiguration.
        self.mgmt_ips: dict[str, int] = {}
        for net_id, info in net_devices.items():
            for host in _management_hosts(info.get("config")):
                self.mgmt_ips.setdefault(host, net_id)

        # MAC -> beobachtete IPv4-Adressen
        self.device_ips: dict[str, list[str]] = defaultdict(list)
        for row in conn.execute(
            "SELECT d.mac, a.ip FROM devices d JOIN addresses a ON a.device_id=d.id WHERE a.family=4"
        ):
            self.device_ips[row["mac"]].append(row["ip"])

    def resolve(self, mac: str | None, name: str) -> int | None:
        if mac:
            if mac in self.by_mac:
                return self.by_mac[mac]
            for ip in self.device_ips.get(mac, []):
                if ip in self.mgmt_ips:
                    return self.mgmt_ips[ip]
        key = name.lower().strip()
        if key:
            if key in self.names:
                return self.names[key]
            short = key.split(".")[0]
            if short in self.names:
                return self.names[short]
        return None

    def describe(self, mac: str | None, name: str) -> str:
        """Beschriftung fuer einen nicht zuordenbaren Nachbarn.

        Mit IP und MAC, damit erkennbar ist, welches Geraet man als Adapter
        nachtragen muesste -- ein blosser SysName hilft dabei nicht weiter.
        """
        parts = [name] if name else []
        ips = self.device_ips.get(mac or "", [])
        if ips:
            parts.append(ips[0])
        if mac:
            parts.append(mac)
        return " · ".join(parts) or "unbekannter Nachbar"


def _management_hosts(config_json: str | None) -> list[str]:
    """Zieht die Management-Adresse aus einer Adapterkonfiguration."""
    try:
        config = json.loads(config_json or "{}")
    except (json.JSONDecodeError, TypeError):
        return []
    hosts = []
    if config.get("host"):
        hosts.append(str(config["host"]).split(":")[0])
    if config.get("base_url"):
        hosts.append(str(config["base_url"]).split("//")[-1].split("/")[0].split(":")[0])
    return [h for h in hosts if h]


def _roots_by_weight(net_devices, adjacency, mac_counts) -> list[int]:
    return sorted(net_devices, key=lambda i: (-mac_counts.get(i, 0), net_devices[i]["name"].lower()))


def _roots(net_devices: dict, parents: dict) -> list[int]:
    return [net_id for net_id in net_devices if net_id not in parents]
