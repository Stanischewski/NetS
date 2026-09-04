"""SQLite-Schema und Verbindung.

Datenmodell-Prinzip: append-only. Wir loeschen nie eine Beobachtung, sondern
leiten den aktuellen Zustand aus der Historie ab. Nur so findet man Geraete,
die selten online sind -- man muss nicht zum richtigen Zeitpunkt scannen,
sondern hat durchgehend zugehoert.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA_VERSION = 7

SCHEMA = """
-- Ein Geraet, identifiziert ueber die MAC. Bei randomisierten MACs entsteht
-- pro Zufalls-MAC erst mal ein eigener Eintrag; identity.py fasst sie spaeter
-- ueber identity_group zusammen.
CREATE TABLE IF NOT EXISTS devices (
    id              INTEGER PRIMARY KEY,
    mac             TEXT NOT NULL UNIQUE,
    mac_random      INTEGER NOT NULL DEFAULT 0,
    vendor          TEXT,
    hostname        TEXT,
    device_type     TEXT,
    os_guess        TEXT,
    addr_mode       TEXT NOT NULL DEFAULT 'unknown',  -- dhcp | static | unknown
    addr_mode_since INTEGER,
    identity_group  INTEGER,          -- FK auf devices.id (Cluster-Anker)
    label           TEXT,             -- vom Nutzer vergeben, hat Vorrang
    notes           TEXT,
    ignored         INTEGER NOT NULL DEFAULT 0,
    first_seen      INTEGER NOT NULL,
    last_seen       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);
CREATE INDEX IF NOT EXISTS idx_devices_group ON devices(identity_group);

-- IP-Historie. Ein Geraet kann mehrere IPs (v4/v6) gleichzeitig haben.
CREATE TABLE IF NOT EXISTS addresses (
    id          INTEGER PRIMARY KEY,
    device_id   INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ip          TEXT NOT NULL,
    family      INTEGER NOT NULL,     -- 4 | 6
    source      TEXT NOT NULL,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    UNIQUE(device_id, ip)
);
CREATE INDEX IF NOT EXISTS idx_addresses_ip ON addresses(ip);

-- Einzelne harte Fakten mit Quellenangabe. Bewusst schmal gehalten:
-- Anwesenheit landet in presence, nicht hier.
CREATE TABLE IF NOT EXISTS facts (
    id          INTEGER PRIMARY KEY,
    device_id   INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ts          INTEGER NOT NULL,
    source      TEXT NOT NULL,        -- arp | dhcp | mdns | ssdp | snmp:<id> | nmap ...
    key         TEXT NOT NULL,        -- hostname | dhcp_fingerprint | vendor_class | model ...
    value       TEXT NOT NULL,
    UNIQUE(device_id, source, key, value)
);
CREATE INDEX IF NOT EXISTS idx_facts_device ON facts(device_id, key);

-- Anwesenheit in Zeit-Buckets (Default 300s). Aggregiert, damit die DB bei
-- Dauerbetrieb nicht explodiert -- 1 Zeile je Geraet und Bucket.
CREATE TABLE IF NOT EXISTS presence (
    device_id   INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    bucket      INTEGER NOT NULL,
    hits        INTEGER NOT NULL DEFAULT 1,
    sources     TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (device_id, bucket)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_presence_bucket ON presence(bucket);

-- Netzwerk-Infrastruktur (Switches, APs, Router), die per Adapter abgefragt
-- wird. config ist JSON und folgt dem config_fields-Schema des Adaptertyps.
CREATE TABLE IF NOT EXISTS net_devices (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL,
    adapter_type TEXT NOT NULL,
    config       TEXT NOT NULL DEFAULT '{}',
    enabled      INTEGER NOT NULL DEFAULT 1,
    poll_seconds INTEGER NOT NULL DEFAULT 300,
    last_ok      INTEGER,
    last_error   TEXT,
    UNIQUE(name)
);

CREATE TABLE IF NOT EXISTS net_ports (
    id            INTEGER PRIMARY KEY,
    net_device_id INTEGER NOT NULL REFERENCES net_devices(id) ON DELETE CASCADE,
    port_key      TEXT NOT NULL,      -- ifIndex / Portname, adapterspezifisch
    name          TEXT,
    kind          TEXT,               -- access | uplink | wireless | unknown
    last_seen     INTEGER NOT NULL,
    UNIQUE(net_device_id, port_key)
);

-- Eigene Adressen der Infrastruktur (Bridge-MAC, Interface-MACs, Management-
-- IPs). Ohne das taucht ein Switch doppelt auf: einmal als abgefragtes
-- net_device und einmal als herrenloses Endgeraet mit eigener MAC.
CREATE TABLE IF NOT EXISTS net_identities (
    net_device_id INTEGER NOT NULL REFERENCES net_devices(id) ON DELETE CASCADE,
    mac           TEXT NOT NULL,
    source        TEXT NOT NULL DEFAULT 'adapter',
    ts            INTEGER NOT NULL,
    PRIMARY KEY (net_device_id, mac)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_net_identities_mac ON net_identities(mac);

-- Aus 802.11-Frames gelesene Assoziationen: welche Station funkt mit welchem
-- Funkmodul. Die einzige Quelle, die ohne Mitwirkung des APs auskommt.
CREATE TABLE IF NOT EXISTS wifi_links (
    station    TEXT NOT NULL,
    bssid      TEXT NOT NULL,
    ssid       TEXT,
    channel    INTEGER,
    signal     INTEGER,
    frames     INTEGER NOT NULL DEFAULT 0,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    PRIMARY KEY (station, bssid)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_wifi_links_bssid ON wifi_links(bssid);
CREATE INDEX IF NOT EXISTS idx_wifi_links_seen ON wifi_links(last_seen);

-- FDB-Eintraege: welche MAC an welchem Port. Eine Zeile je *Zuordnung*, nicht
-- je Abfrage -- der Switch meldet bei jedem Poll dieselbe Tabelle, und die
-- unveraendert wegzuschreiben ergaebe bei 5-Minuten-Takt sechsstellige
-- Zeilenzahlen fuer ein paar Dutzend Fakten. Die Historie steckt stattdessen
-- in first_seen/last_seen: daraus laesst sich ablesen, wann ein Geraet an
-- einen Port kam und wann es dort zuletzt gesehen wurde.
--
-- vlan wird als -1 statt NULL gefuehrt, weil NULL in SQLite nie gleich NULL
-- ist und ein UNIQUE-Index darueber nicht greifen wuerde.
CREATE TABLE IF NOT EXISTS fdb (
    id            INTEGER PRIMARY KEY,
    net_device_id INTEGER NOT NULL REFERENCES net_devices(id) ON DELETE CASCADE,
    port_key      TEXT NOT NULL,
    mac           TEXT NOT NULL,
    vlan          INTEGER NOT NULL DEFAULT -1,
    first_seen    INTEGER NOT NULL,
    last_seen     INTEGER NOT NULL,
    UNIQUE(net_device_id, port_key, mac, vlan)
);
CREATE INDEX IF NOT EXISTS idx_fdb_mac ON fdb(mac, last_seen);
CREATE INDEX IF NOT EXISTS idx_fdb_last_seen ON fdb(last_seen);

-- Gefundene Weboberflaechen. Anders als der Rest des Inventars entsteht das
-- durch *aktives* Anklopfen und ist deshalb standardmaessig abgeschaltet.
-- Schluessel ist (ip, port): ein Geraet kann mehrere Oberflaechen haben, und
-- die IP ist das, was man am Ende in die Adresszeile tippt.
CREATE TABLE IF NOT EXISTS web_services (
    id         INTEGER PRIMARY KEY,
    device_id  INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    ip         TEXT NOT NULL,
    port       INTEGER NOT NULL,
    scheme     TEXT NOT NULL,
    title      TEXT,
    server     TEXT,
    status     INTEGER,
    redirect   TEXT,
    source     TEXT NOT NULL DEFAULT 'scan',   -- scan | ssdp | mdns
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    UNIQUE(ip, port)
);
CREATE INDEX IF NOT EXISTS idx_web_services_device ON web_services(device_id);

-- Antwortende IP-Adressen aus gerouteten Netzen.
--
-- Jenseits des eigenen Segments gibt es keine MAC: ARP ueberquert keinen
-- Router, und der Absender im Antwortpaket traegt die MAC des naechsten Hops.
-- Solche Funde koennen deshalb nicht in `devices` -- dort ist die MAC der
-- Schluessel. Sie hier zu fuehren ist ehrlicher als eine erfundene MAC: wir
-- wissen, *dass* dort etwas antwortet, nicht *was*.
CREATE TABLE IF NOT EXISTS subnet_hosts (
    ip         TEXT PRIMARY KEY,
    subnet     TEXT NOT NULL,
    method     TEXT NOT NULL,      -- icmp | tcp
    detail     TEXT,               -- z.B. offener Port
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_subnet_hosts_subnet ON subnet_hosts(subnet);

-- Infrastruktur-Nachbarschaft aus LLDP/CDP.
CREATE TABLE IF NOT EXISTS links (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    a_device    INTEGER NOT NULL REFERENCES net_devices(id) ON DELETE CASCADE,
    a_port      TEXT NOT NULL,
    b_name      TEXT,               -- Remote-SysName aus LLDP
    b_port      TEXT,
    b_device    INTEGER REFERENCES net_devices(id) ON DELETE SET NULL,
    source      TEXT NOT NULL,
    UNIQUE(a_device, a_port, b_name, b_port)
);

-- Aufgeloeste Kante Geraet -> Infrastruktur-Port (Ergebnis von topology.py).
CREATE TABLE IF NOT EXISTS attachments (
    device_id     INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    net_device_id INTEGER NOT NULL REFERENCES net_devices(id) ON DELETE CASCADE,
    port_key      TEXT NOT NULL,
    medium        TEXT,             -- wired | wireless
    ssid          TEXT,
    confidence    REAL NOT NULL DEFAULT 0,
    ts            INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def connect(path: str | Path) -> sqlite3.Connection:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


#: Nachtraegliche Spalten. CREATE TABLE IF NOT EXISTS aendert bestehende
#: Tabellen nicht, deshalb muessen neue Spalten hier eingetragen werden.
_ADDED_COLUMNS = [
    # Chassis-MAC des LLDP-Nachbarn -- damit laesst sich ein Nachbar auch dann
    # zuordnen, wenn der Adapter anders benannt ist als sein SysName.
    ("links", "b_mac", "b_mac TEXT"),
]


def _migrate_fdb_to_unique(conn: sqlite3.Connection) -> int:
    """Alte fdb-Tabelle (eine Zeile je Abfrage) auf eine Zeile je Zuordnung
    verdichten. Die echte Historie bleibt als first_seen/last_seen erhalten."""
    columns = {r["name"] for r in conn.execute("PRAGMA table_info(fdb)")}
    if "ts" not in columns:
        return 0  # frische Datenbank oder bereits im neuen Format

    # Beim Umbenennen und Verwerfen von Tabellen sollen keine
    # Fremdschluesselpruefungen dazwischenfunken.
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.executescript(
        """
        ALTER TABLE fdb RENAME TO fdb_old;
        CREATE TABLE fdb (
            id            INTEGER PRIMARY KEY,
            net_device_id INTEGER NOT NULL REFERENCES net_devices(id) ON DELETE CASCADE,
            port_key      TEXT NOT NULL,
            mac           TEXT NOT NULL,
            vlan          INTEGER NOT NULL DEFAULT -1,
            first_seen    INTEGER NOT NULL,
            last_seen     INTEGER NOT NULL,
            UNIQUE(net_device_id, port_key, mac, vlan)
        );
        INSERT INTO fdb(net_device_id, port_key, mac, vlan, first_seen, last_seen)
            SELECT net_device_id, port_key, mac, COALESCE(vlan, -1), MIN(ts), MAX(ts)
            FROM fdb_old
            GROUP BY net_device_id, port_key, mac, COALESCE(vlan, -1);
        DROP TABLE fdb_old;
        CREATE INDEX IF NOT EXISTS idx_fdb_mac ON fdb(mac, last_seen);
        CREATE INDEX IF NOT EXISTS idx_fdb_last_seen ON fdb(last_seen);
        """
    )
    conn.execute("PRAGMA foreign_keys=ON")
    return conn.execute("SELECT COUNT(*) AS n FROM fdb").fetchone()["n"]


def init(conn: sqlite3.Connection) -> None:
    # Reihenfolge ist wesentlich: SCHEMA legt Indizes auf fdb(last_seen) an,
    # die es im alten Format noch nicht gibt. Erst umbauen, dann anlegen.
    # Auf einer frischen Datenbank ist die Migration wirkungslos.
    _migrate_fdb_to_unique(conn)
    conn.executescript(SCHEMA)
    for table, column, ddl in _ADDED_COLUMNS:
        existing = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")
    conn.execute(
        "INSERT INTO meta(key, value) VALUES('schema_version', ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(SCHEMA_VERSION),),
    )
