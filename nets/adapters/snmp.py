"""Generischer SNMP-Adapter -- funktioniert mit jedem managed Switch.

Nutzt ausschliesslich Standard-MIBs (BRIDGE, Q-BRIDGE, IF, LLDP, IP). Damit
laeuft er ohne Anpassung auf Cisco, HPE/Aruba, Zyxel, TP-Link, Netgear,
D-Link, Ubiquiti, MikroTik, Extreme und praktisch allem anderen, das SNMP
spricht. Herstellerspezifische MIBs bleiben bewusst draussen -- wer die
braucht, schreibt einen eigenen Adapter daneben.

Implementiert ueber die net-snmp-CLI (`snmpbulkwalk`) statt einer Python-
Bibliothek: eine Systemabhaengigkeit weniger im Python-Stack, SNMPv3 out of
the box, und das Tool ist seit Jahrzehnten stabil.
"""

from __future__ import annotations

import asyncio
import logging
import re
import shutil

from .base import Adapter, Capability, ConfigField, FdbEntry, Identity, Neighbor, Port

log = logging.getLogger("nets.adapters.snmp")

OID = {
    "sysName": "1.3.6.1.2.1.1.5",
    "sysDescr": "1.3.6.1.2.1.1.1",
    "ifDescr": "1.3.6.1.2.1.2.2.1.2",
    "ifName": "1.3.6.1.2.1.31.1.1.1.1",
    "ifAlias": "1.3.6.1.2.1.31.1.1.1.18",
    "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
    # Bridge-Port -> ifIndex (die FDB indiziert Bridge-Ports, nicht ifIndex!)
    "dot1dBasePortIfIndex": "1.3.6.1.2.1.17.1.4.1.2",
    # klassische FDB: Index = MAC als 6 Dezimalstellen
    "dot1dTpFdbPort": "1.3.6.1.2.1.17.4.3.1.2",
    # VLAN-bewusste FDB: Index = vlan . MAC
    "dot1qTpFdbPort": "1.3.6.1.2.1.17.7.1.2.2.1.2",
    # Eigene Identitaet des Geraets
    "dot1dBaseBridgeAddress": "1.3.6.1.2.1.17.1.1",
    "ifPhysAddress": "1.3.6.1.2.1.2.2.1.6",
    "lldpLocChassisId": "1.0.8802.1.1.2.1.3.2",
    "ipAdEntAddr": "1.3.6.1.2.1.4.20.1.1",
    "lldpRemChassisId": "1.0.8802.1.1.2.1.4.1.1.5",
    "lldpRemSysName": "1.0.8802.1.1.2.1.4.1.1.9",
    "lldpRemPortId": "1.0.8802.1.1.2.1.4.1.1.7",
    "lldpLocPortId": "1.0.8802.1.1.2.1.3.7.1.3",
    "ipNetToMediaPhysAddress": "1.3.6.1.2.1.4.22.1.2",
}

_LINE = re.compile(r"^(?P<oid>\.[0-9.]+)\s*=\s*(?:(?P<type>[A-Za-z0-9-]+):\s*)?(?P<value>.*)$")


class SnmpError(RuntimeError):
    pass


class SnmpAdapter(Adapter):
    type_id = "snmp"
    display_name = "SNMP (generisch)"
    description = (
        "Standard-MIBs (BRIDGE/Q-BRIDGE/IF/LLDP). Funktioniert mit nahezu jedem "
        "managed Switch, unabhaengig vom Hersteller."
    )
    capabilities = (
        Capability.FDB,
        Capability.LLDP,
        Capability.PORT_STATUS,
        Capability.ARP_TABLE,
        Capability.IDENTITY,
    )
    config_fields = (
        ConfigField("host", "Hostname / IP", required=True, help="Management-Adresse des Switches"),
        ConfigField("version", "SNMP-Version", type="select", choices=["1", "2c", "3"], default="2c"),
        ConfigField(
            "community", "Community", type="password", default="public",
            help="Nur bei v1/v2c. Read-only genuegt.", depends_on={"version": "2c"},
        ),
        ConfigField("v3_user", "v3 Benutzer", depends_on={"version": "3"}),
        ConfigField(
            "v3_level", "v3 Security-Level", type="select",
            choices=["noAuthNoPriv", "authNoPriv", "authPriv"], default="authPriv",
            depends_on={"version": "3"},
        ),
        ConfigField("v3_auth_proto", "v3 Auth-Verfahren", type="select",
                    choices=["MD5", "SHA", "SHA-256", "SHA-512"], default="SHA",
                    depends_on={"version": "3"}),
        ConfigField("v3_auth_pass", "v3 Auth-Passwort", type="password", depends_on={"version": "3"}),
        ConfigField("v3_priv_proto", "v3 Verschluesselung", type="select",
                    choices=["DES", "AES", "AES-192", "AES-256"], default="AES",
                    depends_on={"version": "3"}),
        ConfigField("v3_priv_pass", "v3 Priv-Passwort", type="password", depends_on={"version": "3"}),
        ConfigField("port", "SNMP-Port", type="int", default=161),
        ConfigField("timeout", "Timeout (s)", type="int", default=5),
        ConfigField(
            "vlan_community_probe", "Cisco VLAN-Indexing", type="bool", default=False,
            help="Bei aelteren Cisco-Switches je VLAN mit 'community@vlan' abfragen. "
                 "Sonst aus lassen.",
        ),
    )

    # ------------------------------------------------------------- SNMP-Aufruf

    def _base_args(self) -> list[str]:
        cfg = self.config
        version = str(cfg.get("version", "2c"))
        args = ["-On", "-Oe", "-t", str(cfg.get("timeout", 5)), "-r", "1"]
        if version in ("1", "2c"):
            args += ["-v", version, "-c", str(cfg.get("community", "public"))]
        else:
            level = cfg.get("v3_level", "authPriv")
            args += ["-v", "3", "-u", str(cfg.get("v3_user", "")), "-l", level]
            if level in ("authNoPriv", "authPriv"):
                args += ["-a", str(cfg.get("v3_auth_proto", "SHA")), "-A", str(cfg.get("v3_auth_pass", ""))]
            if level == "authPriv":
                args += ["-x", str(cfg.get("v3_priv_proto", "AES")), "-X", str(cfg.get("v3_priv_pass", ""))]
        return args

    @property
    def _target(self) -> str:
        return f"{self.config['host']}:{self.config.get('port', 161)}"

    async def _walk(self, oid: str, community_suffix: str = "") -> dict[str, str]:
        """Gibt {oid_rest_nach_base: wert} zurueck."""
        binary = "snmpbulkwalk" if str(self.config.get("version", "2c")) != "1" else "snmpwalk"
        if not shutil.which(binary):
            raise SnmpError(f"{binary} nicht gefunden -- Paket 'snmp' (net-snmp) installieren")

        args = self._base_args()
        if community_suffix:  # Cisco community@vlan
            for i, a in enumerate(args):
                if a == "-c":
                    args[i + 1] = f"{args[i + 1]}@{community_suffix}"
                    break

        proc = await asyncio.create_subprocess_exec(
            binary, *args, self._target, f".{oid}",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=int(self.config.get("timeout", 5)) * 12
            )
        except asyncio.TimeoutError:
            proc.kill()
            raise SnmpError(f"Timeout bei {self.config['host']}")

        text = stdout.decode(errors="replace")
        if proc.returncode != 0 and not text.strip():
            raise SnmpError(stderr.decode(errors="replace").strip()[:200] or "SNMP-Fehler")

        result: dict[str, str] = {}
        prefix = f".{oid}."
        for line in text.splitlines():
            match = _LINE.match(line.strip())
            if not match:
                continue
            full_oid = match.group("oid")
            if not full_oid.startswith(prefix):
                continue
            value = match.group("value").strip().strip('"')
            if value in ("No Such Object available on this agent at this OID", "No Such Instance currently exists at this OID"):
                continue
            result[full_oid[len(prefix):]] = value
        return result

    # ------------------------------------------------------------- Operationen

    async def test(self) -> tuple[bool, str]:
        try:
            name = await self._walk(OID["sysName"])
            descr = await self._walk(OID["sysDescr"])
            label = next(iter(name.values()), "?")
            model = next(iter(descr.values()), "")[:80]
            return True, f"Verbunden: {label} -- {model}"
        except Exception as exc:
            return False, str(exc)

    async def identity(self) -> Identity:
        """Die eigenen Adressen des Switches.

        Ohne das steht der Switch zweimal im Inventar: einmal als abgefragtes
        Geraet und einmal als herrenloses Endgeraet, weil die passiven
        Collector seine Management-MAC im Netz gesehen haben.
        """
        macs: list[str] = []
        for key in ("dot1dBaseBridgeAddress", "lldpLocChassisId", "ifPhysAddress"):
            try:
                for value in (await self._walk(OID[key])).values():
                    mac = _mac_from_snmp(value)
                    # Interfaces ohne eigene MAC melden 00:00:00:00:00:00.
                    if mac and mac != "00:00:00:00:00:00" and mac not in macs:
                        macs.append(mac)
            except SnmpError:
                continue

        ips: list[str] = []
        try:
            for value in (await self._walk(OID["ipAdEntAddr"])).values():
                if value and value not in ips and not value.startswith("127."):
                    ips.append(value)
        except SnmpError:
            pass
        if not ips:
            ips.append(str(self.config["host"]))

        name = next(iter((await self._walk(OID["sysName"])).values()), None)
        descr = next(iter((await self._walk(OID["sysDescr"])).values()), None)
        return Identity(macs=macs, ips=ips, name=name, description=descr)

    async def ports(self) -> list[Port]:
        names = await self._walk(OID["ifName"]) or await self._walk(OID["ifDescr"])
        aliases = await self._walk(OID["ifAlias"])
        return [
            Port(port_key=idx, name=(f"{name} ({aliases[idx]})" if aliases.get(idx) else name))
            for idx, name in names.items()
        ]

    async def _bridge_port_map(self) -> dict[str, str]:
        """Bridge-Port -> ifIndex. Ohne diese Uebersetzung zeigt die FDB auf
        Portnummern, die nichts mit ifIndex/Portnamen zu tun haben."""
        try:
            return await self._walk(OID["dot1dBasePortIfIndex"])
        except SnmpError:
            return {}

    async def fdb(self) -> list[FdbEntry]:
        """Die MAC-Adresstabelle -- das Fundament der Topologie."""
        bridge_map = await self._bridge_port_map()
        entries: list[FdbEntry] = []

        # Bevorzugt Q-BRIDGE (VLAN-bewusst), Index = vlan.m1.m2...m6
        try:
            qfdb = await self._walk(OID["dot1qTpFdbPort"])
        except SnmpError:
            qfdb = {}
        for index, bridge_port in qfdb.items():
            parts = index.split(".")
            if len(parts) != 7:
                continue
            vlan = int(parts[0])
            mac = _mac_from_oid(parts[1:])
            if mac and bridge_port != "0":
                entries.append(FdbEntry(mac, bridge_map.get(bridge_port, bridge_port), vlan))

        if entries:
            return entries

        # Fallback: klassische BRIDGE-MIB, Index = m1.m2...m6
        for index, bridge_port in (await self._walk(OID["dot1dTpFdbPort"])).items():
            parts = index.split(".")
            if len(parts) != 6:
                continue
            mac = _mac_from_oid(parts)
            if mac and bridge_port != "0":
                entries.append(FdbEntry(mac, bridge_map.get(bridge_port, bridge_port), None))
        return entries

    async def lldp(self) -> list[Neighbor]:
        try:
            names = await self._walk(OID["lldpRemSysName"])
            ports = await self._walk(OID["lldpRemPortId"])
            chassis = await self._walk(OID["lldpRemChassisId"])
        except SnmpError:
            return []

        out = []
        # Ueber die Vereinigung aller Indizes laufen, nicht nur ueber die
        # Namen: Geraete duerfen das SysName-TLV weglassen, und dann waere der
        # Nachbar sonst komplett verschwunden -- obwohl seine Chassis-MAC da
        # ist und sich zuordnen liesse.
        for index in sorted(set(names) | set(ports) | set(chassis)):
            # Index ist timeMark.lldpRemLocalPortNum.lldpRemIndex
            parts = index.split(".")
            local_port = parts[1] if len(parts) >= 2 else index
            out.append(Neighbor(
                local_port,
                (names.get(index) or "").strip() or None,
                _format_id(ports.get(index)),
                remote_mac=_mac_from_snmp(chassis.get(index, "")),
            ))
        return out

    async def arp_table(self) -> list[tuple[str, str]]:
        """Der ARP-Cache des Routers -- oft die vollstaendigste IP/MAC-Liste
        im ganzen Netz, inklusive VLANs, in denen wir gar nicht stehen."""
        try:
            raw = await self._walk(OID["ipNetToMediaPhysAddress"])
        except SnmpError:
            return []
        out = []
        for index, value in raw.items():
            parts = index.split(".")
            if len(parts) < 5:
                continue
            ip = ".".join(parts[-4:])
            mac = value.replace(" ", ":").strip().lower()
            if mac.count(":") == 5:
                out.append((mac, ip))
        return out


def _mac_from_oid(octets: list[str]) -> str | None:
    try:
        return ":".join(f"{int(o):02x}" for o in octets)
    except ValueError:
        return None


def _format_id(value: str | None) -> str | None:
    """Port-ID lesbar machen.

    lldpRemPortId ist je nach Subtyp ein Interfacename ("Gi0/3") oder eine
    MAC. net-snmp liefert letztere als rohes '00 D8 61 4E E8 81' -- das gehoert
    als MAC formatiert, sonst steht im Baum eine Hexwurst.
    """
    if not value:
        return None
    return _mac_from_snmp(value) or value.strip()


def _mac_from_snmp(value: str) -> str | None:
    """MAC aus einem SNMP-Wert lesen.

    net-snmp liefert je nach Typ '00 1B A9 44 55 66' (Hex-STRING),
    '0:1b:a9:44:55:66' (STRING) oder bei LLDP eine Chassis-ID mit
    vorangestelltem Subtyp-Byte.
    """
    if not value:
        return None
    parts = value.replace(":", " ").replace("-", " ").split()
    if len(parts) == 7:
        parts = parts[1:]  # LLDP-Chassis-ID: erstes Byte ist der Subtyp
    if len(parts) != 6:
        return None
    try:
        return ":".join(f"{int(p, 16):02x}" for p in parts)
    except ValueError:
        return None
