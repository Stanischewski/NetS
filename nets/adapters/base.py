"""Adapter-Basis: der Vertrag zwischen Kern und Netzwerk-Hardware.

Der Kern kennt *keinen* Hersteller. Er kennt nur diese Schnittstelle. Ein
Adapter beschreibt sich selbst ueber `config_fields` und `capabilities`; die
WebUI rendert daraus generisch ein Formular und blendet Funktionen aus, die
das Geraet nicht kann. Neuer Hersteller = neue Datei in diesem Ordner, kein
Eingriff in Kern oder UI.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, ClassVar, Iterable


class Capability:
    FDB = "fdb"                    # MAC-Adresstabelle -> Port  (Topologie)
    LLDP = "lldp"                  # Nachbarschaft Switch<->Switch
    WIRELESS = "wireless"          # assoziierte WLAN-Clients
    DHCP_LEASES = "dhcp_leases"    # Leases vom DHCP-Server
    ARP_TABLE = "arp_table"        # ARP-/Neighbor-Cache des Routers
    PORT_STATUS = "port_status"    # Link-Status, Portnamen
    IDENTITY = "identity"          # eigene MACs/IPs des Geraets
    INVENTORY = "inventory"        # benannte Hosts (VMs, Container) hinter dem Geraet

    ALL = (FDB, LLDP, WIRELESS, DHCP_LEASES, ARP_TABLE, PORT_STATUS, IDENTITY, INVENTORY)


@dataclass
class ConfigField:
    """Selbstbeschreibung eines Konfigurationsfelds fuer die WebUI."""

    key: str
    label: str
    type: str = "text"  # text | password | int | bool | select
    default: Any = None
    required: bool = False
    help: str = ""
    choices: list[str] | None = None
    depends_on: dict[str, Any] | None = None  # nur zeigen, wenn z.B. {"version": "3"}

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class FdbEntry:
    mac: str
    port_key: str
    vlan: int | None = None


@dataclass
class Neighbor:
    local_port: str
    remote_name: str | None
    remote_port: str | None
    #: Chassis-MAC des Nachbarn. Zuverlaessiger als der SysName, weil sie sich
    #: gegen die bekannten Eigenadressen (net_identities) matchen laesst --
    #: der Nutzer muss den Adapter dann nicht exakt wie den SysName benennen.
    remote_mac: str | None = None


@dataclass
class HostInfo:
    """Ein benannter Host hinter einem Infrastrukturgeraet.

    Gedacht fuer Virtualisierer: Proxmox kennt Name, MAC, Bridge und VLAN
    jeder VM -- damit werden aus anonymen MACs hinter einem Uplink-Port
    benannte Maschinen.
    """

    mac: str
    name: str | None = None
    ip: str | None = None
    kind: str | None = None      # vm | container | host
    note: str | None = None      # z.B. "VM 101 auf pve1"


@dataclass
class Port:
    port_key: str
    name: str | None = None
    kind: str | None = None  # access | uplink | wireless | unknown


@dataclass
class WirelessClient:
    mac: str
    ap_name: str | None = None
    ssid: str | None = None
    signal: int | None = None
    band: str | None = None


@dataclass
class Identity:
    """Die eigenen Adressen eines Infrastrukturgeraets.

    Damit laesst sich das abgefragte net_device mit dem Endgeraet-Eintrag
    zusammenfuehren, den die passiven Collector fuer dieselbe Hardware
    angelegt haben -- sonst steht der Switch zweimal im Inventar.
    """

    macs: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    name: str | None = None
    description: str | None = None


@dataclass
class Lease:
    mac: str
    ip: str | None = None
    hostname: str | None = None
    static: bool = False  # feste Reservierung im DHCP-Server


class Adapter:
    """Basisklasse. Nicht implementierte Faehigkeiten einfach weglassen --
    `capabilities` sagt dem Kern, was er aufrufen darf."""

    type_id: ClassVar[str] = ""
    display_name: ClassVar[str] = ""
    description: ClassVar[str] = ""
    capabilities: ClassVar[tuple[str, ...]] = ()
    config_fields: ClassVar[tuple[ConfigField, ...]] = ()

    #: Registry aller bekannten Adaptertypen, befuellt via __init_subclass__.
    registry: ClassVar[dict[str, type["Adapter"]]] = {}

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if cls.type_id:
            Adapter.registry[cls.type_id] = cls

    def __init__(self, config: dict):
        self.config = self._with_defaults(config)

    @classmethod
    def _with_defaults(cls, config: dict) -> dict:
        merged = {f.key: f.default for f in cls.config_fields if f.default is not None}
        merged.update({k: v for k, v in config.items() if v is not None and v != ""})
        return merged

    @classmethod
    def validate(cls, config: dict) -> list[str]:
        """Gibt eine Liste von Fehlermeldungen zurueck (leer = ok)."""
        errors = []
        merged = cls._with_defaults(config)
        for f in cls.config_fields:
            if f.required and not merged.get(f.key):
                errors.append(f"Feld '{f.label}' ist erforderlich")
            if f.type == "int" and merged.get(f.key) not in (None, ""):
                try:
                    int(merged[f.key])
                except (TypeError, ValueError):
                    errors.append(f"Feld '{f.label}' muss eine Zahl sein")
            if f.choices and merged.get(f.key) and merged[f.key] not in f.choices:
                errors.append(f"Feld '{f.label}': '{merged[f.key]}' ist keine gueltige Auswahl")
        return errors

    @classmethod
    def describe(cls) -> dict:
        """Was die WebUI braucht, um ein Formular zu bauen."""
        return {
            "type_id": cls.type_id,
            "display_name": cls.display_name,
            "description": cls.description,
            "capabilities": list(cls.capabilities),
            "config_fields": [f.to_dict() for f in cls.config_fields],
        }

    def has(self, capability: str) -> bool:
        return capability in self.capabilities

    # ----------------------------------------------------------- Schnittstelle
    # Alle Methoden sind optional; der Kern ruft nur auf, was capabilities sagt.

    async def test(self) -> tuple[bool, str]:
        """Verbindungstest fuer den 'Testen'-Knopf in der UI."""
        raise NotImplementedError

    async def identity(self) -> Identity:
        """Eigene MACs/IPs des Geraets."""
        return Identity()

    async def ports(self) -> Iterable[Port]:
        return []

    async def fdb(self) -> Iterable[FdbEntry]:
        return []

    async def lldp(self) -> Iterable[Neighbor]:
        return []

    async def wireless_clients(self) -> Iterable[WirelessClient]:
        return []

    async def dhcp_leases(self) -> Iterable[Lease]:
        return []

    async def hosts(self) -> Iterable[HostInfo]:
        """Benannte Hosts hinter diesem Geraet (VMs, Container)."""
        return []

    async def arp_table(self) -> Iterable[tuple[str, str]]:
        """(mac, ip)-Paare."""
        return []

    async def close(self) -> None:
        pass


def build(type_id: str, config: dict) -> Adapter:
    cls = Adapter.registry.get(type_id)
    if cls is None:
        raise KeyError(f"Unbekannter Adaptertyp: {type_id}")
    return cls(config)


def all_types() -> list[dict]:
    return [cls.describe() for cls in sorted(Adapter.registry.values(), key=lambda c: c.display_name)]
