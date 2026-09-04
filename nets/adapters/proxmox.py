"""Proxmox VE ueber die REST-API (/api2/json).

Der Sonderfall, den kein Switch aufloesen kann: Hinter einem einzigen
Switchport haengt ein Virtualisierungs-Host mit einer Linux-Bridge, an der ein
Dutzend VMs sitzen. Der Switch sieht dort nur einen Haufen MACs und meldet sie
alle am Uplink-Port.

Proxmox dagegen weiss es genau -- die VM-Konfiguration enthaelt MAC, Bridge und
VLAN-Tag jeder Schnittstelle. Damit wird aus "23 unbekannte MACs an Port 24"
eine benannte Liste von Maschinen.

Zugang einrichten (read-only genuegt):
    pveum role add NetSAudit -privs "VM.Audit,Sys.Audit,Datastore.Audit"
    pveum user add nets@pve
    pveum acl modify / -user nets@pve -role NetSAudit
    pveum user token add nets@pve inventory --privsep 0
"""

from __future__ import annotations

import asyncio
import re

import httpx

from .base import Adapter, Capability, ConfigField, FdbEntry, HostInfo, Identity, Port

_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")


class ProxmoxAdapter(Adapter):
    type_id = "proxmox"
    display_name = "Proxmox VE"
    description = (
        "Loest VMs und Container hinter einem Virtualisierungs-Host auf: Name, MAC, "
        "Bridge und VLAN je Maschine. Damit werden anonyme MACs an einem Uplink-Port "
        "zu benannten Systemen."
    )
    capabilities = (
        Capability.FDB,
        Capability.INVENTORY,
        Capability.IDENTITY,
        Capability.PORT_STATUS,
    )
    config_fields = (
        ConfigField("base_url", "Proxmox-URL", required=True, default="https://192.168.1.10:8006"),
        ConfigField(
            "auth_method", "Anmeldung", type="select", choices=["token", "password"],
            default="token", help="API-Token ist sicherer und laeuft nicht ab.",
        ),
        ConfigField(
            "token_id", "Token-ID", depends_on={"auth_method": "token"},
            help="Vollstaendig, z.B. nets@pve!inventory",
        ),
        ConfigField("token_secret", "Token-Secret", type="password", depends_on={"auth_method": "token"}),
        ConfigField(
            "username", "Benutzer", depends_on={"auth_method": "password"},
            help="Mit Realm, z.B. root@pam",
        ),
        ConfigField("password", "Passwort", type="password", depends_on={"auth_method": "password"}),
        ConfigField("verify_tls", "TLS pruefen", type="bool", default=False,
                    help="Proxmox nutzt ab Werk ein selbstsigniertes Zertifikat."),
    )

    def __init__(self, config: dict):
        super().__init__(config)
        self._client: httpx.AsyncClient | None = None
        self._cache: list[dict] | None = None

    # ---------------------------------------------------------------- Transport

    async def _http(self) -> httpx.AsyncClient:
        if self._client is not None:
            return self._client
        client = httpx.AsyncClient(
            base_url=str(self.config["base_url"]).rstrip("/") + "/api2/json",
            verify=bool(self.config.get("verify_tls", False)),
            timeout=20.0,
        )
        if self.config.get("auth_method", "token") == "token":
            token_id = str(self.config.get("token_id", "")).strip()
            secret = str(self.config.get("token_secret", "")).strip()
            client.headers["Authorization"] = f"PVEAPIToken={token_id}={secret}"
        else:
            resp = await client.post(
                "/access/ticket",
                data={"username": self.config.get("username", ""),
                      "password": self.config.get("password", "")},
            )
            if resp.status_code >= 400:
                await client.aclose()
                raise RuntimeError(f"Proxmox-Login fehlgeschlagen ({resp.status_code})")
            data = resp.json().get("data") or {}
            client.cookies.set("PVEAuthCookie", data.get("ticket", ""))
            client.headers["CSRFPreventionToken"] = data.get("CSRFPreventionToken", "")
        self._client = client
        return client

    async def _get(self, path: str) -> list | dict:
        client = await self._http()
        resp = await client.get(path)
        if resp.status_code in (403, 404):
            return []  # fehlende Berechtigung oder Feature -> ueberspringen
        resp.raise_for_status()
        return resp.json().get("data") or []

    # ------------------------------------------------------------------ Abfrage

    async def _nodes(self) -> list[str]:
        return [n["node"] for n in await self._get("/nodes") if n.get("node")]

    async def _guests(self) -> list[dict]:
        """Alle VMs und Container mit ihren Netzwerkschnittstellen.

        Die Konfiguration muss je Gast einzeln geholt werden; das laeuft
        gebuendelt, damit ein Host mit 40 VMs nicht in Serie abgefragt wird.
        """
        if self._cache is not None:
            return self._cache

        targets: list[tuple[str, str, dict]] = []
        for node in await self._nodes():
            for kind, path in (("vm", "qemu"), ("container", "lxc")):
                for guest in await self._get(f"/nodes/{node}/{path}"):
                    if guest.get("vmid") is not None:
                        targets.append((node, kind, guest))

        semaphore = asyncio.Semaphore(8)

        async def fetch(node: str, kind: str, guest: dict) -> dict:
            path = "qemu" if kind == "vm" else "lxc"
            async with semaphore:
                try:
                    config = await self._get(f"/nodes/{node}/{path}/{guest['vmid']}/config")
                except Exception:
                    config = {}
            return {"node": node, "kind": kind, "guest": guest, "config": config or {}}

        self._cache = list(await asyncio.gather(*(fetch(*t) for t in targets)))
        return self._cache

    # --------------------------------------------------------------- Operationen

    async def test(self) -> tuple[bool, str]:
        try:
            nodes = await self._get("/nodes")
            version = await self._get("/version")
            guests = await self._guests()
            names = ", ".join(n.get("node", "?") for n in nodes) or "?"
            release = (version or {}).get("version", "?") if isinstance(version, dict) else "?"
            return True, f"Verbunden: PVE {release}, Node(s) {names}, {len(guests)} Gäste"
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}"

    async def identity(self) -> Identity:
        macs: list[str] = []
        ips: list[str] = []
        for node in await self._nodes():
            for iface in await self._get(f"/nodes/{node}/network"):
                mac = iface.get("hwaddr") or iface.get("mac")
                if mac and _MAC_RE.match(str(mac)) and mac.lower() not in macs:
                    macs.append(str(mac).lower())
                address = iface.get("address") or iface.get("cidr", "").split("/")[0]
                if address and address not in ips:
                    ips.append(address)
        if not ips:
            ips.append(str(self.config["base_url"]).split("//")[-1].split(":")[0])
        return Identity(macs=macs, ips=ips, name=None, description="Proxmox VE")

    async def ports(self) -> list[Port]:
        """Die Bridges des Hosts sind die 'Ports', an denen VMs haengen."""
        out: list[Port] = []
        for node in await self._nodes():
            for iface in await self._get(f"/nodes/{node}/network"):
                name = iface.get("iface")
                if not name:
                    continue
                kind = "uplink" if iface.get("type") in ("eth", "bond") else "access"
                out.append(Port(
                    port_key=f"{node}:{name}",
                    name=f"{node} / {name}" + (f" ({iface['comments'].strip()})" if iface.get("comments") else ""),
                    kind=kind,
                ))
        return out

    async def fdb(self) -> list[FdbEntry]:
        entries: list[FdbEntry] = []
        for item in await self._guests():
            for mac, bridge, vlan in _interfaces(item["config"]):
                entries.append(FdbEntry(mac, f"{item['node']}:{bridge}", vlan))
        return entries

    async def hosts(self) -> list[HostInfo]:
        out: list[HostInfo] = []
        for item in await self._guests():
            guest, node, kind = item["guest"], item["node"], item["kind"]
            vmid = guest.get("vmid")
            name = guest.get("name") or item["config"].get("hostname") or f"{kind}-{vmid}"
            status = guest.get("status", "")
            for mac, bridge, vlan in _interfaces(item["config"]):
                out.append(HostInfo(
                    mac=mac,
                    name=name,
                    kind=kind,
                    note=f"{'VM' if kind == 'vm' else 'CT'} {vmid} auf {node}"
                         f" · {bridge}{f' · VLAN {vlan}' if vlan else ''}"
                         f"{f' · {status}' if status else ''}",
                ))
        return out

    async def close(self) -> None:
        self._cache = None
        if self._client is not None:
            await self._client.aclose()
            self._client = None


def _interfaces(config: dict) -> list[tuple[str, str, int | None]]:
    """Liest (mac, bridge, vlan) aus den netN-Zeilen einer Gastkonfiguration.

    QEMU:  net0 = "virtio=BC:24:11:00:00:01,bridge=vmbr0,tag=20,firewall=1"
    LXC:   net0 = "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:02,ip=dhcp"

    Bei QEMU steht die MAC als *Wert des Modellschluessels* (virtio, e1000,
    vmxnet3 ...), bei LXC unter hwaddr -- deshalb wird jeder Wert geprueft,
    statt auf feste Schluesselnamen zu setzen.
    """
    out: list[tuple[str, str, int | None]] = []
    for key, raw in config.items():
        if not re.fullmatch(r"net\d+", str(key)) or not isinstance(raw, str):
            continue
        mac = bridge = None
        vlan = None
        for part in raw.split(","):
            name, _, value = part.partition("=")
            value = value.strip()
            if _MAC_RE.match(value):
                mac = value.lower()
            elif name.strip() == "bridge":
                bridge = value
            elif name.strip() == "tag" and value.isdigit():
                vlan = int(value)
        if mac:
            out.append((mac, bridge or "unbekannt", vlan))
    return out
