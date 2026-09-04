"""MikroTik RouterOS v7 ueber die REST-API (/rest).

Auf dem Router aktivieren:
    /ip service enable www-ssl        (oder www fuer HTTP, nicht empfohlen)
Ein eigener Read-only-Benutzer mit Gruppe 'read' genuegt.
"""

from __future__ import annotations

import httpx

from .base import Adapter, Capability, ConfigField, FdbEntry, Lease, Neighbor, Port, WirelessClient


class MikrotikAdapter(Adapter):
    type_id = "mikrotik"
    display_name = "MikroTik RouterOS 7 (REST)"
    description = "RouterOS-Switch/Router. Echte Bridge-Host-Tabelle, DHCP-Leases, LLDP-Nachbarn, WLAN."
    capabilities = (
        Capability.FDB, Capability.DHCP_LEASES, Capability.ARP_TABLE,
        Capability.LLDP, Capability.WIRELESS, Capability.PORT_STATUS,
    )
    config_fields = (
        ConfigField("base_url", "Router-URL", required=True, default="https://192.168.88.1"),
        ConfigField("username", "Benutzer", required=True),
        ConfigField("password", "Passwort", type="password", required=True),
        ConfigField("verify_tls", "TLS pruefen", type="bool", default=False),
    )

    def __init__(self, config: dict):
        super().__init__(config)
        self._client: httpx.AsyncClient | None = None

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=str(self.config["base_url"]).rstrip("/") + "/rest",
                auth=(self.config["username"], self.config["password"]),
                verify=bool(self.config.get("verify_tls", False)),
                timeout=15.0,
            )
        return self._client

    async def _get(self, path: str) -> list[dict]:
        client = await self._http()
        resp = await client.get(path)
        if resp.status_code == 404:
            return []  # Feature auf diesem Modell nicht vorhanden
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, list) else [data]

    async def test(self) -> tuple[bool, str]:
        try:
            identity = await self._get("/system/identity")
            resource = await self._get("/system/resource")
            name = identity[0].get("name") if identity else "?"
            board = resource[0].get("board-name", "") if resource else ""
            version = resource[0].get("version", "") if resource else ""
            return True, f"Verbunden: {name} ({board}, RouterOS {version})"
        except Exception as exc:
            return False, str(exc)

    async def ports(self) -> list[Port]:
        return [
            Port(port_key=i.get("name", ""), name=i.get("comment") or i.get("name"),
                 kind="wireless" if i.get("type", "").startswith("w") else "access")
            for i in await self._get("/interface")
            if i.get("name")
        ]

    async def fdb(self) -> list[FdbEntry]:
        entries = []
        for host in await self._get("/interface/bridge/host"):
            mac, port = host.get("mac-address"), host.get("interface")
            # 'local' markiert die MAC der Bridge selbst -- kein Client.
            if mac and port and host.get("local") != "true":
                vlan = host.get("vid")
                entries.append(FdbEntry(mac, port, int(vlan) if vlan and vlan.isdigit() else None))
        return entries

    async def dhcp_leases(self) -> list[Lease]:
        return [
            Lease(
                mac=lease["mac-address"],
                ip=lease.get("address"),
                hostname=lease.get("host-name") or lease.get("comment"),
                static=lease.get("dynamic") == "false",
            )
            for lease in await self._get("/ip/dhcp-server/lease")
            if lease.get("mac-address")
        ]

    async def arp_table(self) -> list[tuple[str, str]]:
        return [
            (e["mac-address"], e["address"])
            for e in await self._get("/ip/arp")
            if e.get("mac-address") and e.get("address")
        ]

    async def lldp(self) -> list[Neighbor]:
        return [
            Neighbor(
                local_port=n.get("interface", ""),
                remote_name=n.get("identity") or n.get("system-description"),
                remote_port=n.get("interface-name"),
            )
            for n in await self._get("/ip/neighbor")
            if n.get("interface")
        ]

    async def wireless_clients(self) -> list[WirelessClient]:
        out: list[WirelessClient] = []
        # RouterOS 7 kennt je nach Modell /interface/wireless (legacy) oder
        # /interface/wifi (wifiwave2). Beides versuchen, 404 ist harmlos.
        for path in ("/interface/wireless/registration-table", "/interface/wifi/registration-table"):
            for reg in await self._get(path):
                if reg.get("mac-address"):
                    out.append(
                        WirelessClient(
                            mac=reg["mac-address"],
                            ap_name=reg.get("interface"),
                            ssid=reg.get("ssid"),
                            signal=_to_int(reg.get("signal-strength") or reg.get("signal")),
                            band=reg.get("band"),
                        )
                    )
        return out

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


def _to_int(value) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value).split("@")[0].strip().replace("dBm", ""))
    except ValueError:
        return None
