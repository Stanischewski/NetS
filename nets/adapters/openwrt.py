"""OpenWrt ueber ubus/rpcd (JSON-RPC via HTTP).

Voraussetzung auf dem Router:
    opkg install uhttpd-mod-ubus rpcd
und ein ACL-File unter /usr/share/rpcd/acl.d/ das die genutzten Objekte
lesend freigibt (siehe deploy/openwrt-acl.json).
"""

from __future__ import annotations

import httpx

from .base import Adapter, Capability, ConfigField, FdbEntry, Lease, WirelessClient


class OpenWrtAdapter(Adapter):
    type_id = "openwrt"
    display_name = "OpenWrt (ubus)"
    description = "OpenWrt-Router/AP. Liefert DHCP-Leases, ARP-Tabelle und assoziierte WLAN-Clients."
    capabilities = (Capability.DHCP_LEASES, Capability.ARP_TABLE, Capability.WIRELESS, Capability.FDB)
    config_fields = (
        ConfigField("base_url", "Router-URL", required=True, default="http://192.168.1.1"),
        ConfigField("username", "Benutzer", required=True, default="root"),
        ConfigField("password", "Passwort", type="password", required=True),
        ConfigField("verify_tls", "TLS pruefen", type="bool", default=True),
    )

    def __init__(self, config: dict):
        super().__init__(config)
        self._session_id: str | None = None
        self._client: httpx.AsyncClient | None = None
        self._rpc_id = 0

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=str(self.config["base_url"]).rstrip("/"),
                verify=bool(self.config.get("verify_tls", True)),
                timeout=15.0,
            )
        return self._client

    async def _call(self, obj: str, method: str, params: dict | None = None) -> dict:
        if self._session_id is None:
            await self._login()
        return await self._raw_call(self._session_id, obj, method, params or {})

    async def _raw_call(self, session: str, obj: str, method: str, params: dict) -> dict:
        client = await self._http()
        self._rpc_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._rpc_id,
            "method": "call",
            "params": [session, obj, method, params],
        }
        resp = await client.post("/ubus", json=payload)
        resp.raise_for_status()
        body = resp.json()
        if "error" in body:
            raise RuntimeError(f"ubus-Fehler: {body['error']}")
        result = body.get("result", [])
        # ubus antwortet als [status_code, payload]; 0 = ok
        if not result or result[0] != 0:
            raise RuntimeError(f"ubus {obj}.{method} lieferte Status {result[0] if result else '?'} "
                               f"(fehlt eine ACL-Freigabe?)")
        return result[1] if len(result) > 1 else {}

    async def _login(self) -> None:
        result = await self._raw_call(
            "00000000000000000000000000000000",
            "session",
            "login",
            {"username": self.config["username"], "password": self.config["password"]},
        )
        self._session_id = result.get("ubus_rpc_session")
        if not self._session_id:
            raise RuntimeError("ubus-Login fehlgeschlagen")

    async def test(self) -> tuple[bool, str]:
        try:
            info = await self._call("system", "board")
            return True, f"Verbunden: {info.get('model', '?')} / {info.get('release', {}).get('description', '')}"
        except Exception as exc:
            return False, str(exc)

    async def dhcp_leases(self) -> list[Lease]:
        out: list[Lease] = []
        for family in ("ipv4leases", "ipv6leases"):
            try:
                data = await self._call("dhcp", family)
            except Exception:
                continue
            for entries in (data.get("device") or {}).values():
                for lease in entries.get("leases", []):
                    mac = lease.get("mac") or lease.get("duid")
                    if mac:
                        out.append(
                            Lease(
                                mac=mac,
                                ip=lease.get("address"),
                                hostname=lease.get("hostname"),
                                static=not lease.get("expires"),
                            )
                        )
        return out

    async def arp_table(self) -> list[tuple[str, str]]:
        try:
            data = await self._call("network.arp", "list")
        except Exception:
            return []
        return [
            (e["mac"], e["ip"])
            for e in (data.get("entries") or data.get("table") or [])
            if e.get("mac") and e.get("ip")
        ]

    async def _radios(self) -> dict:
        try:
            return (await self._call("network.wireless", "status")) or {}
        except Exception:
            return {}

    async def wireless_clients(self) -> list[WirelessClient]:
        out: list[WirelessClient] = []
        for radio_name, radio in (await self._radios()).items():
            for iface in radio.get("interfaces", []):
                ifname = iface.get("ifname")
                ssid = (iface.get("config") or {}).get("ssid")
                if not ifname:
                    continue
                try:
                    assoc = await self._call("iwinfo", "assoclist", {"device": ifname})
                except Exception:
                    continue
                for client in assoc.get("results", []):
                    if client.get("mac"):
                        out.append(
                            WirelessClient(
                                mac=client["mac"],
                                ap_name=self.config.get("_name") or str(self.config["base_url"]),
                                ssid=ssid,
                                signal=client.get("signal"),
                                band=radio_name,
                            )
                        )
        return out

    async def fdb(self) -> list[FdbEntry]:
        """WLAN-Assoziationen als Topologie-Kante -- der AP ist der 'Switch'."""
        return [
            FdbEntry(c.mac, f"wlan:{c.band or 'radio'}:{c.ssid or ''}", None)
            for c in await self.wireless_clients()
        ]

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
