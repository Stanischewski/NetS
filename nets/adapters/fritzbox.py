"""AVM FRITZ!Box ueber TR-064 (Port 49000).

In der FRITZ!Box aktivieren: Heimnetz -> Netzwerk -> Netzwerkeinstellungen ->
"Zugriff fuer Anwendungen zulassen". Ein eigener Benutzer mit der Berechtigung
"FRITZ!Box Einstellungen" genuegt.

Die Hostliste der Box ist die vollstaendigste Quelle im typischen Heimnetz:
sie enthaelt auch Geraete, die gerade offline sind, und sagt, ob eine IP fest
vergeben wurde.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

import httpx

from .base import Adapter, Capability, ConfigField, FdbEntry, Lease, WirelessClient

_SOAP = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"
            xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body><u:{action} xmlns:u="{service}">{args}</u:{action}></s:Body></s:Envelope>"""


class FritzboxAdapter(Adapter):
    type_id = "fritzbox"
    display_name = "AVM FRITZ!Box (TR-064)"
    description = (
        "Liest die komplette Hostliste inkl. offline-Geraeten, unterscheidet feste "
        "von dynamischen IPs und listet WLAN-Clients je Frequenzband."
    )
    capabilities = (Capability.DHCP_LEASES, Capability.WIRELESS, Capability.FDB)
    config_fields = (
        ConfigField("host", "FRITZ!Box-Adresse", required=True, default="fritz.box"),
        ConfigField("username", "Benutzer", required=True),
        ConfigField("password", "Passwort", type="password", required=True),
        ConfigField("port", "TR-064-Port", type="int", default=49000),
        ConfigField("use_tls", "TLS (Port 49443)", type="bool", default=False),
    )

    def __init__(self, config: dict):
        super().__init__(config)
        self._client: httpx.AsyncClient | None = None

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            scheme = "https" if self.config.get("use_tls") else "http"
            port = 49443 if self.config.get("use_tls") else int(self.config.get("port", 49000))
            self._client = httpx.AsyncClient(
                base_url=f"{scheme}://{self.config['host']}:{port}",
                auth=httpx.DigestAuth(self.config["username"], self.config["password"]),
                verify=False,  # AVM nutzt ein selbstsigniertes Zertifikat
                timeout=15.0,
            )
        return self._client

    async def _soap(self, control_url: str, service: str, action: str, **args) -> dict[str, str]:
        body = _SOAP.format(
            action=action,
            service=service,
            args="".join(f"<{k}>{v}</{k}>" for k, v in args.items()),
        )
        client = await self._http()
        resp = await client.post(
            control_url,
            content=body.encode(),
            headers={
                "Content-Type": 'text/xml; charset="utf-8"',
                "SoapAction": f"{service}#{action}",
            },
        )
        resp.raise_for_status()
        root = ET.fromstring(resp.text)
        out = {}
        for element in root.iter():
            tag = re.sub(r"^\{.*\}", "", element.tag)
            if tag.startswith("New") and element.text is not None:
                out[tag] = element.text
        return out

    async def test(self) -> tuple[bool, str]:
        try:
            info = await self._soap(
                "/upnp/control/deviceinfo", "urn:dslforum-org:service:DeviceInfo:1", "GetInfo"
            )
            return True, f"Verbunden: {info.get('NewModelName', 'FRITZ!Box')} / {info.get('NewSoftwareVersion', '')}"
        except Exception as exc:
            return False, str(exc)

    async def _hosts(self) -> list[dict[str, str]]:
        """Bevorzugt die XML-Hostliste (ein Request statt N)."""
        service = "urn:dslforum-org:service:Hosts:1"
        try:
            result = await self._soap(
                "/upnp/control/hosts", service, "X_AVM-DE_GetHostListPath"
            )
            path = result.get("NewX_AVM-DE_HostListPath")
            if path:
                client = await self._http()
                resp = await client.get(path)
                resp.raise_for_status()
                return [
                    {re.sub(r"^\{.*\}", "", c.tag): (c.text or "") for c in item}
                    for item in ET.fromstring(resp.text)
                ]
        except Exception:
            pass

        # Fallback: Eintraege einzeln durchgehen.
        count = int(
            (await self._soap("/upnp/control/hosts", service, "GetHostNumberOfEntries")).get(
                "NewHostNumberOfEntries", 0
            )
        )
        hosts = []
        for index in range(count):
            entry = await self._soap(
                "/upnp/control/hosts", service, "GetGenericHostEntry", NewIndex=index
            )
            hosts.append({k[3:]: v for k, v in entry.items()})
        return hosts

    async def dhcp_leases(self) -> list[Lease]:
        out = []
        for host in await self._hosts():
            mac = host.get("MACAddress")
            if not mac:
                continue
            out.append(
                Lease(
                    mac=mac,
                    ip=host.get("IPAddress") or None,
                    hostname=host.get("HostName") or None,
                    # AVM meldet feste Zuordnungen als AddressSource "Static".
                    static=host.get("AddressSource", "").lower() == "static",
                )
            )
        return out

    async def wireless_clients(self) -> list[WirelessClient]:
        out = []
        for host in await self._hosts():
            mac = host.get("MACAddress")
            interface = host.get("InterfaceType", "")
            if mac and interface.lower().startswith("802.11") and host.get("Active") == "1":
                out.append(
                    WirelessClient(
                        mac=mac,
                        ap_name=host.get("X_AVM-DE_InfoURL") or "FRITZ!Box",
                        ssid=None,
                        signal=_to_int(host.get("X_AVM-DE_SignalStrength")),
                        band=host.get("X_AVM-DE_Speed") and interface or interface,
                    )
                )
        return out

    async def fdb(self) -> list[FdbEntry]:
        """Die Box weiss, ob ein Host per LAN-Port oder WLAN haengt."""
        entries = []
        for host in await self._hosts():
            mac, interface = host.get("MACAddress"), (host.get("InterfaceType") or "").strip()
            if mac and host.get("Active") == "1" and interface:
                port = "wlan" if interface.lower().startswith("802.11") else f"lan:{interface}"
                entries.append(FdbEntry(mac, port, None))
        return entries

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


def _to_int(value) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None
