"""Ubiquiti UniFi -- API-Schluessel oder Anmeldung.

Entscheidend ist nicht der Zugangsweg, sondern *welche* API angesprochen wird:

* Die **klassische Controller-API** (`/proxy/network/api/s/<site>/...`) liefert
  alles: Switch-Port je Client, SSID, Signalstaerke, VLAN, DHCP-Leases.
* Die **Integrations-API** (`/proxy/network/integration/v1`) ist schlanker und
  nennt nur, *hinter welchem* Geraet ein Client haengt -- nicht an welchem
  Port, ohne SSID und ohne Signal.

Ein API-Schluessel oeffnet gemessen an UniFi Network 10.5 **beide**. Deshalb
wird immer zuerst die klassische API versucht und nur bei Ablehnung auf die
Integrations-API zurueckgefallen. Damit braucht es fuer den vollen Datenumfang
kein Passwort -- und keinen Benutzer ohne Zwei-Faktor-Anmeldung.

Die Anmeldung mit Benutzer/Passwort bleibt fuer aeltere Controller ohne
API-Schluessel. Sie scheitert an Konten mit MFA und an Ubiquiti-Cloud-Konten;
es muss ein lokaler Benutzer sein.

Der Basispfad der Integrations-API ist `/proxy/network/integration/v1`. Die
URL, die die Weboberflaeche unter "Integrationen" anzeigt
(`/unifi-api/network`), liefert nur die Oberflaeche selbst zurueck.
"""

from __future__ import annotations

import httpx

from .base import (
    Adapter,
    Capability,
    ConfigField,
    FdbEntry,
    HostInfo,
    Identity,
    Lease,
    Port,
    WirelessClient,
)

_CAPS = (
    Capability.WIRELESS, Capability.FDB, Capability.PORT_STATUS,
    Capability.DHCP_LEASES, Capability.IDENTITY, Capability.INVENTORY,
)


class UnifiAdapter(Adapter):
    type_id = "unifi"
    display_name = "UniFi Controller"
    description = (
        "Ubiquiti UniFi Network. Liefert Switch-Port je Client, SSID, Signal und Leases. "
        "Ein API-Schluessel genuegt und vertraegt sich mit Zwei-Faktor-Anmeldung; die "
        "Anmeldung mit Passwort bleibt fuer aeltere Controller."
    )
    capabilities = _CAPS
    config_fields = (
        ConfigField("base_url", "Controller-URL", required=True, default="https://192.168.1.1",
                    help="Bei UniFi OS (UDM/Cloud Key Gen2) die Geraete-URL, sonst https://host:8443"),
        ConfigField("auth_method", "Anmeldung", type="select",
                    choices=["api_key", "password"], default="api_key",
                    help="API-Schluessel ist vorzuziehen: widerrufbar und ohne MFA-Probleme."),
        ConfigField("username", "Benutzer", depends_on={"auth_method": "password"},
                    help="Lokaler Controller-Benutzer ohne MFA; Nur-Lese-Rolle genuegt."),
        ConfigField("password", "Passwort", type="password", depends_on={"auth_method": "password"}),
        ConfigField("api_key", "API-Schluessel", type="password", depends_on={"auth_method": "api_key"},
                    help="In der UniFi-Oberflaeche unter Einstellungen -> Integrationen erzeugen."),
        ConfigField("site", "Site", default="default",
                    help="Bei API-Schluessel egal -- dort wird die Site automatisch ermittelt."),
        ConfigField("unifi_os", "UniFi OS", type="bool", default=True,
                    help="Aus, wenn der Controller als reine Software auf Port 8443 laeuft."),
        ConfigField("verify_tls", "TLS pruefen", type="bool", default=False,
                    help="UniFi nutzt meist ein selbstsigniertes Zertifikat."),
    )

    def __init__(self, config: dict):
        super().__init__(config)
        self._client: httpx.AsyncClient | None = None
        self._site_id: str | None = None
        self._devices: list[dict] | None = None
        #: None = noch nicht geprueft. Sagt, ob die klassische API offensteht.
        self._classic: bool | None = None

    @property
    def _uses_api_key(self) -> bool:
        return str(self.config.get("auth_method", "password")) == "api_key"

    def has(self, capability: str) -> bool:
        return capability in _CAPS

    @classmethod
    def validate(cls, config: dict) -> list[str]:
        errors = list(super().validate(config))
        merged = cls._with_defaults(config)
        if str(merged.get("auth_method", "password")) == "api_key":
            if not merged.get("api_key"):
                errors.append("Feld 'API-Schluessel' ist erforderlich")
        else:
            for key, label in (("username", "Benutzer"), ("password", "Passwort")):
                if not merged.get(key):
                    errors.append(f"Feld '{label}' ist erforderlich")
        return errors

    # ---------------------------------------------------------------- Transport

    async def _session(self) -> httpx.AsyncClient:
        if self._client is not None:
            return self._client
        client = httpx.AsyncClient(
            base_url=str(self.config["base_url"]).rstrip("/"),
            verify=bool(self.config.get("verify_tls", False)),
            timeout=20.0,
            follow_redirects=True,
        )
        if self._uses_api_key:
            client.headers.update({
                "X-API-KEY": str(self.config["api_key"]).strip(),
                "Accept": "application/json",
            })
            self._client = client
            return client

        login_path = "/api/auth/login" if self.config.get("unifi_os", True) else "/api/login"
        resp = await client.post(
            login_path,
            json={"username": self.config["username"], "password": self.config["password"]},
        )
        if resp.status_code >= 400:
            await client.aclose()
            hint = " (Zwei-Faktor-Anmeldung wird nicht unterstuetzt)" if resp.status_code == 499 else ""
            raise RuntimeError(f"UniFi-Login fehlgeschlagen ({resp.status_code}){hint}")
        token = resp.headers.get("x-csrf-token")
        if token:
            client.headers["x-csrf-token"] = token
        self._client = client
        return client

    # --------------------------------------------------- Integrations-API (Key)

    async def _v1(self, path: str) -> dict:
        client = await self._session()
        resp = await client.get(f"/proxy/network/integration/v1{path}")
        resp.raise_for_status()
        # Ein unbekannter Pfad liefert bei UniFi OS die Weboberflaeche mit
        # HTTP 200 zurueck -- ohne diese Pruefung scheitert erst das Parsen.
        if "json" not in resp.headers.get("content-type", ""):
            raise RuntimeError("Kein JSON -- falscher Pfad oder API-Schluessel abgelehnt")
        return resp.json()

    async def _site(self) -> str:
        if self._site_id is None:
            sites = (await self._v1("/sites")).get("data") or []
            if not sites:
                raise RuntimeError("Keine Site sichtbar -- hat der Schluessel Zugriff?")
            wanted = str(self.config.get("site", "default")).lower()
            match = next(
                (s for s in sites
                 if wanted in (str(s.get("internalReference", "")).lower(),
                               str(s.get("name", "")).lower())),
                sites[0],
            )
            self._site_id = match["id"]
        return self._site_id

    async def _v1_all(self, path: str) -> list[dict]:
        """Seitenweise Abfrage -- die Integrations-API liefert 25 je Seite."""
        out: list[dict] = []
        offset = 0
        while True:
            sep = "&" if "?" in path else "?"
            page = await self._v1(f"{path}{sep}offset={offset}&limit=200")
            data = page.get("data") or []
            out.extend(data)
            if not data or len(out) >= page.get("totalCount", len(out)):
                return out
            offset = len(out)

    async def _v1_devices(self) -> list[dict]:
        if self._devices is None:
            self._devices = await self._v1_all(f"/sites/{await self._site()}/devices")
        return self._devices

    # -------------------------------------------------- klassische API (Login)

    def _api(self, path: str) -> str:
        prefix = "/proxy/network" if self.config.get("unifi_os", True) else ""
        return f"{prefix}/api/s/{self.config.get('site', 'default')}/{path}"

    async def _get(self, path: str) -> list[dict]:
        client = await self._session()
        resp = await client.get(self._api(path))
        resp.raise_for_status()
        if "json" not in resp.headers.get("content-type", ""):
            raise RuntimeError("Kein JSON von der klassischen API")
        return resp.json().get("data", [])

    async def _classic_available(self) -> bool:
        """Prueft einmalig, ob die klassische API offensteht.

        Ein API-Schluessel oeffnet sie bei aktuellen Controllern mit -- und nur
        dort gibt es Switch-Port, SSID und Signal. Erst wenn sie ablehnt, wird
        auf die schlankere Integrations-API zurueckgefallen.
        """
        if self._classic is None:
            try:
                await self._get("stat/device")
                self._classic = True
            except Exception:
                if not self._uses_api_key:
                    raise  # ohne Schluessel gibt es keine Rueckfallebene
                self._classic = False
        return self._classic

    # --------------------------------------------------------------- Operationen

    async def test(self) -> tuple[bool, str]:
        try:
            if await self._classic_available():
                devices = await self._get("stat/device")
                clients = await self._get("stat/sta")
                with_port = sum(1 for c in clients if c.get("sw_port") is not None)
                return True, (
                    f"Verbunden: {len(devices)} Infrastrukturgeraete, {len(clients)} Clients "
                    f"({with_port} mit Port-Angabe)"
                )
            devices = await self._v1_devices()
            clients = await self._v1_all(f"/sites/{await self._site()}/clients")
            names = ", ".join(d.get("model", "?") for d in devices[:3])
            return True, (
                f"Verbunden ueber die Integrations-API: {len(devices)} Geraete ({names}), "
                f"{len(clients)} Clients -- ohne Port, SSID und Signal. Die klassische API "
                f"wurde abgelehnt."
            )
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}"

    async def identity(self) -> Identity:
        macs, ips = [], []
        if not await self._classic_available():
            for dev in await self._v1_devices():
                if dev.get("macAddress"):
                    macs.append(dev["macAddress"])
                addr = dev.get("ipAddress")
                if addr and addr != "unknown":
                    ips.append(addr)
        else:
            for dev in await self._get("stat/device"):
                if dev.get("mac"):
                    macs.append(dev["mac"])
                if dev.get("ip"):
                    ips.append(dev["ip"])
        if not ips:
            ips.append(str(self.config["base_url"]).split("//")[-1].split("/")[0].split(":")[0])
        return Identity(macs=macs, ips=ips, description="UniFi")

    async def ports(self) -> list[Port]:
        out: list[Port] = []
        if not await self._classic_available():
            site = await self._site()
            for dev in await self._v1_devices():
                name = dev.get("name") or dev.get("model") or dev.get("id")
                try:
                    detail = await self._v1(f"/sites/{site}/devices/{dev['id']}")
                except Exception:
                    continue
                for port in (detail.get("interfaces") or {}).get("ports") or []:
                    out.append(Port(
                        port_key=f"{dev['id']}:{port.get('idx')}",
                        name=f"{name} Port {port.get('idx')} ({port.get('connector', '?')})",
                        kind="access",
                    ))
            return out

        for dev in await self._get("stat/device"):
            name = dev.get("name") or dev.get("model") or dev.get("mac")
            for table in dev.get("port_table") or []:
                out.append(Port(
                    port_key=f"{dev.get('mac')}:{table.get('port_idx')}",
                    name=f"{name} Port {table.get('port_idx')}"
                         + (f" ({table['name']})" if table.get("name") else ""),
                    kind="uplink" if table.get("is_uplink") else "access",
                ))
            if dev.get("radio_table"):
                out.append(Port(port_key=f"{dev.get('mac')}:wlan", name=f"{name} WLAN", kind="wireless"))
        return out

    async def fdb(self) -> list[FdbEntry]:
        if not await self._classic_available():
            # Die Integrations-API nennt nur das *Geraet*, nicht den Port.
            # Einen Port zu erfinden waere schlimmer als die Luecke zu zeigen.
            names = {d["id"]: (d.get("name") or d.get("model") or d["id"])
                     for d in await self._v1_devices()}
            entries = []
            for client in await self._v1_all(f"/sites/{await self._site()}/clients"):
                uplink, mac = client.get("uplinkDeviceId"), client.get("macAddress")
                if uplink and mac:
                    entries.append(FdbEntry(mac, f"{names.get(uplink, uplink)} (Port unbekannt)", None))
            return entries

        entries = []
        for client in await self._get("stat/sta"):
            mac = client.get("mac")
            if not mac:
                continue
            if client.get("sw_mac") and client.get("sw_port") is not None:
                entries.append(FdbEntry(mac, f"{client['sw_mac']}:{client['sw_port']}", client.get("vlan")))
            elif client.get("ap_mac"):
                entries.append(FdbEntry(mac, f"{client['ap_mac']}:wlan", client.get("vlan")))
        return entries

    async def hosts(self) -> list[HostInfo]:
        """Namen, die im Controller vergeben wurden."""
        out: list[HostInfo] = []
        if not await self._classic_available():
            for client in await self._v1_all(f"/sites/{await self._site()}/clients"):
                mac, name = client.get("macAddress"), client.get("name")
                # UniFi setzt als Namen die MAC, wenn keiner vergeben wurde --
                # das als Hostnamen zu uebernehmen waere reines Rauschen.
                if mac and name and name.replace("-", ":").lower() != mac.lower():
                    out.append(HostInfo(mac=mac, name=name, kind=str(client.get("type", "")).lower()))
            return out

        for client in await self._get("stat/sta"):
            mac = client.get("mac")
            name = client.get("name") or client.get("hostname")
            if mac and name and name.lower() != mac.lower():
                out.append(HostInfo(mac=mac, name=name))
        return out

    async def wireless_clients(self) -> list[WirelessClient]:
        if not await self._classic_available():
            return []  # SSID und Signal liefert die Integrations-API nicht
        aps = {d.get("mac"): (d.get("name") or d.get("model")) for d in await self._get("stat/device")}
        out = []
        for client in await self._get("stat/sta"):
            if not client.get("is_wired", True) and client.get("mac"):
                out.append(WirelessClient(
                    mac=client["mac"],
                    ap_name=aps.get(client.get("ap_mac"), client.get("ap_mac")),
                    ssid=client.get("essid"),
                    signal=client.get("signal"),
                    band="5G" if client.get("radio") == "na" else "2.4G",
                ))
        return out

    async def dhcp_leases(self) -> list[Lease]:
        if not await self._classic_available():
            return []
        out = []
        for client in await self._get("list/user"):
            if client.get("mac"):
                out.append(Lease(
                    mac=client["mac"],
                    ip=client.get("fixed_ip") or client.get("last_ip"),
                    hostname=client.get("hostname") or client.get("name"),
                    static=bool(client.get("use_fixedip")),
                ))
        return out

    async def close(self) -> None:
        self._devices = None
        self._site_id = None
        self._classic = None
        if self._client is not None:
            await self._client.aclose()
            self._client = None
