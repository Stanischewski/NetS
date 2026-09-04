"""Weboberflaechen im Netz finden.

Das ist bewusst *aktiv*: Es klopft an TCP-Ports bekannter Geraete an und holt
die Startseite. Deshalb standardmaessig abgeschaltet und mit langem Intervall
-- nicht weil es gefaehrlich waere, sondern weil das Tool ansonsten
ausschliesslich zuhoert und das ein anderes Versprechen ist.

Gesucht wird nur auf Adressen, die ohnehin schon im Inventar stehen. Es
entsteht also kein zusaetzlicher Scan des Adressraums; was hier gefunden wird,
gehoert zu Geraeten, die der passive Teil laengst kennt.
"""

from __future__ import annotations

import asyncio
import logging
import re

import httpx

log = logging.getLogger("nets.webscan")

#: Was in Heimnetzen und kleinen Serverumgebungen tatsaechlich vorkommt.
#: Bewusst kurz -- jeder Port kostet einen Verbindungsversuch je Geraet.
DEFAULT_PORTS = "80,443,8006,8123,8080,8443,3000,5000,8081,9000"

#: Ports, die praktisch immer TLS sprechen.
_TLS_PORTS = {443, 8443, 8006, 9443, 10000}

_TITLE = re.compile(rb"<title[^>]*>(.{0,200}?)</title>", re.IGNORECASE | re.DOTALL)


def parse_ports(value: str | None) -> list[int]:
    """"80, 443, 8006" -> [80, 443, 8006]. Unsinn wird stillschweigend verworfen."""
    out: list[int] = []
    for part in (value or DEFAULT_PORTS).replace(";", ",").split(","):
        part = part.strip()
        if part.isdigit() and 0 < int(part) < 65536 and int(part) not in out:
            out.append(int(part))
    return out


def extract_title(body: bytes, charset: str | None = None) -> str | None:
    match = _TITLE.search(body)
    if not match:
        return None
    raw = match.group(1)
    for encoding in (charset, "utf-8", "latin-1"):
        if not encoding:
            continue
        try:
            title = raw.decode(encoding)
            break
        except (UnicodeDecodeError, LookupError):
            continue
    else:
        return None
    # Titel enthalten oft Zeilenumbrueche und Einrueckung aus dem Template.
    title = re.sub(r"\s+", " ", title).strip()
    return title[:120] or None


class WebScanner:
    def __init__(self, ports: list[int] | None = None, timeout: float = 4.0,
                 concurrency: int = 48, connect_timeout: float = 1.5):
        self.ports = ports or parse_ports(None)
        self.timeout = timeout
        #: Kurz gehalten -- im LAN antwortet ein offener Port in Millisekunden.
        self.connect_timeout = connect_timeout
        self._sem = asyncio.Semaphore(concurrency)

    async def _tcp_open(self, ip: str, port: int) -> bool:
        """Erst nachsehen, ob der Port ueberhaupt offen ist.

        Das ist der entscheidende Unterschied in der Laufzeit: Ein geschlossener
        Port antwortet sofort mit einer Ablehnung, ein gefilterter laeuft in
        einen kurzen Timeout. Ohne diese Vorpruefung zahlt *jede* der hunderten
        Kombinationen den vollen HTTP-Timeout, und bei TLS-Ports zusaetzlich
        einen Handshake-Versuch ins Leere.
        """
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=self.connect_timeout)
        except (OSError, asyncio.TimeoutError):
            return False
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return True

    def _schemes_for(self, port: int) -> tuple[str, ...]:
        """Welche Protokolle an diesem Port plausibel sind."""
        if port in _TLS_PORTS:
            return ("https", "http")
        return ("http", "https")

    async def _fetch(self, client: httpx.AsyncClient, ip: str, port: int,
                     scheme: str) -> dict | None:
        try:
            resp = await client.get(f"{scheme}://{ip}:{port}/",
                                    headers={"Accept": "text/html,*/*"})
        except Exception:
            return None
        # 401/403 sind gueltige Treffer: dort *ist* eine Oberflaeche, sie will
        # nur Anmeldedaten. Genau die will man in der Liste haben.
        if resp.status_code >= 500 or resp.status_code == 404:
            return None
        location = resp.headers.get("location")
        return {
            "ip": ip,
            "port": port,
            "scheme": scheme,
            "status": resp.status_code,
            "server": (resp.headers.get("server") or "")[:120] or None,
            "title": extract_title(resp.content, resp.charset_encoding),
            "redirect": location[:200] if location else None,
        }

    async def probe(self, ip: str, port: int,
                    client: httpx.AsyncClient | None = None) -> dict | None:
        """Einen Port anklopfen. None, wenn dort keine Weboberflaeche ist."""
        async with self._sem:
            if not await self._tcp_open(ip, port):
                return None
            owned = client is None
            client = client or httpx.AsyncClient(
                verify=False, timeout=self.timeout, follow_redirects=False,
            )
            try:
                for scheme in self._schemes_for(port):
                    result = await self._fetch(client, ip, port, scheme)
                    if result is not None:
                        return result
            finally:
                if owned:
                    await client.aclose()
        return None

    async def scan(self, ips: list[str]) -> list[dict]:
        # Ein gemeinsamer Client fuer den ganzen Lauf: sonst baut jede einzelne
        # Anfrage einen eigenen Verbindungspool und TLS-Kontext auf.
        async with httpx.AsyncClient(
            verify=False, timeout=self.timeout, follow_redirects=False,
            limits=httpx.Limits(max_connections=None),
        ) as client:
            tasks = [self.probe(ip, port, client) for ip in ips for port in self.ports]
            results = await asyncio.gather(*tasks, return_exceptions=True)
        found = [r for r in results if isinstance(r, dict)]
        log.info("Web-Suche: %d Adressen x %d Ports -> %d Oberflaechen",
                 len(ips), len(self.ports), len(found))
        return found
