"""Aktive Verfahren -- sparsam eingesetzt, als Ergaenzung zum Lauschen."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import shutil
import xml.etree.ElementTree as ET

from ..store import Observation, Store
from ..util import norm_mac, now

log = logging.getLogger("nets.active")


async def arp_sweep(store: Store, iface: str, cidr: str, rate: int = 50, timeout: float = 2.0) -> int:
    """ARP-Sweep statt Ping-Sweep.

    Der entscheidende Unterschied: ICMP darf ein Host verwerfen, ARP nicht --
    der Kernel muss antworten, sonst kann das Geraet selbst nicht
    kommunizieren. Eine Host-Firewall hilft dagegen nicht.
    """
    from scapy.layers.l2 import ARP, Ether
    from scapy.sendrecv import srp

    net = ipaddress.ip_network(cidr, strict=False)
    if net.version != 4:
        raise ValueError("ARP-Sweep gibt es nur fuer IPv4; fuer v6 siehe icmpv6_sweep()")
    if net.num_addresses > 65536:
        raise ValueError(f"{cidr} ist zu gross fuer einen Sweep")

    found = 0
    hosts = list(net.hosts())
    for start in range(0, len(hosts), 256):
        chunk = hosts[start : start + 256]
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=[str(h) for h in chunk])
        answered, _ = await asyncio.to_thread(
            srp, pkt, iface=iface, timeout=timeout, verbose=False, inter=1.0 / max(rate, 1)
        )
        for _, reply in answered:
            mac = norm_mac(reply.hwsrc)
            if mac:
                store.observe(Observation(mac=mac, ip=reply.psrc, source="arp_sweep"))
                found += 1
    log.info("ARP-Sweep %s: %d Antworten", cidr, found)
    return found


async def icmpv6_sweep(store: Store, iface: str, timeout: float = 3.0) -> int:
    """All-Nodes-Multicast (ff02::1) anpingen.

    Faengt Geraete, die per IPv4 stumm sind. Viele Stacks antworten hier,
    ohne dass jemand daran gedacht haette, es abzuschalten.
    """
    from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
    from scapy.layers.l2 import Ether
    from scapy.sendrecv import srp

    pkt = Ether(dst="33:33:00:00:00:01") / IPv6(dst="ff02::1") / ICMPv6EchoRequest()
    answered, _ = await asyncio.to_thread(
        srp, pkt, iface=iface, timeout=timeout, verbose=False, multi=True
    )
    found = 0
    for _, reply in answered:
        mac = norm_mac(reply[Ether].src)
        if mac:
            store.observe(Observation(mac=mac, ip=reply[IPv6].src, source="icmpv6_sweep"))
            found += 1
    log.info("ICMPv6-Sweep: %d Antworten", found)
    return found


async def local_networks() -> list[str]:
    """Netze, in denen wir selbst mit einem Bein stehen (Layer 2)."""
    proc = await asyncio.create_subprocess_exec(
        "ip", "-j", "-4", "addr", stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    out: list[str] = []
    for iface in json.loads(stdout or b"[]"):
        if is_virtual_iface(iface.get("ifname", "")):
            continue
        for addr in iface.get("addr_info", []):
            if addr.get("family") == "inet" and addr.get("prefixlen", 32) < 31:
                net = ipaddress.ip_network(
                    f"{addr['local']}/{addr['prefixlen']}", strict=False
                )
                if str(net) not in out:
                    out.append(str(net))
    return out


async def routed_networks() -> list[str]:
    """Netze, die wir nur ueber einen Router erreichen.

    Fuer die ist ein ARP-Sweep sinnlos -- ARP ist link-lokal und ueberquert
    keinen Router. Hier hilft nur ein geroutetes Verfahren.
    """
    proc = await asyncio.create_subprocess_exec(
        "ip", "-j", "-4", "route", stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    local = set(await local_networks())
    out: list[str] = []
    for route in json.loads(stdout or b"[]"):
        dst = route.get("dst", "")
        if dst in ("default", "") or "/" not in dst:
            continue
        if is_virtual_iface(route.get("dev", "")):
            continue
        try:
            net = ipaddress.ip_network(dst, strict=False)
        except ValueError:
            continue
        # Zu grosse Bloecke sind Sammelrouten, keine sinnvollen Suchbereiche.
        if str(net) not in local and str(net) not in out and net.num_addresses <= 4096:
            out.append(str(net))
    return out


async def interface_for(target: str) -> str | None:
    """Ueber welches Interface geht ein Paket an diese Adresse?

    Ohne das schickt ein ARP-Sweep seine Anfragen auf dem einen konfigurierten
    Interface los -- und findet in einem Segment, das an einem *anderen*
    Interface haengt, stillschweigend nichts. Gemessen: 0 Antworten ueber
    wlan0, 2 ueber enp0s31f6, dasselbe Subnetz.
    """
    try:
        first = str(next(ipaddress.ip_network(target, strict=False).hosts()))
    except (ValueError, StopIteration):
        first = target
    proc = await asyncio.create_subprocess_exec(
        "ip", "-j", "route", "get", first,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    if proc.returncode != 0:
        return None
    try:
        routes = json.loads(stdout or b"[]")
    except json.JSONDecodeError:
        return None
    for route in routes:
        dev = route.get("dev")
        if dev and not is_virtual_iface(dev):
            return dev
    return None


async def is_local_network(cidr: str) -> bool:
    try:
        target = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    for own in await local_networks():
        if target.subnet_of(ipaddress.ip_network(own)):
            return True
    return False


async def routed_sweep(store: Store, cidr: str, ports: tuple[int, ...] = (80, 443, 22, 445),
                       concurrency: int = 64, timeout: float = 1.0) -> list[str]:
    """Findet antwortende Adressen jenseits des eigenen Segments.

    Zuerst ICMP, dann ein TCP-Verbindungsversuch auf ein paar gaengige Ports --
    viele Hosts verwerfen Ping, aber kaum einer hat gar keinen offenen Port.

    Nebenwirkung, die den eigentlichen Wert ausmacht: Jeder Versuch zwingt den
    zustaendigen **Router**, fuer die Zieladresse zu arpen. Danach steht das
    Paar IP/MAC in seiner ARP-Tabelle -- und die kann ein Adapter auslesen.
    So kommt man auch in fremden Segmenten zu echten MAC-Adressen.
    """
    net = ipaddress.ip_network(cidr, strict=False)
    if net.num_addresses > 4096:
        raise ValueError(f"{cidr} ist zu gross fuer einen Sweep")

    semaphore = asyncio.Semaphore(concurrency)
    found: list[tuple[str, str, str | None]] = []

    async def check(ip: str) -> None:
        async with semaphore:
            if await _icmp_alive(ip, timeout):
                found.append((ip, "icmp", None))
                return
            for port in ports:
                if await _tcp_alive(ip, port, timeout):
                    found.append((ip, "tcp", f"Port {port}"))
                    return

    await asyncio.gather(*(check(str(h)) for h in net.hosts()))
    ts = now()
    for ip, method, detail in found:
        store.record_subnet_host(ip, str(net), method, detail, ts)
    log.info("Gerouteter Sweep %s: %d Adressen antworten", cidr, len(found))
    return [ip for ip, _, _ in found]


#: Einmal nachsehen statt bei jedem Host. None = noch nicht geprueft.
_PING: str | None | bool = False


def _ping_binary() -> str | None:
    global _PING
    if _PING is False:
        _PING = shutil.which("ping")
        if _PING is None:
            log.info("ping nicht gefunden -- geroutete Sweeps nutzen nur TCP")
    return _PING


async def _icmp_alive(ip: str, timeout: float) -> bool:
    """Systemeigenes ping -- braucht keine Raw-Sockets.

    Fehlt das Programm (schlanke Container-Images haben es oft nicht), ist das
    kein Fehler: der TCP-Versuch danach traegt allein. Frueher riss die
    Ausnahme den ganzen Sweep mit, und ein komplettes Subnetz fiel aus.
    """
    binary = _ping_binary()
    if binary is None:
        return False
    try:
        proc = await asyncio.create_subprocess_exec(
            binary, "-c", "1", "-W", str(max(1, int(timeout))), "-n", "-q", ip,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        return await proc.wait() == 0
    except OSError:
        return False


async def _tcp_alive(ip: str, port: int, timeout: float) -> bool:
    try:
        fut = asyncio.open_connection(ip, port)
        _, writer = await asyncio.wait_for(fut, timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return True


async def nmap_scan(store: Store, target: str, args: str = "-sS -T3 --top-ports 200 -O") -> int:
    """Optionales nmap fuer Dienste und OS-Vermutung.

    Bewusst optional: laut, und die passiven Quellen liefern bei Dauerbetrieb
    oft mehr. Nur einzelne Ziele scannen, nicht das ganze Netz im Minutentakt.
    """
    if not shutil.which("nmap"):
        raise RuntimeError("nmap ist nicht installiert")

    cmd = ["nmap", *args.split(), "-oX", "-", target]
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"nmap fehlgeschlagen: {stderr.decode(errors='replace')[:300]}")

    count = 0
    for host in ET.fromstring(stdout).findall("host"):
        mac = ip = None
        for addr in host.findall("address"):
            kind = addr.get("addrtype")
            if kind == "mac":
                mac = norm_mac(addr.get("addr", ""))
            elif kind in ("ipv4", "ipv6"):
                ip = addr.get("addr")
        if not mac:
            continue

        facts: dict[str, str] = {}
        osmatch = host.find("./os/osmatch")
        if osmatch is not None:
            facts["os_guess"] = f"{osmatch.get('name')} ({osmatch.get('accuracy')}%)"
        open_ports = [
            p.get("portid")
            for p in host.findall("./ports/port")
            if (s := p.find("state")) is not None and s.get("state") == "open"
        ]
        if open_ports:
            facts["open_ports"] = ",".join(open_ports[:40])
        for port in host.findall("./ports/port"):
            svc = port.find("service")
            if svc is not None and svc.get("product"):
                facts[f"svc_{port.get('portid')}"] = " ".join(
                    filter(None, [svc.get("product"), svc.get("version")])
                )[:120]

        hostname_el = host.find("./hostnames/hostname")
        store.observe(
            Observation(
                mac=mac,
                ip=ip,
                hostname=hostname_el.get("name") if hostname_el is not None else None,
                facts=facts,
                source="nmap",
            )
        )
        count += 1
    return count


#: Virtuelle Interfaces, deren Nachbarn nicht ins Inventar gehoeren --
#: Container-Bridges, veth-Paare, VPN-Tunnel. Sonst landen z.B. Docker-interne
#: Adressen wie 172.18.0.x als vermeintliche Netzwerkgeraete in der Liste.
VIRTUAL_IFACE_PREFIXES = ("lo", "docker", "br-", "veth", "virbr", "tun", "tap", "wg", "zt", "tailscale")


def is_virtual_iface(name: str) -> bool:
    return name.startswith(VIRTUAL_IFACE_PREFIXES)


async def read_local_neighbours(store: Store, include_virtual: bool = False) -> int:
    """`ip -j neigh` mitnehmen -- der Kernel-Nachbarschaftscache ist gratis."""
    proc = await asyncio.create_subprocess_exec(
        "ip", "-j", "neigh", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
    )
    stdout, _ = await proc.communicate()
    if proc.returncode != 0:
        return 0
    count = 0
    for entry in json.loads(stdout or b"[]"):
        mac = norm_mac(entry.get("lladdr", "") or "")
        iface = entry.get("dev", "")
        if not mac or entry.get("state", [""])[0] in ("FAILED", "INCOMPLETE"):
            continue
        if not include_virtual and is_virtual_iface(iface):
            continue
        store.observe(
            Observation(
                mac=mac, ip=entry.get("dst"), source="neigh",
                facts={"seen_on_iface": iface} if iface else {},
            )
        )
        count += 1
    return count
