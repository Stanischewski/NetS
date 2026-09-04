"""Parser fuer die passiven Quellen.

Alle hier genutzten Protokolle sind Broadcast oder Multicast. Das ist der
Grund, warum das Ganze auch in einem geswitchten Netz ohne Port-Mirroring
funktioniert: diese Pakete bekommt jeder Port zu sehen.
"""

from __future__ import annotations

import re
from typing import Iterable

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS
from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6ND_RA, IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

from ..store import Observation
from ..util import norm_mac

# ------------------------------------------------------------------------ ARP


class ArpParser:
    """Der wichtigste Collector.

    Ein Geraet kann ICMP verwerfen und alle Ports schliessen -- aber ohne ARP
    kann es nicht kommunizieren. Wer im Netz aktiv ist, taucht hier auf.
    """

    name = "arp"
    bpf = "arp"

    def parse(self, pkt: Packet) -> Iterable[Observation]:
        if ARP not in pkt:
            return
        arp = pkt[ARP]
        # Sender: op=1 (request) wie op=2 (reply) belegen beide die Existenz.
        if arp.hwsrc and arp.psrc and arp.psrc != "0.0.0.0":
            yield Observation(mac=arp.hwsrc, ip=arp.psrc, source=self.name)
        # ARP-Reply belegt zusaetzlich das Ziel als aktiven Gespraechspartner.
        if arp.op == 2 and arp.hwdst and arp.pdst and arp.pdst != "0.0.0.0":
            yield Observation(mac=arp.hwdst, ip=arp.pdst, source=self.name)


# ----------------------------------------------------------------------- DHCP

_DHCP_MSG_TYPES = {1: "discover", 2: "offer", 3: "request", 5: "ack", 8: "inform"}


class DhcpParser:
    """Liefert Hostname, Vendor-Class und den Option-55-Fingerprint.

    Option 55 (Parameter Request List) ist die Reihenfolge der angefragten
    Optionen und je nach OS/Stack sehr charakteristisch -- damit laesst sich
    der Geraetetyp auch ohne brauchbare MAC bestimmen (Fingerbank-Prinzip).
    """

    name = "dhcp"
    bpf = "udp and (port 67 or port 68)"

    def parse(self, pkt: Packet) -> Iterable[Observation]:
        if DHCP not in pkt or BOOTP not in pkt:
            return
        chaddr = pkt[BOOTP].chaddr[:6]
        mac = norm_mac(bytes(chaddr)) or (norm_mac(pkt[Ether].src) if Ether in pkt else None)
        if not mac:
            return

        facts: dict[str, str] = {}
        hostname = None
        msg_type = None
        requested_ip = None

        for opt in pkt[DHCP].options:
            if not isinstance(opt, tuple) or len(opt) < 2:
                continue
            key, value = opt[0], opt[1]
            if key == "message-type":
                msg_type = _DHCP_MSG_TYPES.get(int(value), str(value))
            elif key == "hostname":
                hostname = _decode(value)
            elif key == "vendor_class_id":
                facts["vendor_class"] = _decode(value)
            elif key == "param_req_list":
                seq = value if isinstance(value, (list, tuple)) else list(value)
                facts["dhcp_fingerprint"] = ",".join(str(int(x)) for x in seq)
            elif key == "requested_addr":
                requested_ip = str(value)
            elif key == "client_FQDN":
                fqdn = _decode(value)
                if fqdn:
                    hostname = hostname or fqdn.strip("\x00 ")

        if msg_type:
            facts["dhcp_last_msg"] = msg_type

        # Bei ACK/OFFER steht die vergebene IP in yiaddr.
        ip = None
        yiaddr = pkt[BOOTP].yiaddr
        if yiaddr and yiaddr != "0.0.0.0":
            ip = yiaddr
        elif pkt[BOOTP].ciaddr and pkt[BOOTP].ciaddr != "0.0.0.0":
            ip = pkt[BOOTP].ciaddr
        elif requested_ip:
            ip = requested_ip

        # dhcp_seen nur bei Nachrichten *vom Client* -- ein Offer/ACK vom
        # Server richtet sich zwar an den Client, beweist aber ebenso, dass er
        # DHCP spricht. Beides zaehlt, ein Static-Host taucht hier nie auf.
        yield Observation(
            mac=mac, ip=ip, hostname=hostname, facts=facts, source=self.name, dhcp_seen=True
        )


def _decode(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").strip("\x00").strip()
    return str(value).strip()


# ----------------------------------------------------------------------- mDNS

_TXT_KEYS = {
    b"md": "model",          # Apple: Geraetemodell, z.B. "MacBookPro18,3"
    b"model": "model",
    b"am": "model",          # AirPlay
    b"osxvers": "os_version",
    b"ty": "model",          # Drucker (Bonjour)
    b"usb_MDL": "model",
    b"usb_MFG": "manufacturer",
    b"fn": "friendly_name",  # Chromecast
    b"vs": "firmware",
}


class MdnsParser:
    """Bonjour/Avahi. Apple-Geraete, Drucker, Chromecasts und viel IoT
    veroeffentlichen hier Hostname, Modell und Dienste voellig ungefragt."""

    name = "mdns"
    bpf = "udp port 5353"

    def parse(self, pkt: Packet) -> Iterable[Observation]:
        if DNS not in pkt or Ether not in pkt:
            return
        mac = norm_mac(pkt[Ether].src)
        if not mac:
            return
        # Fuer die Reflector-Pruefung wird die IPv4-Quelle getrennt gehalten:
        # der A-Record ist immer IPv4, und ein Vergleich gegen eine
        # IPv6-Absenderadresse wuerde jedes Geraet, das mDNS ueber IPv6
        # schickt, faelschlich zum Weiterleiter erklaeren.
        ipv4_src = pkt["IP"].src if pkt.haslayer("IP") else None
        ip = ipv4_src or (pkt[IPv6].src if IPv6 in pkt else None)

        dns = pkt[DNS]
        hostname = None
        facts: dict[str, str] = {}
        services: set[str] = set()
        #: IPv4 aus den A-Records. Weicht sie von der Absenderadresse ab, hat
        #: jemand die Ankuendigung weitergereicht statt selbst gesendet.
        announced_ip = None

        for section in ("an", "ns", "ar"):
            for rr in _iter_records(getattr(dns, section, None)):
                rrname = _decode(rr.rrname).rstrip(".")
                rtype = rr.type
                if rtype in (1, 28) and rrname.endswith(".local"):  # A / AAAA
                    hostname = hostname or rrname[: -len(".local")]
                    if rtype == 1 and announced_ip is None:
                        announced_ip = _decode(getattr(rr, "rdata", "") or "")
                elif rtype == 12:  # PTR -> Dienstname
                    svc = _decode(getattr(rr, "rdata", b"")).rstrip(".")
                    if "._tcp" in rrname or "._udp" in rrname:
                        services.add(rrname.split(".local")[0])
                    elif "._tcp" in svc or "._udp" in svc:
                        services.add(svc.split(".local")[0])
                elif rtype == 33:  # SRV -- nennt Port und Zielhost des Dienstes
                    port = getattr(rr, "port", None)
                    if port and ("._http._tcp" in rrname or "._https._tcp" in rrname):
                        scheme = "https" if "._https._tcp" in rrname else "http"
                        facts["web_endpoint"] = f"{scheme}:{int(port)}"
                elif rtype == 16:  # TXT
                    for k, target in _parse_txt(getattr(rr, "rdata", None)).items():
                        facts.setdefault(k, target)

        if services:
            facts["mdns_services"] = ",".join(sorted(services)[:12])
        if not hostname and not facts:
            # Reine Query ohne Inhalt -- trotzdem Anwesenheitsbeleg.
            yield Observation(mac=mac, ip=ip, source=self.name)
            return

        # Ein mDNS-Reflector (UniFi, Avahi-Repeater) reicht Ankuendigungen
        # ueber VLAN-Grenzen weiter und setzt dabei seine *eigene* Absender-MAC
        # ein. Wuerde man die Merkmale dem Absender zuschreiben, saugt der
        # Router die Identitaet jedes Geraets auf, fuer das er spiegelt --
        # gemessen: ein UDM-Pro mit 25 fremden Hostnamen und Modellen.
        #
        # Die Wahrheit steht im Paket: der A-Record nennt die Adresse des
        # gemeinten Geraets. Weicht sie vom Absender ab, wird nach ihr
        # zugeordnet statt nach der MAC.
        if announced_ip and ipv4_src and announced_ip != ipv4_src:
            yield Observation(
                mac=mac, ip=ip, facts={"role": "mdns_reflector"}, source=self.name
            )
            yield Observation(
                mac=None, ip=announced_ip, hostname=hostname, facts=facts, source=self.name
            )
            return

        yield Observation(mac=mac, ip=ip, hostname=hostname, facts=facts, source=self.name)


def _iter_records(section):
    """DNS-Records durchlaufen.

    scapy stellt die Abschnitte je nach Version und Herkunft des Pakets
    entweder als Liste dar oder als ueber .payload verkettete DNSRR-Pakete.
    Beides muss funktionieren, sonst verlieren wir mDNS auf manchen Systemen.
    """
    if section is None:
        return
    if isinstance(section, (list, tuple)):
        yield from section
        return
    current = section
    seen = 0
    while current is not None and seen < 64:  # Schleifenschutz
        if getattr(current, "rrname", None) is None:
            break
        yield current
        current = getattr(current, "payload", None)
        if current is not None and not getattr(current, "rrname", None):
            break
        seen += 1


def _parse_txt(rdata) -> dict[str, str]:
    out: dict[str, str] = {}
    if rdata is None:
        return out
    chunks = rdata if isinstance(rdata, (list, tuple)) else [rdata]
    for chunk in chunks:
        if not isinstance(chunk, bytes):
            continue
        key, _, value = chunk.partition(b"=")
        target = _TXT_KEYS.get(key.strip())
        if target and value:
            out[target] = _decode(value)[:120]
    return out


# ----------------------------------------------------------------------- SSDP

_SSDP_HEADER = re.compile(rb"^([A-Za-z0-9\-\.]+)\s*:\s*(.*)$", re.MULTILINE)


class SsdpParser:
    """UPnP/SSDP: SERVER-Header nennt oft OS, Produkt und Firmware."""

    name = "ssdp"
    bpf = "udp port 1900"

    def parse(self, pkt: Packet) -> Iterable[Observation]:
        if Ether not in pkt or not pkt.haslayer("Raw"):
            return
        mac = norm_mac(pkt[Ether].src)
        if not mac:
            return
        ip = pkt["IP"].src if pkt.haslayer("IP") else None
        payload = bytes(pkt["Raw"].load)[:2048]

        facts: dict[str, str] = {}
        for match in _SSDP_HEADER.finditer(payload):
            name = match.group(1).decode("ascii", "replace").lower()
            value = match.group(2).decode("utf-8", "replace").strip()
            if name == "server" and value:
                facts["ssdp_server"] = value[:200]
            elif name in ("nt", "st") and value.startswith("urn:"):
                facts["upnp_type"] = value[:120]
            elif name == "location" and value:
                facts["upnp_location"] = value[:200]
        if not facts:
            return
        yield Observation(mac=mac, ip=ip, facts=facts, source=self.name)


# ----------------------------------------------------------------- IPv6 / NDP


class NdpParser:
    """IPv6 Neighbor Discovery.

    Wichtig, weil viele Geraete per IPv4 stumm sind, aber per IPv6 munter
    Neighbor Solicitations verschicken -- oder umgekehrt.
    """

    name = "ndp"
    bpf = "icmp6"

    def parse(self, pkt: Packet) -> Iterable[Observation]:
        if Ether not in pkt or IPv6 not in pkt:
            return
        mac = norm_mac(pkt[Ether].src)
        if not mac:
            return
        src = pkt[IPv6].src
        ip = src if src and src != "::" else None
        facts: dict[str, str] = {}
        if ICMPv6ND_RA in pkt:
            facts["role"] = "router"  # sendet Router Advertisements
        elif ICMPv6ND_NA in pkt or ICMPv6ND_NS in pkt:
            pass
        else:
            return
        yield Observation(mac=mac, ip=ip, facts=facts, source=self.name)


# ----------------------------------------------------------------------- LLDP


class LldpParser:
    """LLDP-Frames von Switches/APs -- liefert Infrastruktur geschenkt.

    Wir lesen SysName/PortID/SysDescr aus den TLVs. Managed Switches senden
    das periodisch von sich aus.
    """

    name = "lldp"
    bpf = "ether proto 0x88cc"

    _TLV_SYS_NAME = 5
    _TLV_SYS_DESC = 6
    _TLV_PORT_ID = 2
    _ETHERTYPE = 0x88CC

    def parse(self, pkt: Packet) -> Iterable[Observation]:
        # Zwingend: der gemeinsame BPF-Filter laesst auch ARP & Co. durch, und
        # jeder Parser sieht jedes Paket. Ohne diese Pruefung wuerde hier jedes
        # Geraet im Netz als Infrastruktur markiert.
        if Ether not in pkt or _ethertype(pkt) != self._ETHERTYPE:
            return
        mac = norm_mac(pkt[Ether].src)
        if not mac:
            return
        raw = bytes(pkt.payload) if not pkt.haslayer("Raw") else bytes(pkt["Raw"].load)
        facts = {"role": "infrastructure"}
        for tlv_type, value in _iter_lldp_tlvs(raw):
            if tlv_type == self._TLV_SYS_NAME:
                facts["lldp_sysname"] = _decode(value)[:120]
            elif tlv_type == self._TLV_SYS_DESC:
                facts["lldp_sysdescr"] = _decode(value)[:250]
            elif tlv_type == self._TLV_PORT_ID and len(value) > 1:
                facts["lldp_portid"] = _decode(value[1:])[:60]
        yield Observation(
            mac=mac, hostname=facts.get("lldp_sysname"), facts=facts, source=self.name
        )


def _ethertype(pkt: Packet) -> int | None:
    """Ethertype hinter eventuellen VLAN-Tags."""
    layer = pkt[Ether]
    seen = 0
    while layer is not None and seen < 4:
        etype = getattr(layer, "type", None)
        if etype not in (0x8100, 0x88A8):  # 802.1Q / 802.1ad -> weitersuchen
            return etype
        layer = layer.payload
        seen += 1
    return None


def _iter_lldp_tlvs(raw: bytes):
    offset = 0
    while offset + 2 <= len(raw):
        header = int.from_bytes(raw[offset : offset + 2], "big")
        tlv_type, length = header >> 9, header & 0x1FF
        offset += 2
        if tlv_type == 0 or offset + length > len(raw):
            break
        yield tlv_type, raw[offset : offset + length]
        offset += length


ALL_PARSERS = [
    ArpParser(),
    DhcpParser(),
    MdnsParser(),
    SsdpParser(),
    NdpParser(),
    LldpParser(),
]
