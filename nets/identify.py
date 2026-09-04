"""Was ist das für ein Gerät -- auch wenn die MAC nichts verrät.

Bei randomisierten MACs ist der Hersteller-Lookup wertlos. Die Information
steckt dann woanders, und zwar in Daten, die wir ohnehin schon einsammeln:

* **DHCP Option 55** (Parameter Request List). Die *Reihenfolge* der
  angefragten Optionen ist je nach DHCP-Client charakteristisch und aendert
  sich mit der MAC nicht mit -- das Fingerbank-Prinzip.
* **DHCP Option 60** (Vendor Class). Android schickt dort seine Version mit.
* **mDNS-TXT-Records**. Fernseher, Drucker und Chromecasts nennen ihr Modell
  im Klartext.

Ausserdem ist laengst nicht jede lokal vergebene MAC ein Privacy-Handy: BSSIDs
von Access Points und die MACs virtueller Maschinen sehen genauso aus. Sie
alle als "zufaellig" zu labeln verschenkt Information, die wir haben.
"""

from __future__ import annotations

from .util import base_mac_of_bssid, is_locally_administered

# --------------------------------------------------------------- MAC-Herkunft

MAC_PRIVACY = "privacy"        # Privacy-MAC eines Endgeraets
MAC_BSSID = "bssid"            # Funkmodul eines bekannten Geraets
MAC_VIRTUAL = "virtual"        # von einem Hypervisor/Container vergeben
MAC_GLOBAL = "global"          # regulaer vom Hersteller vergeben

#: Praefixe, die Virtualisierer fuer ihre Schnittstellen verwenden.
_VIRTUAL_PREFIXES = {
    "525400": "QEMU/KVM",
    "0242": "Docker",
    "0a0027": "VirtualBox",
    "00163e": "Xen",
    "001c42": "Parallels",
}


def classify_mac(mac: str, known_macs=None, has_guest_fact: bool = False) -> tuple[str, str | None]:
    """Gibt (Art, Erlaeuterung) zurueck.

    `known_macs` sind die MACs, die wir sonst noch kennen -- nur damit laesst
    sich eine BSSID ihrem Geraet zuordnen.
    """
    flat = mac.replace(":", "")
    for prefix, name in _VIRTUAL_PREFIXES.items():
        if flat.startswith(prefix):
            return MAC_VIRTUAL, name
    if has_guest_fact:
        return MAC_VIRTUAL, "Virtualisierung"
    if not is_locally_administered(mac):
        return MAC_GLOBAL, None

    base = base_mac_of_bssid(mac)
    if base and known_macs and base in known_macs:
        return MAC_BSSID, base
    return MAC_PRIVACY, None


# ------------------------------------------------------------ DHCP-Fingerprint

#: DHCP Option 55, exakte Reihenfolge. Bewusst kurz gehalten und nur mit
#: Signaturen, die im Feld wirklich vorkommen -- eine unvollstaendige Liste ist
#: besser als eine mit falschen Treffern.
FINGERPRINTS: dict[str, str] = {
    "1,121,3,6,15,108,114,119,252": "iOS / iPadOS",
    "1,121,3,6,15,108,114,119,162,252": "iOS / iPadOS",
    "1,121,3,6,15,119,252,95,44,46": "macOS",
    "1,121,3,6,15,119,252": "macOS",
    "1,3,6,15,26,28,51,58,59,43,114,108": "Android",
    "1,3,6,15,26,28,51,58,59,43": "Android",
    "1,3,6,15,26,28,51,58,59": "Android (älter)",
    "1,3,6,15,31,33,43,44,46,47,119,121,249,252": "Windows",
    "1,15,3,6,44,46,47,31,33,121,249,43": "Windows (älter)",
    "1,28,2,3,15,6,119,12,44,47,26,121,42": "Linux (dhclient)",
    "1,3,6,12,15,26,28,121,42": "Linux (systemd-networkd)",
    "1,3,6,12,15,17,23,28,29,31,33,40,41,42,119": "Linux (dhcpcd)",
    "1,3,28,6": "ESP32 / ESP8266",
    "1,3,6,12,15,28,42": "eingebettetes Linux",
    "1,3,6,15,28,33,51,58,59": "Drucker / Embedded",
}


def os_from_fingerprint(fingerprint: str | None) -> tuple[str | None, float]:
    """Ordnet einen Option-55-Fingerprint einem System zu.

    Exakter Treffer zaehlt voll. Sonst wird ueber die Schnittmenge verglichen --
    Clients variieren ihre Liste je nach Version leicht, die Grundmenge bleibt
    aber gleich. Unter 75 % Aehnlichkeit wird nichts behauptet.
    """
    if not fingerprint:
        return None, 0.0
    if fingerprint in FINGERPRINTS:
        return FINGERPRINTS[fingerprint], 1.0

    wanted = set(fingerprint.split(","))
    best, score = None, 0.0
    for known, name in FINGERPRINTS.items():
        other = set(known.split(","))
        similarity = len(wanted & other) / len(wanted | other)
        if similarity > score:
            best, score = name, similarity
    return (best, round(score, 2)) if score >= 0.75 else (None, round(score, 2))


def os_from_vendor_class(vendor_class: str | None) -> str | None:
    """Option 60 ist oft eindeutiger als der Fingerprint."""
    if not vendor_class:
        return None
    value = vendor_class.strip()
    lowered = value.lower()
    if lowered.startswith("android-dhcp-"):
        return f"Android {value[len('android-dhcp-'):]}"
    if lowered.startswith("msft"):
        return "Windows"
    if lowered.startswith("dhcpcd"):
        return "Linux (dhcpcd)"
    if lowered.startswith("udhcp"):
        return "BusyBox / Embedded"
    return None


# --------------------------------------------------------------- Geraetetypen

_TYPE_BY_SERVICE = {
    "_googlecast._tcp": "Streaming / TV",
    "_airplay._tcp": "Streaming / TV",
    "_raop._tcp": "Lautsprecher",
    "_ipp._tcp": "Drucker",
    "_pdl-datastream._tcp": "Drucker",
    "_printer._tcp": "Drucker",
    "_shelly._tcp": "Smart Home",
    "_hap._tcp": "Smart Home",
    "_companion-link._tcp": "Apple-Gerät",
    "_smb._tcp": "NAS / Server",
    "_ssh._tcp": "Server",
}

_TYPE_BY_OS = {
    "iOS / iPadOS": "Smartphone / Tablet",
    "Android": "Smartphone / Tablet",
    "macOS": "Computer",
    "Windows": "Computer",
    "ESP32 / ESP8266": "IoT",
}


def transience(presence_buckets: int, ip_count: int, active_minutes: int) -> str | None:
    """Unterscheidet fluechtige Erscheinungen von echten Dauergaesten.

    Eine MAC, die genau einmal in einer Switch-Tabelle auftaucht und nie eine
    IP hatte, ist kein Geraet im Netz -- das ist eine kurz assoziierte Station
    oder ein Rotationsartefakt. Sie mit einem monatelang aktiven Geraet in eine
    Liste zu werfen, macht die Liste unbrauchbar.
    """
    if ip_count == 0 and presence_buckets <= 1:
        return "flüchtig — einmalig gesehen, nie eine IP"
    if ip_count == 0 and active_minutes < 60:
        return "flüchtig — kurz aktiv, nie eine IP"
    return None


def guess(facts: dict[str, str], hostname: str | None = None,
          mac_kind: str = MAC_GLOBAL) -> dict:
    """Leitet aus den gesammelten Merkmalen Betriebssystem und Typ ab.

    Gibt zurueck: os_guess, device_type, label (beste Kurzbeschreibung),
    evidence (worauf die Aussage beruht).
    """
    evidence: list[str] = []

    # Vendor Class schlaegt den Fingerprint -- sie nennt oft die Version.
    os_guess = os_from_vendor_class(facts.get("vendor_class"))
    if os_guess:
        evidence.append(f"DHCP Vendor-Class „{facts['vendor_class']}“")
    else:
        os_guess, score = os_from_fingerprint(facts.get("dhcp_fingerprint"))
        if os_guess:
            evidence.append(
                f"DHCP-Fingerprint {facts['dhcp_fingerprint']}"
                + ("" if score == 1.0 else f" (≈{int(score * 100)} %)")
            )

    # Modell aus mDNS/SSDP ist die konkreteste Angabe, die es gibt.
    model = facts.get("model") or facts.get("friendly_name")
    if model:
        evidence.append("mDNS-Modellangabe")

    device_type = None
    # Reihenfolge nach Belastbarkeit: was ein Hypervisor oder die MAC-Struktur
    # *sagt*, schlaegt das, was aus einem angebotenen Dienst geraten ist. Eine
    # VM, die mit Shellys spricht, ist eine VM -- kein Smart-Home-Geraet.
    if facts.get("guest_kind"):
        device_type = "VM" if facts["guest_kind"] == "vm" else "Container"
        evidence.append(facts.get("guest_note") or "vom Virtualisierer gemeldet")
    elif mac_kind == MAC_BSSID:
        device_type = "Funkmodul"
    else:
        for service in (facts.get("mdns_services") or "").split(","):
            if service in _TYPE_BY_SERVICE:
                device_type = _TYPE_BY_SERVICE[service]
                evidence.append(f"mDNS-Dienst {service}")
                break
    if device_type is None and os_guess:
        device_type = _TYPE_BY_OS.get(os_guess.split()[0] if os_guess else "", None) \
            or _TYPE_BY_OS.get(os_guess)
    if device_type is None and facts.get("ssdp_server"):
        device_type = "UPnP-Gerät"

    # Kurzbeschreibung: das Konkreteste zuerst.
    label = model or hostname or os_guess or device_type
    if model and os_guess:
        label = f"{model} ({os_guess})"

    return {
        "os_guess": os_guess,
        "device_type": device_type,
        "label": label,
        "evidence": evidence,
    }
