"""Adapter-Registry.

Import genuegt zur Registrierung -- Adapter melden sich per __init_subclass__
selbst an. Ein neuer Hersteller braucht nur eine Datei hier und eine Zeile in
`_MODULES`; Kern und WebUI bleiben unveraendert.
"""

from __future__ import annotations

import importlib
import logging

from .base import (  # noqa: F401  (Re-Export fuer Adapterautoren)
    Adapter,
    Capability,
    ConfigField,
    FdbEntry,
    HostInfo,
    Identity,
    Lease,
    Neighbor,
    Port,
    WirelessClient,
    all_types,
    build,
)

log = logging.getLogger("nets.adapters")

_MODULES = ["snmp", "unifi", "openwrt", "mikrotik", "fritzbox", "proxmox"]

for _name in _MODULES:
    try:
        importlib.import_module(f"{__name__}.{_name}")
    except ImportError as exc:
        # Ein Adapter mit fehlender optionaler Abhaengigkeit darf den Rest
        # nicht mit runterreissen -- er taucht dann nur nicht in der UI auf.
        log.warning("Adapter '%s' nicht geladen: %s", _name, exc)

__all__ = [
    "Adapter", "Capability", "ConfigField", "FdbEntry", "HostInfo", "Identity",
    "Lease", "Neighbor", "Port", "WirelessClient", "all_types", "build",
]
