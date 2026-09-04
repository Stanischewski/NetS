"""FastAPI-Anwendung: REST-API + WebUI.

Die UI kennt keinen einzigen Hersteller. Sie holt sich unter
/api/adapter-types die Selbstbeschreibung jedes Adapters und baut das
Konfigurationsformular daraus.
"""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .. import adapters, topology
from ..collect.active import nmap_scan
from ..daemon import DEFAULTS, Daemon
from ..store import PRESENCE_BUCKET, Store, json_config
from ..util import now

log = logging.getLogger("nets.web")

STATIC_DIR = Path(__file__).parent / "static"
MASK = "********"

#: Die Oberflaeche wird bei jedem Neubau ausgetauscht. Ohne Cache-Control
#: wendet der Browser heuristisches Caching an und liefert die alte Datei aus,
#: *ohne* nachzufragen -- dann steht der neue Reiter im HTML, dahinter laeuft
#: aber noch der alte Code. "no-cache" heisst nicht "nicht speichern", sondern
#: "vor Benutzung nachfragen"; dank ETag kostet das im Normalfall ein 304.
_NO_CACHE = {"Cache-Control": "no-cache"}


class _RevalidatingStatic(StaticFiles):
    def file_response(self, *args, **kwargs):
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-cache"
        return response

state: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    store: Store = app.state.store
    daemon = Daemon(store)
    state["daemon"] = daemon
    await daemon.start()
    try:
        yield
    finally:
        await daemon.stop()
        store.close()


def create_app(db_path: str) -> FastAPI:
    app = FastAPI(title="NetS", lifespan=lifespan)
    app.state.store = Store(db_path)

    def store() -> Store:
        return app.state.store

    def daemon() -> Daemon:
        return state["daemon"]

    # ------------------------------------------------------------------ Status

    @app.get("/api/status")
    def api_status():
        conn = store().conn
        counts = conn.execute(
            """
            SELECT
              (SELECT COUNT(*) FROM devices WHERE ignored=0)                            AS devices,
              (SELECT COUNT(*) FROM devices WHERE ignored=0 AND last_seen > ?)          AS online,
              (SELECT COUNT(*) FROM devices WHERE ignored=0 AND mac_random=1)           AS randomized,
              (SELECT COUNT(*) FROM devices WHERE ignored=0 AND addr_mode='static')     AS static_devices,
              (SELECT COUNT(*) FROM devices WHERE ignored=0 AND addr_mode='dhcp')       AS dhcp_devices,
              (SELECT COUNT(*) FROM attachments)                                        AS attached,
              (SELECT COUNT(*) FROM net_devices WHERE enabled=1)                        AS adapters
            """,
            (now() - 600,),
        ).fetchone()
        return {"counts": dict(counts), **daemon().status()}

    # ----------------------------------------------------------------- Geraete

    @app.get("/api/devices")
    def api_devices(
        q: str = "",
        seen_within_days: int | None = None,
        addr_mode: str | None = None,
        include_ignored: bool = False,
        limit: int = Query(500, le=5000),
    ):
        sql = [
            """
            SELECT d.*,
              (SELECT ip FROM addresses a WHERE a.device_id=d.id AND a.family=4
               ORDER BY a.last_seen DESC LIMIT 1) AS ip,
              (SELECT COUNT(*) FROM addresses a WHERE a.device_id=d.id)        AS ip_count,
              (SELECT n.name || ' / ' || at.port_key FROM attachments at
                 JOIN net_devices n ON n.id=at.net_device_id
                WHERE at.device_id=d.id)                                       AS attachment,
              (SELECT at.medium FROM attachments at WHERE at.device_id=d.id)   AS medium,
              (SELECT COUNT(*) FROM presence p WHERE p.device_id=d.id)         AS presence_buckets
            FROM devices d WHERE 1=1
            """
        ]
        params: list = []
        if not include_ignored:
            sql.append("AND d.ignored=0")
        if q:
            sql.append(
                "AND (d.mac LIKE ? OR d.hostname LIKE ? OR d.vendor LIKE ? OR d.label LIKE ?"
                " OR EXISTS (SELECT 1 FROM addresses a WHERE a.device_id=d.id AND a.ip LIKE ?))"
            )
            params += [f"%{q}%"] * 5
        if seen_within_days:
            sql.append("AND d.last_seen >= ?")
            params.append(now() - seen_within_days * 86400)
        if addr_mode:
            sql.append("AND d.addr_mode = ?")
            params.append(addr_mode)
        sql.append("ORDER BY d.last_seen DESC LIMIT ?")
        params.append(limit)

        return [dict(r) for r in store().conn.execute(" ".join(sql), params)]

    @app.get("/api/devices/{device_id}")
    def api_device(device_id: int):
        conn = store().conn
        device = conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        if device is None:
            raise HTTPException(404, "Unbekanntes Geraet")

        facts = [dict(r) for r in conn.execute(
            "SELECT ts, source, key, value FROM facts WHERE device_id=? ORDER BY key, ts DESC", (device_id,)
        )]
        addresses = [dict(r) for r in conn.execute(
            "SELECT ip, family, source, first_seen, last_seen FROM addresses "
            "WHERE device_id=? ORDER BY last_seen DESC", (device_id,)
        )]
        # Anwesenheit der letzten 30 Tage, stundenweise verdichtet.
        since = now() - 30 * 86400
        timeline = [
            {"t": r["hour"], "hits": r["hits"]}
            for r in conn.execute(
                "SELECT (bucket / 3600) * 3600 AS hour, SUM(hits) AS hits FROM presence "
                "WHERE device_id=? AND bucket >= ? GROUP BY hour ORDER BY hour",
                (device_id, since),
            )
        ]
        attachment = conn.execute(
            "SELECT n.name AS net_device, a.port_key, a.medium, a.confidence, a.ts "
            "FROM attachments a JOIN net_devices n ON n.id=a.net_device_id WHERE a.device_id=?",
            (device_id,),
        ).fetchone()
        history = [dict(r) for r in conn.execute(
            "SELECT f.first_seen, f.last_seen, n.name AS net_device, f.port_key, "
            "       NULLIF(f.vlan, -1) AS vlan "
            "FROM fdb f JOIN net_devices n ON n.id=f.net_device_id WHERE f.mac=? "
            "ORDER BY f.last_seen DESC LIMIT 50", (device["mac"],)
        )]

        return {
            "device": dict(device),
            "facts": facts,
            "addresses": addresses,
            "timeline": timeline,
            "bucket_seconds": PRESENCE_BUCKET,
            "attachment": dict(attachment) if attachment else None,
            "port_history": history,
            "similar": store().similar_devices(device_id),
            "identity": _identity_of(store(), device),
        }

    def _identity_of(st, device) -> dict:
        """Ableitung samt Begruendung -- eine Vermutung ohne Beleg ist wertlos."""
        from .. import identify

        facts = {
            r["key"]: r["value"] for r in st.conn.execute(
                "SELECT key, value FROM facts WHERE device_id=? ORDER BY ts ASC", (device["id"],)
            )
        }
        known = {r["mac"] for r in st.conn.execute("SELECT mac FROM devices")}
        mac_kind, detail = identify.classify_mac(
            device["mac"], known, has_guest_fact=bool(facts.get("guest_kind"))
        )
        result = identify.guess(facts, device["hostname"], mac_kind)
        result["mac_kind"] = mac_kind
        result["mac_kind_detail"] = detail
        return result

    @app.patch("/api/devices/{device_id}")
    def api_device_update(device_id: int, payload: dict = Body(...)):
        allowed = {"label", "notes", "ignored", "device_type"}
        fields = {k: v for k, v in payload.items() if k in allowed}
        if not fields:
            raise HTTPException(400, f"Erlaubte Felder: {', '.join(sorted(allowed))}")
        assignments = ", ".join(f"{k}=?" for k in fields)
        store().conn.execute(
            f"UPDATE devices SET {assignments} WHERE id=?", [*fields.values(), device_id]
        )
        return {"ok": True}

    # ------------------------------------------------------- Adapter / Infra

    @app.get("/api/adapter-types")
    def api_adapter_types():
        """Selbstbeschreibung aller Adapter -- die UI baut daraus die Formulare."""
        return adapters.all_types()

    @app.get("/api/net-devices")
    def api_net_devices():
        out = []
        for row in store().net_devices():
            config = json_config(row)
            out.append({
                "id": row["id"],
                "name": row["name"],
                "adapter_type": row["adapter_type"],
                "enabled": bool(row["enabled"]),
                "poll_seconds": row["poll_seconds"],
                "last_ok": row["last_ok"],
                "last_error": row["last_error"],
                "config": _mask(row["adapter_type"], config),
            })
        return out

    @app.post("/api/net-devices")
    def api_net_device_create(payload: dict = Body(...)):
        name = (payload.get("name") or "").strip()
        adapter_type = payload.get("adapter_type") or ""
        config = payload.get("config") or {}
        if not name:
            raise HTTPException(400, "Name fehlt")
        cls = adapters.Adapter.registry.get(adapter_type)
        if cls is None:
            raise HTTPException(400, f"Unbekannter Adaptertyp: {adapter_type}")
        errors = cls.validate(config)
        if errors:
            raise HTTPException(400, "; ".join(errors))
        cur = store().conn.execute(
            "INSERT INTO net_devices(name, adapter_type, config, enabled, poll_seconds) VALUES(?,?,?,?,?)",
            (name, adapter_type, json.dumps(config), int(bool(payload.get("enabled", True))),
             int(payload.get("poll_seconds", 300))),
        )
        return {"id": cur.lastrowid}

    @app.put("/api/net-devices/{net_id}")
    def api_net_device_update(net_id: int, payload: dict = Body(...)):
        row = _net_device(net_id)
        cls = adapters.Adapter.registry.get(row["adapter_type"])
        config = json_config(row)
        # Maskierte Passwortfelder bedeuten "unveraendert lassen".
        for key, value in (payload.get("config") or {}).items():
            if value != MASK:
                config[key] = value
        if cls and (errors := cls.validate(config)):
            raise HTTPException(400, "; ".join(errors))
        store().conn.execute(
            "UPDATE net_devices SET name=?, config=?, enabled=?, poll_seconds=?, last_error=NULL WHERE id=?",
            (
                (payload.get("name") or row["name"]).strip(),
                json.dumps(config),
                int(bool(payload.get("enabled", row["enabled"]))),
                int(payload.get("poll_seconds", row["poll_seconds"])),
                net_id,
            ),
        )
        return {"ok": True}

    @app.delete("/api/net-devices/{net_id}")
    def api_net_device_delete(net_id: int):
        store().conn.execute("DELETE FROM net_devices WHERE id=?", (net_id,))
        return {"ok": True}

    @app.post("/api/net-devices/{net_id}/test")
    async def api_net_device_test(net_id: int):
        row = _net_device(net_id)
        try:
            adapter = adapters.build(row["adapter_type"], json_config(row))
        except KeyError as exc:
            return JSONResponse({"ok": False, "message": str(exc)}, status_code=400)
        try:
            ok, message = await adapter.test()
        except Exception as exc:
            ok, message = False, f"{type(exc).__name__}: {exc}"
        finally:
            await adapter.close()
        store().set_adapter_status(net_id, ok, None if ok else message)
        return {"ok": ok, "message": message}

    @app.post("/api/net-devices/{net_id}/poll")
    async def api_net_device_poll(net_id: int):
        await daemon().poll_one(_net_device(net_id))
        row = _net_device(net_id)
        return {"ok": not row["last_error"], "message": row["last_error"] or "Abfrage abgeschlossen"}

    def _net_device(net_id: int):
        row = store().conn.execute("SELECT * FROM net_devices WHERE id=?", (net_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "Unbekanntes Netzwerkgeraet")
        return row

    def _mask(adapter_type: str, config: dict) -> dict:
        cls = adapters.Adapter.registry.get(adapter_type)
        secrets = {f.key for f in (cls.config_fields if cls else ()) if f.type == "password"}
        return {k: (MASK if k in secrets and v else v) for k, v in config.items()}

    # --------------------------------------------------------------- Topologie

    @app.get("/api/topology")
    def api_topology():
        return topology.tree(store())

    @app.post("/api/topology/rebuild")
    async def api_topology_rebuild():
        count = await asyncio.to_thread(topology.resolve, store())
        return {"resolved": count}

    # --------------------------------------------------------- Einstellungen

    @app.get("/api/settings")
    def api_settings():
        current = store().settings()
        return {key: current.get(key, default) for key, default in DEFAULTS.items()}

    @app.put("/api/settings")
    def api_settings_update(payload: dict = Body(...)):
        restart_sniffer = False
        for key, value in payload.items():
            if key not in DEFAULTS:
                continue
            if key in ("iface", "passive_enabled") and str(value) != store().get_setting(key):
                restart_sniffer = True
            store().set_setting(key, str(value))
        if restart_sniffer:
            if store().get_setting("passive_enabled") == "1":
                daemon().start_sniffer()
            elif daemon().sniffer:
                daemon().sniffer.stop()
                daemon().sniffer = None
        return {"ok": True, "sniffer_restarted": restart_sniffer}

    @app.get("/api/interfaces")
    async def api_interfaces():
        proc = await asyncio.create_subprocess_exec(
            "ip", "-j", "link", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        stdout, _ = await proc.communicate()
        try:
            return [i["ifname"] for i in json.loads(stdout or b"[]") if i.get("ifname") != "lo"]
        except json.JSONDecodeError:
            return []

    # ------------------------------------------------------------ Datenpflege

    @app.get("/api/data/stats")
    def api_data_stats():
        return store().stats()

    @app.post("/api/data/purge")
    def api_data_purge(payload: dict = Body(...)):
        """Loeschen gesammelter Daten.

        `confirm` ist Pflicht: ein versehentlicher Aufruf ohne Body darf
        niemals ein ganzes Inventar wegraeumen.
        """
        if payload.get("confirm") is not True:
            raise HTTPException(400, "Bestätigung fehlt (confirm: true)")
        scope = payload.get("scope")
        try:
            removed = store().purge(scope)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        log.warning("Daten geloescht (%s): %s", scope, removed)
        return {"scope": scope, "removed": removed, "total": sum(removed.values())}

    @app.post("/api/data/purge-stale")
    def api_data_purge_stale(payload: dict = Body(...)):
        if payload.get("confirm") is not True:
            raise HTTPException(400, "Bestätigung fehlt (confirm: true)")
        try:
            days = int(payload.get("days", 0))
        except (TypeError, ValueError):
            raise HTTPException(400, "days muss eine Zahl sein")
        if days < 1:
            raise HTTPException(400, "days muss mindestens 1 sein")
        removed = store().delete_devices_older_than(days)
        store().vacuum()
        return {"removed": removed, "days": days}

    @app.post("/api/data/vacuum")
    def api_data_vacuum():
        before = store().stats()["db_bytes"]
        store().vacuum()
        after = store().stats()["db_bytes"]
        return {"before": before, "after": after, "freed": max(0, before - after)}

    @app.delete("/api/devices/{device_id}")
    def api_device_delete(device_id: int):
        if not store().delete_device(device_id):
            raise HTTPException(404, "Unbekanntes Geraet")
        return {"ok": True}

    # ----------------------------------------------------- Sicherung / Umzug

    @app.get("/api/config/export")
    def api_config_export(include_secrets: bool = True):
        """Adapter und Einstellungen als JSON.

        Ohne Zugangsdaten ist die Sicherung nur die halbe Miete -- deshalb
        standardmaessig enthalten. Die Datei gehoert entsprechend behandelt.
        """
        devices = []
        for row in store().net_devices():
            config = json_config(row)
            if not include_secrets:
                cls = adapters.Adapter.registry.get(row["adapter_type"])
                secrets = {f.key for f in (cls.config_fields if cls else ()) if f.type == "password"}
                config = {k: v for k, v in config.items() if k not in secrets}
            devices.append({
                "name": row["name"],
                "adapter_type": row["adapter_type"],
                "config": config,
                "enabled": bool(row["enabled"]),
                "poll_seconds": row["poll_seconds"],
            })
        return {
            "version": 1,
            "exported_at": now(),
            "contains_secrets": include_secrets,
            "net_devices": devices,
            "settings": store().settings(),
        }

    @app.post("/api/config/import")
    def api_config_import(payload: dict = Body(...)):
        """Spielt eine Sicherung ein. Vorhandene Adapter gleichen Namens
        werden aktualisiert, nicht dupliziert."""
        if payload.get("version") != 1:
            raise HTTPException(400, "Unbekanntes Sicherungsformat")

        imported, skipped = 0, []
        for entry in payload.get("net_devices") or []:
            cls = adapters.Adapter.registry.get(entry.get("adapter_type", ""))
            if cls is None:
                skipped.append(f"{entry.get('name')}: Adaptertyp unbekannt")
                continue
            errors = cls.validate(entry.get("config") or {})
            if errors:
                skipped.append(f"{entry.get('name')}: {'; '.join(errors)}")
                continue
            store().conn.execute(
                "INSERT INTO net_devices(name, adapter_type, config, enabled, poll_seconds) "
                "VALUES(?,?,?,?,?) "
                "ON CONFLICT(name) DO UPDATE SET adapter_type=excluded.adapter_type, "
                "  config=excluded.config, enabled=excluded.enabled, poll_seconds=excluded.poll_seconds",
                (entry["name"], entry["adapter_type"], json.dumps(entry.get("config") or {}),
                 int(bool(entry.get("enabled", True))), int(entry.get("poll_seconds", 300))),
            )
            imported += 1

        for key, value in (payload.get("settings") or {}).items():
            if key in DEFAULTS:
                store().set_setting(key, str(value))

        return {"imported": imported, "skipped": skipped}

    # -------------------------------------------------------------- Subnetze

    @app.get("/api/subnets")
    async def api_subnets():
        """Was ist abgedeckt, was fehlt -- samt Vorschlaegen aus der Routing-Tabelle."""
        from ..collect.active import local_networks, routed_networks

        configured = [s.strip() for s in (store().get_setting("subnets") or "").split(",") if s.strip()]
        local = await local_networks()
        routed = await routed_networks()

        overview = []
        for entry in store().subnet_overview():
            entry = dict(entry)
            entry["configured"] = entry["subnet"] in configured
            entry["reach"] = ("lokal" if entry["subnet"] in local
                              else "geroutet" if entry["subnet"] in routed else "unbekannt")
            overview.append(entry)

        known = {e["subnet"] for e in overview}
        return {
            "subnets": overview,
            "configured": configured,
            # Was der Rechner selbst kennt, aber noch nicht durchsucht wird.
            "suggestions": {
                "lokal": [n for n in local if n not in configured],
                "geroutet": [n for n in routed if n not in configured and n not in known],
            },
        }

    @app.get("/api/subnet-hosts")
    def api_subnet_hosts():
        return [dict(r) for r in store().conn.execute(
            "SELECT * FROM subnet_hosts ORDER BY subnet, ip")]

    # ------------------------------------------------------- Weboberflaechen

    @app.get("/api/web-services")
    def api_web_services():
        return store().web_services()

    @app.post("/api/actions/web-scan")
    async def api_web_scan():
        """Manuell ausloesen -- auch wenn die Suche sonst abgeschaltet ist."""
        targets = store().scan_targets()
        found = await daemon().run_web_scan(force=True)
        return {"targets": len(targets), "found": found}

    @app.delete("/api/web-services/{service_id}")
    def api_web_service_delete(service_id: int):
        store().conn.execute("DELETE FROM web_services WHERE id=?", (service_id,))
        return {"ok": True}

    # -------------------------------------------------------------- Aktionen

    @app.post("/api/actions/sweep")
    async def api_sweep(payload: dict = Body(default={})):
        """Sweep von Hand ausloesen.

        Nutzt dieselbe Weiche wie der geplante Lauf -- ein eigener Pfad hier
        hiesse, dass der Knopf etwas anderes tut als der Zeitplan.
        """
        cidr = payload.get("cidr") or store().get_setting("subnets", "")
        if not cidr:
            raise HTTPException(400, "Kein Subnetz konfiguriert")
        result = await daemon().sweep_subnets(
            [c.strip() for c in cidr.split(",") if c.strip()]
        )
        return result

    @app.post("/api/actions/nmap")
    async def api_nmap(payload: dict = Body(...)):
        target = payload.get("target")
        if not target:
            raise HTTPException(400, "Ziel fehlt")
        try:
            count = await nmap_scan(store(), target, payload.get("args") or "-sS -T3 --top-ports 200 -O")
        except Exception as exc:
            raise HTTPException(500, str(exc))
        return {"hosts": count}

    # --------------------------------------------------------------------- UI

    app.mount("/static", _RevalidatingStatic(directory=STATIC_DIR), name="static")

    @app.get("/")
    def index():
        return FileResponse(STATIC_DIR / "index.html", headers=_NO_CACHE)

    return app
