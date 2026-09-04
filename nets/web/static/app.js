"use strict";

const api = {
  async get(path) {
    const r = await fetch(path);
    if (!r.ok) throw new Error(await r.text());
    return r.json();
  },
  async send(method, path, body) {
    const r = await fetch(path, {
      method,
      headers: { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await r.text();
    const data = text ? JSON.parse(text) : {};
    if (!r.ok) throw new Error(data.detail || text);
    return data;
  },
};

const el = (tag, attrs = {}, ...kids) => {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined) node.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    node.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return node;
};

const ago = (ts) => {
  if (!ts) return "nie";
  const s = Math.max(0, Math.floor(Date.now() / 1000) - ts);
  if (s < 90) return `vor ${s}s`;
  if (s < 5400) return `vor ${Math.round(s / 60)} min`;
  if (s < 172800) return `vor ${Math.round(s / 3600)} h`;
  return `vor ${Math.round(s / 86400)} Tagen`;
};

const MODE_LABEL = { dhcp: "DHCP", static: "statisch", unknown: "unklar" };

const MAC_KIND_LABEL = {
  privacy: "Privacy-MAC des Geräts (rotiert)",
  bssid: "Funkmodul — abgeleitet aus der Geräte-MAC",
  virtual: "von einem Hypervisor/Container vergeben",
  global: "regulär vom Hersteller vergeben",
};

/** Was wir über ein Gerät wissen, wenn die MAC nichts verrät. */
const identityText = (d) =>
  [d.os_guess, d.device_type].filter(Boolean).join(" · ") || "";

// ---------------------------------------------------------------- Navigation

document.querySelectorAll("#tabs button").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("active", b === btn));
    document.querySelectorAll(".tab").forEach((t) =>
      t.classList.toggle("active", t.id === `tab-${btn.dataset.tab}`)
    );
    if (btn.dataset.tab === "topology") loadTopology();
    if (btn.dataset.tab === "web") loadWeb();
    if (btn.dataset.tab === "infra") loadInfra();
    if (btn.dataset.tab === "settings") { loadSettings(); loadData(); }
    if (btn.dataset.tab === "devices") loadDevices();
  });
});

const modal = document.getElementById("modal");
document.getElementById("modal-close").onclick = () => modal.classList.add("hidden");
modal.addEventListener("click", (e) => { if (e.target === modal) modal.classList.add("hidden"); });
const showModal = (...content) => {
  const body = document.getElementById("modal-body");
  body.replaceChildren(...content);
  modal.classList.remove("hidden");
};

// ----------------------------------------------------------------- Übersicht

async function loadStatus() {
  let s;
  try {
    s = await api.get("/api/status");
  } catch {
    document.getElementById("health").className = "pill err";
    document.getElementById("health").textContent = "Backend nicht erreichbar";
    return;
  }
  const c = s.counts;
  const stats = [
    ["Geräte gesamt", c.devices],
    ["gerade aktiv", c.online],
    ["per DHCP", c.dhcp_devices],
    ["statisch", c.static_devices],
    ["zufällige MAC", c.randomized],
    ["Port zugeordnet", c.attached],
  ];
  document.getElementById("stats").replaceChildren(
    ...stats.map(([label, n]) =>
      el("div", { class: "stat" }, el("div", { class: "n" }, n ?? 0), el("div", { class: "l" }, label))
    )
  );

  const sn = s.sniffer || {};
  const health = document.getElementById("health");
  health.className = `pill ${sn.running ? (sn.packets_seen ? "ok" : "warn") : "err"}`;
  health.textContent = !sn.running ? "Sniffer aus"
    : sn.packets_seen ? `Sniffer läuft auf ${sn.iface}`
    : `${sn.iface}: noch keine Pakete`;

  document.getElementById("collector-status").replaceChildren(
    el("dl", { class: "kv" },
      el("dt", {}, "Passiver Sniffer"),
      el("dd", {}, sn.running
        ? `aktiv auf ${sn.iface} — ${sn.packets_seen ?? 0} Pakete`
        + (Object.keys(sn.per_iface || {}).length > 1
            ? ` (${Object.entries(sn.per_iface).map(([i, n]) => `${i}: ${n}`).join(", ")})`
            : "")
        + `, ${sn.parse_errors ?? 0} Parse-Fehler`
        + (sn.packets_seen === 0
            ? "  ⚠ Es kommt kein Broadcast an — Bridge/Firewall des Containers prüfen."
            : "")
        : `nicht aktiv — ${sn.error || "Rechte (CAP_NET_RAW) oder Interface prüfen"}`),
      el("dt", {}, "Parser"),
      el("dd", { class: "mono" }, (sn.parsers || []).join(", ") || "—"),
      el("dt", {}, "Watchdog"),
      el("dd", {}, sn.restarts
        ? `${sn.restarts} Neustart(s), zuletzt ${ago(sn.last_restart)} — ${sn.last_restart_reason || ""}`
        : "keine Neustarts nötig"),
      el("dt", {}, "WLAN-Mitschnitt"),
      el("dd", {}, (() => {
        const w = s.wifi || {};
        if (!w.running) return w.error || (w.iface ? "nicht aktiv" : "nicht konfiguriert");
        return `${w.iface}, Kanal ${w.channel ?? "?"} — ${w.frames_seen ?? 0} Frames, `
          + `${w.associations ?? 0} Zuordnungen, ${(w.networks || []).length} Funknetze`;
      })()),
      el("dt", {}, "Adapter-Abfrage"),
      el("dd", {}, ago(s.last_runs?.adapters)),
      el("dt", {}, "Topologie"),
      el("dd", {}, ago(s.last_runs?.topology)),
      el("dt", {}, "Sweep"),
      el("dd", {}, ago(s.last_runs?.sweep)),
    )
  );

  const recent = await api.get("/api/devices?limit=10");
  document.getElementById("recent").replaceChildren(deviceTable(recent, true));
}

// -------------------------------------------------------------------- Geräte

/**
 * Spaltendefinition. `text` liefert den Wert für Sortierung und Export,
 * `cell` optional eine reichere Darstellung für die Tabelle. So bleiben
 * Anzeige, Sortierung und Export garantiert konsistent.
 */
const DEVICE_COLUMNS = [
  { key: "name", label: "Gerät", text: (d) => d.label || d.hostname || "" },
  { key: "mac", label: "MAC", text: (d) => d.mac, cell: (d) => el("span", { class: "mono" }, d.mac) },
  {
    key: "ip", label: "IP", text: (d) => d.ip || "",
    // Ohne eigenen Sortierschlüssel landet .100 vor .20.
    sort: (d) => ipKey(d.ip),
  },
  {
    // Bei randomisierter MAC ist der Hersteller-Lookup wertlos. Statt nur
    // "zufällige MAC" zu zeigen, kommt hier das, was DHCP-Fingerprint und
    // mDNS über das Gerät verraten haben.
    key: "vendor", label: "Hersteller / Typ",
    text: (d) => d.vendor || identityText(d) || (d.mac_random ? "zufällige MAC" : ""),
    cell: (d) => {
      if (d.vendor) return d.vendor;
      const derived = identityText(d);
      if (derived) {
        return el("span", { title: "aus DHCP-Fingerprint bzw. mDNS abgeleitet" },
          derived, el("span", { class: "inferred" }, "abgeleitet"));
      }
      return d.mac_random ? el("span", { class: "pill warn" }, "zufällige MAC") : "—";
    },
  },
  {
    key: "addr_mode", label: "Adressierung", text: (d) => MODE_LABEL[d.addr_mode],
    cell: (d) => el("span", { class: `pill ${d.addr_mode === "static" ? "warn" : ""}` },
      MODE_LABEL[d.addr_mode]),
  },
  {
    key: "attachment", label: "Anschluss", text: (d) => d.attachment || "",
    cell: (d) => d.attachment
      ? el("span", { class: `pill ${d.medium === "wireless" ? "wireless" : ""}` }, d.attachment)
      : "—",
  },
  { key: "last_seen", label: "zuletzt", text: (d) => ago(d.last_seen), sort: (d) => d.last_seen },
  { key: "first_seen", label: "seit", text: (d) => ago(d.first_seen), sort: (d) => d.first_seen },
];

const COMPACT_COLUMNS = ["name", "ip", "vendor", "last_seen"];

/** IPv4 als 32-Bit-Zahl, damit numerisch statt lexikografisch sortiert wird. */
function ipKey(ip) {
  if (!ip) return null;
  const parts = ip.split(".");
  if (parts.length !== 4) return ip; // IPv6 o. Ä. -> alphabetisch
  return parts.reduce((acc, p) => acc * 256 + (Number(p) || 0), 0);
}

/**
 * Sortiert nach einer Spaltendefinition. Von Geräte- und Web-Tabelle
 * gemeinsam benutzt -- zwei Kopien derselben Regeln würden über kurz oder
 * lang auseinanderlaufen.
 */
function sortRows(rows, columns, sort) {
  const col = columns.find((c) => c.key === sort.key);
  if (!col) return rows;
  const factor = sort.dir === "asc" ? 1 : -1;
  const valueOf = col.sort || col.text;

  return [...rows].sort((a, b) => {
    const va = valueOf(a), vb = valueOf(b);
    // Leere Werte immer ans Ende, egal in welche Richtung sortiert wird --
    // sonst besteht die erste Seite aus lauter "—".
    const ea = va === null || va === undefined || va === "";
    const eb = vb === null || vb === undefined || vb === "";
    if (ea || eb) return ea && eb ? 0 : ea ? 1 : -1;
    if (typeof va === "number" && typeof vb === "number") return (va - vb) * factor;
    return String(va).localeCompare(String(vb), "de", { numeric: true }) * factor;
  });
}

/** Klickbare Kopfzeile; erneuter Klick auf dieselbe Spalte dreht die Richtung. */
function sortableHead(columns, sort, onSort) {
  return el("tr", {}, ...columns.map((col) => {
    const active = sort.key === col.key;
    return el("th", {
      class: `sortable${active ? " sorted" : ""}`,
      title: `Nach „${col.label}“ sortieren`,
      onclick: () => onSort(active
        ? { key: col.key, dir: sort.dir === "asc" ? "desc" : "asc" }
        : { key: col.key, dir: col.defaultDir || "asc" }),
    }, col.label,
      el("span", { class: "sort-arrow" },
        active ? (sort.dir === "asc" ? "▲" : "▼") : "↕"));
  }));
}

let deviceSort = { key: "last_seen", dir: "desc" };
let deviceRows = [];

const sortDevices = (devices) => sortRows(devices, DEVICE_COLUMNS, deviceSort);

function deviceTable(devices, compact) {
  const columns = compact
    ? COMPACT_COLUMNS.map((k) => DEVICE_COLUMNS.find((c) => c.key === k))
    : DEVICE_COLUMNS;

  const header = compact
    ? el("tr", {}, ...columns.map((col) => el("th", {}, col.label)))
    : sortableHead(columns, deviceSort, (next) => { deviceSort = next; renderDevices(); });

  const rows = devices.map((d) =>
    el("tr", { onclick: () => showDevice(d.id) },
      ...columns.map((col) => el("td", {}, col.cell ? col.cell(d) : (col.text(d) || "—")))
    )
  );

  return el("div", { class: "scroll" },
    el("table", {},
      el("thead", {}, header),
      el("tbody", {}, ...rows)
    )
  );
}

function renderDevices() {
  const sorted = sortDevices(deviceRows);
  document.getElementById("dev-count").textContent = `${sorted.length} Geräte`;
  document.getElementById("device-table").replaceChildren(deviceTable(sorted, false));
}

async function loadDevices() {
  const params = new URLSearchParams({ limit: "1000" });
  const q = document.getElementById("dev-search").value.trim();
  const mode = document.getElementById("dev-mode").value;
  const seen = document.getElementById("dev-seen").value;
  if (q) params.set("q", q);
  if (mode) params.set("addr_mode", mode);
  if (seen) params.set("seen_within_days", seen);
  if (document.getElementById("dev-ignored").checked) params.set("include_ignored", "true");

  deviceRows = await api.get(`/api/devices?${params}`);
  renderDevices();
}

// ------------------------------------------------------------------- Export

/** Exportiert genau das, was gerade zu sehen ist -- gefiltert und sortiert. */
function exportDevices(format) {
  const rows = sortDevices(deviceRows);
  if (!rows.length) return;

  const headers = DEVICE_COLUMNS.map((c) => c.label);
  const body = rows.map((d) => DEVICE_COLUMNS.map((c) => c.text(d) || ""));
  const stamp = new Date().toISOString().slice(0, 10);

  if (format === "csv") {
    // Semikolon als Trenner und BOM: so öffnet Excel im deutschen Gebietsschema
    // die Datei direkt richtig, statt alles in eine Spalte zu legen.
    const escape = (v) => `"${String(v).replace(/"/g, '""')}"`;
    const csv = [headers, ...body].map((r) => r.map(escape).join(";")).join("\r\n");
    download(`nets-geraete-${stamp}.csv`, "﻿" + csv, "text/csv;charset=utf-8");
  } else {
    const escape = (v) => String(v).replace(/\|/g, "\\|");
    const md = [
      `# Netzwerkgeräte — Stand ${new Date().toLocaleString("de-DE")}`,
      "",
      `${rows.length} Geräte`,
      "",
      `| ${headers.join(" | ")} |`,
      `| ${headers.map(() => "---").join(" | ")} |`,
      ...body.map((r) => `| ${r.map((v) => escape(v) || "—").join(" | ")} |`),
    ].join("\n");
    download(`nets-geraete-${stamp}.md`, md, "text/markdown;charset=utf-8");
  }
}

function download(filename, content, mime) {
  const url = URL.createObjectURL(new Blob([content], { type: mime }));
  const link = el("a", { href: url, download: filename });
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

document.getElementById("export-csv").onclick = () => exportDevices("csv");
document.getElementById("export-md").onclick = () => exportDevices("md");

["dev-search", "dev-mode", "dev-seen", "dev-ignored"].forEach((id) => {
  const node = document.getElementById(id);
  node.addEventListener(node.tagName === "INPUT" && node.type === "search" ? "input" : "change",
    debounce(loadDevices, 250));
});

function debounce(fn, ms) {
  let timer;
  return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), ms); };
}

async function showDevice(id) {
  const data = await api.get(`/api/devices/${id}`);
  const d = data.device;

  // Fakten nach Schlüssel gruppieren, mehrere Quellen je Schlüssel anzeigen.
  const grouped = {};
  for (const f of data.facts) (grouped[f.key] ||= []).push(f);

  const maxHits = Math.max(1, ...data.timeline.map((t) => t.hits));
  const timeline = el("div", { class: "timeline" },
    ...data.timeline.map((t) =>
      el("i", {
        style: `height:${Math.max(3, Math.round((t.hits / maxHits) * 34))}px`,
        title: `${new Date(t.t * 1000).toLocaleString("de-DE")} — ${t.hits} Beobachtungen`,
      })
    )
  );

  const labelInput = el("input", { value: d.label || "", placeholder: "eigener Name" });
  const notesInput = el("input", { value: d.notes || "", placeholder: "Notiz" });

  showModal(
    el("h2", {}, d.label || d.hostname || d.mac),
    el("dl", { class: "kv" },
      el("dt", {}, "MAC"), el("dd", { class: "mono" }, d.mac + (d.mac_random ? "  (zufällig / lokal vergeben)" : "")),
      el("dt", {}, "Hersteller"), el("dd", {}, d.vendor || "unbekannt"),
      el("dt", {}, "Hostname"), el("dd", {}, d.hostname || "—"),
      el("dt", {}, "Adressierung"), el("dd", {}, MODE_LABEL[d.addr_mode]),
      el("dt", {}, "Erstmals gesehen"), el("dd", {}, new Date(d.first_seen * 1000).toLocaleString("de-DE")),
      el("dt", {}, "Zuletzt gesehen"), el("dd", {}, new Date(d.last_seen * 1000).toLocaleString("de-DE")),
      data.attachment && el("dt", {}, "Anschluss"),
      data.attachment && el("dd", {},
        `${data.attachment.net_device} / Port ${data.attachment.port_key} `
        + `(${data.attachment.medium}, Konfidenz ${data.attachment.confidence})`),
    ),

    // Was wir über das Gerät ableiten konnten — samt Begründung. Eine
    // Vermutung ohne Beleg wäre wertlos.
    data.identity && (data.identity.label || data.identity.os_guess)
      ? el("div", {},
          el("h3", {}, "Abgeleitete Identität"),
          el("dl", { class: "kv" },
            data.identity.os_guess ? el("dt", {}, "System") : null,
            data.identity.os_guess ? el("dd", {}, data.identity.os_guess) : null,
            data.identity.device_type ? el("dt", {}, "Typ") : null,
            data.identity.device_type ? el("dd", {}, data.identity.device_type) : null,
            el("dt", {}, "MAC-Herkunft"),
            el("dd", {}, MAC_KIND_LABEL[data.identity.mac_kind] || data.identity.mac_kind,
              data.identity.mac_kind_detail ? ` (${data.identity.mac_kind_detail})` : ""),
          ),
          data.identity.evidence?.length
            ? el("ul", { class: "evidence" },
                ...data.identity.evidence.map((e) => el("li", {}, e)))
            : el("p", { class: "muted" }, "keine belastbaren Merkmale gesammelt"))
      : null,

    // Nur zeigen, wenn es Kandidaten gibt — die Prüfung ist streng: zeitlich
    // überschneidende MACs werden ausgeschlossen, die können es nicht sein.
    data.similar?.length
      ? el("div", {},
          el("h3", {}, "Möglicherweise dasselbe Gerät"),
          el("p", { class: "muted" },
            "Gleiche Merkmale und zu keinem Zeitpunkt gleichzeitig im Netz gesehen. "
            + "Das ist ein Hinweis, kein Beweis — deshalb wird nichts automatisch zusammengeführt."),
          el("div", { class: "scroll" }, el("table", {},
            el("thead", {}, el("tr", {}, ...["MAC", "Hostname", "Grund", "zuletzt"].map((h) => el("th", {}, h)))),
            el("tbody", {}, ...data.similar.map((s) =>
              el("tr", { onclick: () => showDevice(s.id) },
                el("td", { class: "mono" }, s.mac),
                el("td", {}, s.hostname || "—"),
                el("td", {}, s.reason),
                el("td", {}, ago(s.last_seen)))
            ))
          )))
      : null,

    el("h3", {}, "Anwesenheit (30 Tage)"),
    data.timeline.length ? timeline : el("p", { class: "muted" }, "noch keine Historie"),

    el("h3", {}, "IP-Adressen"),
    el("div", { class: "scroll" }, el("table", {},
      el("thead", {}, el("tr", {}, ...["IP", "Quelle", "erstmals", "zuletzt"].map((h) => el("th", {}, h)))),
      el("tbody", {}, ...data.addresses.map((a) =>
        el("tr", {},
          el("td", { class: "mono" }, a.ip),
          el("td", {}, a.source),
          el("td", {}, ago(a.first_seen)),
          el("td", {}, ago(a.last_seen)))
      ))
    )),

    el("h3", {}, "Merkmale"),
    el("dl", { class: "kv" },
      ...Object.entries(grouped).flatMap(([key, facts]) => [
        el("dt", {}, key),
        el("dd", { class: "mono" }, facts.map((f) => `${f.value}  [${f.source}]`).join("\n")),
      ])
    ),

    data.port_history.length ? el("h3", {}, "Port-Historie") : null,
    data.port_history.length
      ? el("div", { class: "scroll" }, el("table", {},
          el("thead", {}, el("tr", {}, ...["Zeit", "Gerät", "Port", "VLAN"].map((h) => el("th", {}, h)))),
          el("tbody", {}, ...data.port_history.slice(0, 20).map((h) =>
            el("tr", {},
              el("td", {}, new Date(h.ts * 1000).toLocaleString("de-DE")),
              el("td", {}, h.net_device),
              el("td", { class: "mono" }, h.port_key),
              el("td", {}, h.vlan ?? "—"))
          ))
        ))
      : null,

    el("h3", {}, "Eigene Angaben"),
    el("div", { class: "field" }, el("label", {}, "Name"), labelInput),
    el("div", { class: "field" }, el("label", {}, "Notiz"), notesInput),
    el("div", { class: "row" },
      el("button", {
        class: "primary",
        onclick: async () => {
          await api.send("PATCH", `/api/devices/${id}`, {
            label: labelInput.value, notes: notesInput.value,
          });
          modal.classList.add("hidden");
          loadDevices();
        },
      }, "Speichern"),
      el("button", {
        class: "danger",
        onclick: async () => {
          await api.send("PATCH", `/api/devices/${id}`, { ignored: d.ignored ? 0 : 1 });
          modal.classList.add("hidden");
          loadDevices();
        },
      }, d.ignored ? "Nicht mehr ignorieren" : "Ignorieren"),
      el("button", {
        class: "danger",
        title: "Entfernt das Gerät samt Historie. Taucht es wieder im Netz auf, "
             + "wird es neu angelegt — zum dauerhaften Ausblenden „Ignorieren“ nutzen.",
        onclick: async () => {
          if (!confirm(`„${d.label || d.hostname || d.mac}“ samt gesamter Historie löschen?\n\n`
            + "Das lässt sich nicht rückgängig machen. Erscheint das Gerät erneut im Netz, "
            + "wird es als neu erfasst.")) return;
          await api.send("DELETE", `/api/devices/${id}`);
          modal.classList.add("hidden");
          loadDevices();
          loadStatus();
        },
      }, "Löschen")
    )
  );
}

// ----------------------------------------------------------------- Topologie

let topoData = { roots: [], stats: {} };
//: Zugeklappte Knoten-IDs. Endgeräte-Ports starten zugeklappt, damit ein Port
//: mit 23 MACs den Baum nicht sofort unlesbar macht.
let topoCollapsed = new Set();
let topoInitialised = false;

async function loadTopology() {
  topoData = await api.get("/api/topology");
  const s = topoData.stats || {};
  document.getElementById("topo-stats").textContent =
    `${s.infra ?? 0} Infrastruktur · ${s.ports ?? 0} Ports · ${s.attached ?? 0} zugeordnet`
    + (s.self_linked ? ` · ${s.self_linked} Eigenadressen erkannt` : "")
    + (s.unattached ? ` · ${s.unattached} ohne Zuordnung` : "");

  if (!topoInitialised) {
    // Erststart: Ports mit vielen Geräten zugeklappt lassen.
    walkTree(topoData.roots, (n) => {
      if ((n.kind === "port" || n.kind === "group") && n.count > 6) topoCollapsed.add(n.id);
    });
    topoInitialised = true;
  }
  renderTopology();
}

function walkTree(nodes, fn) {
  for (const node of nodes) {
    fn(node);
    walkTree(node.children || [], fn);
  }
}

document.getElementById("topo-rebuild").onclick = async () => {
  await api.send("POST", "/api/topology/rebuild");
  loadTopology();
};
document.getElementById("topo-expand").onclick = () => {
  topoCollapsed.clear();
  renderTopology();
};
document.getElementById("topo-collapse").onclick = () => {
  walkTree(topoData.roots, (n) => { if (n.children?.length) topoCollapsed.add(n.id); });
  renderTopology();
};
document.getElementById("topo-search").addEventListener("input", debounce(renderTopology, 200));

const TREE_ICONS = { infra: "▤", infra_unknown: "▨", port: "⊟", device: "•", group: "⊘" };

/** Trifft der Suchbegriff diesen Knoten selbst? */
function topoMatches(node, needle) {
  if (!needle) return false;
  return [node.label, node.sublabel, node.mac, node.ip]
    .some((v) => v && String(v).toLowerCase().includes(needle));
}

function renderTopology() {
  const container = document.getElementById("topo-tree");
  const needle = document.getElementById("topo-search").value.trim().toLowerCase();

  if (!topoData.roots.length) {
    container.replaceChildren(el("p", { class: "muted", style: "padding:24px" },
      "Noch keine Topologie — unter „Infrastruktur“ einen Switch, AP oder Router hinzufügen. "
      + "Ohne FDB- oder WLAN-Daten lässt sich nicht bestimmen, an welchem Port ein Gerät hängt."));
    return;
  }

  const rendered = topoData.roots.map((n) => treeNode(n, needle, 0)).filter(Boolean);
  container.replaceChildren(
    ...(rendered.length
      ? rendered
      : [el("p", { class: "muted", style: "padding:24px" }, `Keine Treffer für „${needle}“.`)])
  );
}

/**
 * Baut einen Knoten. Bei aktiver Suche werden Zweige ohne Treffer weggelassen
 * und Treffer-Pfade automatisch aufgeklappt -- sonst müsste man sich durch
 * zugeklappte Ports zum gesuchten Gerät durchhangeln.
 */
function treeNode(node, needle, depth) {
  const selfMatch = topoMatches(node, needle);
  const kids = (node.children || [])
    .map((c) => treeNode(c, selfMatch ? "" : needle, depth + 1))
    .filter(Boolean);

  if (needle && !selfMatch && !kids.length) return null;

  const hasKids = (node.children || []).length > 0;
  const open = hasKids && (needle ? true : !topoCollapsed.has(node.id));

  const toggle = hasKids
    ? el("button", {
        class: "ttoggle",
        title: open ? "Zuklappen" : "Aufklappen",
        onclick: (e) => {
          e.stopPropagation();
          topoCollapsed.has(node.id) ? topoCollapsed.delete(node.id) : topoCollapsed.add(node.id);
          renderTopology();
        },
      }, open ? "▾" : "▸")
    : el("span", { class: "ttoggle empty" });

  const row = el("div", {
      // Auch Infrastruktur-Knoten sind anklickbar, sobald sie über die
      // SNMP-Identität mit einem Geräteeintrag verknüpft sind.
      class: `trow ${node.kind}${node.device_id ? " clickable" : ""}`
        + `${selfMatch && needle ? " match" : ""}`,
      onclick: node.device_id ? () => showDevice(node.device_id) : undefined,
    },
    toggle,
    el("span", { class: `tico ${node.kind}` }, TREE_ICONS[node.kind] || "•"),
    el("span", { class: "tlabel" }, node.label),
    node.via_port ? el("span", { class: "tvia" }, `über Port ${node.via_port}`) : null,
    node.sublabel ? el("span", { class: "tsub" }, node.sublabel) : null,
    ...(node.badges || []).map((b) => el("span", { class: `pill ${b.tone}` }, b.text)),
    el("span", { class: "grow" }),
    node.kind !== "device" && node.count
      ? el("span", { class: "tcount", title: "Endgeräte in diesem Zweig" }, node.count)
      : null,
    node.kind === "device" && node.confidence !== null && node.confidence < 0.5
      ? el("span", { class: "pill warn", title: "Port-Zuordnung unsicher — mehrere MACs am selben Port" },
          `± ${node.confidence}`)
      : null,
  );

  // Der Hinweis erscheint nur einmal am Port, nicht an jedem Gerät darunter.
  // Den Text liefert das Backend, weil nur dort bekannt ist, ob LLDP den
  // Nachbarn nennt — das entscheidet, ob man etwas tun kann oder nicht.
  const hint = node.hint && open ? el("div", { class: "thint" }, node.hint) : null;

  return el("div", { class: `tnode depth-${Math.min(depth, 4)}` },
    row,
    hint,
    open && kids.length ? el("div", { class: "tchildren" }, ...kids) : null
  );
}


function svgEl(tag, attrs = {}, ...kids) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs)) if (v !== null && v !== undefined) node.setAttribute(k, v);
  for (const kid of kids) node.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return node;
}

// ----------------------------------------------------------- Weboberflächen

let webRows = [];

/** Bekannte Oberflächen an ihrem Titel oder Server erkennen — dann steht in
 *  der Liste „Proxmox" statt nur einer IP mit Port. */
const WEB_KIND = [
  [/proxmox/i, "Proxmox VE"],
  [/home ?assistant/i, "Home Assistant"],
  [/unifi|ubiquiti/i, "UniFi"],
  [/opnsense|pfsense/i, "Firewall"],
  [/openwrt|luci/i, "OpenWrt"],
  [/fritz!?box/i, "FRITZ!Box"],
  [/speedport/i, "Speedport"],
  [/synology|diskstation/i, "Synology"],
  [/shelly/i, "Shelly"],
  [/grafana/i, "Grafana"],
  [/portainer/i, "Portainer"],
  [/nginx|apache|lighttpd|caddy/i, "Webserver"],
];

const webKind = (row) => {
  const haystack = `${row.title || ""} ${row.server || ""}`;
  for (const [pattern, label] of WEB_KIND) if (pattern.test(haystack)) return label;
  return null;
};

const webUrl = (row) => `${row.scheme}://${row.ip}${
  (row.scheme === "https" && row.port === 443) || (row.scheme === "http" && row.port === 80)
    ? "" : ":" + row.port}/`;

const WEB_COLUMNS = [
  {
    key: "address", label: "Adresse", text: (r) => webUrl(r),
    // Nach IP *und* Port sortieren, sonst landet :8006 zwischen zwei
    // Oberflächen fremder Geräte.
    sort: (r) => (ipKey(r.ip) ?? 0) * 100000 + r.port,
    cell: (r) => el("a", { href: webUrl(r), target: "_blank", rel: "noopener",
                           class: "mono" }, webUrl(r)),
  },
  {
    key: "device", label: "Gerät",
    text: (r) => r.label || r.hostname || r.vendor || r.mac || "",
    cell: (r) => r.device_id
      ? el("a", { href: "#", class: "devlink",
                  onclick: (e) => { e.preventDefault(); showDevice(r.device_id); } },
          r.label || r.hostname || r.vendor || r.mac)
      : el("span", { class: "muted" }, "unbekannt"),
  },
  {
    key: "kind", label: "Erkannt als", text: (r) => webKind(r) || "",
    cell: (r) => { const k = webKind(r); return k ? el("span", { class: "pill info" }, k) : "—"; },
  },
  { key: "title", label: "Titel", text: (r) => r.title || "" },
  {
    key: "server", label: "Server", text: (r) => r.server || "",
    cell: (r) => el("span", { class: "muted" }, r.server || "—"),
  },
  {
    key: "status", label: "Status", text: (r) => r.status, defaultDir: "asc",
    cell: (r) => r.status
      ? el("span", { class: `pill ${r.status < 300 ? "ok" : r.status < 400 ? "" : "warn"}` },
          String(r.status))
      : el("span", { class: "pill" }, r.source),
  },
  { key: "source", label: "Quelle", text: (r) => r.source },
  {
    key: "last_seen", label: "zuletzt", text: (r) => ago(r.last_seen),
    sort: (r) => r.last_seen, defaultDir: "desc",
  },
];

let webSort = { key: "address", dir: "asc" };

async function loadWeb() {
  const [rows, settings] = await Promise.all([
    api.get("/api/web-services"), api.get("/api/settings"),
  ]);
  webRows = rows;

  document.getElementById("web-hint").textContent = settings.web_scan_enabled === "1"
    ? `Regelmäßige Suche ist eingeschaltet (alle ${Math.round(Number(settings.web_scan_interval) / 3600)} h) `
      + `auf den Ports ${settings.web_scan_ports || "Standard"}.`
    : "Die regelmäßige Suche ist ausgeschaltet — sie klopft aktiv an Ports an, "
      + "während der Rest des Tools nur zuhört. Einschalten unter Einstellungen, "
      + "oder hier einmalig „Jetzt suchen“. Ohne sie erscheinen nur Adressen, die "
      + "Geräte von selbst ankündigen (UPnP-LOCATION, mDNS-SRV) — viele Oberflächen "
      + "tun das nicht.";
  renderWeb();
}

function renderWeb() {
  const needle = document.getElementById("web-search").value.trim().toLowerCase();
  const filtered = webRows.filter((r) => !needle || [
    r.ip, r.title, r.server, r.label, r.hostname, r.vendor, String(r.port), webKind(r),
  ].some((v) => v && String(v).toLowerCase().includes(needle)));
  const rows = sortRows(filtered, WEB_COLUMNS, webSort);

  document.getElementById("web-stats").textContent =
    `${rows.length} von ${webRows.length} Oberflächen`;

  if (!webRows.length) {
    document.getElementById("web-list").replaceChildren(
      el("p", { class: "muted", style: "padding:24px" },
        "Noch nichts gefunden. „Jetzt suchen“ klopft einmalig auf allen bekannten "
        + "Adressen an — es wird kein zusätzlicher Adressraum durchsucht."));
    return;
  }

  document.getElementById("web-list").replaceChildren(
    el("div", { class: "scroll" }, el("table", {},
      el("thead", {},
        sortableHead(WEB_COLUMNS, webSort, (next) => { webSort = next; renderWeb(); })),
      el("tbody", {}, ...rows.map((r) =>
        el("tr", {}, ...WEB_COLUMNS.map((col) =>
          el("td", {}, col.cell ? col.cell(r) : (col.text(r) || "—"))))))
    ))
  );
}

document.getElementById("web-search").addEventListener("input", debounce(renderWeb, 200));

document.getElementById("web-scan").onclick = async (e) => {
  e.target.disabled = true;
  const stats = document.getElementById("web-stats");
  stats.textContent = "suche … das dauert je nach Netzgröße eine Weile";
  try {
    const r = await api.send("POST", "/api/actions/web-scan");
    stats.textContent = `${r.found} Oberflächen auf ${r.targets} Adressen gefunden`;
  } catch (err) {
    stats.textContent = String(err);
  }
  e.target.disabled = false;
  loadWeb();
};

// ------------------------------------------------------------ Infrastruktur

let adapterTypes = [];

/** Baut ein Formular allein aus der Adapter-Selbstbeschreibung. */
function adapterForm(type, config = {}) {
  const wrap = el("div", {});
  const inputs = {};

  const render = () => {
    wrap.replaceChildren();
    for (const f of type.config_fields) {
      // depends_on: Feld nur zeigen, wenn ein anderes Feld passend gesetzt ist.
      if (f.depends_on) {
        const [dep, want] = Object.entries(f.depends_on)[0];
        const current = inputs[dep] ? valueOf(inputs[dep]) : config[dep];
        // Bei v3-Feldern gilt: zeigen, sobald der Wert übereinstimmt.
        if (String(current) !== String(want)) continue;
      }
      const current = config[f.key] ?? f.default ?? "";
      let input;
      if (f.type === "select") {
        input = el("select", {}, ...f.choices.map((c) =>
          el("option", { value: c, selected: String(current) === c ? "" : null }, c)));
      } else if (f.type === "bool") {
        input = el("input", { type: "checkbox" });
        input.checked = current === true || current === "true" || current === 1;
      } else {
        input = el("input", {
          type: f.type === "password" ? "password" : f.type === "int" ? "number" : "text",
          value: current,
        });
      }
      input.addEventListener("change", () => { config[f.key] = valueOf(input); render(); });
      inputs[f.key] = input;
      wrap.append(el("div", { class: "field" },
        el("label", {}, f.label + (f.required ? " *" : "")),
        input,
        f.help ? el("div", { class: "help" }, f.help) : null));
    }
  };
  render();

  return {
    node: wrap,
    values: () => Object.fromEntries(Object.entries(inputs).map(([k, i]) => [k, valueOf(i)])),
  };
}

const valueOf = (input) =>
  input.type === "checkbox" ? input.checked
  : input.type === "number" ? (input.value === "" ? null : Number(input.value))
  : input.value;

async function loadInfra() {
  if (!adapterTypes.length) {
    adapterTypes = await api.get("/api/adapter-types");
    document.getElementById("new-adapter-type").replaceChildren(
      ...adapterTypes.map((t) => el("option", { value: t.type_id }, t.display_name))
    );
  }
  const capText = adapterTypes
    .map((t) => `${t.display_name}: ${t.capabilities.join(", ") || "—"}`)
    .join(" · ");
  document.getElementById("adapter-hint").textContent =
    `Verfügbare Adapter und ihre Fähigkeiten — ${capText}`;

  const list = await api.get("/api/net-devices");
  document.getElementById("infra-list").replaceChildren(
    ...(list.length ? list.map(infraCard)
      : [el("div", { class: "card muted" },
          "Noch keine Infrastruktur konfiguriert. Ohne mindestens einen Switch/AP mit "
          + "FDB- oder WLAN-Daten gibt es keine Port-Zuordnung — Geräte werden trotzdem gefunden.")])
  );
}

function infraCard(item) {
  const type = adapterTypes.find((t) => t.type_id === item.adapter_type);
  const status = item.last_error
    ? el("span", { class: "pill err" }, "Fehler")
    : item.last_ok
      ? el("span", { class: "pill ok" }, `ok — ${ago(item.last_ok)}`)
      : el("span", { class: "pill warn" }, "noch nie abgefragt");

  const msg = el("span", { class: "muted" });

  return el("div", { class: "card" },
    el("div", { class: "toolbar" },
      el("strong", {}, item.name),
      el("span", { class: "pill" }, type?.display_name || item.adapter_type),
      status,
      !item.enabled ? el("span", { class: "pill warn" }, "deaktiviert") : null,
      el("span", { class: "grow" }),
      el("button", {
        onclick: async (e) => {
          e.target.disabled = true; msg.textContent = "teste …";
          try {
            const r = await api.send("POST", `/api/net-devices/${item.id}/test`);
            msg.textContent = r.message;
          } catch (err) { msg.textContent = String(err); }
          e.target.disabled = false;
        },
      }, "Verbindung testen"),
      el("button", {
        onclick: async (e) => {
          e.target.disabled = true; msg.textContent = "frage ab …";
          try {
            const r = await api.send("POST", `/api/net-devices/${item.id}/poll`);
            msg.textContent = r.message;
          } catch (err) { msg.textContent = String(err); }
          e.target.disabled = false; loadInfra();
        },
      }, "Jetzt abfragen"),
      el("button", { onclick: () => editAdapter(item) }, "Bearbeiten"),
      el("button", {
        class: "danger",
        onclick: async () => {
          if (confirm(`„${item.name}“ wirklich entfernen?`)) {
            await api.send("DELETE", `/api/net-devices/${item.id}`);
            loadInfra();
          }
        },
      }, "Entfernen")
    ),
    item.last_error ? el("div", { class: "muted mono" }, item.last_error) : null,
    msg
  );
}

document.getElementById("add-adapter").onclick = () => {
  const typeId = document.getElementById("new-adapter-type").value;
  editAdapter({ adapter_type: typeId, name: "", config: {}, enabled: true, poll_seconds: 300 });
};

function editAdapter(item) {
  const type = adapterTypes.find((t) => t.type_id === item.adapter_type);
  const nameInput = el("input", { value: item.name || "", placeholder: "z. B. Switch Keller" });
  const enabledInput = el("input", { type: "checkbox" });
  enabledInput.checked = item.enabled !== false;
  const form = adapterForm(type, { ...item.config });
  const msg = el("div", { class: "muted" });

  showModal(
    el("h2", {}, item.id ? `${item.name} bearbeiten` : `${type.display_name} hinzufügen`),
    el("p", { class: "muted" }, type.description),
    el("p", { class: "muted" }, `Liefert: ${type.capabilities.join(", ") || "—"}`),
    el("div", { class: "field" }, el("label", {}, "Anzeigename *"), nameInput),
    form.node,
    el("label", { class: "check" }, enabledInput, " regelmäßig abfragen"),
    el("div", { class: "row" },
      el("button", {
        class: "primary",
        onclick: async () => {
          const payload = {
            name: nameInput.value,
            adapter_type: item.adapter_type,
            config: form.values(),
            enabled: enabledInput.checked,
            poll_seconds: item.poll_seconds || 300,
          };
          try {
            if (item.id) await api.send("PUT", `/api/net-devices/${item.id}`, payload);
            else await api.send("POST", "/api/net-devices", payload);
            modal.classList.add("hidden");
            loadInfra();
          } catch (err) { msg.textContent = String(err); }
        },
      }, "Speichern"),
      el("button", { onclick: () => modal.classList.add("hidden") }, "Abbrechen"),
      msg
    )
  );
}

// -------------------------------------------------------------- Einstellungen

const SETTING_FIELDS = [
  ["iface", "Netzwerk-Interfaces", "ifaces",
   "Kommagetrennt für mehrere. Broadcast endet am Router — wer in mehreren Segmenten steht, muss auf jedem lauschen."],
  ["subnets", "Subnetze für ARP-Sweep", "text", "Kommagetrennt, z. B. 192.168.1.0/24, 192.168.10.0/24. Leer = kein Sweep."],
  ["passive_enabled", "Passives Mithören", "bool", "Die wichtigste Quelle — sollte immer an sein."],
  ["sweep_enabled", "Aktive Sweeps", "bool", "ARP-Sweep findet Geräte, die gerade nichts senden."],
  ["sweep_interval", "Sweep-Intervall (s)", "int", ""],
  ["adapter_interval", "Adapter-Abfrage (s)", "int", "Wie oft Switches/APs abgefragt werden."],
  ["topology_interval", "Topologie neu berechnen (s)", "int", ""],
  ["wifi_enabled", "WLAN-Mitschnitt (802.11)", "bool",
   "Ordnet Clients ihrem Access Point zu — funktioniert auch bei Routern ohne API. Braucht eine zweite WLAN-Karte im Monitor-Mode."],
  ["wifi_iface", "WLAN-Interface (Monitor-Mode)", "text",
   "Nicht das Interface der normalen Verbindung — die Karte wird zum Kanalspringen benutzt."],
  ["wifi_dwell_seconds", "Verweildauer je Kanal (s)", "int",
   "Kürzer = alle Kanäle schneller durch, aber mehr verpasste Frames."],
  ["web_scan_enabled", "Weboberflächen suchen", "bool",
   "Aktiv: klopft an Ports bekannter Adressen an, während der Rest des Tools nur zuhört. Kein zusätzlicher Scan des Adressraums."],
  ["web_scan_ports", "Ports für die Suche", "text",
   "Kommagetrennt. Leer = 80, 443, 8006, 8123, 8080, 8443, 3000, 5000, 8081, 9000."],
  ["web_scan_interval", "Suchintervall (s)", "int",
   "Standard 21600 = alle 6 Stunden."],
  ["static_infer_days", "Beobachtungsdauer für „statisch“ (Tage)", "int",
   "Erst nach dieser Zeit ohne DHCP-Verkehr gilt ein Gerät als statisch adressiert."],
];

async function loadSettings() {
  const [values, ifaces] = await Promise.all([api.get("/api/settings"), api.get("/api/interfaces")]);
  const form = document.getElementById("settings-form");
  form.replaceChildren();
  form._inputs = {};

  for (const [key, label, type, helpText] of SETTING_FIELDS) {
    let help = helpText;
    let input;
    if (type === "ifaces") {
      input = el("input", { type: "text", value: values[key] ?? "" });
      help = `${help} Verfügbar: ${ifaces.join(", ") || "—"}`;
    } else if (type === "select") {
      const options = ifaces.length ? ifaces : [values[key]];
      input = el("select", {}, ...options.map((i) =>
        el("option", { value: i, selected: values[key] === i ? "" : null }, i)));
    } else if (type === "bool") {
      input = el("input", { type: "checkbox" });
      input.checked = values[key] === "1";
    } else {
      input = el("input", { type: type === "int" ? "number" : "text", value: values[key] ?? "" });
    }
    form._inputs[key] = input;
    form.append(el("div", { class: "field" },
      el("label", {}, label), input, help ? el("div", { class: "help" }, help) : null));
  }
}

document.getElementById("save-settings").onclick = async () => {
  const inputs = document.getElementById("settings-form")._inputs || {};
  const payload = {};
  for (const [key, input] of Object.entries(inputs)) {
    payload[key] = input.type === "checkbox" ? (input.checked ? "1" : "0") : String(input.value);
  }
  const result = await api.send("PUT", "/api/settings", payload);
  document.getElementById("settings-msg").textContent =
    "Gespeichert." + (result.sniffer_restarted ? " Sniffer neu gestartet." : "");
  loadStatus();
};

// --------------------------------------------------------------- Datenpflege

const RETENTION_FIELDS = [
  ["retention_presence_days", "Anwesenheits-Historie (Tage)",
   "Die Grundlage der Zeitleiste. Kürzer spart Platz, kostet aber genau die Langzeitsicht, für die das Tool gebaut ist."],
  ["retention_fdb_days", "MAC-Tabellen der Switches (Tage)", "Grundlage der Port-Historie."],
  ["retention_link_days", "LLDP-Nachbarschaften (Tage)", "Werden bei jeder Abfrage neu geschrieben."],
  ["retention_wifi_days", "WLAN-Assoziationen (Tage)", ""],
];

const BYTES = (n) => n > 1048576 ? `${(n / 1048576).toFixed(1)} MB`
  : n > 1024 ? `${Math.round(n / 1024)} kB` : `${n} B`;

const TABLE_LABEL = {
  devices: "Geräte", addresses: "IP-Adressen", facts: "Merkmale",
  presence: "Anwesenheit", fdb: "MAC-Tabellen", links: "LLDP-Nachbarn",
  wifi_links: "WLAN-Assoziationen", attachments: "Port-Zuordnungen",
  net_devices: "Adapter (Konfiguration)", net_ports: "Ports",
  net_identities: "Eigenadressen", settings: "Einstellungen",
};

async function loadData() {
  const [stats, values] = await Promise.all([
    api.get("/api/data/stats"), api.get("/api/settings"),
  ]);

  const form = document.getElementById("retention-form");
  form.replaceChildren();
  form._inputs = {};
  for (const [key, label, help] of RETENTION_FIELDS) {
    const input = el("input", { type: "number", min: "0", value: values[key] ?? "" });
    form._inputs[key] = input;
    form.append(el("div", { class: "field" },
      el("label", {}, label), input, help ? el("div", { class: "help" }, help) : null));
  }

  const rows = Object.entries(stats.counts)
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1]);
  document.getElementById("data-stats").replaceChildren(
    el("div", { class: "scroll" }, el("table", {},
      el("thead", {}, el("tr", {}, el("th", {}, "Tabelle"), el("th", {}, "Zeilen"))),
      el("tbody", {}, ...rows.map(([t, n]) =>
        el("tr", {}, el("td", {}, TABLE_LABEL[t] || t),
          el("td", { class: "mono" }, n.toLocaleString("de-DE")))))
    )),
    el("p", { class: "muted" },
      `Datenbank: ${BYTES(stats.db_bytes)} unter ${stats.db_path}`
      + (stats.oldest_observation
          ? ` · älteste Beobachtung ${new Date(stats.oldest_observation * 1000).toLocaleDateString("de-DE")}`
          : "")),
  );
}

document.getElementById("save-retention").onclick = async () => {
  const inputs = document.getElementById("retention-form")._inputs || {};
  const payload = Object.fromEntries(
    Object.entries(inputs).map(([k, i]) => [k, String(i.value)])
  );
  await api.send("PUT", "/api/settings", payload);
  document.getElementById("retention-msg").textContent = "Gespeichert.";
};

/** Löschen ist nicht rückgängig zu machen — deshalb beschreibt der Dialog,
 *  was konkret verschwindet, statt nur „Sind Sie sicher?" zu fragen. */
async function purge(scope, title, description, counts) {
  if (!confirm(`${title}\n\n${description}\n\nDas lässt sich nicht rückgängig machen.`)) return;
  const msg = document.getElementById("data-msg");
  msg.textContent = "läuft …";
  try {
    const r = await api.send("POST", "/api/data/purge", { scope, confirm: true });
    msg.textContent = r.total
      ? `${r.total.toLocaleString("de-DE")} Zeilen gelöscht (`
        + Object.entries(r.removed).map(([t, n]) => `${TABLE_LABEL[t] || t}: ${n}`).join(", ") + ")"
      : "Es gab nichts zu löschen.";
  } catch (err) {
    msg.textContent = String(err);
  }
  loadData();
  loadStatus();
  loadDevices();
}

document.getElementById("purge-history").onclick = () => purge(
  "history", "Nur Verlauf löschen",
  "Anwesenheits-Historie, MAC-Tabellen, LLDP-Nachbarn und WLAN-Assoziationen werden entfernt. "
  + "Die Geräteliste mit Namen, Notizen und Merkmalen bleibt erhalten.");

document.getElementById("purge-devices").onclick = () => purge(
  "devices", "Alle gesammelten Daten löschen",
  "Sämtliche Geräte, Adressen, Merkmale und Verläufe werden entfernt — auch selbst vergebene "
  + "Namen und Notizen. Adapter und Einstellungen bleiben.");

document.getElementById("purge-everything").onclick = () => purge(
  "everything", "Alles zurücksetzen",
  "Zusätzlich werden alle Adapter samt Zugangsdaten entfernt. Nur die Einstellungen bleiben. "
  + "Vorher besser eine Sicherung exportieren.");

document.getElementById("purge-stale").onclick = async () => {
  const days = Number(document.getElementById("stale-days").value);
  if (!(days >= 1)) return;
  if (!confirm(`Alle Geräte löschen, die seit ${days} Tagen nicht gesehen wurden?\n\n`
    + "Das lässt sich nicht rückgängig machen.")) return;
  const msg = document.getElementById("data-msg");
  msg.textContent = "läuft …";
  try {
    const r = await api.send("POST", "/api/data/purge-stale", { days, confirm: true });
    msg.textContent = `${r.removed} Gerät(e) gelöscht.`;
  } catch (err) { msg.textContent = String(err); }
  loadData(); loadStatus(); loadDevices();
};

document.getElementById("data-vacuum").onclick = async (e) => {
  e.target.disabled = true;
  const msg = document.getElementById("data-msg");
  msg.textContent = "räume auf …";
  try {
    const r = await api.send("POST", "/api/data/vacuum");
    msg.textContent = r.freed
      ? `${BYTES(r.freed)} freigegeben (${BYTES(r.before)} → ${BYTES(r.after)}).`
      : "Nichts freizugeben.";
  } catch (err) { msg.textContent = String(err); }
  e.target.disabled = false;
  loadData();
};

// ----------------------------------------------------------------- Sicherung

document.getElementById("config-export").onclick = async () => {
  const secrets = document.getElementById("export-secrets").checked;
  const data = await api.get(`/api/config/export?include_secrets=${secrets}`);
  download(`nets-sicherung-${new Date().toISOString().slice(0, 10)}.json`,
    JSON.stringify(data, null, 2), "application/json");
  document.getElementById("backup-msg").textContent =
    `${data.net_devices.length} Adapter exportiert`
    + (secrets ? " — Datei enthält Zugangsdaten." : " (ohne Zugangsdaten).");
};

document.getElementById("config-import").onclick = () =>
  document.getElementById("config-file").click();

document.getElementById("config-file").onchange = async (e) => {
  const file = e.target.files?.[0];
  if (!file) return;
  const msg = document.getElementById("backup-msg");
  try {
    const result = await api.send("POST", "/api/config/import", JSON.parse(await file.text()));
    msg.textContent = `${result.imported} Adapter übernommen`
      + (result.skipped.length ? ` · übersprungen: ${result.skipped.join(" | ")}` : ".");
    loadInfra();
    loadSettings();
  } catch (err) {
    msg.textContent = `Import fehlgeschlagen: ${err}`;
  }
  e.target.value = "";
};

document.getElementById("run-sweep").onclick = async (e) => {
  e.target.disabled = true;
  document.getElementById("settings-msg").textContent = "Sweep läuft …";
  try {
    const r = await api.send("POST", "/api/actions/sweep", {});
    document.getElementById("settings-msg").textContent = `${r.found} Antworten erhalten.`;
  } catch (err) {
    document.getElementById("settings-msg").textContent = String(err);
  }
  e.target.disabled = false;
};

// ------------------------------------------------------------------- Start

loadStatus();
loadDevices();
setInterval(loadStatus, 15000);
