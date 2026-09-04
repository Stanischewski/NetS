// Prueft Sortierung und Export der Geraetetabelle, indem app.js mit einem
// minimalen DOM-Stub in einem vm-Kontext geladen wird. Kein Browser noetig.
//
// Ausfuehren:  node tests/test_ui.mjs
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const APP_JS = join(dirname(fileURLToPath(import.meta.url)), "..", "nets", "web", "static", "app.js");

const captured = {};
const fakeNode = () => ({
  className: "", textContent: "", value: "", checked: false, type: "",
  tagName: "DIV", children: [],
  append(...k) { this.children.push(...k); }, replaceChildren() {}, remove() {},
  addEventListener() {}, setAttribute() {}, click() {}, nodeType: 1,
});

const document = {
  querySelectorAll: () => [],
  getElementById: (id) => (captured[id] ||= { ...fakeNode(), id }),
  createElement: fakeNode,
  createElementNS: fakeNode,
  createTextNode: (t) => ({ nodeType: 3, text: t }),
  body: fakeNode(),
};

const downloads = [];
const ctx = {
  document,
  fetch: async () => ({ ok: true, status: 200, text: async () => "[]", json: async () => [] }),
  setInterval: () => {}, setTimeout: () => {}, clearTimeout: () => {},
  console,
  URL: { createObjectURL: () => "blob:x", revokeObjectURL: () => {} },
  Blob: class { constructor(parts) { downloads.push(parts.join("")); } },
};
ctx.globalThis = ctx;
vm.createContext(ctx);
vm.runInContext(readFileSync(APP_JS, "utf8"), ctx);

const now = Math.floor(Date.now() / 1000);
const devices = [
  { id: 1, mac: "aa:bb:cc:00:00:01", ip: "192.0.2.100", vendor: "Zyxel", hostname: "nas",
    addr_mode: "static", attachment: null, last_seen: now - 60, first_seen: now - 900000 },
  { id: 2, mac: "aa:bb:cc:00:00:02", ip: "192.0.2.20", vendor: "Apple", hostname: null,
    label: "iPad", addr_mode: "dhcp", attachment: "sw-keller / 3", last_seen: now - 10, first_seen: now - 100 },
  { id: 3, mac: "a6:bb:cc:00:00:03", ip: null, vendor: null, mac_random: 1, hostname: null,
    addr_mode: "unknown", attachment: null, last_seen: now - 5000, first_seen: now - 5000 },
  { id: 4, mac: "aa:bb:cc:00:00:04", ip: "192.0.2.3", vendor: "Äbc GmbH", hostname: "drucker",
    addr_mode: "dhcp", attachment: null, last_seen: now - 300, first_seen: now - 400 },
];

// Wichtig: top-level `let` in vm.runInContext landet im lexikalischen Scope
// des Kontexts, nicht auf dem Kontextobjekt. Setzen/Lesen muss deshalb
// ebenfalls *innerhalb* des Kontexts passieren.
const run = (code) => vm.runInContext(code, ctx);
const setSort = (key, dir) => run(`deviceSort = ${JSON.stringify({ key, dir })}`);
run(`deviceRows = ${JSON.stringify(devices)}`);
const sorted = () => run("sortDevices(deviceRows)");

let fails = 0;
const check = (name, cond, extra = "") => {
  console.log(`  ${cond ? "ok  " : "FEHL"} ${name}${cond ? "" : "  " + extra}`);
  if (!cond) fails++;
};

// --- Sortierung ---
setSort("ip", "asc");
let ips = sorted().map((d) => d.ip);
check("IP aufsteigend numerisch (.3 < .20 < .100)",
  JSON.stringify(ips) === JSON.stringify(["192.0.2.3", "192.0.2.20", "192.0.2.100", null]),
  JSON.stringify(ips));

setSort("ip", "desc");
ips = sorted().map((d) => d.ip);
check("IP absteigend, Leerwert bleibt hinten",
  JSON.stringify(ips) === JSON.stringify(["192.0.2.100", "192.0.2.20", "192.0.2.3", null]),
  JSON.stringify(ips));

setSort("last_seen", "desc");
const seen = sorted().map((d) => d.id);
check("zuletzt gesehen, neuestes zuerst", JSON.stringify(seen) === JSON.stringify([2, 1, 4, 3]),
  JSON.stringify(seen));

setSort("vendor", "asc");
// Deutsche Sortierung (DIN 5007-1): Ä zaehlt wie A, also "Äbc" < "Apple"
// (b < p). Und "zufällige MAC" < "Zyxel" (u < y).
const vendors = sorted().map((d) => d.vendor || "zufällige MAC");
check("Hersteller nach deutscher Kollation (Ä wie A)",
  JSON.stringify(vendors) === JSON.stringify(["Äbc GmbH", "Apple", "zufällige MAC", "Zyxel"]),
  JSON.stringify(vendors));

setSort("name", "asc");
const names = sorted().map((d) => d.label || d.hostname || "");
check("Name: Geräte ohne Namen ans Ende",
  names[names.length - 1] === "", JSON.stringify(names));

check("Original bleibt unverändert", run("deviceRows[0].id") === 1);

// --- Export ---
setSort("ip", "asc");
run('exportDevices("csv")');
const csv = downloads.at(-1);
const lines = csv.split("\r\n");
check("CSV hat BOM", csv.charCodeAt(0) === 0xfeff);
check("CSV Kopfzeile", lines[0].includes('"Gerät";"MAC";"IP"'), lines[0]);
check("CSV Zeilenzahl (Kopf + 4)", lines.length === 5, String(lines.length));
check("CSV in Sortierreihenfolge", lines[1].includes("192.0.2.3"), lines[1]);
check("CSV Leerwert als leeres Feld", lines[4].includes(';"";'), lines[4]);
check("CSV zufällige MAC benannt", csv.includes("zufällige MAC"));

run('exportDevices("md")');
const md = downloads.at(-1);
const mdLines = md.split("\n");
check("MD Überschrift", mdLines[0].startsWith("# Netzwerkgeräte"), mdLines[0]);
check("MD Trennzeile", mdLines[5].startsWith("| --- |"), mdLines[5]);
check("MD Tabellenzeilen", mdLines.filter((l) => l.startsWith("| ")).length === 6);
check("MD Leerwert als Gedankenstrich", md.includes("| — |"));

// --- Topologie-Baum ---
const tree = {
  roots: [{
    id: "net:1", kind: "infra", label: "HP-2530", sublabel: "snmp", badges: [], count: 3,
    children: [
      {
        id: "port:1:12", kind: "port", label: "Port 12", sublabel: "2 Geräte", badges: [],
        hidden_infrastructure: true, count: 2,
        children: [
          { id: "dev:1", device_id: 1, kind: "device", label: "drucker", sublabel: "192.0.2.3 · Brother",
            mac: "00:1b:a9:44:55:66", ip: "192.0.2.3", badges: [], count: 1, children: [] },
          { id: "dev:2", device_id: 2, kind: "device", label: "192.0.2.9", sublabel: "Tuya Smart",
            mac: "bc:35:1e:00:00:01", ip: "192.0.2.9", badges: [], count: 1, children: [] },
        ],
      },
      {
        id: "port:1:23", kind: "port", label: "Port 23", sublabel: "1 Gerät", badges: [], count: 1,
        children: [{ id: "dev:3", device_id: 3, kind: "device", label: "shelly", sublabel: "192.0.2.230",
                     mac: "a4:f0:0f:00:00:01", ip: "192.0.2.230", badges: [], count: 1, children: [] }],
      },
    ],
  }],
  stats: { infra: 1, ports: 2, attached: 3, unattached: 0 },
};
run(`topoData = ${JSON.stringify(tree)}`);

const labelsOf = (node) => {
  const out = [];
  (function walk(n) {
    if (!n) return;
    if (typeof n.className === "string" && n.className.startsWith("tlabel")) {
      out.push(n.children.map((c) => c.text ?? "").join(""));
    }
    (n.children || []).forEach(walk);
  })(node);
  return out;
};

run("topoCollapsed = new Set()");
check("Baum ohne Filter zeigt alle Ebenen",
  JSON.stringify(labelsOf(run('treeNode(topoData.roots[0], "", 0)')))
    === JSON.stringify(["HP-2530", "Port 12", "drucker", "192.0.2.9", "Port 23", "shelly"]),
  JSON.stringify(labelsOf(run('treeNode(topoData.roots[0], "", 0)'))));

// Zugeklappter Port darf seine Kinder nicht rendern.
run('topoCollapsed = new Set(["port:1:12"])');
check("zugeklappter Port verbirgt seine Geräte",
  !labelsOf(run('treeNode(topoData.roots[0], "", 0)')).includes("drucker"));

// Suche muss Zweige ohne Treffer weglassen ...
run("topoCollapsed = new Set()");
let hits = labelsOf(run('treeNode(topoData.roots[0], "shelly", 0)'));
check("Suche entfernt Zweige ohne Treffer",
  JSON.stringify(hits) === JSON.stringify(["HP-2530", "Port 23", "shelly"]), JSON.stringify(hits));

// ... und Treffer trotz zugeklapptem Elternteil sichtbar machen.
run('topoCollapsed = new Set(["port:1:12", "net:1"])');
hits = labelsOf(run('treeNode(topoData.roots[0], "brother", 0)'));
check("Suche klappt den Pfad zum Treffer auf",
  hits.includes("drucker") && hits.includes("Port 12"), JSON.stringify(hits));

check("Treffer in MAC findet das Gerät",
  labelsOf(run('treeNode(topoData.roots[0], "a4:f0:0f", 0)')).includes("shelly"));

check("Suche ohne Treffer liefert nichts",
  run('treeNode(topoData.roots[0], "gibtesnicht", 0)') === null);

// Ein Treffer auf dem Port zeigt dessen komplette Geräteliste.
hits = labelsOf(run('treeNode(topoData.roots[0], "port 12", 0)'));
check("Treffer auf Port zeigt alle Kinder darunter",
  hits.includes("drucker") && hits.includes("192.0.2.9"), JSON.stringify(hits));

// --- Weboberflächen: dieselbe Sortiermaschinerie ---
const webData = [
  { ip: "192.0.2.20", port: 8006, scheme: "https", status: 200, source: "scan",
    title: "pve - Proxmox Virtual Environment", server: null, last_seen: 1000,
    hostname: "pve", device_id: 1 },
  { ip: "192.0.2.2", port: 443, scheme: "https", status: 200, source: "scan",
    title: "UniFi OS", server: null, last_seen: 3000, hostname: "udm", device_id: 2 },
  { ip: "192.0.2.2", port: 80, scheme: "http", status: 301, source: "scan",
    title: "301 Moved Permanently", server: null, last_seen: 3000, device_id: 2 },
  { ip: "192.0.2.117", port: 80, scheme: "http", status: null, source: "mdns",
    title: null, server: null, last_seen: 2000, hostname: "Shelly1Mini", device_id: 3 },
];
run(`webRows = ${JSON.stringify(webData)}`);
const setWebSort = (key, dir) => run(`webSort = ${JSON.stringify({ key, dir })}`);
const webSorted = () => run("sortRows(webRows, WEB_COLUMNS, webSort)");

setWebSort("address", "asc");
let addrs = webSorted().map((r) => `${r.ip}:${r.port}`);
check("Web: Adresse numerisch, Port als Nebenschlüssel",
  JSON.stringify(addrs) === JSON.stringify(
    ["192.0.2.2:80", "192.0.2.2:443", "192.0.2.20:8006", "192.0.2.117:80"]),
  JSON.stringify(addrs));

setWebSort("status", "asc");
let stat = webSorted().map((r) => r.status);
check("Web: Status numerisch, ohne Status ans Ende",
  JSON.stringify(stat) === JSON.stringify([200, 200, 301, null]), JSON.stringify(stat));

setWebSort("last_seen", "desc");
const webSeen = webSorted().map((r) => r.last_seen);
check("Web: zuletzt nach Zeitstempel, nicht nach Text",
  JSON.stringify(webSeen) === JSON.stringify([3000, 3000, 2000, 1000]), JSON.stringify(webSeen));

setWebSort("title", "asc");
const titles = webSorted().map((r) => r.title);
check("Web: fehlender Titel ans Ende", titles[titles.length - 1] === null,
  JSON.stringify(titles));

setWebSort("kind", "asc");
const kinds = webSorted().map((r) => run(`webKind(${JSON.stringify(r)})`));
check("Web: erkannte Art sortierbar, Unerkanntes ans Ende",
  kinds[0] === "Proxmox VE" && kinds[kinds.length - 1] === null, JSON.stringify(kinds));

check("Web: Spalten haben alle einen Textwert für den Vergleich",
  run("WEB_COLUMNS.every(c => typeof c.text === 'function')"));

// Geräte- und Web-Tabelle teilen sich dieselbe Funktion.
check("Sortierung wird geteilt, nicht kopiert",
  run("typeof sortRows === 'function' && typeof sortableHead === 'function'"));

console.log(fails ? `\n${fails} Prüfung(en) fehlgeschlagen` : "\nalles gruen");
console.log("\n--- Markdown-Auszug ---\n" + mdLines.slice(4, 9).join("\n"));
process.exit(fails ? 1 : 0);
