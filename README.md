# NetS

Netzwerk-Inventar mit Historie und Layer-2-Topologie. Läuft dauerhaft auf
einem Server oder in einem LXC, hört passiv mit und findet dadurch über Tage
auch Geräte, die selten online sind oder aktiv nicht gefunden werden wollen.

## Grundgedanke

Nicht scannen, sondern **zuhören** — dauerhaft, und alles in eine
Append-only-Historie schreiben. Ein Gerät kann ICMP verwerfen, alle Ports
schließen und sich taub stellen. Aber es kann nicht am Netz teilnehmen, ohne
ARP zu sprechen, und ARP ist Broadcast. Wer aktiv ist, taucht auf.

Damit erledigt sich auch das „Gerät ist meistens offline"-Problem: man muss
nicht zufällig zum richtigen Zeitpunkt scannen.

## Datenquellen

**Passiv** (ein Sniffer, ein gemeinsamer BPF-Filter):

| Quelle | Liefert |
|---|---|
| ARP | MAC↔IP, Anwesenheit — unumgehbar |
| DHCP | Hostname (Opt 12), Vendor Class (Opt 60), **Fingerprint (Opt 55)** |
| mDNS/Bonjour | Hostname, Gerätemodell, angebotene Dienste |
| SSDP/UPnP | Hersteller, Produkt, Firmware aus dem SERVER-Header |
| IPv6 NDP | Geräte, die per IPv4 stumm sind |
| LLDP | Infrastruktur meldet sich selbst mit SysName und Port |

Alle diese Protokolle sind Broadcast oder Multicast — deshalb funktioniert das
auch in einem geswitchten Netz **ohne Port-Mirroring**.

**Aktiv**, sparsam und geplant:

* **ARP-Sweep** statt Ping-Sweep. Der Kernel *muss* ARP beantworten, sonst kann
  das Gerät selbst nicht kommunizieren — eine Host-Firewall hilft dagegen nicht.
* ICMPv6 an `ff02::1` (All-Nodes), fängt IPv4-stumme Geräte.
* `ip neigh` des eigenen Hosts.
* optional nmap für Dienste und OS-Vermutung.

### mDNS-Reflectoren

Router und Smart-Home-Zentralen spiegeln mDNS über VLAN-Grenzen (UniFi:
„mDNS Reflector", Avahi: `reflector=yes`). Dabei setzen sie ihre **eigene**
Absender-MAC ein. Wer die Merkmale dem Absender zuschreibt, lässt den Router
die Identität jedes Geräts aufsaugen, für das er spiegelt — gemessen: ein
UDM-Pro mit 27 fremden Hostnamen und Modellen, von Fernsehern über Shellys
bis zum Drucker.

Die Wahrheit steht im Paket: Der A-Record nennt die Adresse des *gemeinten*
Geräts. Weicht sie von der Absenderadresse ab, werden die Merkmale nach ihr
zugeordnet, und der Absender bekommt stattdessen `role=mdns_reflector`.

Verglichen wird dabei nur IPv4 gegen IPv4 — der A-Record ist immer IPv4, und
ein Vergleich gegen eine IPv6-Absenderadresse würde jedes Gerät, das mDNS über
IPv6 schickt, fälschlich zum Weiterleiter erklären.

### Mehrere Subnetze

Der wichtigste Satz zuerst: **ARP überquert keinen Router.** Ein ARP-Sweep
findet nur im eigenen Layer-2-Segment etwas — für ein geroutetes Netz liefert
er stillschweigend null Treffer, ohne Fehler und ohne Hinweis.

Zwei Dinge müssen dafür stimmen, und beide waren anfangs falsch:

**Das richtige Interface.** Der Sweep nahm immer das eine konfigurierte
Interface. Steht der Rechner in zwei Segmenten, gehen die ARP-Anfragen am Ziel
vorbei — gemessen: 0 Antworten über `wlan0`, 2 über `enp0s31f6`, dasselbe
Subnetz. Das Interface kommt jetzt aus der Routing-Tabelle (`ip route get`).

**Passiv auf allen Interfaces.** Broadcast endet am Router, also sieht jedes
Interface nur sein eigenes Netz. `iface` nimmt deshalb eine kommagetrennte
Liste; scapy bekommt sie direkt und markiert jedes Paket mit `sniffed_on`, was
die Zählung je Interface ergibt. An einem Rechner mit WLAN und Kabel:
15 435 Pakete auf der Kabelseite gegen 474 im WLAN — wer nur auf einem lauscht,
verpasst das meiste.

Deshalb wird nach Erreichbarkeit unterschieden. Was auf einem eigenen
Interface liegt, bekommt einen ARP-Sweep; alles andere einen gerouteten Sweep
aus ICMP plus TCP-Verbindungsversuch (viele Hosts verwerfen Ping, kaum einer
hat gar keinen offenen Port).

Der Unterschied im Ergebnis ist grundsätzlich:

| | eigenes Segment | geroutetes Netz |
|---|---|---|
| passiv (ARP, DHCP, mDNS …) | ja | **nein** — Broadcast endet am Router |
| MAC-Adresse | ja | **nein** |
| Hersteller, Fingerprint, Historie | ja | **nein** |
| „hier antwortet etwas" | ja | ja |

Jenseits des eigenen Segments gibt es keine MAC — im Antwortpaket steht die
des nächsten Hops. Solche Funde landen deshalb in einer eigenen Tabelle statt
in der Geräteliste; eine erfundene MAC wäre schlimmer als die sichtbare Lücke.

**Um trotzdem an echte Geräte zu kommen, gibt es zwei Wege:**

1. **Den Router fragen.** Seine ARP-Tabelle enthält IP↔MAC für jedes Netz, das
   er routet — das ist `Capability.ARP_TABLE`, die der SNMP-Adapter schon
   bedient. Der geroutete Sweep hilft dabei doppelt: Jeder Versuch zwingt den
   Router, für die Zieladresse zu arpen, und füllt so seine Tabelle.
2. **Ein Interface je VLAN.** Dann greifen auch die passiven Quellen. Siehe
   `deploy/README-LXC.md`.

Die Übersicht unter `/api/subnets` zeigt je Netz, wie viele Adressen echtes
Inventar sind (`with_mac`) und wie viele bloß antworten (`responding`) — und
schlägt aus der Routing-Tabelle vor, was noch nicht durchsucht wird.

**Von der Infrastruktur** über Adapter: FDB-Tabellen, LLDP-Nachbarn,
DHCP-Leases, WLAN-Assoziationen, Router-ARP-Cache.

### Watchdog

Der scapy-Sniffer-Thread stirbt bei einem Interface-Wechsel (WLAN-Reconnect,
Link-Down) ohne Fehlermeldung einfach weg — danach sammelt das Tool still
nichts mehr, und das fällt erst Tage später an Lücken in der Historie auf.
Deshalb prüft ein Watchdog jede Minute zwei Dinge und startet bei Bedarf neu:

* Läuft der Thread überhaupt noch?
* Steht der Paketzähler seit über 15 Minuten still? Ein Netz ohne jeden
  Broadcast in dieser Zeit gibt es nicht — dann ist der Socket tot, auch wenn
  der Thread noch läuft. (`sniffer_stall_seconds`, `0` schaltet es ab.)

Neustarts samt Grund stehen in der Übersicht.

## Statisch vs. DHCP

Wird aus der Beobachtungsdauer abgeleitet, nicht geraten: Ein Gerät gilt als
statisch adressiert, wenn es lange genug bekannt ist (Default 3 Tage), eine
IPv4 hat und in der ganzen Zeit **nie** DHCP-Verkehr gezeigt hat. Umgekehrt
setzt jedes DHCP-Paket und jede Lease den Modus sofort auf `dhcp`.

## Hersteller

IEEE-OUI-Datenbank inklusive der feineren MA-M/MA-S-Blöcke (28/36 Bit), das
längste Präfix gewinnt. Bei **randomisierten MACs** (iOS/Android/Win11,
erkennbar am U/L-Bit) wird bewusst *kein* Hersteller angezeigt — ein falscher
wäre schlimmer als keiner.

## Was tun gegen „zufällige MAC"?

Der Hersteller-Lookup ist dort wertlos, die Information steckt aber in Daten,
die ohnehin schon eingesammelt werden. Zwei Schritte:

**1. Nicht jede lokal vergebene MAC ist ein Privacy-Handy.** Unterschieden
werden vier Herkünfte:

| Art | Erkennung |
|---|---|
| **Funkmodul (BSSID)** | unterscheidet sich nur im U/L-Bit von einer bekannten Geräte-MAC |
| **Virtualisierung** | bekanntes Präfix (`52:54:00` QEMU, `02:42` Docker …) oder Meldung des Hypervisors |
| **Privacy-MAC** | lokal vergeben, ohne die obigen Merkmale |
| **regulär** | global vom Hersteller vergeben |

**2. Identität aus dem Verhalten ableiten.** Nach Belastbarkeit sortiert:

* **DHCP Option 60** (Vendor Class) — nennt oft die Version: `android-dhcp-16`
  → Android 16, `MSFT 5.0` → Windows.
* **DHCP Option 55** (Parameter Request List) — die *Reihenfolge* der
  angefragten Optionen ist je Client charakteristisch und ändert sich mit der
  MAC nicht mit. Exakter Treffer oder ≥ 75 % Ähnlichkeit, darunter wird nichts
  behauptet.
* **mDNS-TXT-Records** — Fernseher und Drucker nennen ihr Modell im Klartext.
* **Angebotene Dienste** — `_googlecast._tcp` → Streaming/TV, `_ipp._tcp` →
  Drucker.

Harte Auskünfte schlagen dabei Vermutungen: Was ein Hypervisor über eine VM
meldet, gilt mehr als ein Dienst, den sie zufällig anbietet.

Ergebnis in einem echten Netz — von 14 anonymen MACs blieben 3 unbestimmt:

```
3e:74:da:00:00:01   Android 16 · Smartphone / Tablet      Android-Telefon
86:48:b3:00:00:01   iOS / iPadOS · Smartphone / Tablet    iPhone
02:fd:ac:00:00:01   VM                                    (Home Assistant)
36:19:4d:00:00:01   Funkmodul                             (BSSID des Routers)
e2:66:da:00:00:01   Streaming / TV                        (Fernseher XY-1234)
36:93:8b:00:00:01   flüchtig — einmalig gesehen, nie eine IP
```

Jede Ableitung wird in der Detailansicht mit ihrer **Begründung** angezeigt —
eine Vermutung ohne Beleg wäre wertlos.

### Flüchtige MACs

Eine MAC, die genau einmal in einer Switch-Tabelle auftaucht und nie eine IP
hatte, ist kein Gerät im Netz, sondern eine kurz assoziierte Station oder ein
Rotationsartefakt. Sie wird als solche markiert, statt neben einem seit Stunden
aktiven Gerät gleichrangig in der Liste zu stehen.

### Rotierende MACs zusammenführen?

Wird **vorgeschlagen, nie automatisch gemacht.** Kandidaten brauchen gleichen
DHCP-Fingerprint bzw. Hostnamen **und** dürfen sich zeitlich nicht
überschneiden. Der zweite Teil ist der entscheidende: zwei MACs, die
gleichzeitig im Netz waren, können nicht dasselbe Gerät sein.

Im Testnetz hingen drei MACs mit identischem iOS-Fingerprint und dem Hostnamen
„iPhone" im Netz — zeitlich überlappend. Ein automatisches Zusammenführen hätte
aus drei Geräten eines gemacht.

## Topologie

Aus den FDB-Tabellen (MAC-Adresstabellen) der Switches. Das Kernproblem: eine
MAC steht in der FDB *mehrerer* Switches — beim richtigen und bei jedem davor
über dessen Uplink. Gelöst über die klassische Heuristik:

> Der Port, an dem ein Gerät wirklich hängt, ist der Port mit den **wenigsten**
> gelernten MACs.

Zusätzlich gilt: Ports, an denen LLDP einen Nachbarn meldet, sind nachweislich
Uplinks und werden ausgeschlossen. Jede Zuordnung bekommt eine
Konfidenz (1.0 = genau ein Gerät am Port).

**Voraussetzung:** managed Switches mit SNMP oder API. Bei Dumb-Switches ist
die Port-Zuordnung physikalisch nicht ermittelbar — Geräte werden trotzdem
gefunden, stehen dann aber unter „Ohne Port-Zuordnung".

### Darstellung

Als **hierarchischer Baum**, nicht als Graph. Ein kräftebasiertes Layout ist
bei dieser Datenform unlesbar: In einem typischen Netz hängen fast alle Geräte
an einer Handvoll Ports, und ein einziger Uplink trägt schnell zwei Dutzend
MACs — als Ring um einen Punkt ist das nicht zu entziffern.

```
HP-2530-24G-PoEP — snmp [ok]                                    ×27
   pve.example ←Port 24 — über LLDP gemeldet, nicht konfiguriert   ×0
   Port 12 — 23 Geräte [23 MACs — vermutlich Uplink]            ×23
   Port 23 — 1 Gerät                                             ×1
   Port 24 — 3 Geräte [LLDP-Nachbar]                             ×3
OPNsense — snmp · keine MAC-Tabelle geliefert                    ×0
Ohne Port-Zuordnung — kein Switch meldet diese MACs               ×4
   192.0.2.0/24                                                ×3
   192.0.2.0/24                                                ×1
```

Was der Baum sichtbar macht:

* **Ports mit vielen MACs werden als vermuteter Uplink markiert.** Hängen an
  einem Port vier oder mehr Geräte, steckt dort fast sicher ein unmanaged
  Switch, ein Access Point oder ein Virtualisierungs-Host. Ohne diesen Hinweis
  sieht es so aus, als hingen zwei Dutzend Geräte direkt am Switchport.
* **LLDP-Nachbarn, die nicht konfiguriert sind**, tauchen als Hinweis auf —
  da gibt es Infrastruktur, die du noch hinzufügen könntest.
* **Geräte ohne Zuordnung** stehen nach Subnetz gruppiert sichtbar da, statt
  wie vorher nur als Zahl.
* **Ein Knoten ohne Port-Daten sagt das auch.** Router haben typischerweise
  keine Bridge-FDB; das ist normal und kein Fehler.

Ports mit mehr als sechs Geräten starten zugeklappt. Die Suche filtert Zweige
ohne Treffer weg und klappt den Pfad zum Treffer automatisch auf.

### Wenn hinter einem Port ein WLAN-Router steckt

Ein Provider-Router wie ein Speedport hat keine abfragbare Schnittstelle: kein
SNMP, kein TR-064, und die Geräteliste der Web-Oberfläche steckt hinter dem
Login. Der Switch sieht dort nur einen Haufen MACs an einem Port.

Der Ausweg braucht keine Mitwirkung des Geräts: **802.11-Mitschnitt im
Monitor-Mode.** Die Zuordnung steht in jedem Frame, das durch die Luft geht.
Anders als bei Ethernet hat ein 802.11-Frame bis zu vier Adressfelder, deren
Bedeutung an den Flags ToDS/FromDS hängt:

```
ToDS=1, FromDS=0   Station → AP     addr1=BSSID    addr2=Station
ToDS=0, FromDS=1   AP → Station     addr1=Station  addr2=BSSID
ToDS=0, FromDS=0   Management       addr3=BSSID
```

Damit fällt aus jedem Datenframe ab, welche Station mit welchem Funkmodul
spricht. Beacons liefern zusätzlich BSSID → SSID und Kanal. Im Baum stehen die
Clients dann unter ihrem AP statt flach am Uplink:

```
Port 12 — 22 Geräte [2 Funkmodule erkannt]
   WLAN-Beispiel — 36:19:4d:00:00:01 · Kanal 11 · 2,4 GHz · 8 Clients
   WLAN-Beispiel — 24:41:fe:00:00:10 · Kanal 36 · 5 GHz · 6 Clients
   drucker (kabelgebunden)
```

**Voraussetzung: eine zweite WLAN-Karte im Monitor-Mode.** Die Karte, die die
normale Verbindung trägt, kann das nicht nebenbei — ein USB-Adapter am Host
genügt. Einzuschalten unter Einstellungen (`wifi_enabled`, `wifi_iface`).

Der Sniffer springt Kanäle durch; kürzere Verweildauer bedeutet schnellere
Runden, aber mehr verpasste Frames. Kanäle, die die Karte oder die Regulatory
Domain nicht hergibt, werden automatisch übersprungen.

#### BSSIDs erkennen ohne Mitschnitt

Auch ohne Funkkarte lässt sich sagen, *welche* MACs Funkmodule sind: Access
Points leiten die BSSID fast immer aus der Geräte-MAC ab, indem sie das
U/L-Bit setzen. `36:19:4d:00:00:01` gehört damit eindeutig zum Gerät
`34:19:4d:00:00:01`. Mehrere Radios eines Geräts bekommen meist
aufeinanderfolgende Adressen — das ist allerdings nur ein Hinweis, kein Beweis,
und wird deshalb nie zum Zusammenführen benutzt.

### UniFi: API-Schlüssel oder Passwort?

**Der API-Schlüssel genügt.** Entscheidend ist nicht der Zugangsweg, sondern
welche API angesprochen wird — und ein Schlüssel öffnet (gemessen an Network
10.5) beide:

| API | liefert |
|---|---|
| klassisch `/proxy/network/api/s/<site>/…` | Switch-Port je Client, SSID, Signal, VLAN, DHCP-Leases |
| Integration `/proxy/network/integration/v1` | nur „hinter welchem Gerät", ohne Port, SSID, Signal |

Der Adapter versucht deshalb **immer zuerst die klassische API** und fällt nur
bei Ablehnung auf die Integrations-API zurück. Passiert das, sagt der
Verbindungstest es ausdrücklich.

**API-Schlüssel** anlegen: Einstellungen → Integrationen. Widerrufbar,
read-only, unproblematisch mit Zwei-Faktor-Anmeldung.

**Passwort** bleibt für ältere Controller ohne Schlüssel-Funktion. Dann braucht
es einen *lokalen* Benutzer: kein Ubiquiti-Cloud-Konto (SSO) und keine
Zwei-Faktor-Anmeldung, weil der Login-Endpunkt keinen zweiten Faktor abfragen
kann. Nur-Lese-Rolle genügt.

Vorsicht bei der Basis-URL: Die Adresse, die die Oberfläche unter
„Integrationen" anzeigt (`/unifi-api/network`), ist **nicht** der API-Pfad —
sie liefert die Oberfläche selbst zurück, und zwar mit HTTP 200. Der Adapter
prüft deshalb zusätzlich den Content-Type, sonst scheitert erst das Parsen mit
einer nichtssagenden Meldung.

### Wenn hinter einem Port ein Virtualisierer steckt

Der Fall, den kein Switch auflösen kann: An einem einzigen Port hängt ein
Proxmox-Host mit einer Linux-Bridge, an der ein Dutzend VMs sitzt. Der Switch
sieht dort nur einen Haufen MACs und meldet sie alle am Uplink.

Proxmox weiß es genau — die Gastkonfiguration enthält MAC, Bridge und
VLAN-Tag jeder Schnittstelle. Mit konfiguriertem **Proxmox-Adapter** werden aus
„23 unbekannte MACs an Port 24" benannte Maschinen:

```
HP-2530-24G-PoEP
   Proxmox ←Port 24 — proxmox · 192.0.2.2 · bc:24:11:…
      pve1 / vmbr0 — 12 Geräte
         opnsense       VM 101 auf pve1 · vmbr0 · VLAN 20 · running
         nextcloud      CT 200 auf pve1 · vmbr0 · running
```

Read-only-Zugang genügt:

```bash
pveum role add NetSAudit -privs "VM.Audit,Sys.Audit,Datastore.Audit"
pveum user add nets@pve
pveum acl modify / -user nets@pve -role NetSAudit
pveum user token add nets@pve inventory --privsep 0
```

### Wie ein LLDP-Nachbar einem Adapter zugeordnet wird

LLDP liefert je nach Gegenstelle Unterschiedliches — mal nur eine Chassis-MAC,
mal nur einen SysName, mal beides. Und kaum jemand benennt seinen Adapter
exakt so, wie das Gerät sich selbst nennt. Deshalb vier Schlüssel, vom
Sichersten zum Schwächsten:

1. **Chassis-MAC** gegen die vom Adapter gemeldeten Eigenadressen
2. **Chassis-MAC → passiv beobachtete IP → Management-IP eines Adapters.**
   Der wichtigste Weg in der Praxis: Er trägt auch dann, wenn die API des
   Geräts seine NIC-MACs gar nicht preisgibt. Bei Proxmox ist genau das nicht
   garantiert — die beobachtete IP schlägt dann die Brücke zur Adapter-URL.
3. **SysName** gegen den Adapternamen
4. **Erster Teil eines FQDN** gegen den Adapternamen (`pve.example` → `pve`)

Ein Nachbar, der sich nicht zuordnen lässt, wird mit Name, IP **und** MAC
beschriftet — damit erkennbar ist, welches Gerät man nachtragen müsste:

```
pve.example · 192.0.2.20 · 00:d8:61:00:00:01 ←Port 24   [nicht abgefragt]
```

Gibt ein Gerät seine eigenen MACs gar nicht heraus — Proxmox liefert unter
`/nodes/<node>/network` keine `hwaddr` —, werden sie über die Management-IP
nachgeschlagen: die hat der passive Sniffer längst einer MAC zugeordnet.

### Infrastruktur hinter Infrastruktur

Eine Firewall-VM auf einem Proxmox-Host, der an einem Switchport steckt, ist
drei Ebenen tief. LLDP sagt dazu nichts. Die Verschachtelung kommt deshalb aus
den FDB-Tabellen: Die eigene MAC eines Geräts steht in der Tabelle dessen, was
davor hängt — und der Port mit den **wenigsten** MACs ist der nächstgelegene,
also der richtige Elternteil. Ohne diese Regel hinge die VM genauso am
Kernswitch wie an ihrem Host.

```
Switch — 192.0.2.208
   pve ←24 — 192.0.2.20
      OPNsense ←pve:vmbr1 — 192.0.2.2
      pve / vmbr0 — Home Assistant, vaultwarden
   Port 12 — 22 Geräte [vermutlich Uplink]
```

Eine VM mit Schnittstellen auf mehreren Bridges kann im Baum nur an einer
Stelle stehen; gewählt wird die mit den wenigsten MACs.

## Herstellerunabhängigkeit

Der Kern kennt keinen Hersteller, nur die Adapter-Schnittstelle in
[nets/adapters/base.py](nets/adapters/base.py). Jeder Adapter beschreibt sich
selbst über `capabilities` und `config_fields`; die WebUI baut daraus
generisch das Konfigurationsformular. **Ein neuer Hersteller = eine neue Datei
in `nets/adapters/`, kein Eingriff in Kern oder UI.**

Mitgeliefert:

| Adapter | Fähigkeiten |
|---|---|
| **SNMP (generisch)** | FDB, LLDP, Ports, ARP-Tabelle — nur Standard-MIBs, läuft auf praktisch jedem managed Switch |
| **UniFi Controller** | WLAN-Clients mit AP+SSID, Switch-Ports, Leases |
| **OpenWrt (ubus)** | Leases, ARP, WLAN-Assoziationen |
| **MikroTik RouterOS 7** | echte Bridge-Host-Tabelle, Leases, LLDP, WLAN |
| **AVM FRITZ!Box (TR-064)** | komplette Hostliste inkl. offline, statisch/dynamisch, WLAN |
| **UniFi Controller** | zwei Wege — Passwort (Port, SSID, Signal, Leases) oder API-Schlüssel (nur „hinter welchem Gerät", dafür MFA-fest) |
| **Proxmox VE** | VMs/Container mit Name, MAC, Bridge und VLAN — löst den Uplink-Port eines Virtualisierers auf |

Einen eigenen Adapter schreiben: von `Adapter` erben, `type_id`,
`capabilities` und `config_fields` setzen, die passenden Methoden
implementieren, Modulnamen in `_MODULES` in
[nets/adapters/\_\_init\_\_.py](nets/adapters/__init__.py) eintragen.

## Installation

### Ein Befehl, überall

```bash
git clone <repo-url> NetS && cd NetS
sudo bash deploy/install.sh
```

Das Skript prüft die Versionen der Systempakete und wählt selbst:

* **Debian 13+ / Ubuntu 24.10+** → Debian-Paket aus den Systemabhängigkeiten
* **älter** → virtuelle Umgebung unter `/opt/nets`

Danach wartet es, bis die WebUI wirklich antwortet — `systemctl is-active`
allein wäre irreführend, weil systemd den Dienst sofort als gestartet meldet,
uvicorn aber erst einige Sekunden später lauscht.

Mit `--venv` lässt sich der Paketweg überspringen.

### Auf einem beliebigen Rechner

Ein Befehl, der den passenden Weg selbst wählt:

```bash
git clone <repo-url> nets && cd nets
sudo bash deploy/install.sh
```

Er prüft, ob die Systempakete ausreichen, und baut dann entweder das
Debian-Paket oder legt eine virtuelle Umgebung an. Getestet in Containern
beider Generationen:

```
Debian 13   →  ==> Baue und installiere das Debian-Paket
Debian 12   →  ==> Systempakete sind zu alt fuer den Paketweg:
                     python3-fastapi    0.92.0-1
                     python3-scapy      2.5.0+dfsg-2
                   -> virtuelle Umgebung
```

Beide enden mit laufendem Dienst, WebUI auf Port 8080 und der
Herstellerdatenbank unter `/var/lib/nets/oui.tsv`. Mit `--venv` lässt sich der
Paketweg überspringen.

### Als Debian-Paket (empfohlen für LXC und PC)

**Voraussetzung: Debian 13 (trixie) oder neuer** — bzw. Ubuntu 24.10+. Erst
dort bringt Debian die Abhängigkeiten in ausreichenden Versionen mit
(FastAPI 0.115, scapy 2.6.1, httpx 0.28). Debian 12 hat nur FastAPI 0.92, und
der Code braucht `lifespan=` im Konstruktor — das kam mit 0.93. Für Debian 12
gibt es weiter unten den Weg über eine virtuelle Umgebung.

```bash
bash deploy/build-deb.sh              # oder --docker auf Nicht-Debian-Systemen
sudo apt install --no-install-recommends ./dist/nets_0.1.0-1_all.deb snmp nmap
```

Das `--no-install-recommends` lohnt sich: `python3-scapy` *empfiehlt* ipython3,
was matplotlib und einen C++-Compiler mitzieht. Gemessen — 1,1 GB und 370
Pakete gegen **260 MB und 172 Pakete**. `snmp` und `nmap` deshalb ausdrücklich
mitnennen; ohne sie fehlen der SNMP-Adapter und die optionale
Dienst-Erkennung.

Das Paket erledigt selbst:

* Dienstbenutzer `nets` ohne Login-Shell
* systemd-Unit, aktiviert und gestartet — mit `CAP_NET_RAW`/`CAP_NET_ADMIN`
  statt root
* `/var/lib/nets` mit `0750`
* IEEE-Herstellerdatenbank laden (ohne Netz kein Fehler, nur ein Hinweis)
* `nets` als Befehl in `/usr/bin`

Danach:

```bash
systemctl status nets      # läuft als Benutzer nets
nets check                 # Werkzeuge, Module, Rechte, Datenbank
# WebUI: http://<host>:8080
```

**`libpcap` ist eine harte Abhängigkeit**, keine Empfehlung: ohne sie kann
scapy den BPF-Filter nicht übersetzen, und der Sniffer startet mit
„Cannot set filter" gar nicht. Das Paket zieht sie deshalb selbst.

`apt remove` behält die gesammelten Daten und den Benutzer — die Historie ist
der Wert des Ganzen. Erst `apt purge` entfernt `/var/lib/nets` und den
Benutzer.

Port und Datenbankpfad stehen in der Unit; für eigene Umgebungsvariablen gibt
es `/etc/default/nets`.

### Im LXC über eine virtuelle Umgebung (auch auf Debian 12)

Siehe [deploy/README-LXC.md](deploy/README-LXC.md) — dort steht auch, wie der
Container ans Netz muss, damit überhaupt Broadcast ankommt (das ist der Teil,
an dem es scheitert, nicht die Installation).

```bash
bash deploy/install-lxc.sh
```

### Lokal zum Ausprobieren

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m nets oui-update          # Herstellerdatenbank
.venv/bin/python -m nets check               # Umgebung prüfen
sudo .venv/bin/python -m nets --db ./nets.db serve --port 8080
```

Der Sniffer braucht `CAP_NET_RAW`. Ohne läuft alles andere weiter, die UI sagt
dann auf der Übersicht, woran es liegt.

## Bedienung

WebUI auf Port 8080:

* **Übersicht** — Zählwerte, Sammler-Status, Paketzähler. Steht der nach einer
  Minute auf 0, kommt kein Broadcast an.
* **Geräte** — durchsuchbar, filterbar nach Adressierung und Zeitraum. Klick
  auf eine Spaltenüberschrift sortiert, erneuter Klick dreht die Richtung um;
  IPs werden numerisch sortiert (`.3` vor `.20` vor `.100`), Zeitangaben nach
  echtem Zeitstempel, Text nach deutscher Kollation. Leere Werte bleiben immer
  am Ende. **CSV** und **Markdown** exportieren genau die aktuelle Ansicht —
  gefiltert und sortiert. Klick auf eine Zeile öffnet Details mit
  Anwesenheits-Zeitleiste (30 Tage), IP-Historie, allen Merkmalen samt Quelle
  und der Port-Historie.
* **Topologie** — Graph aus Infrastruktur und Endgeräten; WLAN gestrichelt,
  Uplinks dick, Kantendeckkraft entspricht der Konfidenz.
* **Infrastruktur** — Switches/APs anlegen, Verbindung testen, sofort abfragen.
* **Einstellungen** — Interface, Subnetze, Intervalle, WLAN-Mitschnitt,
  Aufbewahrung, Datenpflege und Sicherung.

## Weboberflächen finden

Eigener Reiter mit klickbaren Adressen, dem Gerät dahinter, Titel und Server.
Bekanntes wird am Titel oder Server-Header benannt — Proxmox, Home Assistant,
UniFi, OpenWrt, FRITZ!Box, Synology, Shelly und einige mehr.

Zwei Quellen, mit unterschiedlichem Charakter:

**Passiv, immer an.** UPnP nennt in seiner Ankündigung eine `LOCATION`-URL,
mDNS im SRV-Record den Port zu `_http._tcp`. Beides liegt ohnehin im Inventar
und kostet keinen einzigen Verbindungsversuch. Im Testnetz fanden sich so fünf
Shellys, ohne irgendwo anzuklopfen.

**Aktiv, standardmäßig aus** (`web_scan_enabled`). Klopft auf bekannten
Adressen an den konfigurierten Ports an — Standard `80, 443, 8006, 8123, 8080,
8443, 3000, 5000, 8081, 9000`. Gesucht wird **nur** auf IPv4-Adressen, die
schon im Inventar stehen und in den letzten sieben Tagen gesehen wurden; es
gibt keinen zusätzlichen Scan des Adressraums.

Die Tabelle ist wie die Geräteliste **sortierbar** — Klick auf die Spalte,
erneuter Klick dreht die Richtung. Adressen sortieren numerisch nach IP mit
dem Port als Nebenschlüssel (`:80` vor `:443` vor `:8006` desselben Geräts),
„zuletzt" nach Zeitstempel statt nach Text. Beide Tabellen teilen sich
dieselbe Sortierfunktion und denselben Kopfzeilen-Bauer; zwei Kopien derselben
Regeln würden über kurz oder lang auseinanderlaufen.

`401` und `403` zählen als Treffer — dort *ist* eine Oberfläche, sie will nur
Anmeldedaten. `404` und `5xx` nicht.

### Warum eine TCP-Vorprüfung

Der häufigste Fall ist der geschlossene Port. Ohne Vorprüfung zahlt jede
Kombination aus Adresse und Port den vollen HTTP-Timeout, bei TLS-Ports
zusätzlich einen Handshake ins Leere. Ein Lauf über 72 Adressen × 10 Ports lief
damit über zehn Minuten.

Mit einem vorgeschalteten `asyncio.open_connection` (1,5 s) fällt der
geschlossene Port sofort raus, und nur wirklich offene Ports bekommen eine
HTTP-Anfrage. Dazu ein gemeinsamer `httpx`-Client für den ganzen Lauf statt
einem pro Anfrage. Ergebnis im selben Netz: **10 Sekunden**.

## Daten verwalten

Unter Einstellungen zeigt eine Übersicht, wie viele Zeilen je Tabelle
existieren und wie groß die Datenbank ist — damit vor dem Löschen sichtbar
ist, was es überhaupt betrifft.

### Eine Zeile je Zuordnung, nicht je Abfrage

Ein Switch meldet bei jeder Abfrage dieselbe MAC-Tabelle. Die unverändert
wegzuschreiben ergäbe bei 5-Minuten-Takt sechsstellige Zeilenzahlen für ein
paar Dutzend Fakten — gemessen: 1215 Zeilen für 61 Zuordnungen nach vier
Stunden, hochgerechnet ~213.000 über die 30 Tage Aufbewahrung.

`fdb` hält deshalb eine Zeile je *Zuordnung* mit `first_seen`/`last_seen`.
Das ist zugleich die bessere Historie: sichtbar wird, **wann** ein Gerät an
einen Port kam und wann es dort zuletzt bestätigt wurde, statt derselbe
Zustand tausendfach mit Zeitstempel.

Dasselbe gilt für LLDP: Eine Abfrage liefert die *vollständige* Nachbartabelle,
alte Einträge werden also ersetzt statt ergänzt. Sonst bleibt ein umgestecktes
Kabel als Geisterkante stehen, bis die Aufbewahrungsfrist greift — im Testnetz
stand der Router dadurch gleichzeitig an Port 1 und Port 12.

Zwei Fallen dabei, beide schon einmal zugeschlagen: **`NULL` ist in SQLite nie
gleich `NULL`**, ein `UNIQUE`-Index über eine nullbare Spalte greift also
nicht. VLAN wird deshalb als `-1` geführt und LLDP-Felder als Leerstring.

### Nach einem Umbau der Infrastruktur

Ports und Eigenadressen werden bei jeder Abfrage **ersetzt**, nicht ergänzt --
ein Adapter meldet stets seine vollständige Liste. Wird ein Switch getauscht
oder umkonfiguriert, verschwinden die alten Einträge beim nächsten
erfolgreichen Poll von selbst.

Bei den Eigenadressen ist das nicht nur Ordnung: Sie wirken als
**Ausschlussliste**. Bleiben MACs getauschter Hardware darin stehen, werden
echte Endgeräte mit diesen Adressen dauerhaft aus der Geräteliste
herausgehalten.

Antwortet ein Adapter gar nicht mehr, greift das Ersetzen nie. Dafür gibt es
zwei Wege:

* **Adapter löschen oder umkonfigurieren.** Beim Löschen räumt `ON DELETE
  CASCADE` Ports, Eigenadressen, FDB-Einträge und LLDP-Nachbarn dieses Geräts
  mit weg. Die *Endgeräte* bleiben — sie gehören dem Netz, nicht dem Switch.
* **`retention_infra_days`** (Standard 30) als Auffangnetz für Adapter, die
  niemand mehr anfasst.

Ein kompletter Reset ist dafür fast nie nötig: FDB, LLDP-Nachbarn und
Port-Zuordnungen bauen sich ohnehin bei jedem Poll neu auf, und die
Anwesenheits-Historie ist genau der Teil, der sich nicht wiederherstellen
lässt.

### Aufbewahrung

Vier getrennte Fenster, weil die Daten unterschiedlich schnell altern und
unterschiedlich wertvoll sind:

| Einstellung | Standard | |
|---|---|---|
| `retention_presence_days` | 90 | Grundlage der Zeitleiste — das Langzeitgedächtnis |
| `retention_fdb_days` | 30 | MAC-Tabellen, Grundlage der Port-Historie |
| `retention_link_days` | 7 | LLDP-Nachbarn, werden bei jeder Abfrage neu geschrieben |
| `retention_wifi_days` | 30 | WLAN-Assoziationen |

`0` bedeutet: nie automatisch löschen.

### Löschen

Drei Stufen, jeweils mit Bestätigung. Die API verlangt zusätzlich ein
ausdrückliches `confirm: true` — ein versehentlicher Aufruf ohne Body darf
kein Inventar wegräumen.

* **Nur Verlauf** — Anwesenheit, MAC-Tabellen, LLDP, WLAN. Geräteliste mit
  selbst vergebenen Namen und Notizen bleibt. Das ist Handarbeit und nicht
  wiederherstellbar.
* **Alle gesammelten Daten** — zusätzlich Geräte, Adressen und Merkmale.
  Adapter und Einstellungen bleiben.
* **Alles zurücksetzen** — zusätzlich die Adapter samt Zugangsdaten.

Dazu: einzelne Geräte löschen (in der Detailansicht), Geräte entfernen, die
seit N Tagen nicht gesehen wurden, und „Aufräumen & komprimieren" (`VACUUM`),
das den Plattenplatz nach dem Löschen wirklich freigibt.

Vorsicht: `fdb` und `wifi_links` hängen an der MAC statt an der Geräte-ID —
dort greift `ON DELETE CASCADE` nicht, sie werden eigens mitgelöscht.

### Sicherung

Adapter und Einstellungen als JSON, wahlweise mit oder ohne Zugangsdaten. Ohne
sie ist die Sicherung nur die halbe Miete; mit ihnen ist die Datei
entsprechend vertraulich. Ein erneuter Import legt keine Duplikate an — Adapter
gleichen Namens werden aktualisiert.

## Tests

```bash
.venv/bin/python tests/test_smoke.py     # Store, Parser, Topologie, API, Watchdog
.venv/bin/python tests/test_replay.py    # kompletter passiver Pfad
node tests/test_ui.mjs                   # Sortierung und Export der Tabelle
.venv/bin/python tests/test_wifi.py      # 802.11-Adressfelder, Roaming, AP-Gruppierung
.venv/bin/python tests/test_identify.py  # Fingerprints, MAC-Herkunft, Clustering-Vorschläge
.venv/bin/python tests/test_data.py      # Löschbereiche, Aufbewahrung, Sicherung
```

`test_replay.py` schickt einen realistischen Paketmix durch Serialisierung und
Neu-Parsen — deckt alles außer dem Raw-Socket selbst ab.

## Bewusste Grenzen

* **VLANs**: Der Sniffer hört auf *einem* Interface. Für weitere VLANs braucht
  der Container je ein Interface — mehrere gleichzeitig sind noch nicht
  verdrahtet (siehe unten).
* **Unicast** zwischen zwei fremden Geräten sieht man nicht. Für Inventar und
  Topologie auch nicht nötig.
* **MAC-Randomisierung** zerstört die Wiedererkennung von Handys über die MAC.
  Das Clustern zufälliger MACs zu einem logischen Gerät (`identity_group` ist
  im Schema vorhanden) ist noch nicht implementiert.
* **WLAN-Client-Isolation** kann den Sniffer im WLAN blind machen — für den
  Server Kabel verwenden.
* Ein Gerät, das *wirklich* nie sendet, findet nur der aktive ARP-Sweep.

## Offen

* Sniffer auf mehreren Interfaces gleichzeitig (Multi-VLAN)
* p0f-artiges TCP/TTL-Fingerprinting
* Benachrichtigung bei neuem unbekanntem Gerät

## Lizenz

MIT — siehe [LICENSE](LICENSE).
