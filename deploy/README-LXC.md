# Betrieb im LXC-Container

Das Wichtigste zuerst: **die Netzwerkanbindung des Containers entscheidet, wie
viel das Tool überhaupt sehen kann.** Alles andere ist Standardinstallation.

## Was der Container sehen muss

Alle passiven Quellen (ARP, DHCP, mDNS, SSDP, NDP, LLDP) sind Broadcast oder
Multicast. Ein normal gebrückter Container mit `veth` an der LAN-Bridge
bekommt die also ohne weiteres Zutun. Was er **nicht** sieht, ist Unicast-
Verkehr zwischen zwei anderen Geräten — dafür bräuchte es einen Mirror-/SPAN-
Port. Für Inventarisierung und Topologie ist das aber auch nicht nötig.

## Proxmox / LXC-Konfiguration

Ein **unprivilegierter** Container reicht. Er braucht:

* eine gebrückte Netzwerkkarte an der LAN-Bridge (nicht NAT),
* `CAP_NET_RAW` — in unprivilegierten Containern hat root im eigenen
  Netzwerk-Namespace diese Capability bereits.

In `/etc/pve/lxc/<vmid>.conf`:

```
net0: name=eth0,bridge=vmbr0,firewall=0,hwaddr=<zufällig>,ip=dhcp,type=veth
features: nesting=1
unprivileged: 1
```

`firewall=0` ist wichtig: Die Proxmox-Firewall am veth filtert sonst
Broadcast-Verkehr weg, und genau der ist die Datenquelle.

### Mehrere VLANs

Pro VLAN ein weiteres Interface an den Container hängen:

```
net1: name=eth1,bridge=vmbr0,tag=20,type=veth
net2: name=eth2,bridge=vmbr0,tag=30,type=veth
```

Aktuell hört der Sniffer auf **einem** Interface (`iface` in den
Einstellungen). Mehrere Interfaces gleichzeitig sind vorbereitet, aber noch
nicht verdrahtet — siehe „Offen“ in der README.

### Alternative: macvlan statt Bridge

Wenn der Container am Host-Interface hängen soll, ohne dass Host und Container
sich sehen:

```
lxc.net.0.type = macvlan
lxc.net.0.macvlan.mode = bridge
lxc.net.0.link = eno1
```

## Installation im Container

```bash
# Repo in den Container kopieren, dann:
bash deploy/install-lxc.sh
```

Das Skript installiert Pakete, legt ein venv unter `/opt/nets` an, erstellt den
Benutzer `nets`, lädt die IEEE-Herstellerdatenbank und aktiviert den Dienst.

Danach: `http://<container-ip>:8080`

## Prüfen, ob wirklich etwas ankommt

```bash
systemctl status nets
journalctl -u nets -f
/opt/nets/.venv/bin/python -m nets check
```

In der WebUI zeigt die Übersicht den Paketzähler des Sniffers. Steht der nach
einer Minute noch auf 0, kommt kein Broadcast an — dann ist die Bridge- oder
Firewall-Konfiguration schuld, nicht das Tool.

## Rechte ohne systemd

Wenn du es von Hand startest, reicht:

```bash
setcap cap_net_raw,cap_net_admin+eip /opt/nets/.venv/bin/python3
```

Bedenke, dass das für **jeden** gilt, der dieses Python-Binary aufruft.
Der systemd-Weg über `AmbientCapabilities` ist sauberer.
