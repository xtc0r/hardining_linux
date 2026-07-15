# Hardening Linux — Debian 13 (Trixie)

Automatisierte Härtung von Debian-13-Systemen nach **FIPS 140-3** und **CIS Benchmark for Debian Linux** (Level 1 + Level 2). Enthält Remediation-Scripts, eine interaktive TUI sowie eine Wazuh-SCA-Policy für Monitoring und Health-Scoring.

---

## Inhalt

1. [Überblick: FIPS vs. CIS vs. CIS L2](#überblick-fips-vs-cis-vs-cis-l2)
2. [Dateien](#dateien)
3. [Schnellstart](#schnellstart)
4. [Mass Deployment mit Wazuh](#mass-deployment-mit-wazuh)
5. [Mass Deployment mit Uyuni](#mass-deployment-mit-uyuni)
6. [Syslog-Integration und zentrales Logging](#syslog-integration-und-zentrales-logging)
7. [Verifikation](#verifikation)
8. [Compliance-Mapping](#compliance-mapping)

---

## Überblick: FIPS vs. CIS vs. CIS L2

Die drei Härtungsstufen unterscheiden sich in **Umfang, Zielsetzung und Eingriffstiefe**.

| Kriterium | FIPS 140-3 | CIS Level 1 | CIS Level 2 |
|-----------|-----------|-------------|-------------|
| **Fokus** | Kryptografische Algorithmen | Grundlegende Systemhärtung | Erweiterte Härtung |
| **Umfang** | ~15 Prüfpunkte | ~100 Prüfpunkte | ~200+ Prüfpunkte |
| **Kryptografie** | ✅ Algorithmen, Modi, Schlüssellängen | ❌ | ❌ |
| **Dateisystem** | ❌ | ✅ mount-Optionen, Sticky-Bit | ✅ + separate Partitionen |
| **Netzwerk** | ❌ | ✅ IP-Forwarding, ICMP, SYN-Cookies | ✅ + ungewöhnliche Protokolle |
| **SSH** | ❌ | ✅ Ciphers, MACs, PermitRoot | ✅ + feinere Cipher-Auswahl |
| **Authentifizierung** | ❌ | ✅ Passwort-Alterung, Umask | ✅ + Account-Lockout, Passwort-Historie |
| **Audit** | ❌ | ✅ auditd, Basis-Regeln | ✅ + System-Call-Überwachung |
| **Logging** | ❌ | ✅ rsyslog, journald, Log-Rotation | ✅ |
| **Firewall** | ❌ | ✅ nftables Default-Deny | ✅ |
| **Dienste** | ❌ | ✅ Unnötige Dienste deaktivieren | ✅ |
| **AppArmor** | ❌ | ❌ | ✅ AppArmor-Enforce |
| **Kernel-Module** | ❌ | ❌ ✅ Unsichere Dateisysteme sperren |
| **System-Wartung** | ❌ | ✅ Dateiberechtigungen, SUID/SGID | ✅ |
| **Betriebsrisiko** | Gering (nur Krypto) | Mittel (System-Konfiguration) | Höher (AppArmor, Module) |
| **Empfohlen für** | Behörden, Finanzinstitute | Standard-Server | Hochsicherheits-Umgebungen |

**Empfehlung:** FIPS + CIS Level 1 als Basis für jeden Server. CIS Level 2 nur nach sorgfältiger Prüfung der Auswirkungen auf die eingesetzte Software.

---

## Dateien

| Datei | Beschreibung | Detaildokumentation |
|-------|-------------|---------------------|
| `enable-debian-fips.sh` | FIPS 140-3 Aktivierung | [fips-hardening.md](fips-hardening.md) |
| `cis-hardening.sh` | CIS Level 1 + Level 2 Härtung | [cis-hardening.md](cis-hardening.md) |
| `wazuh-sca-cis-debian-13.yml` | Wazuh SCA Policy für Health-Scoring | [cis-hardening.md](cis-hardening.md#syslog-integration) |

### `enable-debian-fips.sh`

**Zweck:** Aktiviert den FIPS 140-3-Modus auf Debian 13.

**Detaildokumentation:** [fips-hardening.md](fips-hardening.md) — alle 5 Prüfpunkte mit Erklärung, Konfiguration und Verifikation.

**Was passiert:**

1. **Kernel-Parameter** — `fips=1` wird an `GRUB_CMDLINE_LINUX` und `GRUB_CMDLINE_LINUX_DEFAULT` angehängt, sodass der Kernel beim Booten den FIPS-Selbsttest durchführt.
2. **OpenSSL FIPS Provider** — Das Paket `openssl-provider-fips` wird installiert.
3. **FIPS-Modul-Konfiguration** — `openssl fipsinstall` generiert die `fipsmodule.cnf` mit Integritätsprüfung (MAC der `fips.so`).
4. **OpenSSL-Konfiguration** — Die `/etc/ssl/openssl.cnf` wird so angepasst, dass der FIPS-Provider geladen und `default_properties = fips=yes` gesetzt wird. Dadurch stehen nur FIPS-konforme Algorithmen zur Verfügung.
5. **Initramfs** — Wird neu generiert, damit die kryptografischen Prüfungen beim Booten korrekt initialisiert werden.

**Ausführung:**

```bash
sudo ./enable-debian-fips.sh
```

**Verifikation nach Neustart:**

```bash
cat /proc/sys/crypto/fips_enabled       # Muss 1 sein
openssl list -providers -provider fips   # Muss 'active' zeigen
echo 'test' | openssl dgst -md5          # Muss fehlschlagen (MD5 nicht FIPS-konform)
```

---

### `cis-hardening.sh`

**Zweck:** Härtet ein Debian-13-System nach CIS Benchmark for Debian Linux (Level 1 + Level 2).

**Detaildokumentation:** [cis-hardening.md](cis-hardening.md) — alle 13 Kategorien mit vollständiger Prüfpunkt-Beschreibung, Konfiguration und Verifikation.

**13 Kategorien:**

| Kategorie | ID | Level | CIS-Referenzen |
|-----------|----|-------|----------------|
| Dateisystem-Härtung | `filesystem` | L1+L2 | 1.1.1–1.1.27 |
| Paketquellen und Updates | `updates` | L1 | 1.2.1–1.2.2 |
| Bootloader-Sicherheit | `bootloader` | L1+L2 | 1.4.1–1.5.3 |
| Netzwerk-Parameter | `network` | L1+L2 | 3.1.1–3.3.10 |
| Authentifizierung | `auth` | L1+L2 | 5.3.1–5.4.5 |
| SSH-Server-Härtung | `ssh` | L1+L2 | 5.2.1–5.2.22 |
| Audit-Daemon | `audit` | L1+L2 | 4.1.1–4.1.21 |
| Logging und Überwachung | `logging` | L1 | 4.2.1–4.2.4 |
| Firewall (nftables) | `firewall` | L1 | 3.5.1–3.5.4 |
| Dienst-Härtung | `services` | L1 | 2.1.1–2.3.3 |
| AppArmor | `apparmor` | L2 | 1.6.1–1.6.3 |
| Kernel-Module sperren | `modules` | L2 | 1.1.1.1–1.1.1.7 |
| System-Wartung | `maintenance` | L1 | 6.1.1–6.2.6 |

**Ausführung — TUI-Modus (interaktiv):**

```bash
sudo ./cis-hardening.sh
```

Öffnet eine `whiptail`-basierte Checkliste. Mit Leertaste werden Kategorien ausgewählt, mit Enter bestätigt.

![TUI-Screenshot fehlt — whiptail öffnet eine Checkliste mit 13 Kategorien]

**Ausführung — Headless (vollautomatisch):**

```bash
# Alle Massnahmen (L1 + L2)
sudo ./cis-hardening.sh --all --headless

# Nur Level 1
sudo ./cis-hardening.sh --all --headless --only L1

# Nur bestimmte Kategorien
sudo ./cis-hardening.sh --headless --ssh --network --firewall

# Trockenlauf (nur anzeigen, nichts ändern)
sudo ./cis-hardening.sh --all --dry-run
```

**Optionen im Überblick:**

| Option | Beschreibung |
|--------|-------------|
| `-a, --all` | Alle Kategorien auswählen |
| `-H, --headless` | Keine TUI, nur CLI-Parameter |
| `-l, --list` | Verfügbare Kategorien auflisten |
| `-n, --dry-run` | Nur anzeigen, ohne Änderungen |
| `-h, --help` | Hilfe anzeigen |
| `-o, --only L1` / `L2` | Auf Level beschränken |

**Logging:**

```
/var/log/cis-hardening.log
```

Jede geänderte Konfigurationsdatei wird als `.bak-$(date +%Y%m%d%H%M%S)` gesichert.

---

### `wazuh-sca-cis-debian-13.yml`

**Zweck:** Wazuh Security Configuration Assessment (SCA) Policy für Debian 13. Ermöglicht automatisiertes **Monitoring und Health-Scoring** der Härtungsmassnahmen im Wazuh-Dashboard.

**80+ Checks** mit:
- Vollständigen CIS-Referenznummern
- Level-1- und Level-2-Unterscheidung
- `condition`-Logik (`any`, `none`, `all`)
- `rules` mit `command`- und `package`-Typen
- `remediation`-Text für jede fehlgeschlagene Regel

**Installation auf dem Wazuh-Agent:**

```bash
# Policy ins Shared-Verzeichnis kopieren
cp wazuh-sca-cis-debian-13.yml /var/ossec/etc/shared/default/

# Oder bei zentraler Verteilung über Wazuh-Server:
# /var/ossec/etc/shared/default/cis_debian_13.yml

# Agent neustarten, um SCA-Scan zu triggern
systemctl restart wazuh-agent
```

**Im Wazuh-Dashboard:**

1. Navigieren zu: **Endpoint Security → Configuration Assessment**
2. Ziel-Endpoint auswählen
3. Policy **CIS Benchmark for Debian Linux 13** auswählen
4. Score einsehen (passed / failed / not applicable)

---

## Mass Deployment mit Wazuh

### Variante 1: Wazuh Command Module (Active Response)

Das Wazuh Command Module führt Remediation-Scripts periodisch oder auf Ereignisse hin aus. Damit kann `cis-hardening.sh` auf allen Agenten automatisch ausgerollt werden.

**Schritt 1 — Script auf Agenten verteilen:**

```bash
# Auf dem Wazuh-Server
scp cis-hardening.sh root@zielhost:/var/ossec/active-response/bin/cis-hardening.sh
ssh root@zielhost "chmod 750 /var/ossec/active-response/bin/cis-hardening.sh"
```

Für Massenverteilung bietet sich ein zentrales Skript oder eine Salt- / Ansible-State-Konfiguration an (siehe [Uyuni-Abschnitt](#mass-deployment-mit-uyuni)).

**Schritt 2 — Wazuh Command Module konfigurieren (`/var/ossec/etc/ossec.conf`):**

```xml
<ossec_config>
  <command>
    <name>cis-hardening-l1</name>
    <executable>cis-hardening.sh</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <active-response>
    <command>cis-hardening-l1</command>
    <location>local</location>
    <rules_id>100,101,102</rules_id>
    <timeout>0</timeout>
    <repeated_offenders>30,60,120</repeated_offenders>
  </active-response>
</ossec_config>
```

**Schritt 3 — Periodische Ausführung (Cron-ähnlich via Wazuh Command Module):**

Das Command Module unterstützt keine native Cron-Funktion. Für periodische Härtung wird empfohlen, die Scripte über einen systemd-Timer oder den Uyuni-Salt-Stack zu schedulen (siehe unten).

### Variante 2: Wazuh SCA + manuelle Remediation

1. SCA-Policy (`cis_debian_13.yml`) auf allen Agenten installieren
2. SCA-Scans laufen automatisch (standardmässig alle 8h)
3. Fehlgeschlagene Checks im Dashboard identifizieren
4. `cis-hardening.sh` manuell oder per Salt/Ansible nachziehen

### Variante 3: Wazuh SCA + Salt/Ansible Automation

**Empfohlener Workflow:**

```
[Wazuh SCA Scan] → [Failed Checks] → [Salt/Ansible State] → [cis-hardening.sh] → [Erneuter SCA Scan]
```

1. Wazuh SCA erkennt Abweichungen (z.B. SSH-PermitRootLogin wieder aktiv)
2. Salt/Ansible triggert `cis-hardening.sh --headless --ssh` auf dem betroffenen Host
3. SCA-Scan bestätigt die Korrektur

---

## Mass Deployment mit Uyuni

Uyuni (ehemals SUSE Manager) verwendet Salt States zur Konfigurationsverwaltung. Damit lassen sich Härtungsscripts zentral definieren, auf tausende Systeme ausrollen und deren Compliance überwachen.

### Salt State für CIS Level 1

**Datei: `salt/cis-hardening/init.sls`**

```sls
{% if grains['os'] == 'Debian' and grains['osrelease'] == '13' %}

# CIS-Härtungsscript bereitstellen
cis-hardening-script:
  file.managed:
    - name: /usr/local/bin/cis-hardening.sh
    - source: salt://cis-hardening/files/cis-hardening.sh
    - mode: 750
    - owner: root
    - group: root

# CIS-Härtung ausführen (nur Level 1, headless)
cis-hardening-run:
  cmd.run:
    - name: /usr/local/bin/cis-hardening.sh --all --headless --only L1
    - onchanges:
      - file: cis-hardening-script
    - require:
      - file: cis-hardening-script
    - timeout: 300

# SCA Policy bereitstellen
cis-sca-policy:
  file.managed:
    - name: /var/ossec/etc/shared/default/cis_debian_13.yml
    - source: salt://cis-hardening/files/wazuh-sca-cis-debian-13.yml
    - mode: 640
    - owner: root
    - group: ossec
    - require:
      - pkg: wazuh-agent

# Wazuh-Agent neustarten nach Policy-Update
wazuh-agent-restart:
  cmd.run:
    - name: systemctl restart wazuh-agent
    - onchanges:
      - file: cis-sca-policy
    - require:
      - file: cis-sca-policy
{% endif %}
```

### Salt State für FIPS

**Datei: `salt/fips/init.sls`**

```sls
{% if grains['os'] == 'Debian' and grains['osrelease'] == '13' %}

fips-script:
  file.managed:
    - name: /usr/local/bin/enable-debian-fips.sh
    - source: salt://fips/files/enable-debian-fips.sh
    - mode: 750
    - owner: root
    - group: root

fips-run:
  cmd.run:
    - name: /usr/local/bin/enable-debian-fips.sh
    - onchanges:
      - file: fips-script
    - require:
      - file: fips-script
    - timeout: 300

# Reboot-Erforderlich-Markierung setzen
fips-reboot-required:
  file.append:
    - name: /run/reboot-required
    - text: "*** FIPS aktiviert — Neustart erforderlich ***"
    - onchanges:
      - cmd: fips-run
{% endif %}
```

### Uyuni-Formel für CIS-Härtung (Advanced)

Uyuni unterstützt Formulare (Forms), mit denen einzelne Härtungskategorien pro Systemgruppe aktiviert werden können.

**Formel-Konfiguration (`cis-hardening/form.yml`):**

```yaml
cis_hardening:
  $type: group
  $name: "CIS-Härtungskategorien"
  $help: "Wähle die zu härtenden Bereiche. Level 2 nur nach Prüfung aktivieren."

  enabled:
    $type: boolean
    $name: "CIS-Härtung aktivieren"
    $default: true

  level:
    $type: select
    $name: "Härtungslevel"
    $values:
      - "L1"
      - "L1+L2"
    $default: "L1"

  categories:
    $type: group
    $name: "Kategorien"

    filesystem:
      $type: boolean
      $name: "Dateisystem-Härtung"
      $default: true

    network:
      $type: boolean
      $name: "Netzwerk-Parameter"
      $default: true

    ssh:
      $type: boolean
      $name: "SSH-Server-Härtung"
      $default: true

    firewall:
      $type: boolean
      $name: "Firewall (nftables)"
      $default: true

    auth:
      $type: boolean
      $name: "Authentifizierung"
      $default: true

    services:
      $type: boolean
      $name: "Dienst-Härtung"
      $default: true

    audit:
      $type: boolean
      $name: "Audit-Daemon"
      $default: true

    logging:
      $type: boolean
      $name: "Logging"
      $default: true

    updates:
      $type: boolean
      $name: "Paketquellen und Updates"
      $default: true

    bootloader:
      $type: boolean
      $name: "Bootloader-Sicherheit"
      $default: false

    maintenance:
      $type: boolean
      $name: "System-Wartung"
      $default: true

    apparmor:
      $type: boolean
      $name: "AppArmor (L2)"
      $default: false

    modules:
      $type: boolean
      $name: "Kernel-Module sperren (L2)"
      $default: false
```

**Salt State mit Formel-Integration (`cis-hardening/init.sls`):**

```sls
{% if pillar.cis_hardening.enabled is defined and pillar.cis_hardening.enabled %}

include:
  - cis-hardening.script

cis-hardening-run:
  cmd.run:
    - name: >
        /usr/local/bin/cis-hardening.sh --headless
        {% if pillar.cis_hardening.level == 'L1' %}--only L1{% endif %}
        {% if pillar.cis_hardening.level == 'L1+L2' %}--all{% endif %}
        {% for cat, enabled in pillar.cis_hardening.categories.items() %}
          {% if enabled %}--{{ cat }}{% endif %}
        {% endfor %}
    - require:
      - file: cis-hardening-script
    - timeout: 300
    - onchanges:
      - file: cis-hardening-script
{% endif %}
```

### Deployment-Strategie

**Phasenweises Rollout mit Uyuni:**

```
Phase 1: Testgruppe (3–5 Systeme)
  → Salt State cis-hardening mit Level L1
  → Wazuh SCA Scan nach 24h auswerten
  → Ggf. Anpassungen vornehmen

Phase 2: Staging (50–100 Systeme)
  → Gleiche Konfiguration
  → Monitoring auf Fehlschläge im Wazuh-Dashboard

Phase 3: Produktion (alle Systeme)
  → Vollrollout
  → Periodische SCA-Scans (alle 8h) + Alerting bei Abweichungen
```

**Wartung und Updates:**

- Script-Updates über `file.managed` mit `source_hash`-Prüfung
- Bei neuen CIS-Benchmark-Versionen: Script aktualisieren → Salt-Highstate triggert erneute Härtung
- `onchanges` stellt sicher, dass Härtung nur bei geändertem Script erneut läuft (idempotent)

---

## Syslog-Integration und zentrales Logging

Beide Härtungsscripts senden alle Meldungen über `logger(1)` an den Syslog-Daemon. Dadurch können die Logs von einem zentralen Log-Server (z.B. Graylog, ELK, rsyslog) erfasst, gefiltert und ausgewertet werden.

### Syslog-Tags und Facilities

| Script | Tag | Facility | Prioritäten |
|--------|-----|----------|-------------|
| `enable-debian-fips.sh` | `FIPS-HARDENING` | `local0` | `info`, `notice`, `warning`, `err` |
| `cis-hardening.sh` | `CIS-HARDENING` | `local0` | `info`, `notice`, `warning`, `err` |

### Log-Ausgaben im Detail

**`enable-debian-fips.sh` — FIPS-HARDENING:**

```
INFO: Erstelle ein Backup der GRUB-Konfiguration...
INFO: Fuege 'fips=1' zu GRUB_CMDLINE_LINUX_DEFAULT hinzu...
NOTICE: FIPS-Vorbereitungen abgeschlossen.
ERR: Die Datei fips.so konnte im System nicht lokalisiert werden.
```

**`cis-hardening.sh` — CIS-HARDENING:**

```
INFO: STEP [1/18]: CIS 3.1.1: IP-Forwarding deaktivieren
NOTICE: OK: sysctl net.ipv4.ip_forward = 0 (gesetzt)
WARNING: WARN: Einige Paketquellen haben keine explizite GPG-Signaturprüfung
ERR: FEHLER: SSH-Konfiguration fehlerhaft. Bitte pruefen: sshd -t
```

### Rsyslog-Forwarding zum zentralen Log-Server

Damit die Härtungslogs auf einem zentralen Server (z.B. Graylog unter `192.168.3.15:1514`) ankommen, wird eine rsyslog-Forward-Regel konfiguriert.

**Datei: `/etc/rsyslog.d/90-hardening-forward.conf`**

```
# Härtungs-Logs aller Systeme an zentralen Log-Server senden
local0.*  @192.168.3.15:1514
```

**Aktivierung:**

```bash
systemctl restart rsyslog
```

**Filter im zentralen Log-Server (Graylog):**

Nach Graylog-Query-Sprache:
```
application_name:FIPS-HARDENING
application_name:CIS-HARDENING
```

**Verwendung in der Uyuni-Salt-State-Integration:**

Das Rsyslog-Forwarding kann als Salt State auf allen verwalteten Systemen ausgerollt werden:

```sls
# salt/hardening-logging/init.sls
hardening-rsyslog-forward:
  file.managed:
    - name: /etc/rsyslog.d/90-hardening-forward.conf
    - contents: |
        # Härtungs-Logs an zentralen Log-Server senden
        local0.*  @192.168.3.15:1514
    - mode: 644
    - owner: root
    - group: root
    - notify:
      - service: rsyslog-restart

rsyslog-restart:
  service.running:
    - name: rsyslog
    - enable: True
```

### Lokale Log-Dateien

Zusätzlich zum Syslog schreiben die Scripts in lokale Log-Dateien:

| Script | Log-Datei |
|--------|-----------|
| `enable-debian-fips.sh` | Konsolenausgabe (Stdout/Stderr) |
| `cis-hardening.sh` | `/var/log/cis-hardening.log` |

---

## Verifikation

### Kernel- und FIPS-Status

```bash
# FIPS-Status
cat /proc/sys/crypto/fips_enabled

# Kernel ASLR
sysctl kernel.randomize_va_space

# Kernel-Parameter (Netzwerk)
sysctl net.ipv4.ip_forward
sysctl net.ipv4.conf.all.send_redirects
sysctl net.ipv4.conf.all.accept_redirects
sysctl net.ipv4.tcp_syncookies
```

### OpenSSL-Status

```bash
# Verfügbare Provider
openssl list -providers

# FIPS-konforme Algorithmen
openssl list -providers -provider fips

# FIPS-Enforcement-Test (muss fehlschlagen)
echo 'test' | openssl dgst -md5
```

### Firewall-Status

```bash
nft list ruleset
```

### Audit-Status

```bash
auditctl -l
systemctl status auditd
```

### AppArmor-Status

```bash
aa-status
```

### Wazuh SCA-Score

```bash
# SCA-Scan manuell triggern
systemctl restart wazuh-agent

# Letzten SCA-Scan-Status prüfen
cat /var/ossec/logs/ossec.log | grep "sca"
```

---

## Compliance-Mapping

### Abgedeckte CIS-Regeln (Level 1)

| CIS-ID | Beschreibung | Status |
|--------|-------------|--------|
| 1.1.2 | /tmp mit nodev | ✅ |
| 1.1.4 | /dev/shm mit nodev | ✅ |
| 1.1.21 | Sticky-Bit auf world-writable | ✅ |
| 1.1.22 | Automount deaktivieren | ✅ |
| 1.2.1 | GPG-Schlüssel konfigurieren | ✅ |
| 1.2.2 | Paketquellen (HTTPS) | ✅ |
| 1.4.1 | GRUB-Berechtigungen | ✅ |
| 1.5.1 | Core-Dumps einschränken | ✅ |
| 1.5.2 | ASLR aktivieren | ✅ |
| 2.1.1 | xinetd deinstallieren | ✅ |
| 2.2.2 | Avahi deaktivieren | ✅ |
| 2.2.3 | CUPS deaktivieren | ✅ |
| 2.2.4 | DHCP-Server deaktivieren | ✅ |
| 2.2.5 | DNS-Server deaktivieren | ✅ |
| 2.2.17 | NIS-Client deinstallieren | ✅ |
| 3.1.1 | IP-Forwarding deaktivieren | ✅ |
| 3.1.2 | Paket-Redirects deaktivieren | ✅ |
| 3.2.1 | Source-Routed-Pakete ablehnen | ✅ |
| 3.2.2 | ICMP-Redirects deaktivieren | ✅ |
| 3.3.1 | Reverse-Path-Filter aktivieren | ✅ |
| 3.3.2 | TCP-SYN-Cookies aktivieren | ✅ |
| 3.5.1 | nftables installieren | ✅ |
| 3.5.2 | Default-Deny-Policy | ✅ |
| 4.1.1.1 | auditd installieren | ✅ |
| 4.2.1.1 | rsyslog installieren | ✅ |
| 5.2.1 | SSH-Protokoll v2 | ✅ |
| 5.2.2 | SSH-Loglevel INFO | ✅ |
| 5.2.6 | PermitRootLogin deaktivieren | ✅ |
| 5.2.7 | MaxAuthTries ≤ 4 | ✅ |
| 5.2.9 | X11Forwarding deaktivieren | ✅ |
| 5.3.1 | SHA512-Passwort-Hashing | ✅ |
| 5.3.2 | Passwort-Komplexität | ✅ |
| 5.4.1 | Passwort-Alterung | ✅ |
| 5.4.2 | Default-Umask 027 | ✅ |
| 6.1.2 | /etc/passwd Berechtigungen | ✅ |
| 6.1.3 | /etc/shadow Berechtigungen | ✅ |
| 6.2.6 | UID 0 nur für root | ✅ |

### Abgedeckte CIS-Regeln (Level 2)

| CIS-ID | Beschreibung | Status |
|--------|-------------|--------|
| 1.1.1.1–7 | Unsichere Dateisysteme sperren | ✅ |
| 1.1.23 | USB-Storage deaktivieren | ✅ |
| 1.4.2 | GRUB-Passwort (Konfiguration) | ✅ (optional) |
| 1.6.1–3 | AppArmor installieren + Enforce | ✅ |
| 3.4 | DCCP, SCTP, RDS, TIPC sperren | ✅ |
| 4.1.1.6 | SUID/SGID-Änderungen auditieren | ✅ |
| 4.1.1.7 | Kernel-Modul-Änderungen auditieren | ✅ |
| 5.3.3 | Account-Lockout (Konfiguration) | ✅ (optional) |
| 5.3.4 | Passwort-Historie (Konfiguration) | ✅ (optional) |

---

## Lizenz

MIT — siehe [LICENSE](LICENSE).

---

## Beitragen

Pull Requests sind willkommen. Für grössere Änderungen bitte vorher ein Issue öffnen.

**Entwicklungsrichtlinien:**

- Jedes Script muss `set -euo pipefail` verwenden
- Alle Änderungen müssen idempotent sein (Prüfung vor Setzung)
- Backups vor jeder Konfigurationsänderung
- Keine DU/SIE-Ansprache — neutrale Formulierungen
- Kommentare in Deutsch (Zielgruppe: deutschsprachige Administratoren)
- **Syslog-Integration:** Alle Meldungen müssen zusätzlich über `logger` an den Syslog-Daemon gesendet werden (Facility `local0`, Tag `FIPS-HARDENING` oder `CIS-HARDENING`)
- SCA-Checks im YAML müssen mit den Script-Regeln korrespondieren