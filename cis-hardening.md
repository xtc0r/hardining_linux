# CIS-Härtung für Debian 13 — alle Prüfpunkte

Dieses Dokument beschreibt die 13 Härtungskategorien des Scripts `cis-hardening.sh` für Debian 13 (Trixie) nach dem CIS Benchmark for Debian Linux. Jeder Prüfpunkt enthält die CIS-Referenznummer, eine Erklärung der Massnahme, die Konfigurationsänderung und die Verifikationsmethode.

---

## Inhaltsverzeichnis

1. [Dateisystem-Härtung](#1-dateisystem-härtung)
2. [Paketquellen und Updates](#2-paketquellen-und-updates)
3. [Bootloader-Sicherheit](#3-bootloader-sicherheit)
4. [Netzwerk-Parameter](#4-netzwerk-parameter)
5. [Authentifizierung](#5-authentifizierung)
6. [SSH-Server-Härtung](#6-ssh-server-härtung)
7. [Audit-Daemon](#7-audit-daemon)
8. [Logging und Überwachung](#8-logging-und-überwachung)
9. [Firewall](#9-firewall)
10. [Dienst-Härtung](#10-dienst-härtung)
11. [AppArmor (L2)](#11-apparmor-l2)
12. [Kernel-Module sperren (L2)](#12-kernel-module-sperren-l2)
13. [System-Wartung](#13-system-wartung)

---

## 1. Dateisystem-Härtung

**Kategorie-ID:** `--filesystem`  
**Level:** L1 + L2  
**CIS-Referenzen:** 1.1.1–1.1.27

### 1.1.2 — /tmp mit nodev, nosuid, noexec (L1)

**Problem:** Das `/tmp`-Verzeichnis wird standardmässig ohne Einschränkungen gemountet. Benutzer können dort ausführbare Dateien und Device-Files ablegen.

**Massnahme:** `/tmp` wird mit den Optionen `nodev` (keine Device-Files), `nosuid` (keine SUID-Binaries) und `noexec` (keine Ausführung) gemountet.

**Konfiguration:** In `/etc/fstab` wird die entsprechende Zeile angepasst. Bei systemd-tmpfs wird das Verhalten über `/etc/tmpfiles.d/tmp.conf` gesteuert.

**Prüfung:**
```bash
mount | grep /tmp
# Erwartet: nodev,nosuid,noexec
```

### 1.1.3 — /var/tmp mit nodev, nosuid, noexec (L1)

**Problem:** Gleiche Angriffsvektoren wie bei `/tmp`. `/var/tmp` bleibt zwischen Neustarts erhalten.

**Massnahme:** Wie 1.1.2, nur für `/var/tmp`.

**Prüfung:**
```bash
mount | grep /var/tmp
# Erwartet: nodev,nosuid,noexec (falls eigene Partition)
```

### 1.1.4 — /dev/shm mit nodev, nosuid, noexec (L1)

**Problem:** `/dev/shm` (Shared Memory) wird standardmässig mit vollen Rechten gemountet. Prozesse können dort ausführbaren Code ablegen.

**Massnahme:** `/dev/shm` wird als tmpfs mit `nodev,nosuid,noexec` gemountet.

**Konfiguration:** Eintrag in `/etc/fstab`:
```
tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0
```

**Prüfung:**
```bash
mount | grep /dev/shm
# Erwartet: nodev,nosuid,noexec
```

### 1.1.5 — /home mit nodev (L1)

**Problem:** Benutzerverzeichnisse sollten keine Device-Files enthalten.

**Massnahme:** `/home` wird mit `nodev` gemountet.

**Prüfung:**
```bash
mount | grep /home
# Erwartet: nodev (falls eigene Partition)
```

### 1.1.21 — Sticky-Bit auf world-writable Verzeichnissen (L1)

**Problem:** World-writable Verzeichnisse ohne Sticky-Bit erlauben jedem Benutzer, Dateien anderer Benutzer zu löschen oder umzubenennen.

**Massnahme:** Das Sticky-Bit wird auf allen world-writable Verzeichnissen gesetzt:
```bash
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -exec chmod +t {} +
```

**Prüfung:**
```bash
df --local -P | awk '{if(NR>1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print
# Sollte keine Ausgabe liefern
```

### 1.1.22 — Automount deaktivieren (L1)

**Problem:** Der Automount-Dienst (autofs) mountet Wechselmedien automatisch, was ein Sicherheitsrisiko darstellt.

**Massnahme:** Der Dienst wird deaktiviert:
```bash
systemctl disable autofs
```

### 1.1.23 — USB-Storage deaktivieren (L2)

**Problem:** USB-Speichergeräte können zur Datenexfiltration oder zum Einschleusen von Malware verwendet werden.

**Massnahme:** Das Kernel-Modul `usb-storage` wird gesperrt:
```bash
echo "install usb-storage /bin/true" > /etc/modprobe.d/usb-storage.conf
```

**Prüfung:**
```bash
grep -r "install usb-storage" /etc/modprobe.d/
# Erwartet: install usb-storage /bin/true
```

---

## 2. Paketquellen und Updates

**Kategorie-ID:** `--updates`  
**Level:** L1  
**CIS-Referenzen:** 1.2.1–1.2.2

### 1.2.1 — GPG-Schlüssel für Paketquellen (L1)

**Problem:** Ohne GPG-Signaturprüfung können manipuliert Pakete installiert werden.

**Massnahme:** Prüfung, ob alle Paketquellen über GPG-Schlüssel verfügen. Das Verzeichnis `/etc/apt/keyrings` wird angelegt.

**Prüfung:**
```bash
grep -r "^deb " /etc/apt/sources.list /etc/apt/sources.list.d/ | grep -v "signed-by"
# Sollte keine Ausgabe liefern
```

### 1.2.2 — Paketquellen auf HTTPS prüfen (L1)

**Problem:** HTTP-Übertragungen können manipuliert werden (MITM).

**Massnahme:** Prüfung, ob HTTP-Quellen existieren. Debian verwendet standardmässig GPG-signierte Pakete, sodass HTTP akzeptabel ist, aber HTTPS wird bevorzugt.

### 1.2.3 — unattended-upgrades (L1)

**Problem:** Sicherheitsupdates werden nicht automatisch eingespielt.

**Massnahme:** Installation und Konfiguration von `unattended-upgrades`:
```bash
apt-get install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades
```

**Prüfung:**
```bash
dpkg -l | grep unattended-upgrades
```

---

## 3. Bootloader-Sicherheit

**Kategorie-ID:** `--bootloader`  
**Level:** L1 + L2  
**CIS-Referenzen:** 1.4.1–1.5.3

### 1.4.1 — GRUB-Berechtigungen (L1)

**Problem:** Die GRUB-Konfiguration (`grub.cfg`) enthält sensible Daten (z.B. Passwort-Hashes) und darf nicht von unprivilegierten Benutzern gelesen werden.

**Massnahme:** Die Berechtigungen werden auf `400` (root:root) gesetzt:
```bash
chmod 400 /boot/grub/grub.cfg
chown root:root /boot/grub/grub.cfg
```

**Prüfung:**
```bash
stat -c '%a %U:%G' /boot/grub/grub.cfg
# Erwartet: 400 root:root
```

### 1.4.2 — GRUB-Bootloader-Passwort (L2)

**Problem:** Ohne GRUB-Passwort kann jeder mit Konsolenzugriff die Boot-Parameter ändern und so Root-Rechte erlangen (Single-User-Mode).

**Massnahme:** Das Skript prüft, ob ein GRUB-Passwort konfiguriert ist, und gibt eine Installationsanleitung aus, falls nicht.

**Konfiguration (manuell):**
```bash
grub-mkpasswd-pbkdf2
# Ausgabe in /etc/grub.d/40_custom eintragen
update-grub
```

### 1.5.1 — Core-Dumps einschränken (L1)

**Problem:** Core-Dumps enthalten Speicherabbilder und können sensible Daten (Passwörter, Schlüssel) preisgeben.

**Massnahme:** Core-Dumps werden in `/etc/security/limits.conf` und der systemd-Core-Dump-Konfiguration unterbunden:
```bash
echo "* hard core 0" >> /etc/security/limits.conf
```

**Prüfung:**
```bash
grep "hard core" /etc/security/limits.conf
# Erwartet: * hard core 0
ulimit -c
# Erwartet: 0
```

### 1.5.2 — ASLR aktivieren (L1)

**Problem:** Ohne Address Space Layout Randomization können Angreifer Speicheradressen vorhersagen und Exploits gezielt platzieren.

**Massnahme:** Der Kernel-Parameter `kernel.randomize_va_space` wird auf `2` (vollständige Randomisierung) gesetzt:
```bash
sysctl -w kernel.randomize_va_space=2
```

**Prüfung:**
```bash
sysctl kernel.randomize_va_space
# Erwartet: kernel.randomize_va_space = 2
```

---

## 4. Netzwerk-Parameter

**Kategorie-ID:** `--network`  
**Level:** L1  
**CIS-Referenzen:** 3.1.1–3.3.9

### 3.1.1 — IP-Forwarding deaktivieren (L1)

**Problem:** Wenn IP-Forwarding aktiv ist, kann das System als Router missbraucht werden.

**Massnahme:**
```bash
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv6.conf.all.forwarding=0
```

### 3.1.2 — Paket-Redirects deaktivieren (L1)

**Problem:** Das System sendet ICMP-Redirects, die von Angreifern für MITM-Angriffe genutzt werden können.

**Massnahme:**
```bash
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
```

### 3.2.1 — ICMP-Redirects deaktivieren (L1)

**Problem:** Das System akzeptiert ICMP-Redirects, die Routing-Tabellen manipulieren können.

**Massnahme:**
```bash
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
```

### 3.2.2 — Secure ICMP-Redirects deaktivieren (L1)

**Problem:** Secure ICMP-Redirects erlauben Redirects von Gateway-Adressen. Auch diese sollten deaktiviert sein.

**Massnahme:**
```bash
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
```

### 3.2.3 — Routing-Traffic-Logs aktivieren (L1)

**Problem:** Martians (unmögliche Pakete) werden nicht geloggt.

**Massnahme:**
```bash
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
```

### 3.2.4 — Broadcast-ICMP ignorieren (L1)

**Problem:** ICMP-Broadcasts können für Smurf-Angriffe genutzt werden.

**Massnahme:**
```bash
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
```

### 3.2.5 — ICMP-Error-Responses ratelimiten (L1)

**Problem:** Gefälschte ICMP-Fehlermeldungen können Verbindungen stören.

**Massnahme:**
```bash
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
```

### 3.3.1 — Reverse-Path-Filter aktivieren (L1)

**Problem:** Ohne RPF können IP-Spoofing-Angriffe durchgeführt werden.

**Massnahme:**
```bash
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
```

### 3.3.2 — TCP-SYN-Cookies aktivieren (L1)

**Problem:** SYN-Flood-Angriffe können den TCP-Stack erschöpfen.

**Massnahme:**
```bash
sysctl -w net.ipv4.tcp_syncookies=1
```

### 3.3.3 — IPv6 Router Advertisements deaktivieren (L1)

**Problem:** Gefälschte Router Advertisements können Routing-Tabellen manipulieren.

**Massnahme:**
```bash
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
```

### 3.3.4 — TCP-Timestamps deaktivieren (L1)

**Problem:** TCP-Timestamps erlauben die Abschätzung der System-Uptime und erleichtern OS-Fingerprinting.

**Massnahme:**
```bash
sysctl -w net.ipv4.tcp_timestamps=0
```

### 3.3.8 — TCP-SYN-Backlog erhöhen (L1)

**Problem:** Der Standard-SYN-Backlog ist zu klein für Systeme mit vielen Verbindungen.

**Massnahme:**
```bash
sysctl -w net.ipv4.tcp_syn_backlog=2048
sysctl -w net.core.somaxconn=1024
```

### 3.4 — Ungewöhnliche Netzwerkprotokolle deaktivieren (L2)

**Problem:** DCCP, SCTP, RDS und TIPC werden selten benötigt und vergrössern die Angriffsfläche.

**Massnahme:** Kernel-Module für diese Protokolle werden gesperrt:
```bash
echo "install dccp /bin/true" > /etc/modprobe.d/dccp.conf
echo "install sctp /bin/true" > /etc/modprobe.d/sctp.conf
echo "install rds /bin/true" > /etc/modprobe.d/rds.conf
echo "install tipc /bin/true" > /etc/modprobe.d/tipc.conf
```

---

## 5. Authentifizierung

**Kategorie-ID:** `--auth`  
**Level:** L1 + L2  
**CIS-Referenzen:** 5.3.1–5.4.5

### 5.3.1 — SHA512-Passwort-Hashing (L1)

**Problem:** Debian verwendet standardmässig SHA512 (`$6$`), aber die Konfiguration sollte explizit gesetzt sein.

**Massnahme:**
```bash
echo "ENCRYPT_METHOD SHA512" >> /etc/login.defs
```

**Prüfung:**
```bash
grep 'ENCRYPT_METHOD' /etc/login.defs
# Erwartet: ENCRYPT_METHOD SHA512
```

### 5.3.2 — Passwort-Komplexität (libpam-pwquality) (L1)

**Problem:** Ohne Qualitätsanforderungen werden schwache Passwörter akzeptiert.

**Massnahme:**
- Installation von `libpam-pwquality`
- Konfiguration in `/etc/security/pwquality.conf`:
  - `minlen = 14` (Mindestlänge 14 Zeichen)
  - `minclass = 4` (alle 4 Zeichenklassen erforderlich)
  - `maxrepeat = 3` (maximal 3 Wiederholungen)

**Prüfung:**
```bash
grep -E '^(minlen|minclass|maxrepeat)' /etc/security/pwquality.conf
```

### 5.3.3 — Account-Lockout nach Fehlversuchen (L2)

**Problem:** Ohne Lockout können Passwörter durch Brute-Force erraten werden.

**Massnahme:** Konfiguration von `pam_faillock` über `pam-auth-update`-Profil.

**Konfiguration (optional):**
```bash
pam-auth-update --enable faillock
```

### 5.4.1 — Passwort-Alterung (L1)

**Problem:** Passwörter laufen nie ab, wenn keine Altersgrenzen gesetzt sind.

**Massnahme:**
```bash
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   365/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
```

**Prüfung:**
```bash
grep -E '^PASS_' /etc/login.defs
# Erwartet: PASS_MAX_DAYS 365, PASS_MIN_DAYS 7, PASS_WARN_AGE 7
```

### 5.4.2 — Default-Umask (L1)

**Problem:** Eine zu lockere Umask (022) erlaubt anderen Benutzern das Lesen neuer Dateien.

**Massnahme:**
```bash
echo "UMASK 027" >> /etc/login.defs
```

**Prüfung:**
```bash
grep '^UMASK' /etc/login.defs
# Erwartet: UMASK 027
```

---

## 6. SSH-Server-Härtung

**Kategorie-ID:** `--ssh`  
**Level:** L1 + L2  
**CIS-Referenzen:** 5.2.1–5.2.22

### 5.2.1 — SSH-Protokoll auf v2 (L1)

**Problem:** SSH-Protokoll v1 enthält bekannte Sicherheitslücken.

**Massnahme:**
```bash
echo "Protocol 2" >> /etc/ssh/sshd_config
```

### 5.2.2 — SSH-Loglevel auf INFO (L1)

**Problem:** Zu geringe Protokollierung erschwert forensische Analysen.

**Massnahme:**
```bash
echo "LogLevel INFO" >> /etc/ssh/sshd_config
```

### 5.2.3 — SSH-Ciphers (L1)

**Problem:** Veraltete Ciphers (3DES, RC4, CBC) sind unsicher.

**Massnahme:** Nur moderne, starke Ciphers werden erlaubt:
```
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
```

### 5.2.4 — SSH-MACs (L1)

**Problem:** Veraltete MACs (HMAC-MD5, HMAC-RIPEMD160) sind unsicher.

**Massnahme:** Nur HMAC-SHA2-Varianten werden erlaubt:
```
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
```

### 5.2.6 — PermitRootLogin deaktivieren (L1)

**Problem:** Root-Login über SSH ist ein primäres Angriffsziel.

**Massnahme:**
```bash
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
```

### 5.2.7 — MaxAuthTries auf 4 (L1)

**Problem:** Zu viele Authentifizierungsversuche erlauben Brute-Force.

**Massnahme:**
```bash
echo "MaxAuthTries 4" >> /etc/ssh/sshd_config
```

### 5.2.9 — X11Forwarding deaktivieren (L1)

**Problem:** X11-Forwarding erlaubt die Manipulation von grafischen Anwendungen.

**Massnahme:**
```bash
echo "X11Forwarding no" >> /etc/ssh/sshd_config
```

### 5.2.10 — MaxSessions limitieren (L1)

**Problem:** Unbegrenzte Sitzungen können Ressourcen erschöpfen.

**Massnahme:**
```bash
echo "MaxSessions 10" >> /etc/ssh/sshd_config
```

### 5.2.11 — SSH-Timeout konfigurieren (L1)

**Problem:** Inaktive SSH-Sitzungen bleiben unbegrenzt offen.

**Massnahme:**
```bash
echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config
```

Wirkung: Nach 300 Sekunden Inaktivität wird die Verbindung getrennt.

### 5.2.12 — LoginGraceTime auf 60s (L1)

**Problem:** Zu lange Login-Frist erlaubt parallele Brute-Force-Versuche.

**Massnahme:**
```bash
echo "LoginGraceTime 60" >> /etc/ssh/sshd_config
```

---

## 7. Audit-Daemon

**Kategorie-ID:** `--audit`  
**Level:** L1 + L2  
**CIS-Referenzen:** 4.1.1.1–4.1.21

### 4.1.1.1 — auditd installieren (L1)

**Problem:** Ohne Audit-System werden sicherheitsrelevante Ereignisse nicht protokolliert.

**Massnahme:**
```bash
apt-get install -y auditd audispd-plugins
```

### 4.1.2.1 — Audit-Log-Grösse konfigurieren (L1)

**Problem:** Audit-Logs können unbegrenzt wachsen und den Speicher füllen.

**Massnahme:** In `/etc/audit/auditd.conf`:
```
max_log_file = 100
max_log_file_action = ROTATE
num_logs = 5
space_left_action = EMAIL
action_mail_acct = root
```

### 4.1.3 — Audit-Regeln (L1)

**Problem:** Ohne Regeln werden keine Ereignisse aufgezeichnet.

**Massnahme:** Folgende Ereignisse werden überwacht:

| Regel | Ereignis | Key |
|-------|----------|-----|
| `adjtimex`, `settimeofday`, `clock_settime` | Zeitänderungen | `time-change` |
| `/etc/group`, `/etc/passwd`, `/etc/shadow` | Benutzerverwaltung | `identity` |
| `sethostname`, `setdomainname` | Netzwerk-Umgebung | `system-locale` |
| `/etc/apparmor/` | MAC-Policy-Änderungen | `MAC-policy` |
| `creat`, `open`, `openat` mit `-EACCES` | Zugriffsfehler | `access` |
| `mount` | Mount-Operationen | `mounts` |
| `unlink`, `rename` | Datei-Löschungen | `delete` |
| `chmod`, `chown`, `setxattr` | Berechtigungsänderungen | `perm_mod` |
| `init_module`, `delete_module` | Kernel-Module | `modules` |

### 4.1.8 — Audit-Konfiguration sperren (L2)

**Problem:** Ein Angreifer mit Root-Rechten kann die Audit-Konfiguration deaktivieren.

**Massnahme:** Die letzte Regel in der Audit-Konfiguration ist `-e 2` (unveränderbar machen). Diese Regel wird erst nach einem Neustart wirksam.

---

## 8. Logging und Überwachung

**Kategorie-ID:** `--logging`  
**Level:** L1  
**CIS-Referenzen:** 4.2.1–4.2.4

### 4.2.1.1 — rsyslog installieren (L1)

**Problem:** Ohne rsyslog werden Systemmeldungen nicht persistent gespeichert.

**Massnahme:**
```bash
apt-get install -y rsyslog
systemctl enable --now rsyslog
```

### 4.2.1.3 — Log-Datei-Berechtigungen (L1)

**Problem:** Log-Dateien mit lesbaren Berechtigungen geben Systeminformationen preis.

**Massnahme:** In `/etc/rsyslog.conf`:
```
$FileCreateMode 0640
```

### 4.2.2.1 — Journald konfigurieren (L1)

**Problem:** Journald speichert nur im Speicher, wenn nicht auf persistente Speicherung umgestellt.

**Massnahme:** In `/etc/systemd/journald.conf`:
```
Storage=persistent
Compress=yes
SystemMaxUse=500M
MaxRetentionSec=1month
ForwardToSyslog=yes
```

### 4.2.5 — Detailliertes Logging (L1)

**Problem:** Wichtige Log-Kategorien werden nicht getrennt gespeichert.

**Massnahme:** In `/etc/rsyslog.d/50-cis-hardening.conf`:
```
auth,authpriv.*  /var/log/auth.log
kern.*           /var/log/kern.log
cron.*           /var/log/cron.log
mail.*           /var/log/mail.log
```

---

## 9. Firewall

**Kategorie-ID:** `--firewall`  
**Level:** L1  
**CIS-Referenzen:** 3.5.1–3.5.4

### 3.5.1.1 — nftables installieren (L1)

**Problem:** Ohne Firewall ist der gesamte Netzwerkverkehr uneingeschränkt.

**Massnahme:**
```bash
apt-get install -y nftables
```

### 3.5.1.3 — Default-Deny-Policy (L1)

**Problem:** Eine Default-Accept-Policy erlaubt allen unerwünschten Verkehr.

**Massnahme:** nftables-Regelwerk mit Default-Deny für Input:
```
table inet cis_hardening {
    chain input {
        type filter hook input priority 0; policy drop;
        iif lo accept
        ct state established,related accept
        tcp dport 22 accept
    }
}
```

### 3.5.1.4 — Loopback-Schutz (L1)

**Problem:** Ohne Loopback-Schutz können Angreifer lokale Dienste über Loopback erreichen.

**Massnahme:** Loopback-Verkehr wird explizit erlaubt, aber nur von der Loopback-Schnittstelle. Fremde Pakete mit Loopback-Quelladresse werden verworfen.

---

## 10. Dienst-Härtung

**Kategorie-ID:** `--services`  
**Level:** L1  
**CIS-Referenzen:** 2.1.1–2.3.3

### Deaktivierte Dienste

| Dienst | CIS-ID | Grund |
|--------|--------|-------|
| `xinetd` | 2.1.1 | Superserver-Dienst, fast nie benötigt |
| `avahi-daemon` | 2.2.2 | mDNS/Bonjour, nur in lokalen Netzwerken |
| `cups`, `cups-browsed` | 2.2.3 | Druckerserver, nur bei Bedarf |
| `isc-dhcp-server` | 2.2.4 | DHCP-Server, nur bei Bedarf |
| `bind9` | 2.2.5 | DNS-Server, nur bei Bedarf |
| `vsftpd`, `proftpd` | 2.2.7 | FTP-Server, unsicher (SFTP bevorzugen) |
| `dovecot`, `cyrus` | 2.2.9 | IMAP/POP3-Server, nur bei Bedarf |
| `smbd` | 2.2.10 | Samba, nur bei Bedarf |
| `snmpd` | 2.2.11 | SNMP, nur bei Bedarf |
| `nis` | 2.2.17 | NIS, veraltet und unsicher |
| `rsync` | 2.2.19 | rsync-Daemon, nur bei Bedarf |

### X11 Display Manager (L1)

**Problem:** Display-Manager (GDM, LightDM, SDDM) sind für Server nicht nötig und vergrössern die Angriffsfläche.

**Massnahme:** Deaktivierung aller installierten Display-Manager.

### Zeitsynchronisation (L1)

**Problem:** Ohne genaue Zeit sind Log-Analysen und Zertifikatsprüfungen unzuverlässig.

**Massnahme:** Installation von `chrony` und Aktivierung des Dienstes. Fallback auf `ntp` oder `ntpsec`.

---

## 11. AppArmor (L2)

**Kategorie-ID:** `--apparmor`  
**Level:** L2  
**CIS-Referenzen:** 1.6.1–1.6.3

### 1.6.1 — AppArmor installieren (L2)

**Problem:** Ohne Mandatory Access Control (MAC) können Prozesse auf alle Dateien zugreifen, die der Benutzer lesen darf.

**Massnahme:**
```bash
apt-get install -y apparmor apparmor-profiles apparmor-utils
```

### 1.6.2 — AppArmor im Enforce-Modus (L2)

**Problem:** AppArmor kann im Complain-Modus laufen, der Verstösse nur loggt, aber nicht blockiert.

**Massnahme:** Kernel-Parameter `apparmor=1 security=apparmor` werden in GRUB konfiguriert.

**Prüfung:**
```bash
cat /proc/cmdline | grep apparmor
# Erwartet: apparmor=1 security=apparmor
```

### 1.6.3 — AppArmor-Profile in den Enforce-Modus (L2)

**Problem:** Standardmässig sind viele Profile im Complain-Modus.

**Massnahme:**
```bash
aa-enforce /etc/apparmor.d/*
```

**Prüfung:**
```bash
aa-status
# Erwartet: Alle Profile zeigen "enforce mode"
```

---

## 12. Kernel-Module sperren (L2)

**Kategorie-ID:** `--modules`  
**Level:** L2  
**CIS-Referenzen:** 1.1.1.1–1.1.1.7

### Gesperrte Module

| Modul | CIS-ID | Verwendung | Risiko |
|-------|--------|------------|--------|
| `cramfs` | 1.1.1.1 | Komprimiertes ROM-Dateisystem | Veraltet, kaum verwendet |
| `freevxfs` | 1.1.1.2 | Veritas-Dateisystem | Nur auf historischen Systemen |
| `jffs2` | 1.1.1.3 | Flash-Dateisystem | Nur auf Embedded-Systemen |
| `hfs` | 1.1.1.4 | Mac OS-Dateisystem | Nur auf alten Macs |
| `hfsplus` | 1.1.1.5 | Mac OS-Dateisystem | Nur auf Macs |
| `squashfs` | 1.1.1.6 | Komprimiertes Nur-Lese-Dateisystem | Selten auf Servern |
| `udf` | 1.1.1.7 | Universal Disk Format (DVD) | Nur auf optischen Medien |

**Massnahme für jedes Modul:**
```bash
echo "install <modul> /bin/true" > /etc/modprobe.d/<modul>.conf
```

**Zusätzlich gesperrte Module (empfohlen):**
| Modul | Begründung |
|-------|------------|
| `usb-storage` | Datentransfer über USB |
| `firewire-core` | FireWire (DMA-Angriffe) |
| `bluetooth`, `btusb` | Bluetooth |
| `joydev` | Gamecontroller (nicht auf Servern) |

---

## 13. System-Wartung

**Kategorie-ID:** `--maintenance`  
**Level:** L1  
**CIS-Referenzen:** 6.1.1–6.2.6

### 6.1.1 — System-Datei-Berechtigungen korrigieren (L1)

**Problem:** Falsche Berechtigungen auf Systemdateien erlauben unautorisierten Zugriff.

**Massnahme:**
```
/etc/passwd  → 644
/etc/group   → 644
/etc/shadow  → 640
/etc/gshadow → 640
/etc/shells  → 644
/etc/issue   → 644
/etc/issue.net → 644
```

### 6.1.2 — UID-0-Prüfung (L1)

**Problem:** Nur `root` sollte die UID 0 haben. Weitere Benutzer mit UID 0 haben uneingeschränkten Root-Zugriff.

**Massnahme:**
```bash
awk -F: '($3 == 0) {print $1}' /etc/passwd
# Sollte nur "root" ausgeben
```

### 6.1.3 — Shadow-Passwörter prüfen (L1)

**Problem:** Benutzer ohne Shadow-Passwort (`x` in `/etc/passwd` Feld 2) haben kein Passwort.

**Massnahme:**
```bash
for user in $(awk -F: '($2 != "x" && $2 != "!" && $2 != "*") {print $1}' /etc/passwd); do
    passwd -l "${user}"
done
```

### 6.1.4 — World-Writable-Dateien prüfen (L1)

**Problem:** World-writable Dateien können von jedem Benutzer verändert werden.

**Massnahme:** Suche nach world-writable Dateien und Ausgabe der Liste:
```bash
find / -xdev -type f -perm -0002 -print | head -20
```

### 6.1.6 — SUID/SGID-Dateien prüfen (L1)

**Problem:** SUID/SGID-Binaries erlauben die Ausführung mit erweiterten Rechten und müssen auditiert werden.

**Massnahme:** Die Liste aller SUID/SGID-Dateien wird in `/var/log/cis-hardening-suid.log` gespeichert.

**Prüfung:**
```bash
cat /var/log/cis-hardening-suid.log
```

### 6.2.6 — Root-Heimatverzeichnis (L1)

**Problem:** `/root` mit lockeren Berechtigungen erlaubt anderen Benutzern das Lesen von Root-Dateien.

**Massnahme:**
```bash
chmod 750 /root
```

---

## Syslog-Integration

Das Script `cis-hardening.sh` sendet alle Meldungen über `logger(1)` an den Syslog-Daemon:

| Tag | Facility | Priorität | Inhalt |
|-----|----------|-----------|--------|
| `CIS-HARDENING` | `local0` | `info` | Normale Fortschrittsmeldungen und Schritt-Informationen |
| `CIS-HARDENING` | `local0` | `notice` | Erfolgreich abgeschlossene Massnahmen (`[OK]`) |
| `CIS-HARDENING` | `local0` | `warning` | Warnungen (`[WARN]`) |
| `CIS-HARDENING` | `local0` | `err` | Fehler (`[FEHLER]`) |

**Filter im zentralen Log-Server:**
```
application_name:CIS-HARDENING
```

**Hinweis:** Die Scripts senden nur an den **lokalen** Syslog-Daemon. Wenn auf dem System ein Rsyslog-Forwarding zum zentralen Log-Server konfiguriert ist, werden die Härtungslogs automatisch mit übertragen. Es ist keine zusätzliche Konfiguration für die Härtungslogs erforderlich.