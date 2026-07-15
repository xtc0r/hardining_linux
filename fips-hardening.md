# FIPS 140-3 Härtung für Debian 13

Dieses Dokument beschreibt die einzelnen Prüfpunkte und Konfigurationsschritte, die das Script `enable-debian-fips.sh` zur Aktivierung des FIPS 140-3-Modus auf Debian 13 (Trixie) durchführt.

---

## 1. Kernel-FIPS-Parameter

### GRUB-Kernel-Boot-Parameter: `fips=1`

**Ziel:** Der Linux-Kernel führt beim Booten einen kryptografischen Selbsttest (FIPS-KAT) durch und schaltet den Kernel-FIPS-Modus ein.

**Konfiguration:** Der Parameter `fips=1` wird in `/etc/default/grub` an die Variablen `GRUB_CMDLINE_LINUX_DEFAULT` und `GRUB_CMDLINE_LINUX` angehängt. Dadurch ist FIPS sowohl im normalen als auch im Recovery-Boot-Modus aktiv.

**Wirkung nach Neustart:**
- `/proc/sys/crypto/fips_enabled` zeigt `1`
- Der Kernel verwendet nur FIPS-geprüfte kryptografische Operationen
- Nicht-FIPS-konforme Kernel-Kryptografie schlägt fehl

**Prüfung:**
```bash
cat /proc/sys/crypto/fips_enabled
# Erwartet: 1

cat /proc/cmdline | grep fips
# Erwartet: fips=1
```

**Risiko:** Ein fehlerhafter FIPS-Selbsttest führt zu einer Kernel-Panic (Boot-Abbruch). Ursachen können sein:
- Kernel-Konfiguration ohne `CONFIG_CRYPTO_FIPS=y`
- Beschädigte Kernel-Module
- Hardware-Fehler im kryptografischen Coprozessor

---

## 2. OpenSSL FIPS Provider

### Paket `openssl-provider-fips`

**Ziel:** Installation des OpenSSL-3-FIPS-Providers, der FIPS 140-3-geprüfte kryptografische Algorithmen bereitstellt.

**Debian-Paket:** `openssl-provider-fips` (Version 3.5.6-1~deb13u2, Stand Juli 2026)

**Installierte Dateien:**
- `/usr/lib/$(dpkg-architecture -q DEB_HOST_MULTIARCH)/ossl-modules/fips.so` — das FIPS-Provider-Modul
- Integritätszertifikat und HMAC-Prüfsummen zur Laufzeit-Prüfung

**Prüfung nach Installation:**
```bash
openssl list -providers -provider fips
# Erwartet: OpenSSL FIPS Provider (active)
```

---

## 3. FIPS-Modul-Initialisierung

### `openssl fipsinstall`

**Ziel:** Generierung der `fipsmodule.cnf`, die den kryptografischen Fingerprint und die Integritätsdaten der `fips.so` enthält.

**Befehl:**
```bash
openssl fipsinstall -out /etc/ssl/fipsmodule.cnf -module /usr/lib/.../ossl-modules/fips.so
```

**Erzeugte Datei:** `/etc/ssl/fipsmodule.cnf`

**Inhalt der fipsmodule.cnf:**
```ini
[fips_sect]
activate = 1
# MAC-Adresse der fips.so (Integritätsprüfung)
# Status-Flags der KATs (Known Answer Tests)
# HMAC-Schlüssel und Zertifikatsdaten
```

**Wirkung:** Der OpenSSL FIPS-Provider führt beim Laden automatisch die KATs durch. Schlägt einer der Tests fehl, wird der Provider nicht geladen.

**Prüfung:**
```bash
ls -la /etc/ssl/fipsmodule.cnf
# Erwartet: Datei existiert, root:root, 644
```

---

## 4. OpenSSL-Konfiguration

### Include der fipsmodule.cnf

**Ziel:** Die Hauptkonfiguration `/etc/ssl/openssl.cnf` muss die generierte `fipsmodule.cnf` einbinden.

**Änderung:** Die vorhandene, kommentierte Zeile `# .include fipsmodule.cnf` wird aktiviert und auf den absoluten Pfad geändert:
```bash
.include /etc/ssl/fipsmodule.cnf
```

**Wirkung:** Die Sektion `[fips_sect]` aus der `fipsmodule.cnf` steht in der OpenSSL-Konfiguration zur Verfügung.

### Konfigurations-Engine aktivieren

**Ziel:** Die `openssl_conf`-Direktive muss auf die `[openssl_init]`-Sektion verweisen.

**Änderung:** In `/etc/ssl/openssl.cnf`:
```ini
openssl_conf = openssl_init
```

### Provider-Sektionen aktivieren

**Ziel:** Der FIPS-Provider und der Base-Provider müssen in der Provider-Sektion gelistet sein.

**Änderung:** In `/etc/ssl/openssl.cnf` werden folgende Sektionen aktiviert oder erstellt:

```ini
[openssl_init]
providers = provider_sect
alg_section = alg_section

[provider_sect]
default = default_sect
fips = fips_sect
base = base_sect

[default_sect]
activate = 1

[base_sect]
activate = 1

[alg_section]
default_properties = fips=yes
```

### Default-Provider aktivieren

**Ziel:** Der Default-Provider stellt kryptografische Basis-Funktionen bereit. Ohne ihn sind viele OpenSSL-Anwendungen (z.B. `openssl enc`) nicht funktionsfähig.

**Änderung:** Die Zeile `# activate = 1` in `[default_sect]` wird aktiviert.

### Base-Provider aktivieren

**Ziel:** Der Base-Provider stellt nicht-kryptografische Hilfsfunktionen bereit (z.B. Base64-Kodierung, Dateioperationen).

**Änderung:** Die Sektion `[base_sect]` mit `activate = 1` wird hinzugefügt.

### `default_properties = fips=yes`

**Ziel:** Erzwingt, dass OpenSSL ausschließlich FIPS-konforme Algorithmen anbietet. Jeder Aufruf eines Algorithmus wird gegen die FIPS-Approved-Liste geprüft.

**Wirkung:**
- Algorithmen, die nicht FIPS-zertifiziert sind, schlagen mit Fehlern fehl
- `openssl dgst -md5` schlägt fehl (MD5 ist nicht FIPS-konform)
- `openssl enc -aes-256-cbc` funktioniert (AES-256 ist FIPS-konform)

**Prüfung:**
```bash
# Soll funktionieren (AES-256-CBC ist FIPS-konform)
echo 'test' | openssl enc -aes-256-cbc -pass pass:test -e > /dev/null 2>&1 && echo "OK"

# Soll fehlschlagen (MD5 ist nicht FIPS-konform)
echo 'test' | openssl dgst -md5 2>&1 | grep -q "disabled" && echo "FIPS greift"
```

---

## 5. Initramfs-Regenerierung

### `update-initramfs -u -k all`

**Ziel:** Die Initial Ramdisk muss die FIPS-Prüfungen und -Module enthalten, damit der Kernel-FIPS-Selbsttest beim Booten korrekt abläuft.

**Änderung:** Das Initramfs wird für alle installierten Kernel-Versionen neu generiert:
```bash
update-initramfs -u -k all
```

**Wirkung:** Beim nächsten Booten führt der Kernel die FIPS-KATs in der Ramdisk aus, bevor das Dateisystem eingehängt wird.

---

## 6. Syslog-Integration

Das Script sendet alle Meldungen über `logger(1)` an den Syslog-Daemon:

| Tag | Facility | Priorität | Inhalt |
|-----|----------|-----------|--------|
| `FIPS-HARDENING` | `local0` | `info` | Normale Fortschrittsmeldungen |
| `FIPS-HARDENING` | `local0` | `warning` | Warnungen (z.B. falsche OS-Version) |
| `FIPS-HARDENING` | `local0` | `err` | Fehler (z.B. fips.so nicht gefunden) |
| `FIPS-HARDENING` | `local0` | `notice` | Erfolgsmeldungen (Abschluss) |

**Filter im zentralen Log-Server:**
```
application_name:FIPS-HARDENING
```

---

## Gesamtprüfung nach Neustart

```bash
# 1. Kernel-FIPS-Status
cat /proc/sys/crypto/fips_enabled
# → 1

# 2. GRUB-Kernel-Parameter
cat /proc/cmdline | tr ' ' '\n' | grep fips
# → fips=1

# 3. OpenSSL FIPS-Provider-Status
openssl list -providers -provider fips
# → OpenSSL FIPS Provider (active)

# 4. FIPS-Enforcement (MD5 blockiert)
echo 'test' | openssl dgst -md5 2>&1
# → Error: 'md5' is disabled

# 5. FIPS-konformer Algorithmus funktioniert
openssl speed -bytes 1024 -evp aes-256-gcm 2>/dev/null | head -5
# → Zeigt Leistungsdaten für AES-256-GCM
```