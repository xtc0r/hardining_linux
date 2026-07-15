#!/bin/bash

# ==============================================================================
# DATEI: enable-debian-fips.sh
# BESCHREIBUNG: Automatisierte Aktivierung des FIPS-Modus (FIPS 140-3)
#                unter Debian 13 (Trixie) über Kernel-Parameter und
#                die Konfiguration des OpenSSL 3 FIPS-Providers.
# ANFORDERUNGEN: Ausführung mit Root-Privilegien (sudo / root).
# ==============================================================================

# Abbruch des Skripts bei Fehlern, unaufgelösten Variablen oder Fehlern in Pipelines.
set -euo pipefail

# ------------------------------------------------------------------------------
# 1. PRÜFUNG DER AUSFÜHRUNGSRECHTE
# ------------------------------------------------------------------------------
# Es wird verifiziert, ob das Skript mit administrativen Rechten (root) gestartet wurde.
if [ "$(id -u)" -ne 0 ]; then
    echo "[FEHLER] Dieses Skript muss mit Root-Rechten ausgeführt werden." >&2
    exit 1
fi

# ------------------------------------------------------------------------------
# 2. PRÜFUNG DER BETRIEBSSYSTEM-KOMPATIBILITÄT
# ------------------------------------------------------------------------------
# Es wird überprüft, ob die Linux-Distribution Debian 13 entspricht.
if [ ! -f /etc/os-release ]; then
    echo "[FEHLER] Die Datei /etc/os-release existiert nicht." >&2
    exit 1
fi

# Laden der Betriebssystem-Spezifikationen
. /etc/os-release

# Validierung, ob das System Debian in der Version 13 ist
if [ "${ID:-}" != "debian" ] || [ "${VERSION_ID:-}" != "13" ]; then
    echo "[WARNUNG] Dieses Skript wurde speziell für Debian 13 (Trixie) entwickelt." >&2
    echo "Aktuelles System: ${NAME:-Unbekannt} Version: ${VERSION_ID:-Unbekannt}" >&2
    echo "Soll die Ausführung dennoch fortgesetzt werden? (Eingabetaste drücken, andernfalls Strg+C)"
    read -r _
fi

# ------------------------------------------------------------------------------
# 3. KERNEL-FIPS-PARAMETRIERUNG ÜBER GRUB
# ------------------------------------------------------------------------------
# Um dem Kernel beim Booten den FIPS-Selbsttest vorzuschreiben, muss der 
# Parameter 'fips=1' an die Kernel-Kommandozeile angehängt werden.
GRUB_CONFIG="/etc/default/grub"
GRUB_BACKUP="/etc/default/grub.bak-$(date +%Y%m%d%H%M%S)"

echo "[INFO] Erstelle ein Backup der GRUB-Konfiguration unter ${GRUB_BACKUP}..."
cp "${GRUB_CONFIG}" "${GRUB_BACKUP}"

# Einfügen von 'fips=1' in die Zeile GRUB_CMDLINE_LINUX_DEFAULT, falls nicht bereits vorhanden.
if grep -q "GRUB_CMDLINE_LINUX_DEFAULT" "${GRUB_CONFIG}"; then
    if ! grep -q "fips=1" "${GRUB_CONFIG}"; then
        echo "[INFO] Füge 'fips=1' zu GRUB_CMDLINE_LINUX_DEFAULT hinzu..."
        sed -i 's/\(GRUB_CMDLINE_LINUX_DEFAULT="[^"]*\)"/\1 fips=1"/' "${GRUB_CONFIG}"
    else
        echo "[INFO] 'fips=1' ist bereits in GRUB_CMDLINE_LINUX_DEFAULT konfiguriert."
    fi
else
    echo "[FEHLER] GRUB_CMDLINE_LINUX_DEFAULT wurde in ${GRUB_CONFIG} nicht gefunden." >&2
    exit 1
fi

# Aktualisierung des Bootloaders, um die Änderungen in /boot/grub/grub.cfg zu schreiben.
echo "[INFO] Aktualisiere GRUB..."
update-grub

# ------------------------------------------------------------------------------
# 4. INSTALLATION DES OPENSSL FIPS PROVIDERS
# ------------------------------------------------------------------------------
# Unter Debian 13 wird die FIPS-Implementierung für OpenSSL über das Paket 
# 'openssl-provider-fips' bereitgestellt.
echo "[INFO] Aktualisiere APT-Paketquellen..."
apt-get update

echo "[INFO] Installiere das Paket openssl-provider-fips..."
apt-get install -y openssl-provider-fips

# ------------------------------------------------------------------------------
# 5. INITIALISIERUNG DES FIPS-MODULS (FIPSINSTALL)
# ------------------------------------------------------------------------------
# Der OpenSSL FIPS-Provider erfordert die Erstellung einer fipsmodule.cnf, 
# welche die Integritätsprüfung (MAC-Adresse der fips.so) sowie Status-Flags 
# der kryptografischen Selbsttests (KATs) enthält.
ARCH_TRIPLET=$(dpkg-architecture -q DEB_HOST_MULTIARCH 2>/dev/null || echo "x86_64-linux-gnu")
FIPS_SO_PATH="/usr/lib/${ARCH_TRIPLET}/ossl-modules/fips.so"
FIPS_CNF_PATH="/etc/ssl/fipsmodule.cnf"

# Falls das Triplet abweicht, wird das Modul dynamisch gesucht.
if [ ! -f "${FIPS_SO_PATH}" ]; then
    FIPS_SO_PATH=$(find /usr/lib -name fips.so | head -n 1)
    if [ -z "${FIPS_SO_PATH}" ]; then
        echo "[FEHLER] Die Datei fips.so konnte im System nicht lokalisiert werden." >&2
        exit 1
    fi
fi

echo "[INFO] Gefundenes FIPS-Modul: ${FIPS_SO_PATH}"
echo "[INFO] Generiere FIPS-Modul-Konfiguration unter ${FIPS_CNF_PATH}..."
openssl fipsinstall -out "${FIPS_CNF_PATH}" -module "${FIPS_SO_PATH}"

# ------------------------------------------------------------------------------
# 6. SYSTEMWEITE OPENSSL-KONFIGURATION ANPASSEN
# ------------------------------------------------------------------------------
# Die Konfigurationsdatei /etc/ssl/openssl.cnf muss angepasst werden, um 
# den FIPS-Provider standardmäßig zu laden und unzulässige Altkryptografie zu sperren.
OPENSSL_CNF="/etc/ssl/openssl.cnf"
OPENSSL_CNF_BACKUP="/etc/ssl/openssl.cnf.bak-$(date +%Y%m%d%H%M%S)"

echo "[INFO] Erstelle ein Backup von ${OPENSSL_CNF} unter ${OPENSSL_CNF_BACKUP}..."
cp "${OPENSSL_CNF}" "${OPENSSL_CNF_BACKUP}"

# Einbinden der generierten fipsmodule.cnf am Anfang der openssl.cnf Datei.
if ! grep -q "fipsmodule.cnf" "${OPENSSL_CNF}"; then
    echo "[INFO] Inkludiere fipsmodule.cnf in die Hauptkonfiguration..."
    sed -i '1i .include /etc/ssl/fipsmodule.cnf' "${OPENSSL_CNF}"
fi

# Aktivierung der Konfigurations-Engine in OpenSSL.
if ! grep -q "^openssl_conf = openssl_init" "${OPENSSL_CNF}"; then
    sed -i 's/^#\s*openssl_conf =.*/openssl_conf = openssl_init/' "${OPENSSL_CNF}"
    if ! grep -q "^openssl_conf = openssl_init" "${OPENSSL_CNF}"; then
        sed -i '1i openssl_conf = openssl_init' "${OPENSSL_CNF}"
    fi
fi

# Einkommentieren der Provider-Sektionen und Verweis auf das FIPS-Modul.
echo "[INFO] Konfiguriere OpenSSL Provider-Zuordnungen..."
sed -i 's/^#\s*providers = provider_sect/providers = provider_sect/' "${OPENSSL_CNF}"
sed -i 's/^#\s*\[provider_sect\]/\[provider_sect\]/' "${OPENSSL_CNF}"
sed -i 's/^#\s*fips = fips_sect/fips = fips_sect/' "${OPENSSL_CNF}"

# Der Base-Provider wird benötigt, um unkritische Hilfsfunktionen (z.B. Dateikodierungen) bereitzustellen.
if ! grep -q "base = base_sect" "${OPENSSL_CNF}"; then
    sed -i '/\[provider_sect\]/a base = base_sect' "${OPENSSL_CNF}"
fi

if ! grep -q "\[base_sect\]" "${OPENSSL_CNF}"; then
    cat << 'EOF' >> "${OPENSSL_CNF}"

[base_sect]
activate = 1
EOF
fi

# Durch das Setzen der 'default_properties' auf 'fips=yes' wird sichergestellt, 
# dass OpenSSL ausschließlich FIPS-konforme Algorithmen anbietet und lädt.
if ! grep -q "\[alg_section\]" "${OPENSSL_CNF}"; then
    cat << 'EOF' >> "${OPENSSL_CNF}"

[alg_section]
default_properties = fips=yes
EOF
    # Einbinden der Algorithmensektion in die globale Initialisierung.
    sed -i '/\[openssl_init\]/a alg_section = alg_section' "${OPENSSL_CNF}"
fi

# ------------------------------------------------------------------------------
# 7. REGENERIERUNG DER RAMDISK (INITRAMFS)
# ------------------------------------------------------------------------------
# Um sicherzustellen, dass die kryptografischen Integritätsprüfungen beim Booten 
# korrekt initialisiert werden, muss die Initial Ramdisk neu erstellt werden.
echo "[INFO] Regeneriere das Initramfs für alle installierten Kernel..."
update-initramfs -u -k all

# ------------------------------------------------------------------------------
# 8. ABSCHLIESSENDE VERIFIZIERUNGSHINWEISE
# ------------------------------------------------------------------------------
echo "=============================================================================="
echo "[ERFOLG] FIPS-Vorbereitungen abgeschlossen."
echo "=============================================================================="
echo "Wichtige Schritte zur Finalisierung:"
echo "1. System neustarten, um den Kernel-FIPS-Modus zu aktivieren:"
echo "   sudo reboot"
echo "2. Nach dem Neustart verifizieren Sie den Kernel-Status über:"
echo "   cat /proc/sys/crypto/fips_enabled"
echo "   (Muss den Wert '1' zurückgeben)"
echo "3. Überprüfung erfolgreiche OpenSSL-Aktivierung mit:"
echo "   openssl list -providers -provider fips"
echo "   (Der 'OpenSSL FIPS Provider' muss als 'active' aufgeführt werden)"
echo "=============================================================================="
