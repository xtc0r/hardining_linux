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
    echo "[FEHLER] Dieses Skript muss mit Root-Rechten ausgefuehrt werden." >&2
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
    echo "[WARNUNG] Dieses Skript wurde speziell fuer Debian 13 (Trixie) entwickelt." >&2
    echo "Aktuelles System: ${NAME:-Unbekannt} Version: ${VERSION_ID:-Unbekannt}" >&2
    echo "Soll die Ausfuehrung dennoch fortgesetzt werden? (Eingabetaste druecken, andernfalls Strg+C)"
    read -r _
fi

# ------------------------------------------------------------------------------
# 3. KERNEL-FIPS-PARAMETRIERUNG ÜBER GRUB
# ------------------------------------------------------------------------------
# Um dem Kernel beim Booten den FIPS-Selbsttest vorzuschreiben, muss der
# Parameter 'fips=1' an die Kernel-Kommandozeile angehaengt werden.
# Dies wird sowohl in GRUB_CMDLINE_LINUX_DEFAULT (normaler Boot) als auch
# in GRUB_CMDLINE_LINUX (Recovery-Mode) gesetzt.
GRUB_CONFIG="/etc/default/grub"
GRUB_BACKUP="/etc/default/grub.bak-$(date +%Y%m%d%H%M%S)"

echo "[INFO] Erstelle ein Backup der GRUB-Konfiguration unter ${GRUB_BACKUP}..."
cp "${GRUB_CONFIG}" "${GRUB_BACKUP}"

# Hilfsfunktion: fuegt fips=1 zu einer GRUB-Variablen hinzu, falls nicht vorhanden.
add_fips_to_grub_var() {
    local var_name="$1"
    if grep -q "^${var_name}=" "${GRUB_CONFIG}"; then
        if ! grep -q "^${var_name}=.*fips=1" "${GRUB_CONFIG}"; then
            echo "[INFO] Fuege 'fips=1' zu ${var_name} hinzu..."
            sed -i "s/^\(${var_name}=\"[^\"]*\)\"/\1 fips=1\"/" "${GRUB_CONFIG}"
        else
            echo "[INFO] 'fips=1' ist bereits in ${var_name} konfiguriert."
        fi
    else
        echo "[INFO] ${var_name} existiert nicht in der Konfiguration. Lege sie an..."
        echo "${var_name}=\"fips=1\"" >> "${GRUB_CONFIG}"
    fi
}

add_fips_to_grub_var "GRUB_CMDLINE_LINUX_DEFAULT"
add_fips_to_grub_var "GRUB_CMDLINE_LINUX"

# Aktualisierung des Bootloaders, um die Aenderungen in /boot/grub/grub.cfg zu schreiben.
echo "[INFO] Aktualisiere GRUB..."
update-grub

# ------------------------------------------------------------------------------
# 4. INSTALLATION DES OPENSSL FIPS PROVIDERS
# ------------------------------------------------------------------------------
# Unter Debian 13 wird die FIPS-Implementierung fuer OpenSSL ueber das Paket
# 'openssl-provider-fips' bereitgestellt.
echo "[INFO] Aktualisiere APT-Paketquellen..."
apt-get update

echo "[INFO] Installiere das Paket openssl-provider-fips..."
apt-get install -y openssl-provider-fips

# ------------------------------------------------------------------------------
# 5. INITIALISIERUNG DES FIPS-MODULS (FIPSINSTALL)
# ------------------------------------------------------------------------------
# Der OpenSSL FIPS-Provider erfordert die Erstellung einer fipsmodule.cnf,
# welche die Integritaetspruefung (MAC-Adresse der fips.so) sowie Status-Flags
# der kryptografischen Selbsttests (KATs) enthaelt.
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
# den FIPS-Provider standardmaessig zu laden und unzulaessige Altkryptografie zu sperren.
OPENSSL_CNF="/etc/ssl/openssl.cnf"
OPENSSL_CNF_BACKUP="/etc/ssl/openssl.cnf.bak-$(date +%Y%m%d%H%M%S)"

echo "[INFO] Erstelle ein Backup von ${OPENSSL_CNF} unter ${OPENSSL_CNF_BACKUP}..."
cp "${OPENSSL_CNF}" "${OPENSSL_CNF_BACKUP}"

# Einbinden der generierten fipsmodule.cnf in die openssl.cnf.
# Die Debian-Standard-openssl.cnf enthaelt eine kommentierte .include-Zeile.
# Der grep auf "fipsmodule.cnf" wuerde auch auf den Kommentar matchen.
# Daher wird hier zunaechst auf eine vorhandene, noch kommentierte Direktive
# geprueft und diese aktiviert. Erst wenn gar keine Referenz existiert, wird
# eine neue .include-Zeile an Position 1 eingefuegt.
if grep -q "^# \.include fipsmodule\.cnf" "${OPENSSL_CNF}"; then
    echo "[INFO] Aktiviere vorhandene .include-Direktive fuer fipsmodule.cnf..."
    sed -i 's|^# \.include fipsmodule\.cnf|.include /etc/ssl/fipsmodule.cnf|' "${OPENSSL_CNF}"
elif ! grep -q "^\.include.*fipsmodule\.cnf" "${OPENSSL_CNF}"; then
    echo "[INFO] Fuege .include-Direktive fuer fipsmodule.cnf ein..."
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

# Default-Provider aktivieren. Der Debian-Standard hat den Default-Provider
# in [provider_sect] gelistet, aber '# activate = 1' in [default_sect] ist
# auskommentiert. Ohne Aktivierung stehen viele kryptografische Basis-
# funktionen nicht zur Verfuegung. Die default_properties = fips=yes
# (siehe unten) stellt sicher, dass trotz aktivem Default-Provider nur
# FIPS-konforme Algorithmen angeboten werden.
if grep -q "^# activate = 1" "${OPENSSL_CNF}"; then
    echo "[INFO] Aktiviere Default-Provider..."
    sed -i 's/^# activate = 1/activate = 1/' "${OPENSSL_CNF}"
fi

# Der Base-Provider wird benoetigt, um unkritische Hilfsfunktionen (z.B. Dateikodierungen) bereitzustellen.
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
# dass OpenSSL ausschliesslich FIPS-konforme Algorithmen anbietet und laedt.
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
# Um sicherzustellen, dass die kryptografischen Integritaetspruefungen beim Booten
# korrekt initialisiert werden, muss die Initial Ramdisk neu erstellt werden.
echo "[INFO] Regeneriere das Initramfs fuer alle installierten Kernel..."
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
echo "2. Nach dem Neustart verifizieren Sie den Kernel-Status ueber:"
echo "   cat /proc/sys/crypto/fips_enabled"
echo "   (Muss den Wert '1' zurueckgeben)"
echo "3. Ueberpruefung erfolgreiche OpenSSL-Aktivierung mit:"
echo "   openssl list -providers -provider fips"
echo "   (Der 'OpenSSL FIPS Provider' muss als 'active' aufgefuehrt sein)"
echo "4. Zusaetzliche Verifikation des FIPS-Enforcements:"
echo "   echo 'test' | openssl dgst -md5"
echo "   (Muss fehlschlagen - MD5 ist nicht FIPS-konform)"
echo "=============================================================================="