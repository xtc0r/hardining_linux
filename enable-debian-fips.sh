#!/bin/bash

# ==============================================================================
# DATEI: enable-debian-fips.sh
# BESCHREIBUNG: Automatisierte Aktivierung des FIPS-Modus (FIPS 140-3)
#               unter Debian 13 (Trixie) über Kernel-Parameter und
#               die Konfiguration des OpenSSL 3 FIPS-Providers.
# AUSGABE:      Alle Meldungen werden sowohl auf der Konsole als auch über
#               syslog (local0, Tag FIPS-HARDENING) ausgegeben, sodass sie
#               von einem zentralen Log-Server erfasst und ausgewertet werden können.
# ANFORDERUNGEN: Ausführung mit Root-Privilegien (sudo / root).
# ==============================================================================

# Abbruch des Skripts bei Fehlern, unaufgelösten Variablen oder Fehlern in Pipelines.
set -euo pipefail

# ==============================================================================
# LOGGING-FUNKTIONEN MIT SYSLOG-INTEGRATION
# ==============================================================================
# Alle Ausgaben werden zusätzlich über logger(1) an den Syslog-Daemon
# gesendet (Facility local0, Tag FIPS-HARDENING). Der zentrale Log-Server
# kann über die rsyslog-Konfiguration auf local0.* filtern.
# Siehe README.md → Abschnitt "Syslog-Integration und zentrales Logging".

log_info() {
    echo "[INFO] $*"
    logger -t FIPS-HARDENING -p local0.info "INFO: $*"
}

log_warn() {
    echo "[WARN] $*" >&2
    logger -t FIPS-HARDENING -p local0.warning "WARN: $*"
}

log_error() {
    echo "[FEHLER] $*" >&2
    logger -t FIPS-HARDENING -p local0.err "FEHLER: $*"
}

log_success() {
    echo "[ERFOLG] $*"
    logger -t FIPS-HARDENING -p local0.notice "ERFOLG: $*"
}

log_separator() {
    echo "================================================================================"
}

# ==============================================================================
# 1. PRÜFUNG DER AUSFÜHRUNGSRECHTE
# ==============================================================================
# Es wird verifiziert, ob das Skript mit administrativen Rechten (root) gestartet wurde.
if [ "$(id -u)" -ne 0 ]; then
    log_error "Dieses Skript muss mit Root-Rechten ausgefuehrt werden."
    exit 1
fi

# ==============================================================================
# 2. PRÜFUNG DER BETRIEBSSYSTEM-KOMPATIBILITÄT
# ==============================================================================
# Es wird überprüft, ob die Linux-Distribution Debian 13 entspricht.
if [ ! -f /etc/os-release ]; then
    log_error "Die Datei /etc/os-release existiert nicht."
    exit 1
fi

# Laden der Betriebssystem-Spezifikationen
. /etc/os-release

# Validierung, ob das System Debian in der Version 13 ist
if [ "${ID:-}" != "debian" ] || [ "${VERSION_ID:-}" != "13" ]; then
    log_warn "Dieses Skript wurde speziell fuer Debian 13 (Trixie) entwickelt."
    log_warn "Aktuelles System: ${NAME:-Unbekannt} Version: ${VERSION_ID:-Unbekannt}"
    log_warn "Einige Konfigurationen könnten abweichen."
    echo ""
    echo -n "Fortsetzen? (j/N): "
    read -r confirm
    if [ "${confirm:-n}" != "j" ] && [ "${confirm:-n}" != "J" ]; then
        log_info "Abgebrochen."
        exit 0
    fi
fi

# ==============================================================================
# 3. KERNEL-FIPS-PARAMETRIERUNG ÜBER GRUB
# ==============================================================================
# Um dem Kernel beim Booten den FIPS-Selbsttest vorzuschreiben, muss der
# Parameter 'fips=1' an die Kernel-Kommandozeile angehängt werden.
# Dies wird sowohl in GRUB_CMDLINE_LINUX_DEFAULT (normaler Boot) als auch
# in GRUB_CMDLINE_LINUX (Recovery-Mode) gesetzt.
GRUB_CONFIG="/etc/default/grub"
GRUB_BACKUP="/etc/default/grub.bak-$(date +%Y%m%d%H%M%S)"

log_info "Erstelle ein Backup der GRUB-Konfiguration unter ${GRUB_BACKUP}..."
cp "${GRUB_CONFIG}" "${GRUB_BACKUP}"

# Hilfsfunktion: fügt fips=1 zu einer GRUB-Variablen hinzu, falls nicht vorhanden.
add_fips_to_grub_var() {
    local var_name="$1"
    if grep -q "^${var_name}=" "${GRUB_CONFIG}"; then
        if ! grep -q "^${var_name}=.*fips=1" "${GRUB_CONFIG}"; then
            log_info "Fuege 'fips=1' zu ${var_name} hinzu..."
            sed -i "s/^\(${var_name}=\"[^\"]*\)\"/\1 fips=1\"/" "${GRUB_CONFIG}"
        else
            log_info "'fips=1' ist bereits in ${var_name} konfiguriert."
        fi
    else
        log_info "${var_name} existiert nicht in der Konfiguration. Lege sie an..."
        echo "${var_name}=\"fips=1\"" >> "${GRUB_CONFIG}"
    fi
}

add_fips_to_grub_var "GRUB_CMDLINE_LINUX_DEFAULT"
add_fips_to_grub_var "GRUB_CMDLINE_LINUX"

# Aktualisierung des Bootloaders, um die Änderungen in /boot/grub/grub.cfg zu schreiben.
log_info "Aktualisiere GRUB..."
update-grub

# ==============================================================================
# 4. INSTALLATION DES OPENSSL FIPS PROVIDERS
# ==============================================================================
# Unter Debian 13 wird die FIPS-Implementierung für OpenSSL über das Paket
# 'openssl-provider-fips' bereitgestellt.
log_info "Aktualisiere APT-Paketquellen..."
apt-get update

log_info "Installiere das Paket openssl-provider-fips..."
apt-get install -y openssl-provider-fips

# ==============================================================================
# 5. INITIALISIERUNG DES FIPS-MODULS (FIPSINSTALL)
# ==============================================================================
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
        log_error "Die Datei fips.so konnte im System nicht lokalisiert werden."
        exit 1
    fi
fi

log_info "Gefundenes FIPS-Modul: ${FIPS_SO_PATH}"
log_info "Generiere FIPS-Modul-Konfiguration unter ${FIPS_CNF_PATH}..."
openssl fipsinstall -out "${FIPS_CNF_PATH}" -module "${FIPS_SO_PATH}"

# ==============================================================================
# 6. SYSTEMWEITE OPENSSL-KONFIGURATION ANPASSEN
# ==============================================================================
# Die Konfigurationsdatei /etc/ssl/openssl.cnf muss angepasst werden, um
# den FIPS-Provider standardmäßig zu laden und unzulässige Altkryptografie zu sperren.
OPENSSL_CNF="/etc/ssl/openssl.cnf"
OPENSSL_CNF_BACKUP="/etc/ssl/openssl.cnf.bak-$(date +%Y%m%d%H%M%S)"

log_info "Erstelle ein Backup von ${OPENSSL_CNF} unter ${OPENSSL_CNF_BACKUP}..."
cp "${OPENSSL_CNF}" "${OPENSSL_CNF_BACKUP}"

# Einbinden der generierten fipsmodule.cnf in die openssl.cnf.
# Die Debian-Standard-openssl.cnf enthält eine kommentierte .include-Zeile.
# Der grep auf "fipsmodule.cnf" würde auch auf den Kommentar matchen.
# Daher wird hier zunächst auf eine vorhandene, noch kommentierte Direktive
# geprüft und diese aktiviert. Erst wenn gar keine Referenz existiert, wird
# eine neue .include-Zeile an Position 1 eingefügt.
if grep -q "^# \.include fipsmodule\.cnf" "${OPENSSL_CNF}"; then
    log_info "Aktiviere vorhandene .include-Direktive fuer fipsmodule.cnf..."
    sed -i 's|^# \.include fipsmodule\.cnf|.include /etc/ssl/fipsmodule.cnf|' "${OPENSSL_CNF}"
elif ! grep -q "^\.include.*fipsmodule\.cnf" "${OPENSSL_CNF}"; then
    log_info "Fuege .include-Direktive fuer fipsmodule.cnf ein..."
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
log_info "Konfiguriere OpenSSL Provider-Zuordnungen..."
sed -i 's/^#\s*providers = provider_sect/providers = provider_sect/' "${OPENSSL_CNF}"
sed -i 's/^#\s*\[provider_sect\]/\[provider_sect\]/' "${OPENSSL_CNF}"
sed -i 's/^#\s*fips = fips_sect/fips = fips_sect/' "${OPENSSL_CNF}"

# Default-Provider aktivieren. Der Debian-Standard hat den Default-Provider
# in [provider_sect] gelistet, aber '# activate = 1' in [default_sect] ist
# auskommentiert. Ohne Aktivierung stehen viele kryptografische Basis-
# funktionen nicht zur Verfügung. Die default_properties = fips=yes
# (siehe unten) stellt sicher, dass trotz aktivem Default-Provider nur
# FIPS-konforme Algorithmen angeboten werden.
if grep -q "^# activate = 1" "${OPENSSL_CNF}"; then
    log_info "Aktiviere Default-Provider..."
    sed -i 's/^# activate = 1/activate = 1/' "${OPENSSL_CNF}"
fi

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

# ==============================================================================
# 7. REGENERIERUNG DER RAMDISK (INITRAMFS)
# ==============================================================================
# Um sicherzustellen, dass die kryptografischen Integritätsprüfungen beim Booten
# korrekt initialisiert werden, muss die Initial Ramdisk neu erstellt werden.
log_info "Regeneriere das Initramfs fuer alle installierten Kernel..."
update-initramfs -u -k all

# ==============================================================================
# 8. ABSCHLIESSENDE VERIFIZIERUNGSHINWEISE
# ==============================================================================
log_separator
log_success "FIPS-Vorbereitungen abgeschlossen."
log_separator
log_info "Wichtige Schritte zur Finalisierung:"
log_info "1. System neustarten, um den Kernel-FIPS-Modus zu aktivieren:"
log_info "   sudo reboot"
log_info "2. Nach dem Neustart verifizieren Sie den Kernel-Status ueber:"
log_info "   cat /proc/sys/crypto/fips_enabled"
log_info "   (Muss den Wert '1' zurueckgeben)"
log_info "3. Ueberpruefung erfolgreiche OpenSSL-Aktivierung mit:"
log_info "   openssl list -providers -provider fips"
log_info "   (Der 'OpenSSL FIPS Provider' muss als 'active' aufgefuehrt sein)"
log_info "4. Zusaetzliche Verifikation des FIPS-Enforcements:"
log_info "   echo 'test' | openssl dgst -md5"
log_info "   (Muss fehlschlagen - MD5 ist nicht FIPS-konform)"
log_separator