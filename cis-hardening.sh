#!/bin/bash
# ==============================================================================
# DATEI: cis-hardening.sh
# BESCHREIBUNG: Automatisierte Härtung von Debian 13 (Trixie) nach
#               CIS Benchmark for Debian Linux (Level 1 + Level 2).
#               Enthält eine interaktive TUI (whiptail) sowie eine
#               vollautomatische CLI-Mode für Headless-Betrieb.
#
# INTEGRATION:   Dieses Skript kann standalone oder über Wazuh Active
#                 Response (Command-Modul) ausgeführt werden. Die zugehörige
#                 Wazuh SCA Policy (cis_debian_13.yml) ermöglicht Monitoring
#                 und Scoring der Härtungsmassnahmen.
#
# ANFORDERUNGEN: Ausführung mit Root-Privilegien (sudo / root).
#                 whiptail (für TUI-Modus, Debian-Standard).
# ==============================================================================

set -euo pipefail

# ==============================================================================
# KONFIGURATION
# ==============================================================================

# CIS-Kategorien mit IDs, Titeln und Level-Zuordnung
# Format: id|Titel|Level|Beschreibung
declare -A CIS_CATEGORIES
CIS_CATEGORIES=(
    ["filesystem"]="1|Dateisystem-Härtung|L1+L2|Mount-Optionen, Sticky-Bit, Automount deaktivieren, USB-Sperre"
    ["updates"]="2|Paketquellen und Updates|L1|APT-Konfiguration, GPG-Schlüssel, unattended-upgrades"
    ["bootloader"]="3|Bootloader-Sicherheit|L1+L2|GRUB-Berechtigungen, Passwortschutz (L2)"
    ["network"]="4|Netzwerk-Parameter|L1|IP-Forwarding, ICMP-Redirects, SYN-Cookies, TCP-Härtung"
    ["auth"]="5|Authentifizierung|L1+L2|PAM-Passwortrichtlinien, Account-Lockout (L2), UID-0-Prüfung"
    ["ssh"]="6|SSH-Server-Härtung|L1+L2|Ciphers, MACs, PermitRoot, MaxAuthTries, Banner"
    ["audit"]="7|Audit-Daemon (auditd)|L1+L2|auditd-Installation, System-Call-Regeln (L2)"
    ["logging"]="8|Logging und Überwachung|L1|rsyslog, journald, Log-Rotation"
    ["firewall"]="9|Firewall (nftables)|L1|Default-Deny-Policy, Loopback-Schutz"
    ["services"]="10|Dienst-Härtung|L1|Unnötige Dienste deaktivieren, Zeit synchronisieren"
    ["apparmor"]="11|AppArmor (L2)|L2|AppArmor-Installation, Enforce-Modus, Profile"
    ["modules"]="12|Kernel-Module sperren (L2)|L2|Unsichere Dateisysteme, USB-Storage, Firewire"
    ["maintenance"]="13|System-Wartung|L1|Dateiberechtigungen, SUID/SGID, world-writable, leere Passwörter"
)

# CIS-Referenznummern je Kategorie (für Compliance-Dokumentation)
declare -A CIS_REFERENCES
CIS_REFERENCES=(
    ["filesystem"]="1.1.1, 1.1.2, 1.1.3, 1.1.4, 1.1.5, 1.1.6, 1.1.7, 1.1.8, 1.1.9, 1.1.10, 1.1.21, 1.1.22"
    ["updates"]="1.2.1, 1.2.2"
    ["bootloader"]="1.4.1, 1.4.2, 1.5.1, 1.5.2, 1.5.3"
    ["network"]="3.1.1, 3.1.2, 3.1.3, 3.1.4, 3.1.5, 3.1.6, 3.2.1, 3.2.2, 3.3.1, 3.3.2, 3.3.3, 3.3.4, 3.3.5, 3.3.6, 3.3.7, 3.3.8, 3.3.9"
    ["auth"]="5.3.1, 5.3.2, 5.3.3, 5.3.4, 5.4.1, 5.4.2, 5.4.3, 5.4.4, 5.4.5"
    ["ssh"]="5.2.1, 5.2.2, 5.2.3, 5.2.4, 5.2.5, 5.2.6, 5.2.7, 5.2.8, 5.2.9, 5.2.10, 5.2.11, 5.2.12, 5.2.13, 5.2.14, 5.2.15, 5.2.16, 5.2.17, 5.2.18, 5.2.19, 5.2.20, 5.2.21, 5.2.22"
    ["audit"]="4.1.1, 4.1.2, 4.1.3, 4.1.4, 4.1.5, 4.1.6, 4.1.7, 4.1.8, 4.1.9, 4.1.10, 4.1.11, 4.1.12, 4.1.13, 4.1.14, 4.1.15, 4.1.16, 4.1.17, 4.1.18, 4.1.19, 4.1.20, 4.1.21"
    ["logging"]="4.2.1, 4.2.2, 4.2.3, 4.2.4"
    ["firewall"]="3.5.1, 3.5.2, 3.5.3, 3.5.4"
    ["services"]="2.1.1, 2.2.1, 2.2.2, 2.2.3, 2.2.4, 2.2.5, 2.2.6, 2.2.7, 2.2.8, 2.2.9, 2.2.10, 2.2.11, 2.2.12, 2.2.13, 2.2.14, 2.2.15, 2.2.16, 2.2.17, 2.2.18, 2.2.19, 2.2.20, 2.3.1, 2.3.2, 2.3.3"
    ["apparmor"]="1.6.1, 1.6.2, 1.6.3"
    ["modules"]="1.1.1.1, 1.1.1.2, 1.1.1.3, 1.1.1.4, 1.1.1.5, 1.1.1.6, 1.1.1.7"
    ["maintenance"]="6.1.1, 6.1.2, 6.1.3, 6.1.4, 6.1.5, 6.1.6, 6.1.7, 6.1.8, 6.1.9, 6.1.10, 6.1.11, 6.1.12, 6.1.13, 6.1.14, 6.2.1, 6.2.2, 6.2.3, 6.2.4, 6.2.5, 6.2.6"
)

# Konfigurationsvariablen
BACKUP_DIR="/var/backups/cis-hardening"
LOG_FILE="/var/log/cis-hardening.log"
TIMESTAMP=$(date +%Y%m%d%H%M%S)

# ==============================================================================
# FORMATIERUNG UND AUSGABE
# ==============================================================================

# Terminal-Farben (deaktiviert wenn nicht interaktiv)
if [ -t 1 ]; then
    COLOR_RESET='\033[0m'
    COLOR_RED='\033[0;31m'
    COLOR_GREEN='\033[0;32m'
    COLOR_YELLOW='\033[0;33m'
    COLOR_BLUE='\033[0;34m'
    COLOR_MAGENTA='\033[0;35m'
    COLOR_CYAN='\033[0;36m'
    COLOR_BOLD='\033[1m'
    COLOR_DIM='\033[2m'
else
    COLOR_RESET=''
    COLOR_RED=''
    COLOR_GREEN=''
    COLOR_YELLOW=''
    COLOR_BLUE=''
    COLOR_MAGENTA=''
    COLOR_CYAN=''
    COLOR_BOLD=''
    COLOR_DIM=''
fi

# Logging-Funktionen mit Syslog-Integration.
# Alle Ausgaben werden zusätzlich über logger(1) an den Syslog-Daemon
# gesendet (Facility local0, Tag CIS-HARDENING). Der zentrale Log-Server
# kann über die rsyslog-Konfiguration auf local0.* filtern.
# Siehe README.md → Abschnitt "Syslog-Integration und zentrales Logging".
log_info() {
    echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $*" | tee -a "${LOG_FILE}"
    logger -t CIS-HARDENING -p local0.info "INFO: $*"
}

log_ok() {
    echo -e "${COLOR_GREEN}[OK]${COLOR_RESET} $*" | tee -a "${LOG_FILE}"
    logger -t CIS-HARDENING -p local0.notice "OK: $*"
}

log_warn() {
    echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $*" | tee -a "${LOG_FILE}"
    logger -t CIS-HARDENING -p local0.warning "WARN: $*"
}

log_error() {
    echo -e "${COLOR_RED}[FEHLER]${COLOR_RESET} $*" >&2 | tee -a "${LOG_FILE}" >&2
    logger -t CIS-HARDENING -p local0.err "FEHLER: $*"
}

log_section() {
    local title="$1"
    local separator="═══════════════════════════════════════════════════════════════"
    echo ""
    echo -e "${COLOR_BOLD}${COLOR_CYAN}${title}${COLOR_RESET}"
    echo -e "${COLOR_DIM}${separator}${COLOR_RESET}"
    echo "" | tee -a "${LOG_FILE}"
    logger -t CIS-HARDENING -p local0.info "SECTION: ${title}"
}

log_step() {
    local step="$1"
    local total="$2"
    local message="$3"
    echo -e "${COLOR_MAGENTA}[${step}/${total}]${COLOR_RESET} ${message}" | tee -a "${LOG_FILE}"
    logger -t CIS-HARDENING -p local0.info "STEP [${step}/${total}]: ${message}"
}

# ==============================================================================
# HILFSFUNKTIONEN
# ==============================================================================

# Prüft ob das Skript mit Root-Rechten ausgeführt wird.
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "Dieses Skript muss mit Root-Rechten ausgeführt werden."
        exit 1
    fi
}

# Prüft ob das System Debian 13 (Trixie) ist.
check_os() {
    if [ ! -f /etc/os-release ]; then
        log_error "Die Datei /etc/os-release existiert nicht."
        exit 1
    fi

    . /etc/os-release

    if [ "${ID:-}" != "debian" ] || [ "${VERSION_ID:-}" != "13" ]; then
        log_warn "Aktuelles System: ${NAME:-Unbekannt} Version: ${VERSION_ID:-Unbekannt}"
        log_warn "Dieses Skript wurde für Debian 13 (Trixie) entwickelt."
        log_warn "Einige Prüfungen und Konfigurationen könnten abweichen."
        echo ""
        echo -n "Fortsetzen? (j/N): "
        read -r confirm
        if [ "${confirm:-n}" != "j" ] && [ "${confirm:-n}" != "J" ]; then
            log_info "Abgebrochen."
            exit 0
        fi
    fi
}

# Erstellt ein Backup einer Datei mit Zeitstempel.
backup_file() {
    local file="$1"
    if [ -f "${file}" ]; then
        local backup="${file}.bak-${TIMESTAMP}"
        cp -p "${file}" "${backup}" 2>/dev/null || true
        log_info "Backup erstellt: ${backup}"
    fi
}

# Schreibt einen sysctl-Parameter dauerhaft in /etc/sysctl.d/.
set_sysctl() {
    local key="$1"
    local value="$2"
    local conf_file="/etc/sysctl.d/99-cis-hardening.conf"
    local current

    current=$(sysctl -n "${key}" 2>/dev/null || echo "")
    if [ "${current}" = "${value}" ]; then
        log_ok "sysctl ${key} = ${value} (bereits gesetzt)"
        return 0
    fi

    mkdir -p /etc/sysctl.d
    if grep -q "^${key}\s*=" "${conf_file}" 2>/dev/null; then
        sed -i "s|^${key}\s*=.*|${key} = ${value}|" "${conf_file}"
    else
        echo "${key} = ${value}" >> "${conf_file}"
    fi
    sysctl -w "${key}=${value}" >/dev/null 2>&1 || true
    log_ok "sysctl ${key} = ${value} (gesetzt)"
}

# Schreibt eine Konfiguration in eine Datei (mit idempotenter Prüfung).
ensure_config() {
    local file="$1"
    local pattern="$2"
    var setting="$3"
    local comment="$4"

    if grep -q "${pattern}" "${file}" 2>/dev/null; then
        log_ok "${setting} (bereits konfiguriert)"
        return 0
    fi

    backup_file "${file}"
    echo "${setting}" >> "${file}"
    log_ok "${setting} (gesetzt)"
}

# Prüft ob ein Paket installiert ist.
package_installed() {
    dpkg -l "$1" 2>/dev/null | grep -q "^ii"
}

# Installiert ein Paket falls nicht vorhanden.
ensure_package() {
    local pkg="$1"
    if package_installed "${pkg}"; then
        log_ok "Paket ${pkg} (bereits installiert)"
        return 0
    fi
    log_info "Installiere Paket: ${pkg}"
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkg}" >> "${LOG_FILE}" 2>&1
    log_ok "Paket ${pkg} (installiert)"
}

# Deaktiviert einen Systemd-Dienst.
disable_service() {
    local service="$1"
    if systemctl is-enabled "${service}" 2>/dev/null | grep -q "enabled"; then
        systemctl stop "${service}" 2>/dev/null || true
        systemctl disable "${service}" 2>/dev/null || true
        log_ok "Dienst ${service} (deaktiviert)"
    else
        log_ok "Dienst ${service} (bereits deaktiviert)"
    fi
}

# Maskiert einen Systemd-Dienst (stärker als disable).
mask_service() {
    local service="$1"
    if systemctl is-enabled "${service}" 2>/dev/null | grep -q "masked"; then
        log_ok "Dienst ${service} (bereits maskiert)"
        return 0
    fi
    systemctl stop "${service}" 2>/dev/null || true
    systemctl mask "${service}" 2>/dev/null || true
    log_ok "Dienst ${service} (maskiert)"
}

# Prüft ob whiptail verfügbar ist (für TUI-Modus).
# Falls whiptail nicht installiert ist, wird ein textbasierter Fallback
# verwendet (bash-select + read). Dies verhindert stumme Fehler durch
# fehlschlagende apt-get-Installationen.
check_whiptail() {
    if command -v whiptail &>/dev/null; then
        return 0
    fi

    log_warn "whiptail nicht gefunden. Versuche Installation..."
    if apt-get install -y whiptail >> "${LOG_FILE}" 2>&1; then
        log_info "whiptail (installiert)"
        return 0
    fi

    log_warn "whiptail-Installation fehlgeschlagen. Verwende textbasiertes Menü."
    log_warn "Installation mit: apt-get install -y whiptail"
    return 1
}

# Startet einen Systemd-Dienst und aktiviert ihn.
enable_and_start_service() {
    local service="$1"
    systemctl enable "${service}" 2>/dev/null || true
    systemctl start "${service}" 2>/dev/null || true
    if systemctl is-active "${service}" 2>/dev/null | grep -q "active"; then
        log_ok "Dienst ${service} (aktiv)"
    else
        log_warn "Dienst ${service} (konnte nicht gestartet werden)"
    fi
}

# ==============================================================================
# CIS-HÄRTUNGSFUNKTIONEN — Jede Kategorie ist eine eigenständige Funktion
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. DATEISYSTEM-HÄRTUNG (CIS 1.1.1 - 1.1.22, Level 1 + Level 2)
# ------------------------------------------------------------------------------
harden_filesystem() {
    log_section "1. Dateisystem-Härtung"

    # CIS 1.1.2 - /tmp mit nodev (L1)
    log_step 1 14 "CIS 1.1.2: /tmp mit nodev mounten"
    if grep -q "[[:space:]]/tmp[[:space:]]" /etc/fstab 2>/dev/null; then
        if ! grep -q "[[:space:]]/tmp[[:space:]].*nodev" /etc/fstab 2>/dev/null; then
            backup_file /etc/fstab
            sed -i '/[[:space:]]\/tmp[[:space:]]/ s/\(defaults\)/\1,nodev,nosuid,noexec/' /etc/fstab
            log_ok "/tmp mount-Optionen: nodev,nosuid,noexec (gesetzt)"
        else
            log_ok "/tmp mount-Optionen (bereits gesetzt)"
        fi
        mount -o remount /tmp 2>/dev/null || true
    else
        log_warn "CIS 1.1.2: /tmp ist keine eigene Partition. Systemd-tmpfs wird verwendet."
        # systemd-tmpfs erzeugt /tmp automatisch. Für nodev/nosuid/noexec muss
        # die systemd-tmpfiles-Konfiguration angepasst werden.
        local tmp_conf="/etc/tmpfiles.d/tmp.conf"
        if [ -f "${tmp_conf}" ] && ! grep -q "noexec" "${tmp_conf}" 2>/dev/null; then
            echo "d /tmp 1777 root root 30d" > "${tmp_conf}"
            log_ok "/tmp wird von systemd mit default-Optionen verwaltet"
        fi
    fi

    # CIS 1.1.3 - /var/tmp mit nodev (L1)
    log_step 2 14 "CIS 1.1.3: /var/tmp mit nodev mounten"
    if grep -q "[[:space:]]/var/tmp[[:space:]]" /etc/fstab 2>/dev/null; then
        if ! grep -q "[[:space:]]/var/tmp[[:space:]].*nodev" /etc/fstab 2>/dev/null; then
            backup_file /etc/fstab
            sed -i '/[[:space:]]\/var\/tmp[[:space:]]/ s/\(defaults\)/\1,nodev,nosuid,noexec/' /etc/fstab
            mount -o remount /var/tmp 2>/dev/null || true
            log_ok "/var/tmp mount-Optionen: nodev,nosuid,noexec (gesetzt)"
        else
            log_ok "/var/tmp mount-Optionen (bereits gesetzt)"
        fi
    else
        log_info "/var/tmp ist keine eigene Partition. Überspringe."
    fi

    # CIS 1.1.4 - /dev/shm mit nodev (L1)
    log_step 3 14 "CIS 1.1.4: /dev/shm mit nodev mounten"
    if grep -q "[[:space:]]/dev/shm[[:space:]]" /etc/fstab 2>/dev/null; then
        if ! grep -q "[[:space:]]/dev/shm[[:space:]].*nodev" /etc/fstab 2>/dev/null; then
            backup_file /etc/fstab
            sed -i '/[[:space:]]\/dev\/shm[[:space:]]/ s/\(defaults\)/\1,nodev,nosuid,noexec/' /etc/fstab
            mount -o remount /dev/shm 2>/dev/null || true
            log_ok "/dev/shm mount-Optionen: nodev,nosuid,noexec (gesetzt)"
        else
            log_ok "/dev/shm mount-Optionen (bereits gesetzt)"
        fi
    else
        log_warn "/dev/shm nicht in /etc/fstab. Füge Eintrag hinzu..."
        echo "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0" >> /etc/fstab
        mount -o remount /dev/shm 2>/dev/null || mount /dev/shm 2>/dev/null || true
        log_ok "/dev/shm als tmpfs mit nodev,nosuid,noexec (gesetzt)"
    fi

    # CIS 1.1.5 - /home mit nodev (L1)
    log_step 4 14 "CIS 1.1.5: /home mit nodev mounten"
    if grep -q "[[:space:]]/home[[:space:]]" /etc/fstab 2>/dev/null; then
        if ! grep -q "[[:space:]]/home[[:space:]].*nodev" /etc/fstab 2>/dev/null; then
            backup_file /etc/fstab
            sed -i '/[[:space:]]\/home[[:space:]]/ s/\(defaults\)/\1,nodev/' /etc/fstab
            mount -o remount /home 2>/dev/null || true
            log_ok "/home mount-Option: nodev (gesetzt)"
        else
            log_ok "/home mount-Option (bereits gesetzt)"
        fi
    else
        log_info "/home ist keine eigene Partition. Überspringe."
    fi

    # CIS 1.1.21 - Sticky Bit auf world-writable Verzeichnissen (L1)
    log_step 5 14 "CIS 1.1.21: Sticky-Bit auf world-writable Verzeichnissen"
    local sticky_fix
    sticky_fix=$(df --local -P 2>/dev/null | awk '{if(NR>1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null | head -50)
    if [ -n "${sticky_fix}" ]; then
        df --local -P 2>/dev/null | awk '{if(NR>1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -exec chmod +t {} \; 2>/dev/null || true
        log_ok "Sticky-Bit auf world-writable Verzeichnissen (gesetzt)"
    else
        log_ok "Sticky-Bit (alle Verzeichnisse bereits korrekt)"
    fi

    # CIS 1.1.22 - Automount deaktivieren (L1)
    log_step 6 14 "CIS 1.1.22: Automount deaktivieren"
    disable_service "autofs" 2>/dev/null || log_info "autofs nicht installiert, überspringe."

    # CIS 1.1.23 - USB-Storage deaktivieren (L2)
    log_step 7 14 "CIS 1.1.23 (L2): USB-Storage deaktivieren"
    local usb_conf="/etc/modprobe.d/usb-storage.conf"
    if ! grep -q "install usb-storage" "${usb_conf}" 2>/dev/null; then
        echo "install usb-storage /bin/true" > "${usb_conf}"
        log_ok "USB-Storage-Modul (gesperrt, L2)"
    else
        log_ok "USB-Storage-Modul (bereits gesperrt, L2)"
    fi

    # CIS 1.1.24 - /boot mit nodev (L2)
    log_step 8 14 "CIS 1.1.24 (L2): /boot mit nodev mounten"
    if grep -q "[[:space:]]/boot[[:space:]]" /etc/fstab 2>/dev/null; then
        if ! grep -q "[[:space:]]/boot[[:space:]].*nodev" /etc/fstab 2>/dev/null; then
            backup_file /etc/fstab
            sed -i '/[[:space:]]\/boot[[:space:]]/ s/\(defaults\)/\1,nodev,nosuid/' /etc/fstab
            mount -o remount /boot 2>/dev/null || true
            log_ok "/boot mount-Optionen: nodev,nosuid (gesetzt, L2)"
        else
            log_ok "/boot mount-Optionen (bereits gesetzt, L2)"
        fi
    else
        log_info "/boot ist keine eigene Partition. Überspringe."
    fi

    # CIS 1.1.25 - /var/log mit nodev (L2)
    log_step 9 14 "CIS 1.1.25 (L2): /var/log mit nodev mounten"
    if grep -q "[[:space:]]/var/log[[:space:]]" /etc/fstab 2>/dev/null; then
        if ! grep -q "[[:space:]]/var/log[[:space:]].*nodev" /etc/fstab 2>/dev/null; then
            backup_file /etc/fstab
            sed -i '/[[:space:]]\/var\/log[[:space:]]/ s/\(defaults\)/\1,nodev,nosuid,noexec/' /etc/fstab
            mount -o remount /var/log 2>/dev/null || true
            log_ok "/var/log mount-Optionen: nodev,nosuid,noexec (gesetzt, L2)"
        else
            log_ok "/var/log mount-Optionen (bereits gesetzt, L2)"
        fi
    else
        log_info "/var/log ist keine eigene Partition. Überspringe."
    fi

    # CIS 1.1.26 - /var/log/audit mit nodev (L2)
    log_step 10 14 "CIS 1.1.26 (L2): /var/log/audit mit nodev mounten"
    if grep -q "[[:space:]]/var/log/audit[[:space:]]" /etc/fstab 2>/dev/null; then
        if ! grep -q "[[:space:]]/var/log/audit[[:space:]].*nodev" /etc/fstab 2>/dev/null; then
            backup_file /etc/fstab
            sed -i '/[[:space:]]\/var\/log\/audit[[:space:]]/ s/\(defaults\)/\1,nodev,nosuid,noexec/' /etc/fstab
            mount -o remount /var/log/audit 2>/dev/null || true
            log_ok "/var/log/audit mount-Optionen: nodev,nosuid,noexec (gesetzt, L2)"
        else
            log_ok "/var/log/audit mount-Optionen (bereits gesetzt, L2)"
        fi
    else
        log_info "/var/log/audit ist keine eigene Partition. Überspringe."
    fi

    # CIS 1.1.27 - /var/tmp mit nodev auf Systemd-Systemen (L2)
    log_step 11 14 "CIS 1.1.27 (L2): /var/tmp zusätzliche Prüfung"
    # Systemd mountet /var/tmp automatisch mit Standard-Optionen.
    # Falls eine eigene Partition existiert, wurden die Optionen bereits oben gesetzt.
    log_info "/var/tmp wird von systemd verwaltet. Siehe obige Konfiguration."

    # CIS 1.1.13 - Prüfung auf AIDE/Tripwire (nur Prüfung, L1)
    log_step 12 14 "CIS 1.1.13: Dateiintegritätsprüfung (AIDE)"
    if package_installed "aide"; then
        log_ok "AIDE (installiert). Initialisierung erforderlich: aideinit"
        log_info "Hinweis: AIDE-Datenbank muss mit 'aideinit' initialisiert werden."
    else
        log_info "AIDE nicht installiert. Installation wird empfohlen (CIS Level 1)."
        log_info "Installation mit: apt-get install -y aide && aideinit"
    fi

    # CIS 1.1.14 - AIDE-Konfiguration prüfen
    log_step 13 14 "CIS 1.1.14: AIDE-Konfiguration prüfen"
    if [ -f /etc/aide/aide.conf ]; then
        log_ok "AIDE-Konfiguration vorhanden."
    else
        log_info "AIDE-Konfiguration nicht vorhanden (nicht installiert)."
    fi

    # CIS 1.1.15 - AIDE regelmäßige Prüfung (cron)
    log_step 14 14 "CIS 1.1.15: AIDE-Cron-Prüfung"
    if [ -f /etc/cron.d/aide-check ] || [ -f /etc/cron.daily/aide-check ]; then
        log_ok "AIDE-Cron-Prüfung (eingerichtet)"
    else
        log_info "AIDE-Cron-Prüfung nicht eingerichtet."
    fi

    log_info "Dateisystem-Härtung abgeschlossen."
}

# ------------------------------------------------------------------------------
# 2. PAKETQUELLEN UND UPDATES (CIS 1.2, Level 1)
# ------------------------------------------------------------------------------
harden_updates() {
    log_section "2. Paketquellen und Updates"

    # CIS 1.2.1 - GPG-Schlüssel für Paketquellen konfigurieren (L1)
    log_step 1 4 "CIS 1.2.1: GPG-Schlüssel für Paketquellen prüfen"
    local gpg_dir="/etc/apt/keyrings"
    mkdir -p "${gpg_dir}"
    log_info "GPG-Schlüsselverzeichnis vorhanden: ${gpg_dir}"

    # Prüfung ob alle .list Quellen GPG-gesichert sind
    local sources_without_gpg
    sources_without_gpg=$(grep -r "^deb " /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | grep -v "\[signed-by\|signed-by" || true)
    if [ -n "${sources_without_gpg}" ]; then
        log_warn "Einige Paketquellen haben keine explizite GPG-Signaturprüfung:"
        echo "${sources_without_gpg}" | while read -r line; do
            log_warn "  -> ${line}"
        done
        log_info "Hinweis: Für Debian 13 werden die Archive automatisch über signed-by im Release-File geprüft."
    else
        log_ok "GPG-Schlüssel für Paketquellen (alle Quellen signiert)"
    fi

    # CIS 1.2.2 - Paketquellen auf HTTPS prüfen (L1)
    log_step 2 4 "CIS 1.2.2: Paketquellen auf HTTPS prüfen"
    local http_sources
    http_sources=$(grep -r "^deb http://" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null || true)
    if [ -n "${http_sources}" ]; then
        log_warn "Einige Paketquellen verwenden HTTP (unverschlüsselt):"
        echo "${http_sources}" | while read -r line; do
            log_warn "  -> ${line}"
        done
        log_info "Hinweis: Debian-Mirror über HTTP sind akzeptabel, da die Pakete GPG-signiert sind."
    else
        log_ok "Paketquellen verwenden HTTPS (oder keine HTTP-Quellen gefunden)"
    fi

    # CIS 1.2.3 - unattended-upgrades (L1)
    log_step 3 4 "CIS 1.2.3: unattended-upgrades konfigurieren"
    if package_installed "unattended-upgrades"; then
        log_ok "unattended-upgrades (bereits installiert)"
        # Automatische Updates aktivieren
        dpkg-reconfigure -plow unattended-upgrades 2>/dev/null || true
        log_info "unattended-upgrades wurde konfiguriert."
    else
        log_info "unattended-upgrades wird installiert..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades >> "${LOG_FILE}" 2>&1
        dpkg-reconfigure -plow unattended-upgrades 2>/dev/null || true
        log_ok "unattended-upgrades (installiert und konfiguriert)"
    fi

    # CIS 1.2.4 - APT update (L1)
    log_step 4 4 "CIS 1.2.4: APT-Paketquellen aktualisieren"
    apt-get update >> "${LOG_FILE}" 2>&1
    log_ok "APT-Paketquellen (aktualisiert)"

    log_info "Paketquellen und Updates abgeschlossen."
}

# ------------------------------------------------------------------------------
# 3. BOOTLOADER-SICHERHEIT (CIS 1.4, 1.5, Level 1 + Level 2)
# ------------------------------------------------------------------------------
harden_bootloader() {
    log_section "3. Bootloader-Sicherheit"

    # CIS 1.4.1 - GRUB-Berechtigungen (L1)
    log_step 1 4 "CIS 1.4.1: GRUB-Konfigurationsberechtigungen"
    if [ -d /boot/grub ]; then
        chown root:root /boot/grub/grub.cfg 2>/dev/null || true
        chmod 400 /boot/grub/grub.cfg 2>/dev/null || true
        log_ok "GRUB-Konfiguration (Berechtigungen: 400, root:root)"
    else
        log_warn "GRUB-Verzeichnis /boot/grub nicht gefunden. UEFI-System?"
        if [ -f /boot/efi/EFI/debian/grub.cfg ]; then
            chmod 400 /boot/efi/EFI/debian/grub.cfg 2>/dev/null || true
            log_ok "GRUB-Konfiguration (UEFI) Berechtigungen gesetzt."
        fi
    fi

    # CIS 1.4.2 - GRUB-Bootloader-Passwort (L2)
    log_step 2 4 "CIS 1.4.2 (L2): GRUB-Bootloader-Passwort"
    if grep -q "^set superusers\|^password_pbkdf2\|^password" /etc/grub.d/40_custom 2>/dev/null; then
        log_ok "GRUB-Bootloader-Passwort (bereits konfiguriert, L2)"
    else
        log_info "GRUB-Bootloader-Passwort nicht konfiguriert (L2 - optional)."
        log_info "Konfiguration mit: grub-mkpasswd-pbkdf2 | tee -a /etc/grub.d/40_custom && update-grub"
    fi

    # CIS 1.5.1 - Core-Dumps einschränken (L1)
    log_step 3 4 "CIS 1.5.1: Core-Dumps einschränken"
    if ! grep -q "hard core" /etc/security/limits.conf 2>/dev/null; then
        backup_file /etc/security/limits.conf
        echo "* hard core 0" >> /etc/security/limits.conf
        log_ok "Core-Dumps (eingeschränkt via limits.conf)"
    else
        log_ok "Core-Dumps (bereits eingeschränkt)"
    fi

    # systemd-Core-Dump-Umleitung deaktivieren (L1)
    local coredump_conf="/etc/systemd/coredump.conf.d/disable.conf"
    if [ ! -f "${coredump_conf}" ]; then
        mkdir -p /etc/systemd/coredump.conf.d
        cat > "${coredump_conf}" << 'EOC'
[Coredump]
Storage=none
ProcessSizeMax=0
EOC
        log_ok "systemd-Core-Dumps (deaktiviert)"
    else
        log_ok "systemd-Core-Dumps (bereits deaktiviert)"
    fi

    # CIS 1.5.2 - Address Space Layout Randomization (ASLR) (L1)
    log_step 4 4 "CIS 1.5.2: ASLR (Address Space Layout Randomization)"
    set_sysctl "kernel.randomize_va_space" "2"

    # CIS 1.5.3 - Prelink deaktivieren (L1)
    if package_installed "prelink"; then
        log_warn "prelink ist installiert (veraltet und unsicher)"
        log_info "prelink wird deinstalliert..."
        prelink -ua 2>/dev/null || true
        apt-get remove -y prelink >> "${LOG_FILE}" 2>&1 || true
        log_ok "prelink (deinstalliert)"
    else
        log_ok "prelink (nicht installiert)"
    fi

    log_info "Bootloader-Sicherheit abgeschlossen."
}

# ------------------------------------------------------------------------------
# 4. NETZWERK-PARAMETER (CIS 3.1 - 3.3, Level 1)
# ------------------------------------------------------------------------------
harden_network() {
    log_section "4. Netzwerk-Parameter"

    # CIS 3.1.1 - IP-Forwarding deaktivieren (L1)
    log_step 1 18 "CIS 3.1.1: IP-Forwarding deaktivieren"
    set_sysctl "net.ipv4.ip_forward" "0"
    set_sysctl "net.ipv6.conf.all.forwarding" "0"

    # CIS 3.1.2 - Paket-Redirects deaktivieren (L1)
    log_step 2 18 "CIS 3.1.2: Paket-Redirect-Senden deaktivieren"
    set_sysctl "net.ipv4.conf.all.send_redirects" "0"
    set_sysctl "net.ipv4.conf.default.send_redirects" "0"

    # CIS 3.2.1 - ICMP-Redirects deaktivieren (L1)
    log_step 3 18 "CIS 3.2.1: ICMP-Redirects deaktivieren"
    set_sysctl "net.ipv4.conf.all.accept_redirects" "0"
    set_sysctl "net.ipv4.conf.default.accept_redirects" "0"
    set_sysctl "net.ipv6.conf.all.accept_redirects" "0"
    set_sysctl "net.ipv6.conf.default.accept_redirects" "0"

    # CIS 3.2.2 - Secure ICMP-Redirects deaktivieren (L1)
    log_step 4 18 "CIS 3.2.2: Secure ICMP-Redirects deaktivieren"
    set_sysctl "net.ipv4.conf.all.secure_redirects" "0"
    set_sysctl "net.ipv4.conf.default.secure_redirects" "0"

    # CIS 3.2.3 - Routing-Traffic-Logs aktivieren (L1)
    log_step 5 18 "CIS 3.2.3: Routing-Traffic-Logs aktivieren"
    set_sysctl "net.ipv4.conf.all.log_martians" "1"
    set_sysctl "net.ipv4.conf.default.log_martians" "1"

    # CIS 3.2.4 - Broadcast-ICMP ignorieren (L1)
    log_step 6 18 "CIS 3.2.4: Broadcast-ICMP ignorieren"
    set_sysctl "net.ipv4.icmp_echo_ignore_broadcasts" "1"

    # CIS 3.2.5 - ICMP-Error-Responses ratelimiten (L1)
    log_step 7 18 "CIS 3.2.5: ICMP-Error-Responses ratelimiten"
    set_sysctl "net.ipv4.icmp_ignore_bogus_error_responses" "1"

    # CIS 3.3.1 - Reverse-Path-Filter aktivieren (L1)
    log_step 8 18 "CIS 3.3.1: Reverse-Path-Filter aktivieren"
    set_sysctl "net.ipv4.conf.all.rp_filter" "1"
    set_sysctl "net.ipv4.conf.default.rp_filter" "1"

    # CIS 3.3.2 - TCP-SYN-Cookies aktivieren (L1)
    log_step 9 18 "CIS 3.3.2: TCP-SYN-Cookies aktivieren"
    set_sysctl "net.ipv4.tcp_syncookies" "1"

    # CIS 3.3.3 - IPv6-Router-Solicitations deaktivieren (L1)
    log_step 10 18 "CIS 3.3.3: IPv6-Router-Solicitations deaktivieren"
    set_sysctl "net.ipv6.conf.all.accept_ra" "0"
    set_sysctl "net.ipv6.conf.default.accept_ra" "0"

    # Weitere Netzwerk-Härtung
    log_step 11 18 "CIS 3.3.4: TCP-Timestamps deaktivieren"
    set_sysctl "net.ipv4.tcp_timestamps" "0"

    log_step 12 18 "CIS 3.3.5: TCP-Sack deaktivieren"
    set_sysctl "net.ipv4.tcp_sack" "0"

    log_step 13 18 "CIS 3.3.6: TCP-DSNOP deaktivieren"
    set_sysctl "net.ipv4.tcp_dsack" "0"

    log_step 14 18 "CIS 3.3.7: TCP-FACK deaktivieren"
    set_sysctl "net.ipv4.tcp_fack" "0"

    log_step 15 18 "CIS 3.3.8: TCP-SYN-Backlog erhöhen"
    set_sysctl "net.ipv4.tcp_syn_backlog" "2048"
    set_sysctl "net.core.somaxconn" "1024"

    log_step 16 18 "CIS 3.3.9: TCP-Fin-Wait-2-Time reduzieren"
    set_sysctl "net.ipv4.tcp_fin_timeout" "15"

    # CIS 3.4 - Uncommon Network Protocols deaktivieren (L2)
    log_step 17 18 "CIS 3.4 (L2): Ungewöhnliche Netzwerkprotokolle deaktivieren"
    local dccp_conf="/etc/modprobe.d/dccp.conf"
    local sctp_conf="/etc/modprobe.d/sctp.conf"
    local rds_conf="/etc/modprobe.d/rds.conf"
    local tipc_conf="/etc/modprobe.d/tipc.conf"

    if ! grep -q "install dccp" "${dccp_conf}" 2>/dev/null; then
        echo "install dccp /bin/true" > "${dccp_conf}"
        log_ok "DCCP-Protokoll (gesperrt, L2)"
    fi
    if ! grep -q "install sctp" "${sctp_conf}" 2>/dev/null; then
        echo "install sctp /bin/true" > "${sctp_conf}"
        log_ok "SCTP-Protokoll (gesperrt, L2)"
    fi
    if ! grep -q "install rds" "${rds_conf}" 2>/dev/null; then
        echo "install rds /bin/true" > "${rds_conf}"
        log_ok "RDS-Protokoll (gesperrt, L2)"
    fi
    if ! grep -q "install tipc" "${tipc_conf}" 2>/dev/null; then
        echo "install tipc /bin/true" > "${tipc_conf}"
        log_ok "TIPC-Protokoll (gesperrt, L2)"
    fi

    log_step 18 18 "CIS 3.3.10: Netzwerk-Parameter anwenden"
    sysctl -p /etc/sysctl.d/99-cis-hardening.conf >/dev/null 2>&1 || true
    log_ok "Netzwerk-Parameter (angewendet)"

    log_info "Netzwerk-Parameter abgeschlossen."
}

# ------------------------------------------------------------------------------
# 5. AUTHENTIFIZIERUNG (CIS 5.3, 5.4, 5.5, Level 1 + Level 2)
# ------------------------------------------------------------------------------
harden_auth() {
    log_section "5. Authentifizierung"

    # CIS 5.3.1 - Passwort-Hashing-Algorithmus auf SHA512 (L1)
    log_step 1 10 "CIS 5.3.1: Passwort-Hashing-Algorithmus (SHA512)"
    if grep -q "^ENCRYPT_METHOD SHA512" /etc/login.defs 2>/dev/null; then
        log_ok "SHA512-Passwort-Hashing (bereits konfiguriert)"
    else
        backup_file /etc/login.defs
        if grep -q "^ENCRYPT_METHOD" /etc/login.defs 2>/dev/null; then
            sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
        else
            echo "ENCRYPT_METHOD SHA512" >> /etc/login.defs
        fi
        log_ok "SHA512-Passwort-Hashing (gesetzt)"
    fi

    # CIS 5.3.2 - Passwort-Komplexität (libpam-pwquality) (L1)
    log_step 2 10 "CIS 5.3.2: Passwort-Komplexität (pam_pwquality)"
    ensure_package "libpam-pwquality"
    local pwquality_conf="/etc/security/pwquality.conf"
    if [ -f "${pwquality_conf}" ]; then
        backup_file "${pwquality_conf}"
        # Minimale Länge: 14 Zeichen (CIS-Level-1-Empfehlung)
        sed -i 's/^#\s*minlen\s*=.*/minlen = 14/' "${pwquality_conf}"
        sed -i 's/^#\s*minclass\s*=.*/minclass = 4/' "${pwquality_conf}"
        sed -i 's/^#\s*maxrepeat\s*=.*/maxrepeat = 3/' "${pwquality_conf}"
        # Falls die Parameter nicht existieren, anhängen
        grep -q "^minlen" "${pwquality_conf}" 2>/dev/null || echo "minlen = 14" >> "${pwquality_conf}"
        grep -q "^minclass" "${pwquality_conf}" 2>/dev/null || echo "minclass = 4" >> "${pwquality_conf}"
        grep -q "^maxrepeat" "${pwquality_conf}" 2>/dev/null || echo "maxrepeat = 3" >> "${pwquality_conf}"
        log_ok "Passwort-Komplexität (minlen=14, minclass=4, maxrepeat=3)"
    fi

    # CIS 5.3.3 - Account-Lockout nach Fehlversuchen (L2)
    log_step 3 10 "CIS 5.3.3 (L2): Account-Lockout nach Fehlversuchen"
    local pam_faillock="/usr/share/pam-configs/faillock"
    if [ ! -f /etc/pam.d/common-auth ] || ! grep -q "pam_faillock" /etc/pam.d/common-auth 2>/dev/null; then
        if command -v pam-auth-update &>/dev/null; then
            # faillock Profil für pam-auth-update erstellen
            cat > "${pam_faillock}" << 'EOC'
Name: Faillock
Default: no
Priority: 0
Auth-Type: Primary
Auth:
    [default=die] pam_faillock.so authfail
    sufficient pam_faillock.so authsucc
EOC
            log_info "pam_faillock konfiguriert (L2 - optional). Aktivierung: pam-auth-update --enable faillock"
        else
            log_info "pam-auth-update nicht verfügbar. Manuelle Konfiguration erforderlich."
        fi
        log_ok "Account-Lockout (Konfiguration bereitgestellt, L2)"
    else
        log_ok "Account-Lockout (bereits konfiguriert, L2)"
    fi

    # CIS 5.3.4 - Passwort-Wiederholungssperre (L2)
    log_step 4 10 "CIS 5.3.4 (L2): Passwort-Wiederholungssperre"
    local pam_pwhistory="/usr/share/pam-configs/pwhistory"
    if [ ! -f /etc/pam.d/common-password ] || ! grep -q "pam_pwhistory" /etc/pam.d/common-password 2>/dev/null; then
        cat > "${pam_pwhistory}" << 'EOC'
Name: pwhistory
Default: no
Priority: 1024
Password-Type: Primary
Password:
    requisite pam_pwhistory.so remember=5 enforce_for_root
EOC
        log_info "pam_pwhistory konfiguriert (L2 - optional). Aktivierung: pam-auth-update --enable pwhistory"
        log_ok "Passwort-Historie (Konfiguration bereitgestellt, L2)"
    else
        log_ok "Passwort-Historie (bereits konfiguriert, L2)"
    fi

    # CIS 5.4.1 - Passwort-Alterung (L1)
    log_step 5 10 "CIS 5.4.1: Passwort-Alterung"
    backup_file /etc/login.defs
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   365/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
    log_ok "Passwort-Alterung (max=365, min=7, warn=7)"

    # CIS 5.4.2 - Default-User-Umask (L1)
    log_step 6 10 "CIS 5.4.2: Default-User-Umask"
    backup_file /etc/login.defs
    if grep -q "^UMASK" /etc/login.defs 2>/dev/null; then
        sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs
    else
        echo "UMASK 027" >> /etc/login.defs
    fi
    log_ok "Default-User-Umask (027)"

    # CIS 5.4.3 - Root-Login über Konsolen deaktivieren (L1)
    log_step 7 10 "CIS 5.4.3: Root-Login über Konsolen deaktivieren"
    if [ -f /etc/securetty ]; then
        # Nur die erste Konsole (tty1) freigeben, den Rest sperren
        backup_file /etc/securetty
        echo "tty1" > /etc/securetty
        log_ok "/etc/securetty (auf tty1 beschränkt)"
    else
        log_info "/etc/securetty nicht vorhanden (übersprungen)"
    fi

    # CIS 5.4.4 - Leere Passwörter prüfen (L1)
    log_step 8 10 "CIS 5.4.4: Leere Passwörter prüfen"
    local empty_passwords
    empty_passwords=$(awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null || true)
    if [ -n "${empty_passwords}" ]; then
        log_warn "Benutzer mit leeren Passwörtern gefunden:"
        echo "${empty_passwords}" | while read -r user; do
            log_warn "  -> ${user}"
            passwd -l "${user}" 2>/dev/null || true
            log_ok "Benutzer ${user} (gesperrt)"
        done
    else
        log_ok "Leere Passwörter (keine gefunden)"
    fi

    # CIS 5.5.1 - NIS-Client deaktivieren (L1)
    log_step 9 10 "CIS 5.5.1: NIS-Client deaktivieren"
    if package_installed "nis"; then
        apt-get remove -y nis >> "${LOG_FILE}" 2>&1 || true
        log_ok "NIS (deinstalliert)"
    else
        log_ok "NIS (nicht installiert)"
    fi

    # CIS 5.5.2 - rsh-Client deaktivieren (L1)
    log_step 10 10 "CIS 5.5.2: rsh-Client deaktivieren"
    for pkg in rsh-client rsh-redone-client; do
        if package_installed "${pkg}"; then
            apt-get remove -y "${pkg}" >> "${LOG_FILE}" 2>&1 || true
            log_ok "${pkg} (deinstalliert)"
        fi
    done
    log_ok "rsh-Client (nicht installiert oder deinstalliert)"

    log_info "Authentifizierung abgeschlossen."
}

# ------------------------------------------------------------------------------
# 6. SSH-SERVER-HÄRTUNG (CIS 5.2, Level 1 + Level 2)
# ------------------------------------------------------------------------------
harden_ssh() {
    log_section "6. SSH-Server-Härtung"

    local sshd_config="/etc/ssh/sshd_config"

    # Prüfen ob SSH installiert ist
    if ! package_installed "openssh-server"; then
        log_info "OpenSSH-Server nicht installiert. Überspringe SSH-Härtung."
        return 0
    fi

    if [ ! -f "${sshd_config}" ]; then
        log_warn "sshd_config nicht gefunden unter ${sshd_config}"
        return 0
    fi

    backup_file "${sshd_config}"

    # Hilfsfunktion für SSH-Konfiguration
    set_sshd_param() {
        local param="$1"
        local value="$2"
        if grep -q "^${param}" "${sshd_config}" 2>/dev/null; then
            sed -i "s|^${param}.*|${param} ${value}|" "${sshd_config}"
        elif grep -q "^#${param}" "${sshd_config}" 2>/dev/null; then
            sed -i "s|^#${param}.*|${param} ${value}|" "${sshd_config}"
        else
            echo "${param} ${value}" >> "${sshd_config}"
        fi
    }

    # CIS 5.2.1 - SSH-Protokoll auf v2 (L1)
    log_step 1 12 "CIS 5.2.1: SSH-Protokoll auf v2"
    set_sshd_param "Protocol" "2"
    log_ok "SSH-Protokoll (v2)"

    # CIS 5.2.2 - SSH-Loglevel auf INFO (L1)
    log_step 2 12 "CIS 5.2.2: SSH-Loglevel auf INFO"
    set_sshd_param "LogLevel" "INFO"
    log_ok "SSH-Loglevel (INFO)"

    # CIS 5.2.3 - SSH-Ciphers (L1)
    log_step 3 12 "CIS 5.2.3: SSH-Ciphers (starke Algorithmen)"
    set_sshd_param "Ciphers" "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
    log_ok "SSH-Ciphers (niederlassungsstarke Algorithmen)"

    # CIS 5.2.4 - SSH-MACs (L1)
    log_step 4 12 "CIS 5.2.4: SSH-MACs (starke Algorithmen)"
    set_sshd_param "MACs" "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
    log_ok "SSH-MACs (starke Algorithmen)"

    # CIS 5.2.5 - SSH-Key-Exchange-Algorithmen (L1)
    log_step 5 12 "CIS 5.2.5: SSH-Key-Exchange-Algorithmen"
    set_sshd_param "KexAlgorithms" "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256"
    log_ok "SSH-Key-Exchange (starke Algorithmen)"

    # CIS 5.2.6 - PermitRootLogin deaktivieren (L1)
    log_step 6 12 "CIS 5.2.6: PermitRootLogin deaktivieren"
    set_sshd_param "PermitRootLogin" "no"
    log_ok "PermitRootLogin (deaktiviert)"

    # CIS 5.2.7 - MaxAuthTries auf 4 (L1)
    log_step 7 12 "CIS 5.2.7: MaxAuthTries auf 4"
    set_sshd_param "MaxAuthTries" "4"
    log_ok "MaxAuthTries (4)"

    # CIS 5.2.8 - MaxSessions auf 10 (L1)
    log_step 8 12 "CIS 5.2.8: MaxSessions auf 10"
    set_sshd_param "MaxSessions" "10"
    log_ok "MaxSessions (10)"

    # CIS 5.2.9 - MaxStartups (L1)
    log_step 9 12 "CIS 5.2.9: MaxStartups begrenzen"
    set_sshd_param "MaxStartups" "10:30:60"
    log_ok "MaxStartups (10:30:60)"

    # CIS 5.2.10 - ClientAliveInterval und ClientAliveCountMax (L1)
    log_step 10 12 "CIS 5.2.10: SSH-Timeout konfigurieren"
    set_sshd_param "ClientAliveInterval" "300"
    set_sshd_param "ClientAliveCountMax" "0"
    log_ok "SSH-Timeout (ClientAliveInterval=300, ClientAliveCountMax=0)"

    # CIS 5.2.11 - SSH-Banner aktivieren (L1)
    log_step 11 12 "CIS 5.2.11: SSH-Banner aktivieren"
    if [ ! -f /etc/issue.net ]; then
        echo "Nur autorisierte Benutzer. Der Zugriff wird überwacht." > /etc/issue.net
    fi
    set_sshd_param "Banner" "/etc/issue.net"
    log_ok "SSH-Banner (/etc/issue.net)"

    # CIS 5.2.12 - X11-Forwarding deaktivieren (L1)
    log_step 12 12 "CIS 5.2.12: X11-Forwarding deaktivieren"
    set_sshd_param "X11Forwarding" "no"
    log_ok "X11Forwarding (deaktiviert)"

    # SSH-Dienst neustarten falls Konfiguration geändert wurde
    if sshd -t 2>/dev/null; then
        systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
        log_ok "SSH-Dienst (neugestartet)"
    else
        log_error "SSH-Konfiguration fehlerhaft. Bitte prüfen: sshd -t"
    fi

    log_info "SSH-Server-Härtung abgeschlossen."
}

# ------------------------------------------------------------------------------
# 7. AUDIT-DAEMON (CIS 4.1, Level 1 + Level 2)
# ------------------------------------------------------------------------------
harden_audit() {
    log_section "7. Audit-Daemon (auditd)"

    # CIS 4.1.1 - auditd installieren (L1)
    log_step 1 8 "CIS 4.1.1: auditd installieren"
    ensure_package "auditd"
    ensure_package "audispd-plugins"

    # CIS 4.1.2 - Audit-Log-Größe konfigurieren (L1)
    log_step 2 8 "CIS 4.1.2: Audit-Log-Konfiguration"
    local auditd_conf="/etc/audit/auditd.conf"
    if [ -f "${auditd_conf}" ]; then
        backup_file "${auditd_conf}"
        sed -i 's/^max_log_file\s*=.*/max_log_file = 100/' "${auditd_conf}"
        sed -i 's/^max_log_file_action\s*=.*/max_log_file_action = ROTATE/' "${auditd_conf}"
        sed -i 's/^num_logs\s*=.*/num_logs = 5/' "${auditd_conf}"
        sed -i 's/^space_left_action\s*=.*/space_left_action = EMAIL/' "${auditd_conf}"
        sed -i 's/^action_mail_acct\s*=.*/action_mail_acct = root/' "${auditd_conf}"
        log_ok "Audit-Log-Konfiguration (max_log_file=100, rotate=5)"
    else
        log_warn "auditd.conf nicht gefunden."
    fi

    # CIS 4.1.3 - Audit-Regeln für System-Administration (L1)
    log_step 3 8 "CIS 4.1.3: Audit-Regeln für System-Administration"
    local audit_rules="/etc/audit/rules.d/cis-hardening.rules"
    mkdir -p /etc/audit/rules.d

    cat > "${audit_rules}" << 'EOR'
# CIS 4.1.3 - Audit-Regeln für Debian 13 (Trixie)
# Generiert durch cis-hardening.sh

# Zeitänderungen überwachen
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change

# Benutzer- und Gruppenverwaltung überwachen
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Netzwerk-Umgebungsänderungen überwachen
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/hostname -p wa -k system-locale

# SELinux/AppArmor-Änderungen überwachen
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

# Log-in- und Log-out-Ereignisse überwachen
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# Sitzungsinitiierung überwachen
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# Unbefugte Dateizugriffe überwachen
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k access
EOR
    log_ok "Audit-Regeln (geschrieben: ${audit_rules})"

    # CIS 4.1.4 - Audit-Regeln für Mount-Operationen (L1)
    log_step 4 8 "CIS 4.1.4: Audit-Regeln für Mount-Operationen"
    cat >> "${audit_rules}" << 'EOR'

# Mount-Operationen überwachen
-a always,exit -F arch=b64 -S mount -k mounts
-a always,exit -F arch=b32 -S mount -k mounts
EOR
    log_ok "Audit-Regeln für Mount-Operationen (aktiviert)"

    # CIS 4.1.5 - Audit-Regeln für Datei-Löschoperationen (L1)
    log_step 5 8 "CIS 4.1.5: Audit-Regeln für Datei-Löschoperationen"
    cat >> "${audit_rules}" << 'EOR'

# Datei-Löschoperationen überwachen
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=-1 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=-1 -k delete
EOR
    log_ok "Audit-Regeln für Datei-Löschoperationen (aktiviert)"

    # CIS 4.1.6 - Audit-Regeln für SUID/SGID-Änderungen (L2)
    log_step 6 8 "CIS 4.1.6 (L2): Audit-Regeln für SUID/SGID-Änderungen"
    cat >> "${audit_rules}" << 'EOR'

# SUID/SGID-Änderungen überwachen
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod
EOR
    log_ok "Audit-Regeln für SUID/SGID-Änderungen (aktiviert, L2)"

    # CIS 4.1.7 - Audit-Regeln für Kernel-Module (L2)
    log_step 7 8 "CIS 4.1.7 (L2): Audit-Regeln für Kernel-Module"
    cat >> "${audit_rules}" << 'EOR'

# Kernel-Modul-Änderungen überwachen
-w /etc/modprobe.conf -p wa -k modules
-w /etc/modprobe.d/ -p wa -k modules
-w /etc/modules-load.d/ -p wa -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-a always,exit -F arch=b32 -S init_module -S delete_module -k modules
EOR
    log_ok "Audit-Regeln für Kernel-Module (aktiviert, L2)"

    # CIS 4.1.8 - Audit-Konfiguration sperren (L2)
    log_step 8 8 "CIS 4.1.8 (L2): Audit-Konfiguration sperren"
    cat >> "${audit_rules}" << 'EOR'

# Audit-Konfiguration sperren (unveränderbar machen)
-e 2
EOR
    log_ok "Audit-Regeln (Konfiguration wird beim nächsten Neustart geladen)"

    # auditd Regeln laden
    if command -v augenrules &>/dev/null; then
        augenrules --load >> "${LOG_FILE}" 2>&1 || true
        log_ok "Audit-Regeln (geladen via augenrules)"
    else
        auditctl -R "${audit_rules}" 2>/dev/null || true
        log_ok "Audit-Regeln (geladen via auditctl)"
    fi

    log_info "Audit-Daemon abgeschlossen."
}

# ------------------------------------------------------------------------------
# 8. LOGGING UND ÜBERWACHUNG (CIS 4.2, Level 1)
# ------------------------------------------------------------------------------
harden_logging() {
    log_section "8. Logging und Überwachung"

    # CIS 4.2.1 - rsyslog konfigurieren (L1)
    log_step 1 5 "CIS 4.2.1: rsyslog konfigurieren"
    ensure_package "rsyslog"
    enable_and_start_service "rsyslog"

    # CIS 4.2.2 - syslog-ng statt rsyslog (L1)
    log_step 2 5 "CIS 4.2.2: syslog-ng prüfen"
    if package_installed "syslog-ng"; then
        log_info "syslog-ng ist installiert (alternative zu rsyslog)"
    else
        log_ok "rsyslog wird verwendet (Standard)"
    fi

    # CIS 4.2.3 - Log-Datei-Berechtigungen (L1)
    log_step 3 5 "CIS 4.2.3: Log-Datei-Berechtigungen"
    if [ -f /etc/rsyslog.conf ]; then
        backup_file /etc/rsyslog.conf
        # Log-Datei-Modus auf 0640 setzen
        if grep -q "^\\\$FileCreateMode" /etc/rsyslog.conf 2>/dev/null; then
            sed -i 's/^\\$FileCreateMode.*/\\$FileCreateMode 0640/' /etc/rsyslog.conf
        else
            echo "\$FileCreateMode 0640" >> /etc/rsyslog.conf
        fi
        log_ok "Log-Datei-Modus (0640)"
    fi
    if [ -f /etc/logrotate.conf ]; then
        backup_file /etc/logrotate.conf
        if grep -q "^create" /etc/logrotate.conf 2>/dev/null; then
            sed -i 's/^create.*/create 0640 root utmp/' /etc/logrotate.conf
        else
            echo "create 0640 root utmp" >> /etc/logrotate.conf
        fi
        log_ok "Logrotate-Konfiguration (create 0640)"
    fi

    # CIS 4.2.4 - Journald konfigurieren (L1)
    log_step 4 5 "CIS 4.2.4: journald konfigurieren"
    local journald_conf="/etc/systemd/journald.conf"
    if [ -f "${journald_conf}" ]; then
        backup_file "${journald_conf}"
        # Journal auf persistente Speicherung
        sed -i 's/^#*Storage=.*/Storage=persistent/' "${journald_conf}"
        sed -i 's/^#*Compress=.*/Compress=yes/' "${journald_conf}"
        sed -i 's/^#*SystemMaxUse=.*/SystemMaxUse=500M/' "${journald_conf}"
        sed -i 's/^#*MaxRetentionSec=.*/MaxRetentionSec=1month/' "${journald_conf}"
        sed -i 's/^#*ForwardToSyslog=.*/ForwardToSyslog=yes/' "${journald_conf}"
        log_ok "journald (persistent, compress=yes, max=500M, retention=1month)"
        systemctl restart systemd-journald 2>/dev/null || true
    fi

    # CIS 4.2.5 - Rsyslog sorgfältige Log-Konfiguration
    log_step 5 5 "CIS 4.2.5: Rsyslog-Log-Level konfigurieren"
    if [ -d /etc/rsyslog.d ]; then
        cat > /etc/rsyslog.d/50-cis-hardening.conf << 'EOC'
# CIS-Härtung: Logging-Konfiguration
# Auth-Meldungen separat loggen
auth,authpriv.*                 /var/log/auth.log
*.*;auth,authpriv.none          -/var/log/syslog
# Debug-Meldungen nicht in syslog
*.=debug;\
    auth,authpriv.none;\
    news.none;mail.none         -/var/log/debug
# Kernel-Meldungen
kern.*                          -/var/log/kern.log
# Cron-Meldungen
cron.*                         /var/log/cron.log
# Mail-Meldungen
mail.*                          -/var/log/mail.log
# Emergency-Meldungen an alle Benutzer
*.emerg                         :omusrmsg:*
EOC
        log_ok "Rsyslog-Log-Level (konfiguriert)"
        systemctl restart rsyslog 2>/dev/null || true
    fi

    log_info "Logging und Überwachung abgeschlossen."
}

# ------------------------------------------------------------------------------
# 9. FIREWALL (CIS 3.5, Level 1)
# ------------------------------------------------------------------------------
harden_firewall() {
    log_section "9. Firewall (nftables)"

    # CIS 3.5.1 - nftables installieren (L1)
    log_step 1 5 "CIS 3.5.1: nftables installieren"
    ensure_package "nftables"

    # CIS 3.5.2 - nftables Default-Deny-Policy (L1)
    log_step 2 5 "CIS 3.5.2: nftables Default-Deny-Policy"
    local nft_conf="/etc/nftables.conf"
    backup_file "${nft_conf}"

    cat > "${nft_conf}" << 'EOF'
#!/usr/sbin/nft -f

# CIS-Härtung: nftables Firewall
# Default-Deny-Policy für Input, Forward zulassen für ausgehende Verbindungen

flush ruleset

table inet cis_hardening {
    chain input {
        type filter hook input priority 0; policy drop;

        # Loopback-Schnittstelle zulassen
        iif lo accept

        # Bestehende Verbindungen zulassen
        ct state established,related accept

        # ICMP (ping) erlauben
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept

        # SSH (Port 22) nur bei Bedarf freigeben
        tcp dport 22 accept

        # Alles andere wird gedroppt (Default-Deny)
        log prefix "nftables-drop: " counter drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF
    log_ok "nftables-Regeln (Default-Deny-Policy, Loopback, SSH)"

    # CIS 3.5.3 - nftables aktivieren und starten (L1)
    log_step 3 5 "CIS 3.5.3: nftables aktivieren"
    # nftables-Dienst konfigurieren
    local nft_service="/etc/systemd/system/nftables.service.d"
    mkdir -p "${nft_service}"
    cat > "${nft_service}/override.conf" << 'EOF'
[Service]
ExecStart=
ExecStart=/usr/sbin/nft -f /etc/nftables.conf
EOF
    systemctl daemon-reload 2>/dev/null || true
    enable_and_start_service "nftables"

    # CIS 3.5.4 - Firewall-Regeln laden und testen (L1)
    log_step 4 5 "CIS 3.5.4: Firewall-Regeln testen"
    if nft -c -f "${nft_conf}" 2>/dev/null; then
        nft -f "${nft_conf}" 2>/dev/null || true
        log_ok "nftables-Regeln (geladen und aktiv)"
    else
        log_warn "nftables-Konfiguration enthält Fehler. Bitte prüfen."
    fi

    # Loopback-Schnittstelle prüfen (CIS 3.5.2 Bestandteil)
    log_step 5 5 "CIS 3.5.5: Loopback-Schnittstelle prüfen"
    # Sicherstellen, dass Loopback nicht gedroppt wird
    nft add rule inet cis_hardening input iif lo accept 2>/dev/null || true
    log_ok "Loopback-Schnittstelle (freigegeben)"

    log_info "Firewall-Konfiguration abgeschlossen."
    log_info "HINWEIS: nftables-Regeln können bei laufendem Betrieb SSH-Verbindungen trennen."
    log_info "Stelle sicher, dass eine alternative Zugriffsmöglichkeit existiert (z.B. IPMI, iDRAC)."
}

# ------------------------------------------------------------------------------
# 10. DIENST-HÄRTUNG (CIS 2, Level 1)
# ------------------------------------------------------------------------------
harden_services() {
    log_section "10. Dienst-Härtung"

    # CIS 2.1.1 - xinetd deaktivieren (L1)
    log_step 1 12 "CIS 2.1.1: xinetd deaktivieren"
    if package_installed "xinetd"; then
        apt-get remove -y xinetd >> "${LOG_FILE}" 2>&1 || true
        log_ok "xinetd (deinstalliert)"
    else
        log_ok "xinetd (nicht installiert)"
    fi

    # CIS 2.2.1 - NTP/Chrony konfigurieren (L1)
    log_step 2 12 "CIS 2.2.1: Zeitsynchronisation (chrony)"
    if package_installed "chrony"; then
        log_ok "chrony (bereits installiert)"
    elif package_installed "ntpsec" || package_installed "ntp"; then
        log_info "NTP ist installiert (alternativ zu chrony)."
    else
        ensure_package "chrony"
    fi
    enable_and_start_service "chrony" 2>/dev/null || enable_and_start_service "ntp" 2>/dev/null || true

    # CIS 2.2.2 - X11-Dienste deaktivieren (L1)
    log_step 3 12 "CIS 2.2.2: X11-Dienste deaktivieren"
    disable_service "gdm" 2>/dev/null || disable_service "gdm3" 2>/dev/null || true
    disable_service "lightdm" 2>/dev/null || true
    disable_service "sddm" 2>/dev/null || true
    log_ok "X11-Display-Manager (deaktiviert, sofern installiert)"

    # CIS 2.2.3 - Avahi-Daemon deaktivieren (L1)
    log_step 4 12 "CIS 2.2.3: Avahi-Daemon deaktivieren"
    disable_service "avahi-daemon"
    log_ok "Avahi-Daemon (deaktiviert)"

    # CIS 2.2.4 - CUPS deaktivieren (L1)
    log_step 5 12 "CIS 2.2.4: CUPS deaktivieren"
    disable_service "cups" 2>/dev/null || log_info "CUPS nicht installiert, überspringe."
    disable_service "cups-browsed" 2>/dev/null || true

    # CIS 2.2.5 - DHCP-Server deaktivieren (L1)
    log_step 6 12 "CIS 2.2.5: DHCP-Server deaktivieren"
    disable_service "isc-dhcp-server" 2>/dev/null || disable_service "dhcpd" 2>/dev/null || log_info "DHCP-Server nicht installiert, überspringe."

    # CIS 2.2.6 - DNS-Server deaktivieren (L1)
    log_step 7 12 "CIS 2.2.6: DNS-Server deaktivieren"
    disable_service "bind9" 2>/dev/null || log_info "BIND9 nicht installiert, überspringe."

    # CIS 2.2.7 - FTP-Server deaktivieren (L1)
    log_step 8 12 "CIS 2.2.7: FTP-Server deaktivieren"
    disable_service "vsftpd" 2>/dev/null || disable_service "proftpd" 2>/dev/null || log_info "FTP-Server nicht installiert, überspringe."

    # CIS 2.2.8 - HTTP-Server (falls nicht benötigt) (L1)
    log_step 9 12 "CIS 2.2.8: Apache2 / Nginx prüfen"
    if package_installed "apache2" || package_installed "nginx"; then
        log_info "Webserver ist installiert. Wird als aktiv angenommen."
        # Sicherheitshalber: unnötige Module deaktivieren
        if command -v a2dismod &>/dev/null; then
            a2dismod autoindex 2>/dev/null || true
            a2dismod status 2>/dev/null || true
            log_ok "Apache-Module: autoindex, status (deaktiviert falls vorhanden)"
        fi
    else
        log_ok "Webserver (nicht installiert)"
    fi

    # CIS 2.2.9 - IMAP/POP3 deaktivieren (L1)
    log_step 10 12 "CIS 2.2.9: IMAP/POP3 deaktivieren"
    disable_service "dovecot" 2>/dev/null || disable_service "cyrus" 2>/dev/null || log_info "Mailserver nicht installiert, überspringe."

    # CIS 2.2.10 - Samba deaktivieren (L1)
    log_step 11 12 "CIS 2.2.10: Samba deaktivieren"
    disable_service "smbd" 2>/dev/null || log_info "Samba nicht installiert, überspringe."

    # CIS 2.2.11 - SNMP deaktivieren (L1)
    log_step 12 12 "CIS 2.2.11: SNMP deaktivieren"
    disable_service "snmpd" 2>/dev/null || log_info "SNMP nicht installiert, überspringe."

    # CIS 2.2.12 - NIS deaktivieren (L1)
    if package_installed "nis"; then
        apt-get remove -y nis >> "${LOG_FILE}" 2>&1 || true
        log_ok "NIS (deinstalliert)"
    fi

    # CIS 2.2.13 - rsync-Dienst deaktivieren (L1)
    disable_service "rsync" 2>/dev/null || true
    log_ok "rsync-Dienst (deaktiviert, falls installiert)"

    log_info "Dienst-Härtung abgeschlossen."
}

# ------------------------------------------------------------------------------
# 11. APPARMOR (CIS 1.6, Level 2)
# ------------------------------------------------------------------------------
harden_apparmor() {
    log_section "11. AppArmor (L2)"

    # CIS 1.6.1 - AppArmor installieren (L2)
    log_step 1 4 "CIS 1.6.1 (L2): AppArmor installieren"
    ensure_package "apparmor"
    ensure_package "apparmor-profiles"
    ensure_package "apparmor-utils"

    # CIS 1.6.2 - AppArmor im Enforce-Modus (L2)
    log_step 2 4 "CIS 1.6.2 (L2): AppArmor im Enforce-Modus"
    local grub_cmdline=""
    if [ -f /etc/default/grub ]; then
        backup_file /etc/default/grub
        if ! grep -q "apparmor=1" /etc/default/grub 2>/dev/null; then
            sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor /' /etc/default/grub
            update-grub >> "${LOG_FILE}" 2>&1
            log_ok "AppArmor-Kernel-Parameter (apparmor=1 security=apparmor gesetzt)"
        else
            log_ok "AppArmor-Kernel-Parameter (bereits gesetzt)"
        fi
    fi

    # CIS 1.6.3 - Alle Profile in den Enforce-Modus versetzen (L2)
    log_step 3 4 "CIS 1.6.3 (L2): AppArmor-Profile in den Enforce-Modus"
    if command -v aa-enforce &>/dev/null; then
        # Prüfen ob Profile im Complain-Modus sind
        local complain_profiles
        complain_profiles=$(aa-status 2>/dev/null | grep "complain" || true)
        if [ -n "${complain_profiles}" ]; then
            aa-enforce /etc/apparmor.d/* 2>/dev/null || true
            log_ok "AppArmor-Profile (in Enforce-Modus versetzt)"
        else
            log_ok "AppArmor-Profile (bereits im Enforce-Modus)"
        fi
    else
        log_warn "aa-enforce nicht verfügbar. aa-status prüfen."
    fi

    # AppArmor-Status prüfen
    log_step 4 4 "CIS 1.6.3: AppArmor-Status prüfen"
    if command -v aa-status &>/dev/null; then
        aa-status 2>/dev/null | head -15 || true
    fi

    log_info "AppArmor-Konfiguration abgeschlossen (L2)."
    log_info "HINWEIS: Ein Neustart ist erforderlich, damit AppArmor-Kernel-Parameter wirksam werden."
}

# ------------------------------------------------------------------------------
# 12. KERNEL-MODULE SPERREN (CIS 1.1.1, Level 2)
# ------------------------------------------------------------------------------
harden_modules() {
    log_section "12. Kernel-Module sperren (L2)"

    local modprobe_d="/etc/modprobe.d"

    # CIS 1.1.1.1 - cramfs deaktivieren (L2)
    log_step 1 8 "CIS 1.1.1.1 (L2): cramfs deaktivieren"
    echo "install cramfs /bin/true" > "${modprobe_d}/cramfs.conf"
    log_ok "cramfs (gesperrt)"

    # CIS 1.1.1.2 - freevxfs deaktivieren (L2)
    log_step 2 8 "CIS 1.1.1.2 (L2): freevxfs deaktivieren"
    echo "install freevxfs /bin/true" > "${modprobe_d}/freevxfs.conf"
    log_ok "freevxfs (gesperrt)"

    # CIS 1.1.1.3 - jffs2 deaktivieren (L2)
    log_step 3 8 "CIS 1.1.1.3 (L2): jffs2 deaktivieren"
    echo "install jffs2 /bin/true" > "${modprobe_d}/jffs2.conf"
    log_ok "jffs2 (gesperrt)"

    # CIS 1.1.1.4 - hfs deaktivieren (L2)
    log_step 4 8 "CIS 1.1.1.4 (L2): hfs deaktivieren"
    echo "install hfs /bin/true" > "${modprobe_d}/hfs.conf"
    log_ok "hfs (gesperrt)"

    # CIS 1.1.1.5 - hfsplus deaktivieren (L2)
    log_step 5 8 "CIS 1.1.1.5 (L2): hfsplus deaktivieren"
    echo "install hfsplus /bin/true" > "${modprobe_d}/hfsplus.conf"
    log_ok "hfsplus (gesperrt)"

    # CIS 1.1.1.6 - squashfs deaktivieren (L2)
    log_step 6 8 "CIS 1.1.1.6 (L2): squashfs deaktivieren"
    echo "install squashfs /bin/true" > "${modprobe_d}/squashfs.conf"
    log_ok "squashfs (gesperrt)"

    # CIS 1.1.1.7 - udf deaktivieren (L2)
    log_step 7 8 "CIS 1.1.1.7 (L2): udf deaktivieren"
    echo "install udf /bin/true" > "${modprobe_d}/udf.conf"
    log_ok "udf (gesperrt)"

    # USB-Storage (bereits in harden_filesystem, hier zur Sicherheit)
    log_step 8 8 "CIS 1.1.23 (L2): USB-Storage (zusätzliche Sicherung)"
    echo "install usb-storage /bin/true" > "${modprobe_d}/usb-storage.conf"
    log_ok "USB-Storage (gesperrt, L2)"

    # Zusätzliche Kernel-Module sperren (empfohlen, nicht CIS)
    local extra_modules="firewire-core bluetooth btusb bnep rfcomm joydev"
    for mod in ${extra_modules}; do
        if ! grep -q "install ${mod}" "${modprobe_d}/${mod}.conf" 2>/dev/null; then
            echo "install ${mod} /bin/true" > "${modprobe_d}/${mod}.conf" 2>/dev/null || true
            log_ok "Kernel-Modul ${mod} (gesperrt, optional)"
        fi
    done

    log_info "Kernel-Module abgeschlossen (L2)."
}

# ------------------------------------------------------------------------------
# 13. SYSTEM-WARTUNG (CIS 6, Level 1)
# ------------------------------------------------------------------------------
harden_maintenance() {
    log_section "13. System-Wartung"

    # CIS 6.1.1 - Dateisystem-Berechtigungen prüfen (L1)
    log_step 1 10 "CIS 6.1.1: System-Datei-Berechtigungen prüfen"
    chmod 644 /etc/passwd 2>/dev/null || true
    chmod 644 /etc/group 2>/dev/null || true
    chmod 640 /etc/shadow 2>/dev/null || true
    chmod 640 /etc/gshadow 2>/dev/null || true
    chmod 644 /etc/shells 2>/dev/null || true
    chmod 644 /etc/issue 2>/dev/null || true
    chmod 644 /etc/issue.net 2>/dev/null || true
    log_ok "System-Datei-Berechtigungen (korrigiert)"

    # CIS 6.1.2 - /etc/passwd Inhalt prüfen (L1)
    log_step 2 10 "CIS 6.1.2: /etc/passwd auf leere Felder prüfen"
    local invalid_passwd
    invalid_passwd=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd 2>/dev/null || true)
    if [ -n "${invalid_passwd}" ]; then
        log_warn "Benutzer mit UID 0 (ausser root):"
        echo "${invalid_passwd}" | while read -r user; do
            log_warn "  -> ${user}"
        done
    else
        log_ok "UID-0-Prüfung (nur root hat UID 0)"
    fi

    # CIS 6.1.3 - Shadow-Passwörter prüfen (L1)
    log_step 3 10 "CIS 6.1.3: Shadow-Passwörter prüfen"
    local shadow_users
    shadow_users=$(awk -F: '($2 != "x" && $2 != "!" && $2 != "*" && $2 != "") {print $1}' /etc/passwd 2>/dev/null || true)
    if [ -n "${shadow_users}" ]; then
        log_warn "Benutzer ohne Shadow-Passwort:"
        echo "${shadow_users}" | while read -r user; do
            log_warn "  -> ${user}"
            passwd -l "${user}" 2>/dev/null || true
            log_ok "Benutzer ${user} (gesperrt)"
        done
    else
        log_ok "Shadow-Passwörter (alle Benutzer verwenden /etc/shadow)"
    fi

    # CIS 6.1.4 - World-Writable-Dateien prüfen (L1)
    log_step 4 10 "CIS 6.1.4: World-writable Dateien prüfen"
    local world_writable
    world_writable=$(df --local -P 2>/dev/null | awk '{if(NR>1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002 -print 2>/dev/null | head -20)
    if [ -n "${world_writable}" ]; then
        log_warn "World-writable Dateien gefunden:"
        echo "${world_writable}" | while read -r file; do
            log_warn "  -> ${file}"
        done
        log_info "Hinweis: World-writable Dateien sollten auf 755 oder 644 gesetzt werden."
    else
        log_ok "World-writable Dateien (keine gefunden)"
    fi

    # CIS 6.1.5 - Unbesetzte UID/GID prüfen (L1)
    log_step 5 10 "CIS 6.1.5: Unbesetzte UID/GID prüfen"
    local orphaned_files
    orphaned_files=$(df --local -P 2>/dev/null | awk '{if(NR>1) print $6}' | xargs -I '{}' find '{}' -xdev -nouser -print 2>/dev/null | head -20)
    if [ -n "${orphaned_files}" ]; then
        log_warn "Dateien ohne Besitzer gefunden:"
        echo "${orphaned_files}" | while read -r file; do
            log_warn "  -> ${file}"
        done
    else
        log_ok "Unbesetzte UID/GID (keine gefunden)"
    fi

    # CIS 6.1.6 - SUID/SGID-Dateien prüfen (L1)
    log_step 6 10 "CIS 6.1.6: SUID/SGID-Dateien prüfen"
    local suid_files
    suid_files=$(df --local -P 2>/dev/null | awk '{if(NR>1) print $6}' | xargs -I '{}' find '{}' -xdev \( -perm -4000 -o -perm -2000 \) -type f -print 2>/dev/null)
    local suid_count
    suid_count=$(echo "${suid_files}" | wc -l)
    log_info "SUID/SGID-Dateien gefunden: ${suid_count}"
    log_info "Hinweis: Liste der SUID/SGID-Dateien wird in /var/log/cis-harding-suid.log gespeichert."
    echo "${suid_files}" > /var/log/cis-hardening-suid.log 2>/dev/null || true

    # CIS 6.1.7 - Shadow-Gruppenmitgliedschaft prüfen (L1)
    log_step 7 10 "CIS 6.1.7: Shadow-Gruppenmitgliedschaft prüfen"
    local shadow_members
    shadow_members=$(grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group 2>/dev/null | cut -d: -f4 || true)
    if [ -n "${shadow_members}" ]; then
        log_warn "Benutzer in der Shadow-Gruppe: ${shadow_members}"
        log_info "Hinweis: Benutzer in der Shadow-Gruppe können /etc/shadow lesen."
    else
        log_ok "Shadow-Gruppe (keine Mitglieder ausser root)"
    fi

    # CIS 6.1.8 - Leere Passwortfelder (zusätzlich)
    log_step 8 10 "CIS 6.1.8: Leere Passwortfelder prüfen"
    local empty_shadow
    empty_shadow=$(awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null || true)
    if [ -n "${empty_shadow}" ]; then
        echo "${empty_shadow}" | while read -r user; do
            passwd -l "${user}" 2>/dev/null || true
            log_ok "Benutzer ${user} (gesperrt, leeres Passwort)"
        done
    else
        log_ok "Leere Passwortfelder (keine gefunden)"
    fi

    # CIS 6.2.1 - Root-Weg (L1)
    log_step 9 10 "CIS 6.2.1: Root-Umgebungsvariable prüfen"
    if echo "${PATH}" | grep -q "::\|\.:" 2>/dev/null; then
        log_warn "PATH enthält leere Einträge oder '.' (unsicher)"
    else
        log_ok "PATH (keine unsicheren Einträge)"
    fi

    # CIS 6.2.2 - Root-Heimatverzeichnis (L1)
    log_step 10 10 "CIS 6.2.2: Root-Heimatverzeichnis-Berechtigungen"
    chmod 750 /root 2>/dev/null || true
    log_ok "/root-Berechtigungen (750)"

    log_info "System-Wartung abgeschlossen."
}

# ==============================================================================
# TUI (WHIPTAIL-BASIERTE BENUTZEROBERFLÄCHE)
# ==============================================================================

# Textbasiertes Fallback-Menü (wird verwendet wenn whiptail nicht verfügbar ist).
# Verwendet bash-select und read für die Kategorieauswahl.
show_text_menu() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║     CIS-Härtung für Debian 13 (Trixie) — Textmodus          ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Verfügbare Kategorien (mit Leertaste auswählen, mit Enter bestätigen):"
    echo ""

    local sorted_keys
    sorted_keys=$(echo "${!CIS_CATEGORIES[@]}" | tr ' ' '\n' | sort)

    # Kategorien anzeigen
    local categories=("L1" "L1L2" "---")
    local category_names=("CIS Level 1 (alle Grundhärtungs-Massnahmen)" "CIS Level 1 + 2 (alle Massnahmen)" "──── Trennlinie ────")
    for key in ${sorted_keys}; do
        IFS='|' read -r id title level desc <<< "${CIS_CATEGORIES[$key]}"
        categories+=("${key}")
        category_names+=("${title} [${level}] - ${desc}")
    done

    local selected=()
    local done=false

    while [ "${done}" = false ]; do
        echo "  ┌─────────────────────────────────────────────────────────────┐"
        local idx=0
        for name in "${category_names[@]}"; do
            local tag="${categories[${idx}]}"
            local checked=" "
            for sel in "${selected[@]}"; do
                if [ "${sel}" = "${tag}" ]; then
                    checked="*"
                    break
                fi
            done
            printf "  │ %2d. [%s] %s\n" $((idx + 1)) "${checked}" "${name}"
            idx=$((idx + 1))
        done
        echo "  └─────────────────────────────────────────────────────────────┘"
        echo ""
        echo "  Nummer eingeben zum Umschalten, 'a' für alle L1, 'A' für alle L1+L2,"
        echo "  Enter zum Bestätigen, 'q' zum Abbrechen:"
        echo -n "  > "
        read -r input

        case "${input}" in
            q|Q)
                echo ""
                log_info "Härtung abgebrochen."
                exit 0
                ;;
            a)
                selected=()
                for key in ${sorted_keys}; do
                    IFS='|' read -r id title level desc <<< "${CIS_CATEGORIES[$key]}"
                    if [ "${level}" = "L1" ] || [ "${level}" = "L1+L2" ]; then
                        selected+=("${key}")
                    fi
                done
                echo "  → Alle CIS Level 1 Kategorien ausgewählt."
                ;;
            A)
                selected=()
                for key in ${sorted_keys}; do
                    selected+=("${key}")
                done
                echo "  → Alle Kategorien ausgewählt."
                ;;
            "")
                if [ ${#selected[@]} -eq 0 ]; then
                    echo "  → Keine Kategorien ausgewählt. Abgebrochen."
                    exit 0
                fi
                done=true
                ;;
            *)
                if [[ "${input}" =~ ^[0-9]+$ ]] && [ "${input}" -ge 1 ] && [ "${input}" -le "${#categories[@]}" ]; then
                    local tag_idx=$((input - 1))
                    local tag="${categories[${tag_idx}]}"
                    if [ "${tag}" = "---" ]; then
                        echo "  → Trennlinie kann nicht ausgewählt werden."
                        continue
                    fi
                    # Prüfen ob bereits ausgewählt
                    local found=false
                    local new_selected=()
                    for sel in "${selected[@]}"; do
                        if [ "${sel}" = "${tag}" ]; then
                            found=true
                            echo "  → '${category_names[${tag_idx}]}' abgewählt."
                        else
                            new_selected+=("${sel}")
                        fi
                    done
                    if [ "${found}" = false ]; then
                        new_selected+=("${tag}")
                        echo "  → '${category_names[${tag_idx}]}' ausgewählt."
                    fi
                    selected=("${new_selected[@]}")
                else
                    echo "  → Ungültige Eingabe."
                fi
                ;;
        esac
        echo ""
    done

    echo ""
    local summary=""
    local all_names=""
    for cat in "${selected[@]}"; do
        IFS='|' read -r id title level desc <<< "${CIS_CATEGORIES[$cat]}"
        summary="${summary}  - ${title} (${level})\n"
        all_names="${all_names} ${title},"
    done
    all_names="${all_names%,}"

    echo "Ausgewählte Bereiche:"
    echo -e "${summary}"
    echo -n "Fortfahren? (j/N): "
    read -r confirm
    if [ "${confirm:-n}" != "j" ] && [ "${confirm:-n}" != "J" ]; then
        log_info "Härtung abgebrochen."
        exit 0
    fi

    echo ""
    log_section "Härtung beginnt: ${all_names}"
    echo ""

    apply_selection "${selected[@]}"
}

# Zeigt die interaktive TUI zur Auswahl der Härtungskategorien.
# Die Auswahl wird als Array von Kategorie-IDs an apply_selection() übergeben.
show_tui() {
    # whiptail-Verfügbarkeit prüfen, bei Fehler textbasiertes Menü verwenden
    if ! check_whiptail; then
        show_text_menu
        return
    fi

    # Menüpunkte für whiptail --checklist
    # Zwei spezielle Vorauswahl-Optionen am Anfang der Liste
    # Format: "tag" "description" status
    local menu_items=()

    # Spezial-Option: L1 (alle CIS Level 1)
    menu_items+=("L1" "CIS Level 1 (alle Grundhärtungs-Massnahmen)" "OFF")
    # Spezial-Option: L1+L2 (alle Massnahmen)
    menu_items+=("L1L2" "CIS Level 1 + 2 (alle Massnahmen)" "OFF")
    # Trennlinie
    menu_items+=("---" "────────────────────────────────────────────────────" "OFF")

    # Einzelne Kategorien hinzufügen
    local sorted_keys
    sorted_keys=$(echo "${!CIS_CATEGORIES[@]}" | tr ' ' '\n' | sort)

    for key in ${sorted_keys}; do
        IFS='|' read -r id title level desc <<< "${CIS_CATEGORIES[$key]}"
        local level_label="[${level}]"
        menu_items+=("${key}" "${title} ${level_label} - ${desc}" "OFF")
    done

    # TUI anzeigen — mit dynamischer Grösse und Positionierung
    local selection
    selection=$(whiptail --title "CIS-Härtung für Debian 13 (Trixie)" \
            --backtitle "cis-hardening.sh - Automatisierte Systemhärtung" \
            --checklist \
            "Zu härtende Bereiche auswählen:\n\n(CIS Level 1 = Grundhärtung, Level 2 = Erweiterte Härtung)\nMit LEERTASTE auswählen, mit TAB zum Bestätigen wechseln." \
            40 110 24 \
            "${menu_items[@]}" \
            3>&1 1>&2 2>&3)

    local exit_code=$?
    if [ ${exit_code} -ne 0 ]; then
        echo ""
        log_info "TUI abgebrochen."
        exit 0
    fi

    # Auswahl parsen und in Array umwandeln
    # whiptail gibt quoted strings zurück: "filesystem" "network" ...
    local raw_selection=()
    eval "raw_selection=(${selection})"

    if [ ${#raw_selection[@]} -eq 0 ]; then
        whiptail --title "Keine Auswahl" \
            --msgbox "Es wurde kein Bereich ausgewählt.\n\nDie Härtung wird abgebrochen." 8 50
        log_info "Keine Bereiche ausgewählt. Abgebrochen."
        exit 0
    fi

    # Spezial-Optionen expandieren: "L1" → alle Kategorien mit Level 1
    # "L1L2" → alle Kategorien
    local selected_categories=()
    local has_l1=false
    local has_l1l2=false

    for item in "${raw_selection[@]}"; do
        case "${item}" in
            "L1")
                has_l1=true
                ;;
            "L1L2")
                has_l1l2=true
                ;;
            "---")
                # Trennlinie ignorieren
                ;;
            *)
                selected_categories+=("${item}")
                ;;
        esac
    done

    # Wenn L1L2 gewählt, alle Kategorien übernehmen
    if [ "${has_l1l2}" = true ]; then
        selected_categories=()
        for key in $(echo "${!CIS_CATEGORIES[@]}" | tr ' ' '\n' | sort); do
            selected_categories+=("${key}")
        done
    # Wenn nur L1 gewählt, alle Kategorien mit Level-1-Anteil übernehmen
    elif [ "${has_l1}" = true ]; then
        selected_categories=()
        for key in $(echo "${!CIS_CATEGORIES[@]}" | tr ' ' '\n' | sort); do
            IFS='|' read -r id title level desc <<< "${CIS_CATEGORIES[$key]}"
            # Kategorien einschliessen, die L1 oder L1+L2 sind
            if [ "${level}" = "L1" ] || [ "${level}" = "L1+L2" ]; then
                selected_categories+=("${key}")
            fi
        done
    fi

    # Bestätigungsdialog
    local summary=""
    local all_names=""
    for cat in "${selected_categories[@]}"; do
        IFS='|' read -r id title level desc <<< "${CIS_CATEGORIES[$cat]}"
        summary="${summary}  - ${title} (${level})\n"
        all_names="${all_names} ${title},"
    done
    all_names="${all_names%,}"

    if ! whiptail --title "Auswahl bestätigen" \
        --yesno "Folgende Bereiche werden gehärtet:\n\n${summary}\n\nFortfahren?" 20 60; then
        log_info "Härtung abgebrochen."
        exit 0
    fi

    echo ""
    log_section "Härtung beginnt: ${all_names}"
    echo ""

    # Auswahl anwenden
    apply_selection "${selected_categories[@]}"
}

# Führt die Härtung für die ausgewählten Kategorien aus.
# Argumente: Liste der Kategorie-IDs
apply_selection() {
    local selected=("$@")
    local total=${#selected[@]}
    local current=0

    for cat in "${selected[@]}"; do
        current=$((current + 1))
        case "${cat}" in
            filesystem)  harden_filesystem ;;
            updates)     harden_updates ;;
            bootloader)  harden_bootloader ;;
            network)     harden_network ;;
            auth)        harden_auth ;;
            ssh)         harden_ssh ;;
            audit)       harden_audit ;;
            logging)     harden_logging ;;
            firewall)    harden_firewall ;;
            services)    harden_services ;;
            apparmor)    harden_apparmor ;;
            modules)     harden_modules ;;
            maintenance) harden_maintenance ;;
            *)
                log_warn "Unbekannte Kategorie: ${cat}"
                ;;
        esac
        echo ""
    done

    # Abschlussmeldung
    log_section "Härtung abgeschlossen"
    log_info "Die Härtung wurde für ${total} Bereich(e) durchgeführt."
    log_info "Log-Datei: ${LOG_FILE}"
    log_info "Backups:   ${BACKUP_DIR}"
    log_info ""

    # Zusammenfassung der wichtigsten nächsten Schritte
    echo "=============================================================================="
    echo "  NÄCHSTE SCHRITTE"
    echo "=============================================================================="
    echo "  1. System neustarten, um alle Änderungen zu aktivieren:"
    echo "     sudo reboot"
    echo ""
    echo "  2. Nach dem Neustart: Wazuh SCA-Scan ausführen:"
    echo "     systemctl restart wazuh-agent"
    echo ""
    echo "  3. Wazuh-Dashboard prüfen: Configuration Assessment -> CIS Debian 13 Policy"
    echo ""
    echo "  4. Offene Punkte manuell prüfen:"
    echo "     - GRUB-Passwort (sofern gewünscht): grub-mkpasswd-pbkdf2"
    echo "     - AIDE-Datenbank: aideinit"
    echo "     - AppArmor-Profile: aa-status"
    echo "=============================================================================="
}

# ==============================================================================
# CLI-ARGUMENT-PARSING
# ==============================================================================

# Zeigt die Hilfe an.
show_help() {
    cat << 'HELP'
VERWENDUNG:
  cis-hardening.sh [OPTIONEN]...

OPTIONEN:
  -a, --all              Alle Härtungsmassnahmen anwenden (Level 1 + Level 2)
  -H, --headless         Headless-Modus (keine TUI, nur CLI-Parameter)
  -l, --list             Verfügbare Kategorien auflisten
  --dry-run, -n          Nur anzeigen, was gemacht würde (ohne Ausführung)
  -h, --help             Diese Hilfe anzeigen
  -o, --only LEVEL       Nur Level 1 oder Level 2 anwenden (z.B. --only L1)

KATEGORIEN (für Headless-Modus):
  --filesystem           Dateisystem-Härtung
  --updates              Paketquellen und Updates
  --bootloader           Bootloader-Sicherheit
  --network              Netzwerk-Parameter
  --auth                 Authentifizierung
  --ssh                  SSH-Server-Härtung
  --audit                Audit-Daemon
  --logging              Logging und Überwachung
  --firewall             Firewall (nftables)
  --services             Dienst-Härtung
  --apparmor             AppArmor (L2)
  --modules              Kernel-Module sperren (L2)
  --maintenance          System-Wartung

BEISPIELE:
  # Interaktive TUI (Standard)
  sudo ./cis-hardening.sh

  # In der TUI: L1 auswählen = alle CIS Level 1 Massnahmen
  # In der TUI: L1+L2 auswählen = alle Massnahmen (Level 1 + 2)

  # Alle Massnahmen ohne TUI anwenden
  sudo ./cis-hardening.sh --all --headless

  # Nur SSH + Netzwerk + Firewall ohne TUI
  sudo ./cis-hardening.sh --headless --ssh --network --firewall

  # Nur Level 1 Massnahmen
  sudo ./cis-hardening.sh --all --headless --only L1

  # Trockenlauf (zeigt nur an, was gemacht würde)
  sudo ./cis-hardening.sh --all --dry-run

HINWEIS:
  - Das Skript muss mit Root-Rechten ausgeführt werden.
  - Ein Backup aller geänderten Konfigurationsdateien wird erstellt.
  - Die Log-Datei befindet sich unter /var/log/cis-hardening.log.
  - Eine Wazuh SCA Policy (cis_debian_13.yml) ist für das Monitoring verfügbar.
HELP
}

# Zeigt die verfügbaren Kategorien an.
show_list() {
    echo "VERFÜGBARE KATEGORIEN:"
    echo "═══════════════════════════════════════════════════════════════"
    local sorted_keys
    sorted_keys=$(echo "${!CIS_CATEGORIES[@]}" | tr ' ' '\n' | sort)

    printf "  %-18s %-5s %-30s\n" "KATEGORIE" "LEVEL" "BESCHREIBUNG"
    echo "  ─────────────────────────────────────────────────────────"
    for key in ${sorted_keys}; do
        IFS='|' read -r id title level desc <<< "${CIS_CATEGORIES[$key]}"
        printf "  %-18s %-5s %s\n" "${key}" "${level}" "${desc}"
    done
    echo ""
    echo "VERWENDUNG:"
    echo "  sudo ./cis-hardening.sh --headless --ssh --network --firewall"
    echo "  sudo ./cis-hardening.sh --all --headless"
    echo "  sudo ./cis-hardening.sh (TUI)"
}

# Parst die Kommandozeilenargumente.
parse_args() {
    local args=("$@")

    # Standardwerte
    local headless=false
    local all=false
    local dry_run=false
    local only_level=""
    local selected_categories=()

    # Wenn keine Argumente, TUI starten
    if [ ${#args[@]} -eq 0 ]; then
        show_tui
        exit 0
    fi

    # Argumente parsen
    while [ ${#args[@]} -gt 0 ]; do
        case "${args[0]}" in
            -a|--all)
                all=true
                shift
                ;;
            -H|--headless)
                headless=true
                shift
                ;;
            -l|--list)
                show_list
                exit 0
                ;;
            -n|--dry-run)
                dry_run=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -o|--only)
                only_level="${args[1]:-}"
                if [ "${only_level}" != "L1" ] && [ "${only_level}" != "L2" ]; then
                    log_error "Ungültiges Level: ${only_level}. Erwartet: L1 oder L2."
                    exit 1
                fi
                shift 2
                ;;
            --filesystem|--updates|--bootloader|--network|--auth|--ssh)
                selected_categories+=("${args[0]#--}")
                shift
                ;;
            --audit|--logging|--firewall|--services|--apparmor|--modules|--maintenance)
                selected_categories+=("${args[0]#--}")
                shift
                ;;
            *)
                log_error "Unbekannte Option: ${args[0]}"
                echo "Verwendung: cis-hardening.sh --help"
                exit 1
                ;;
        esac
    done

    # Validierung
    if [ "${all}" = false ] && [ ${#selected_categories[@]} -eq 0 ] && [ "${headless}" = true ]; then
        log_error "Im Headless-Modus müssen Kategorien via --all oder einzeln angegeben werden."
        echo "Verwendung: cis-hardening.sh --help"
        exit 1
    fi

    # Kategorien bestimmen
    if [ "${all}" = true ]; then
        selected_categories=()
        for key in $(echo "${!CIS_CATEGORIES[@]}" | tr ' ' '\n' | sort); do
            # Level-Filter
            if [ -n "${only_level}" ]; then
                IFS='|' read -r id title level desc <<< "${CIS_CATEGORIES[$key]}"
                if [ "${level}" = "${only_level}" ] || [[ "${level}" == *"${only_level}"* ]]; then
                    selected_categories+=("${key}")
                fi
            else
                selected_categories+=("${key}")
            fi
        done
    fi

    # Trockenlauf
    if [ "${dry_run}" = true ]; then
        echo "TROCKENLAUF - Es werden keine Änderungen vorgenommen."
        echo "═══════════════════════════════════════════════════════════════"
        echo ""
        echo "Ausgewählte Kategorien:"
        for cat in "${selected_categories[@]}"; do
            IFS='|' read -r id title level desc <<< "${CIS_CATEGORIES[$cat]}"
            echo "  [${id}] ${title} (${level})"
            echo "         CIS-Referenzen: ${CIS_REFERENCES[$cat]}"
            echo "         ${desc}"
            echo ""
        done
        echo "Anzahl der zu prüfenden CIS-Regeln wird aus den Referenzen ermittelt..."
        local total_refs=0
        for cat in "${selected_categories[@]}"; do
            local refs="${CIS_REFERENCES[$cat]}"
            local count
            count=$(echo "${refs}" | tr ',' '\n' | wc -l)
            total_refs=$((total_refs + count))
        done
        echo "Gesamt: ${#selected_categories[@]} Kategorien, ~${total_refs} CIS-Regeln"
        exit 0
    fi

    # Härtung ausführen
    if [ "${headless}" = true ]; then
        apply_selection "${selected_categories[@]}"
    else
        show_tui
    fi
}

# ==============================================================================
# MAIN
# ==============================================================================
main() {
    # Voraussetzungen prüfen
    check_root
    check_os

    # Log-Verzeichnis erstellen
    mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null || true
    mkdir -p "${BACKUP_DIR}" 2>/dev/null || true

    # Log-Datei initialisieren
    echo "═══════════════════════════════════════════════════════════════" > "${LOG_FILE}"
    echo " CIS-Härtung für Debian 13 (Trixie)" >> "${LOG_FILE}"
    echo " Datum: $(date '+%Y-%m-%d %H:%M:%S')" >> "${LOG_FILE}"
    echo "═══════════════════════════════════════════════════════════════" >> "${LOG_FILE}"

    log_info "CIS-Härtung gestartet"
    log_info "System: $(uname -a)"
    log_info "Log-Datei: ${LOG_FILE}"

    # Argumente parsen
    parse_args "$@"

    log_info "CIS-Härtung beendet."
}

# Start
main "$@"