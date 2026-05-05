#!/bin/bash
#===============================================================================
# AUTONMAP v2.1.0 - The Silent Port Hunter
# Autor: N2O
# Descripción: Herramienta modular de reconocimiento de red TODO-EN-UNO.
#              Escanea puertos, detecta servicios, fingerprinting web,
#              enumeración SMB y genera reportes PDF profesionales.
# Uso: sudo ./autonmap <IP> [OPCIONES]
#===============================================================================

set -o pipefail
VERSION="2.1.0"
AUTONMAP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ============================================================================
# CONFIGURACIÓN POR DEFECTO
# ============================================================================
SCAN_RATE=5000
SMB_TIMEOUT=5
REPORT_HTTP_PORT=8080
DEFAULT_OUTPUT_DIR="./reports"
LOG_ENABLED=true
LOG_LEVEL="INFO"
FAST_MODE=false

# Detectar BINDIR según privilegios
if [ "$EUID" -eq 0 ]; then
    BINDIR="/usr/local/bin"
else
    BINDIR="$HOME/.local/bin"
fi

# ============================================================================
# COLORES ANSI
# ============================================================================
export CR=$'\033[1;31m'   CG=$'\033[1;32m'   CY=$'\033[1;33m'
export CB=$'\033[1;34m'   CM=$'\033[1;35m'   CC=$'\033[1;36m'
export CW=$'\033[1;37m'   CN=$'\033[0m'

log_info()    { echo -e "${CG}[+]${CN} $1"; }
log_warn()    { echo -e "${CY}[*]${CN} $1"; }
log_error()   { echo -e "${CR}[!]${CN} $1"; }
log_success() { echo -e "${CG}[✓]${CN} $1"; }
log_question(){ echo -e "${CB}[?]${CN} $1"; }
log_step()    { echo -e "${CM}[→]${CN} $1"; }
log_data()    { echo -e "${CC}[i]${CN} $1"; }
log_sep()     { echo -e "${CW}-------------------------------------------------------------${CN}"; }

# ============================================================================
# LOGGER
# ============================================================================
LOG_FILE=""
logger_init() {
    LOG_FILE="$1"
    if [ "$LOG_ENABLED" = true ] && [ -n "$LOG_FILE" ]; then
        mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null
        { echo "=== autonmap v${VERSION} - $(date) ==="; echo "Target: ${TARGET_IP:-N/A}"; echo "Usuario: $(whoami)"; echo "--------------------------------------------------"; } > "$LOG_FILE"
    fi
}
_log() { [ "$LOG_ENABLED" = true ] && [ -n "$LOG_FILE" ] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$1] $2" >> "$LOG_FILE"; }
logger_info()    { _log "INFO" "$1"; log_info "$1"; }
logger_warn()    { _log "WARN" "$1"; log_warn "$1"; }
logger_error()   { _log "ERROR" "$1"; log_error "$1"; }
logger_success() { _log "OK" "$1"; log_success "$1"; }
logger_step()    { _log "STEP" "$1"; log_step "$1"; }
logger_cmd()     { _log "CMD" "$1"; }
logger_close()   { [ "$LOG_ENABLED" = true ] && [ -n "$LOG_FILE" ] && { echo "=== Sesión finalizada: $(date) ===" >> "$LOG_FILE"; }; }

# ============================================================================
# VALIDACIONES
# ============================================================================
check_root() {
    [ "$EUID" -ne 0 ] && { log_error "Ejecuta como root: sudo autonmap <IP>"; return 1; }
    log_success "Permisos de root OK"
    return 0
}

validate_ip() {
    local ip="$1"
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        IFS='.' read -ra oct <<< "$ip"
        for o in "${oct[@]}"; do [[ "$o" =~ ^[0-9]+$ ]] && [ "$o" -gt 255 ] && { log_error "Octeto fuera de rango: $o"; return 1; }; done
    elif [[ ! "$ip" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$ ]]; then
        log_error "IP o hostname inválido: $ip"; return 1
    fi
    log_success "Target válido: $ip"; return 0
}

# CORREGIDO: verifica solo comandos en PATH
check_cmd() { command -v "$1" &>/dev/null; }

check_deps() {
    local missing=()
    for dep in "$@"; do check_cmd "$dep" || missing+=("$dep"); done
    if [ ${#missing[@]} -gt 0 ]; then log_warn "Faltan: ${missing[*]}"; return 1; fi
    return 0
}

check_core_deps() {
    logger_step "Verificando dependencias..."
    if ! check_deps nmap grep cut paste; then
        log_error "Instala: sudo apt install nmap"; return 1
    fi
    log_success "Dependencias del núcleo: OK"; return 0
}

validate_all() {
    local ip="$1"
    log_sep; logger_step "Validaciones previas..."; log_sep
    check_root || return 1
    validate_ip "$ip" || return 1
    check_core_deps || return 1
    log_success "Todas las validaciones pasaron"; log_sep; return 0
}

# ============================================================================
# UTILIDADES
# ============================================================================
ask_user() {
    local prompt="$1"; local default="${2:-n}"
    [ "$INTERACTIVE" = false ] && { [[ "$default" =~ ^[sSyY]$ ]] && return 0 || return 1; }
    [ "$FULL_MODE" = true ] && return 0
    log_question "$prompt [s/N]"; read -r r; [[ "$r" =~ ^[sSyY]$ ]]
}

maybe_sleep() {
    [ "$FAST_MODE" != true ] && sleep "$1"
}

# ============================================================================
# BANNER
# ============================================================================
show_banner() {
    echo -e "${CG}   █████╗ ██╗   ██╗████████╗ ██████╗ ███╗   ██╗███╗   ███╗ █████╗ ██████╗ "
    echo -e "${CG}  ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗████╗  ██║████╗ ████║██╔══██╗██╔══██╗"
    echo -e "${CY}  ███████║██║   ██║   ██║   ██║   ██║██╔██╗ ██║██╔████╔██║███████║██████╔╝"
    echo -e "${CR}  ██╔══██║██║   ██║   ██║   ██║   ██║██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝ "
    echo -e "${CR}  ██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║ ╚████║██║ ╚═╝ ██║██║  ██║██║     "
    echo -e "${CR}  ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ${CN}"
    echo ""
    echo -e "${CC}                    ⚡ The Silent Port Hunter ⚡${CN}"
    echo -e "${CW}                                N2O${CN}"
    echo -e "${CW}                                v${VERSION}${CN}"
    echo "-------------------------------------------------------------"
    echo ""
}

# ============================================================================
# AYUDA
# ============================================================================
show_help() {
    show_banner
    echo -e "${CB}USO:${CN}  sudo ./autonmap <IP> [OPCIONES]"
    echo ""
    echo -e "${CB}OPCIONES:${CN}"
    echo -e "  ${CG}-h${CN}                Mostrar esta ayuda"
    echo -e "  ${CG}-V${CN}                Mostrar versión"
    echo -e "  ${CG}-o <directorio>${CN}   Directorio de salida (default: ./reports)"
    echo -e "  ${CG}-f${CN}                Modo completo (sin preguntas)"
    echo -e "  ${CG}-r <rate>${CN}         Rate mínimo de escaneo (default: 5000)"
    echo -e "  ${CG}-n${CN}                No verificar conectividad"
    echo -e "  ${CG}--fast${CN}            Modo rápido (sin pausas entre etapas)"
    echo -e "  ${CG}--which-system <path>${CN} Ruta al script whichSystem.py"
    echo -e "  ${CG}--no-web${CN}          Saltar WhatWeb"
    echo -e "  ${CG}--no-smb${CN}          Saltar enumeración SMB"
    echo -e "  ${CG}--no-report${CN}       No generar reportes"
    echo -e "  ${CG}--no-interactive${CN}  Sin preguntas"
    echo -e "  ${CG}--pdf${CN}             Generar reporte PDF profesional"
    echo -e "  ${CG}--pdf-only${CN}        Solo PDF (automático, sin preguntas)"
    echo -e "  ${CG}--title <texto>${CN}   Título para el PDF"
    echo -e "  ${CG}--author <texto>${CN}  Autor para el PDF"
    echo ""
    echo -e "${CB}EJEMPLOS:${CN}"
    echo -e "  sudo ./autonmap 192.168.1.1"
    echo -e "  sudo ./autonmap 192.168.1.1 -f --fast"
    echo -e "  sudo ./autonmap 192.168.1.1 --pdf-only --which-system ~/tools/whichSystem.py"
    echo ""
    echo -e "${CB}FLUJO:${CN}"
    echo -e "  1. Validación → 2. OS → 3. Scan puertos → 4. Servicios →"
    echo -e "  5. Reportes (HTML/PDF) → 6. WhatWeb → 7. SMB"
    echo ""
}

# ============================================================================
# DETECCIÓN DE OS
# ============================================================================
detect_os() {
    local target="$1"
    log_sep; logger_step "Detectando SO del target..."

    local ws_cmd=""
    if [ -n "$WHICH_SYSTEM_PATH" ]; then
        if [ -f "$WHICH_SYSTEM_PATH" ] && [ -x "$WHICH_SYSTEM_PATH" ]; then
            ws_cmd="$WHICH_SYSTEM_PATH"
        else
            log_warn "whichSystem.py no encontrado en la ruta: $WHICH_SYSTEM_PATH"
        fi
    fi
    [ -z "$ws_cmd" ] && command -v whichSystem.py &>/dev/null && ws_cmd="whichSystem.py"
    if [ -z "$ws_cmd" ] && [ -f "$AUTONMAP_DIR/whichSystem.py" ]; then
        ws_cmd="$AUTONMAP_DIR/whichSystem.py"
    fi

    if [ -n "$ws_cmd" ]; then
        local r; r=$("$ws_cmd" "$target" 2>/dev/null)
        if [ $? -eq 0 ] && [ -n "$r" ]; then
            log_info "OS detectado: ${CB}$r${CN}"
            return 0
        fi
    fi
    log_warn "whichSystem.py no disponible. Saltando detección de OS."
    return 1
}

# ============================================================================
# MÓDULO: ESCANEO DE PUERTOS
# ============================================================================
scan_all_ports() {
    local target="$1"
    PORT_SCAN_FILE="${OUTPUT_DIR}/allPorts_${target}.gnmap"
    OPEN_PORTS_FILE="${OUTPUT_DIR}/p_${target}.txt"
    OPEN_PORTS=""

    log_sep; logger_info "Escaneando todos los puertos..."
    logger_cmd "nmap -p- -sS --min-rate $SCAN_RATE --open -vvv -n -Pn $target -oG $PORT_SCAN_FILE"

    if nmap -p- -sS --min-rate "$SCAN_RATE" --open -vvv -n -Pn "$target" -oG "$PORT_SCAN_FILE"; then
        logger_success "Escaneo completado: $PORT_SCAN_FILE"
        OPEN_PORTS=$(grep -oP '\d+/open' "$PORT_SCAN_FILE" 2>/dev/null | cut -d'/' -f1 | paste -sd ',')
        if [ -z "$OPEN_PORTS" ]; then log_warn "No se encontraron puertos abiertos"; return 1; fi
        log_data "Puertos: ${CR}$OPEN_PORTS${CN}"
        echo "$OPEN_PORTS" > "$OPEN_PORTS_FILE"
        log_success "Puertos guardados: $OPEN_PORTS_FILE"
        return 0
    else
        log_error "Escaneo falló"; return 1
    fi
}

# ============================================================================
# MÓDULO: ESCANEO DE SERVICIOS (ÚNICO -oA)
# ============================================================================
run_service_scan() {
    local target="$1"; local ports="$2"
    SERVICE_BASE="${OUTPUT_DIR}/services_${target}"
    SERVICE_NORMAL="${SERVICE_BASE}.nmap"
    SERVICE_XML="${SERVICE_BASE}.xml"

    log_sep; logger_info "Detectando versiones/servicios..."
    logger_cmd "nmap -sCV -p$ports $target -oA $SERVICE_BASE"

    if nmap -sCV -p"$ports" "$target" -oA "$SERVICE_BASE"; then
        logger_success "Servicios detectados: $SERVICE_NORMAL"
        return 0
    else
        log_error "Escaneo de servicios falló"; return 1
    fi
}

detect_services() {
    if [ -f "$SERVICE_NORMAL" ]; then
        log_data "Resultados del escaneo de servicios:"
        echo -e "${CM}--- Primeros 50 líneas del reporte ---${CN}"
        head -n 50 "$SERVICE_NORMAL"
        echo -e "${CM}... (archivo completo en $SERVICE_NORMAL)${CN}"
        return 0
    else
        log_error "Archivo de servicios no encontrado"
        return 1
    fi
}

# ============================================================================
# MÓDULO: REPORTES HTML
# ============================================================================
generate_html_report() {
    local xml_file="$1"; local html_file="$2"
    local xsl=""
    for p in /usr/share/nmap/nmap.xsl /usr/local/share/nmap/nmap.xsl; do [ -f "$p" ] && xsl="$p" && break; done

    if [ -n "$xsl" ]; then
        logger_step "Generando HTML (xsltproc)..."
        if xsltproc "$xsl" "$xml_file" -o "$html_file" 2>/dev/null; then
            logger_success "HTML generado: $html_file"; return 0
        fi
    fi
    logger_step "Generando HTML alternativo..."

    local tname tdate
    tname=$(grep -oP 'hostname name="\K[^"]+' "$xml_file" 2>/dev/null | head -1)
    tdate=$(grep -oP 'startstr="\K[^"]+' "$xml_file" 2>/dev/null | head -1)
    [ -z "$tname" ] && tname="Target"
    [ -z "$tdate" ] && tdate=$(date)

    local rows=""
    while IFS= read -r line; do
        local pid pst psvc pprod pver
        pid=$(echo "$line" | grep -oP 'portid="\K[^"]+')
        pst=$(echo "$line" | grep -oP 'state="\K[^"]+')
        psvc=$(echo "$line" | grep -oP 'name="\K[^"]+')
        pprod=$(echo "$line" | grep -oP 'product="\K[^"]+')
        pver=$(echo "$line" | grep -oP 'version="\K[^"]+')
        [ -z "$pst" ] && continue
        local sc="#e74c3c"; [ "$pst" = "open" ] && sc="#2ecc71"
        rows+="<tr><td>$pid</td><td style='color:$sc;font-weight:bold'>$pst</td><td>${psvc:-N/A}</td><td>${pprod:-N/A}</td><td>${pver:-N/A}</td></tr>"
    done < <(grep '<port ' "$xml_file" 2>/dev/null)

    cat > "$html_file" <<HTMLEOF
<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"><title>autonmap - Reporte</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#1a1a2e,#16213e);color:#e0e0e0;min-height:100vh;padding:2rem}
.container{max-width:1000px;margin:0 auto}.header{text-align:center;padding:2rem;margin-bottom:2rem;background:rgba(255,255,255,.05);border-radius:12px;border:1px solid rgba(255,255,255,.1)}
.header h1{font-size:2.5rem;margin-bottom:.5rem;background:linear-gradient(90deg,#e94560,#0f3460);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.header .sub{color:#888;font-size:1.1rem}.ig{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:2rem}
.ic{background:rgba(255,255,255,.05);padding:1.5rem;border-radius:8px;border:1px solid rgba(255,255,255,.1)}.ic h3{color:#e94560;margin-bottom:.5rem}
table{width:100%;border-collapse:collapse;background:rgba(255,255,255,.03);border-radius:8px;overflow:hidden}
th{background:rgba(233,69,96,.2);padding:1rem;text-align:left;color:#e94560;font-weight:600}
td{padding:.75rem 1rem;border-bottom:1px solid rgba(255,255,255,.05)}tr:hover{background:rgba(255,255,255,.05)}
.ft{text-align:center;margin-top:2rem;color:#666;font-size:.9rem}</style></head><body>
<div class="container"><div class="header"><h1>AUTONMAP</h1><p class="sub">Reporte de Escaneo</p></div>
<div class="ig"><div class="ic"><h3>Target</h3><p style="font-size:1.2rem">${tname}</p></div>
<div class="ic"><h3>Fecha</h3><p style="font-size:1.2rem">${tdate}</p></div></div>
<table><thead><tr><th>Puerto</th><th>Estado</th><th>Servicio</th><th>Producto</th><th>Versión</th></tr></thead>
<tbody>${rows}</tbody></table><div class="ft"><p>Generado por <strong>autonmap</strong> by N2O</p></div></div></body></html>
HTMLEOF
    logger_success "HTML generado: $html_file"; return 0
}

serve_report() {
    local html_file="$1"; local port="${2:-8080}"
    [ ! -f "$html_file" ] && { log_error "HTML no encontrado"; return 1; }
    local dir; dir=$(dirname "$html_file"); cd "$dir" || return 1

    log_info "Sirviendo en http://localhost:$port/$(basename "$html_file")"
    log_info "Ctrl+C para detener"

    python3 -m http.server "$port" &
    local pid=$!
    trap "kill $pid 2>/dev/null; wait $pid 2>/dev/null; log_success 'Servidor detenido'" INT
    wait $pid
}

# ============================================================================
# MÓDULO: REPORTE PDF (CORREGIDO PARA SUDO Y ENTORNOS VIRTUALES)
# ============================================================================
generate_pdf_report() {
    local xml_file="$1"; local pdf_file="$2"; local title="${3:-autonmap - Reporte de Escaneo}"; local author="${4:-autonmap by N2O}"

    [ ! -f "$xml_file" ] && { log_error "XML no encontrado: $xml_file"; return 1; }

    if ! command -v python3 &>/dev/null; then
        log_error "python3 no instalado"; return 1
    fi

    # ---------------------------------------------------------------------
    # Localizar autonmap_pdf.py
    # ---------------------------------------------------------------------
    local shared_dir=""
    if [ "$EUID" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
        local user_home
        user_home=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)
        if [ -n "$user_home" ] && [ -f "$user_home/.local/share/autonmap/autonmap_pdf.py" ]; then
            shared_dir="$user_home/.local/share/autonmap"
        fi
    fi
    if [ -z "$shared_dir" ] && [ -f "$AUTONMAP_DIR/autonmap_pdf.py" ]; then
        shared_dir="$AUTONMAP_DIR"
    fi
    if [ -z "$shared_dir" ] && [ -f "$HOME/.local/share/autonmap/autonmap_pdf.py" ]; then
        shared_dir="$HOME/.local/share/autonmap"
    fi
    if [ -z "$shared_dir" ] && [ -f "/usr/local/share/autonmap/autonmap_pdf.py" ]; then
        shared_dir="/usr/local/share/autonmap"
    fi

    if [ -z "$shared_dir" ]; then
        log_error "No se encontró autonmap_pdf.py. Revisa la instalación."
        return 1
    fi

    local python_script="${shared_dir}/autonmap_pdf.py"

    # ---------------------------------------------------------------------
    # Buscar el intérprete adecuado (venv creado por install.sh o uno temporal)
    # ---------------------------------------------------------------------
    local venv_python=""
    # 1. Buscar venv en el home del usuario original (sudo)
    if [ "$EUID" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
        local user_home
        user_home=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)
        for candidate in \
            "$user_home/.local/pipx/venvs/reportlab/bin/python3" \
            "$user_home/.local/share/autonmap/venv/bin/python3"; do
            if [ -x "$candidate" ]; then
                venv_python="$candidate"; break
            fi
        done
    fi
    # 2. Buscar en el home del usuario actual
    if [ -z "$venv_python" ]; then
        for candidate in \
            "$HOME/.local/pipx/venvs/reportlab/bin/python3" \
            "$HOME/.local/share/autonmap/venv/bin/python3" \
            "/usr/local/share/autonmap/venv/bin/python3"; do
            if [ -x "$candidate" ]; then
                venv_python="$candidate"; break
            fi
        done
    fi
    # 3. Buscar en el mismo shared_dir
    if [ -z "$venv_python" ] && [ -x "$shared_dir/venv/bin/python3" ]; then
        venv_python="$shared_dir/venv/bin/python3"
    fi

    # Si no se encuentra ningún venv, crear uno automáticamente en shared_dir
    if [ -z "$venv_python" ]; then
        local auto_venv="$shared_dir/venv"
        if [ ! -d "$auto_venv" ]; then
            log_warn "Creando entorno virtual en $auto_venv (esto puede tardar unos segundos)..."
            python3 -m venv "$auto_venv" 2>/dev/null || { log_error "No se pudo crear venv"; return 1; }
            "$auto_venv/bin/pip" install --upgrade pip &>/dev/null
            "$auto_venv/bin/pip" install reportlab &>/dev/null || { log_error "No se pudo instalar reportlab"; return 1; }
        fi
        if [ -x "$auto_venv/bin/python3" ]; then
            venv_python="$auto_venv/bin/python3"
        else
            log_error "El entorno virtual no es válido."
            return 1
        fi
    fi

    local cmd=("$venv_python" "$python_script" -x "$xml_file" -o "$pdf_file" -t "$title" --author "$author")

    log_sep; logger_step "Generando PDF profesional..."
    logger_cmd "${cmd[*]}"

    if "${cmd[@]}"; then
        logger_success "PDF generado: $pdf_file"
        [ -f "$pdf_file" ] && log_data "Tamaño: $(du -h "$pdf_file" | cut -f1)"
        return 0
    else
        log_error "PDF falló"
        return 1
    fi
}

# ============================================================================
# MÓDULO: FINGERPRINTING WEB
# ============================================================================
web_fingerprint_full() {
    local target="$1"
    log_sep; logger_info "=== Fingerprinting Web ==="

    if ! command -v whatweb &>/dev/null; then
        log_warn "WhatWeb no instalado (opcional). Instala: sudo apt install whatweb"; return 1
    fi

    logger_step "WhatWeb básico..."
    whatweb "$target" && logger_success "WhatWeb básico OK"
    echo ""; maybe_sleep 2
    logger_step "WhatWeb verbose..."
    whatweb "$target" -v && logger_success "WhatWeb verbose OK"
}

# ============================================================================
# MÓDULO: ENUMERACIÓN SMB
# ============================================================================
smb_enum_full() {
    local target="$1"; local ports="$2"
    log_sep; logger_info "=== Enumeración SMB ==="

    if ! echo ",$ports," | grep -q ",445,"; then
        log_warn "Puerto 445 (SMB) no abierto. Saltando."; return 1
    fi

    if command -v netexec &>/dev/null; then
        logger_step "netexec SMB (sesión nula)..."
        logger_cmd "netexec smb $target -u '' -p '' --verbose --timeout $SMB_TIMEOUT"
        netexec smb "$target" -u '' -p '' --verbose --timeout "$SMB_TIMEOUT" && logger_success "netexec OK"
    else
        log_warn "netexec no instalado. Instala: sudo apt install netexec"
        if ask_user "¿Instalar netexec ahora?" "n"; then
            sudo apt install netexec -y && netexec smb "$target" -u '' -p '' --verbose --timeout "$SMB_TIMEOUT"
        fi
    fi

    echo ""; maybe_sleep 2

    if command -v smbclient &>/dev/null; then
        logger_step "smbclient (sesión anónima)..."
        logger_cmd "smbclient -L $target -N"
        smbclient -L "$target" -N && logger_success "smbclient OK"
    else
        log_warn "smbclient no instalado. Instala: sudo apt install smbclient"
    fi
}

# ============================================================================
# PARSEO DE ARGUMENTOS
# ============================================================================
TARGET_IP=""
OUTPUT_DIR=""
SKIP_CONNECTIVITY=false
INTERACTIVE=true
FULL_MODE=false
SKIP_WEB=false
SKIP_SMB=false
SKIP_REPORT=false
GEN_PDF=false
PDF_ONLY=false
PDF_TITLE="autonmap - Reporte de Escaneo"
PDF_AUTHOR="autonmap by N2O"
WHICH_SYSTEM_PATH=""

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help) show_help; exit 0 ;;
            -V|--version) echo "autonmap v${VERSION}"; exit 0 ;;
            -o) OUTPUT_DIR="$2"; shift 2 ;;
            -f|--full) FULL_MODE=true; INTERACTIVE=false; shift ;;
            -r) SCAN_RATE="$2"; shift 2 ;;
            -n|--no-ping) SKIP_CONNECTIVITY=true; shift ;;
            --fast) FAST_MODE=true; shift ;;
            --which-system) WHICH_SYSTEM_PATH="$2"; shift 2 ;;
            --no-web) SKIP_WEB=true; shift ;;
            --no-smb) SKIP_SMB=true; shift ;;
            --no-report) SKIP_REPORT=true; shift ;;
            --no-interactive) INTERACTIVE=false; shift ;;
            --pdf) GEN_PDF=true; shift ;;
            --pdf-only) GEN_PDF=true; PDF_ONLY=true; INTERACTIVE=false; SKIP_WEB=true; SKIP_SMB=true; shift ;;
            --title) PDF_TITLE="$2"; shift 2 ;;
            --author) PDF_AUTHOR="$2"; shift 2 ;;
            -*) log_error "Opción desconocida: $1"; echo "Usa -h para ayuda"; exit 1 ;;
            *)
                if [ -z "$TARGET_IP" ]; then TARGET_IP="$1"
                else log_error "Demasiados argumentos"; exit 1; fi
                shift ;;
        esac
    done
}

# ============================================================================
# MAIN
# ============================================================================
main() {
    parse_args "$@"
    show_banner

    [ -z "$TARGET_IP" ] && {
        log_error "No se proporcionó IP."
        echo -e "Uso: ${CG}sudo ./autonmap <IP> [OPCIONES]${CN}"
        echo -e "Usa ${CG}-h${CN} para ayuda"
        exit 1
    }

    OUTPUT_DIR="${OUTPUT_DIR:-$DEFAULT_OUTPUT_DIR}"
    OUTPUT_DIR="${OUTPUT_DIR%/}"
    mkdir -p "$OUTPUT_DIR"

    LOG_FILE="${OUTPUT_DIR}/autonmap_${TARGET_IP}_$(date +%Y%m%d_%H%M%S).log"
    logger_init "$LOG_FILE"

    validate_all "$TARGET_IP" || exit 1

    # FASE 1: OS
    detect_os "$TARGET_IP"; maybe_sleep 2

    # FASE 2: Puertos
    if ! scan_all_ports "$TARGET_IP"; then
        log_error "Escaneo falló"; logger_close; exit 1
    fi
    [ -z "$OPEN_PORTS" ] && { log_error "Sin puertos abiertos"; logger_close; exit 1; }
    maybe_sleep 3

    # FASE 3: Servicios
    if ! run_service_scan "$TARGET_IP" "$OPEN_PORTS"; then
        log_error "Escaneo de servicios falló"; logger_close; exit 1
    fi
    detect_services
    maybe_sleep 3

    # FASE 4: Reportes
    if [ "$SKIP_REPORT" != true ]; then
        if [ "$GEN_PDF" = true ]; then
            local xml="${SERVICE_XML}"
            [ ! -f "$xml" ] && { log_error "XML no encontrado"; logger_close; exit 1; }
            local pdf="${OUTPUT_DIR}/autonmap_report_${TARGET_IP}.pdf"
            generate_pdf_report "$xml" "$pdf" "$PDF_TITLE" "$PDF_AUTHOR"
            if [ -f "$pdf" ]; then
                echo -e "${CG}═════════════════════════════════════════════${CN}"
                echo -e "${CG}   PDF GENERADO EXITOSAMENTE${CN}"
                echo -e "${CG}═════════════════════════════════════════════${CN}"
                echo -e "${CW}  Archivo: ${CC}$pdf${CN}"
            fi
            maybe_sleep 2
        else
            if ask_user "¿Generar reporte XML + HTML?" "s"; then
                local h="${OUTPUT_DIR}/index.html"
                generate_html_report "$SERVICE_XML" "$h"
                if ask_user "¿Servir HTML en localhost?" "n"; then
                    serve_report "$h" "$REPORT_HTTP_PORT"
                fi
            fi
            maybe_sleep 3
        fi
    fi

    # FASE 5: WhatWeb
    if [ "$SKIP_WEB" != true ]; then
        if ask_user "¿Ejecutar WhatWeb?" "n"; then
            web_fingerprint_full "$TARGET_IP"
        fi
        maybe_sleep 3
    fi

    # FASE 6: SMB
    if [ "$SKIP_SMB" != true ]; then
        log_sep
        log_info "Puedes ejecutar netexec y smbclient (requiere puerto 445)"
        if ask_user "¿Enumerar SMB?" "n"; then
            smb_enum_full "$TARGET_IP" "$OPEN_PORTS"
        fi
    fi

    # ==============================
    # Ajustar permisos para el usuario original (si se ejecutó con sudo)
    # ==============================
    if [ -n "${SUDO_USER:-}" ]; then
        log_step "Ajustando permisos..."
        chown -R "$SUDO_USER":"$SUDO_USER" "$OUTPUT_DIR" 2>/dev/null
        # También ajustamos el archivo de log (que está dentro de $OUTPUT_DIR)
        log_success "Los archivos ahora pertenecen a $SUDO_USER"
    fi

    # RESUMEN
    log_sep
    echo -e "${CG}╔══════════════════════════════════════════╗${CN}"
    echo -e "${CG}║        ESCANEO COMPLETADO                ║${CN}"
    echo -e "${CG}╠══════════════════════════════════════════╣${CN}"
    echo -e "${CG}║ Target:  ${CW}$TARGET_IP${CN}"
    echo -e "${CG}║ Puertos: ${CR}$OPEN_PORTS${CN}"
    echo -e "${CG}║ Output:  ${CW}$OUTPUT_DIR${CN}"
    echo -e "${CG}║ Log:     ${CW}$LOG_FILE${CN}"
    if [ "$GEN_PDF" = true ] && [ -f "${OUTPUT_DIR}/autonmap_report_${TARGET_IP}.pdf" ]; then
        echo -e "${CG}║ PDF:     ${CC}${OUTPUT_DIR}/autonmap_report_${TARGET_IP}.pdf${CN}"
    fi
    echo -e "${CG}╚══════════════════════════════════════════╝${CN}"
    log_sep

    logger_close
    exit 0
}

main "$@"