#!/bin/bash
# ============================================================================
# INSTALL.SH - Instalador de autonmap v2.1.0
# ============================================================================
set -euo pipefail

VERSION="2.1.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

R='\033[1;31m'   G='\033[1;32m'   Y='\033[1;33m'
B='\033[1;34m'   C='\033[0;36m'   N='\033[0m'

info()    { echo -e "${G}[+]${N} $1"; }
warn()    { echo -e "${Y}[*]${N} $1"; }
error()   { echo -e "${R}[!]${N} $1"; }
step()    { echo -e "${B}[→]${N} $1"; }
success() { echo -e "${G}[✓]${N} $1"; }
question(){ echo -e "${C}[?]${N} $1"; }

# Detectar privilegios
if [ "$EUID" -eq 0 ]; then
    PREFIX="/usr/local"
    BINDIR="${PREFIX}/bin"
    SHAREDIR="${PREFIX}/share/autonmap"
else
    PREFIX="$HOME/.local"
    BINDIR="${PREFIX}/bin"
    SHAREDIR="${PREFIX}/share/autonmap"
fi

# Banner
echo ""
echo -e "${B}   █████╗ ██╗   ██╗████████╗ ██████╗ ███╗   ██╗███╗   ███╗ █████╗ ██████╗ ${N}"
echo -e "${B}  ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗████╗  ██║████╗ ████║██╔══██╗██╔══██╗${N}"
echo -e "${G}  ███████║██║   ██║   ██║   ██║   ██║██╔██╗ ██║██╔████╔██║███████║██████╔╝${N}"
echo -e "${G}  ██╔══██║██║   ██║   ██║   ██║   ██║██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝ ${N}"
echo -e "${R}  ██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║ ╚████║██║ ╚═╝ ██║██║  ██║██║     ${N}"
echo -e "${R}  ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ${N}"
echo ""
echo -e "${C}                    ⚡ instalador v${VERSION} ⚡${N}"
echo -e "${C}                            N2O${N}"
echo "-------------------------------------------------------------"
echo ""

# 1. Verificar dependencias del sistema
step "Verificando dependencias del sistema..."
MISSING_PKGS=()
check_and_mark() { command -v "$1" &>/dev/null || MISSING_PKGS+=("$2"); }
check_and_mark nmap nmap
check_and_mark xsltproc xsltproc
check_and_mark python3 python3
check_and_mark pip3 python3-pip
check_and_mark netexec netexec
check_and_mark smbclient smbclient
check_and_mark whatweb whatweb

if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
    warn "Faltan: ${MISSING_PKGS[*]}"
    question "¿Instalar ahora? (requiere sudo) [s/N]"
    read -r resp
    if [[ "$resp" =~ ^[sSyY]$ ]]; then
        if command -v apt &>/dev/null; then sudo apt update && sudo apt install -y "${MISSING_PKGS[@]}"
        elif command -v dnf &>/dev/null; then sudo dnf install -y "${MISSING_PKGS[@]}"
        elif command -v pacman &>/dev/null; then sudo pacman -S --noconfirm "${MISSING_PKGS[@]}"
        elif command -v zypper &>/dev/null; then sudo zypper install -y "${MISSING_PKGS[@]}"
        else error "Gestor de paquetes no soportado."; exit 1; fi
    fi
else
    success "Dependencias del sistema OK."
fi

# 2. Instalar reportlab (PEP 668)
step "Verificando reportlab..."
reportlab_available() { python3 -c "import reportlab" 2>/dev/null; }

PDF_WRAPPER="${BINDIR}/autonmap-pdf"

if reportlab_available; then
    success "reportlab ya instalado."
    cat > "$PDF_WRAPPER" <<EOF
#!/bin/bash
exec python3 "$SHAREDIR/autonmap_pdf.py" "\$@"
EOF
    chmod +x "$PDF_WRAPPER"
else
    install_pipx() {
        if ! command -v pipx &>/dev/null; then
            if command -v apt &>/dev/null; then sudo apt install -y pipx
            elif command -v dnf &>/dev/null; then sudo dnf install -y pipx
            elif command -v pacman &>/dev/null; then sudo pacman -S --noconfirm python-pipx
            else return 1; fi
        fi
        command -v pipx &>/dev/null
    }

    pipx_used=false
    if install_pipx; then
        step "Instalando reportlab con pipx..."
        if pipx install reportlab 2>/dev/null; then
            cat > "$PDF_WRAPPER" <<EOF
#!/bin/bash
export PYTHONPATH="\$HOME/.local/pipx/venvs/reportlab/lib/python3/site-packages:\$PYTHONPATH"
exec python3 "$SHAREDIR/autonmap_pdf.py" "\$@"
EOF
            chmod +x "$PDF_WRAPPER"
            success "reportlab instalado con pipx."
            pipx_used=true
        else
            warn "pipx falló, probando venv..."
        fi
    fi

    if ! $pipx_used; then
        step "Creando entorno virtual..."
        VENV_DIR="$SHAREDIR/venv"
        python3 -m venv "$VENV_DIR"
        "$VENV_DIR/bin/pip" install --upgrade pip
        "$VENV_DIR/bin/pip" install reportlab
        cat > "$PDF_WRAPPER" <<EOF
#!/bin/bash
exec "$VENV_DIR/bin/python3" "$SHAREDIR/autonmap_pdf.py" "\$@"
EOF
        chmod +x "$PDF_WRAPPER"
        success "reportlab instalado en venv."
    fi

    if ! reportlab_available; then
        warn "No se pudo instalar reportlab."
        question "¿Usar --break-system-packages? (riesgo) [s/N]"
        read -r resp
        if [[ "$resp" =~ ^[sSyY]$ ]]; then
            pip3 install --break-system-packages reportlab
            cat > "$PDF_WRAPPER" <<EOF
#!/bin/bash
exec python3 "$SHAREDIR/autonmap_pdf.py" "\$@"
EOF
            chmod +x "$PDF_WRAPPER"
        else
            error "El módulo PDF no funcionará."
        fi
    fi
fi

# 3. Copiar archivos
step "Creando directorios..."
mkdir -p "$BINDIR" "$SHAREDIR"

copy_with_backup() {
    local src="$1" dest="$2"
    if [ -f "$dest" ]; then
        question "Sobrescribir $dest? [s/N]"
        read -r resp
        [[ ! "$resp" =~ ^[sSyY]$ ]] && { info "Saltando $dest"; return; }
        cp "$dest" "${dest}.bak.$(date +%Y%m%d%H%M%S)"
    fi
    cp "$src" "$dest"
    success "Instalado: $dest"
}

AUTONMAP_SH="${SCRIPT_DIR}/autonmap.sh"
AUTONMAP_PDF="${SCRIPT_DIR}/autonmap_pdf.py"
WHICHSYSTEM_SRC="${SCRIPT_DIR}/whichSystem.py"

[ -f "$AUTONMAP_SH" ] || { error "No se encontró autonmap.sh"; exit 1; }
copy_with_backup "$AUTONMAP_SH" "$BINDIR/autonmap"
chmod +x "$BINDIR/autonmap"

[ -f "$AUTONMAP_PDF" ] && { copy_with_backup "$AUTONMAP_PDF" "$SHAREDIR/autonmap_pdf.py"; chmod +x "$SHAREDIR/autonmap_pdf.py"; }

# 4. whichSystem.py
step "Verificando whichSystem.py..."
whichsystem_available() {
    command -v whichSystem.py &>/dev/null || [ -x "${BINDIR}/whichSystem.py" ] || [ -x "${SHAREDIR}/whichSystem.py" ]
}

if whichsystem_available; then
    success "whichSystem.py ya instalado."
else
    if [ -f "$WHICHSYSTEM_SRC" ]; then
        cp "$WHICHSYSTEM_SRC" "$BINDIR/whichSystem.py"
        chmod +x "$BINDIR/whichSystem.py"
        [ ! -f "${SHAREDIR}/whichSystem.py" ] && cp "$WHICHSYSTEM_SRC" "${SHAREDIR}/whichSystem.py"
        success "whichSystem.py instalado."
    else
        warn "whichSystem.py no incluido. La detección de SO no funcionará."
    fi
fi

export PATH=\"\$PATH:$BINDIR\" >> ~/.bashrc
export PATH=\"\$PATH:$BINDIR\" >> ~/.zshrc

# 5. Verificar PATH
step "Verificando PATH..."
if ! echo "$PATH" | grep -q "$BINDIR"; then
    warn "$BINDIR no está en tu PATH."
    info "Agrega: export PATH=\"\$PATH:$BINDIR\" a tu ~/.bashrc o ~/.zshrc"
fi


# 6. Mensaje final
echo ""
echo -e "${G}══════════════════════════════════════════════${N}"
echo -e "${G}   INSTALACIÓN COMPLETADA${N}"
echo -e "${G}══════════════════════════════════════════════${N}"
echo -e "${C}  autonmap v${VERSION} instalado en: ${BINDIR}${N}"
echo -e "${C}  Scripts complementarios en: ${SHAREDIR}${N}"
echo -e "${Y}  USO: sudo autonmap <IP>${N}"
echo ""
exit 0