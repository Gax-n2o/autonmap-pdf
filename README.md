<div align="center">

<pre style="text-align: center; font-family: monospace; background: none; border: none; color: #58a6ff;">
   █████╗ ██╗   ██╗████████╗ ██████╗ ███╗   ██╗███╗   ███╗ █████╗ ██████╗ 
  ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗████╗  ██║████╗ ████║██╔══██╗██╔══██╗
  ███████║██║   ██║   ██║   ██║   ██║██╔██╗ ██║██╔████╔██║███████║██████╔╝
  ██╔══██║██║   ██║   ██║   ██║   ██║██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝ 
  ██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║ ╚████║██║ ╚═╝ ██║██║  ██║██║     
  ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
</pre>

**⚡ The Silent Port Hunter ⚡**

[![Bash](https://img.shields.io/badge/Made%20with-Bash-1f425f.svg?logo=gnu-bash)](https://www.gnu.org/software/bash/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-2.1.0-blue)]()

</div>

---

## 📖 Descripción

**autonmap** es una herramienta modular de reconocimiento de red diseñada para agilizar las fases iniciales de un pentesting o auditoría de seguridad. Automatiza por completo el flujo de trabajo con `nmap`, recopila información crítica del objetivo y genera **reportes profesionales en PDF y HTML** con hallazgos de seguridad automáticos.

> **Ideal para laboratorios (HTB, VulnHub, Proving Grounds) y evaluaciones rápidas.**

---

## ✨ Características Principales

- 🔎 **Escaneo inteligente de puertos** (`-p-` con `--min-rate`, grepeable).
- 🧠 **Detección automática de servicios y versiones** (`-sCV` unificado).
- 🖥️ **Identificación del sistema operativo** (vía `whichSystem.py`).
- 🕸️ **Fingerprinting web** con WhatWeb (modo básico y verbose).
- 🗂️ **Enumeración SMB** con `netexec` y `smbclient` (sesión nula/anónima).
- 📊 **Generación de reportes**:
  - **HTML** interactivo (con servidor local integrado).
  - **PDF profesional** con portada, índice, gráficos de distribución, tabla de puertos, hallazgos de seguridad y recomendaciones.
  - **Markdown** para documentación rápida.
- ⚡ **Modo completo y modo rápido** sin preguntas ni pausas.
- 📝 **Logging** detallado de cada fase.
- 🛡️ **Cumple con PEP 668**: instalación segura de dependencias Python.

---

## 📦 Requisitos

| Herramienta        | Uso                             | ¿Obligatorio?            |
|--------------------|---------------------------------|--------------------------|
| `nmap`             | Escaneo de puertos y servicios  | ✅ Sí                    |
| `xsltproc`         | Generar HTML desde XML de nmap  | Opcional                 |
| `python3`          | Reportes PDF                    | Opcional (para PDF)      |
| `pip3` / `pipx`    | Instalar `reportlab`            | Opcional (para PDF)      |
| `whatweb`          | Fingerprinting web              | Opcional                 |
| `netexec`          | Enumeración SMB                 | Opcional                 |
| `smbclient`        | Acceso a recursos SMB           | Opcional                 |
| `whichSystem.py`   | Detección del SO                | Opcional (incluido)      |

---

## 🚀 Instalación

### Método 1 (recomendado) – Instalación automática
```
git clone https://github.com/Gax-n2o/autonmap-pdf.git
cd autonmap-pdf
chmod +x install.sh
./install.sh
```

Método 2 – Script remoto (directo)

```bash
curl -sL https://raw.githubusercontent.com/Gax-n2o/autonmap-pdf/main/install.sh | bash
```

El instalador se encargará de:

Verificar e instalar las dependencias del sistema (nmap, python3, etc.)

Instalar reportlab de forma aislada respetando PEP 668 (con pipx o venv)

Copiar los scripts a ~/.local/bin (o /usr/local/bin si ejecutas como root)

Añadir whichSystem.py si está en el repositorio

🧪 Uso

```bash
sudo autonmap <IP> [OPCIONES]
```
Opciones principales

Flag	Descripción

-f, --full	Modo completo (sin preguntas)

--fast	Modo rápido (sin pausas entre fases)

--pdf	Generar reporte PDF profesional

--pdf-only	Solo PDF, automático, sin interacción

--no-web	Saltar WhatWeb

--no-smb	Saltar enumeración SMB

--no-report	No generar reportes

-o <dir>	Directorio de salida (por defecto ./reports)

--which-system <path>	Ruta personalizada a whichSystem.py

Ejemplos
```bash
# Escaneo completo interactivo
sudo autonmap 192.168.1.10
````
# Modo rápido con PDF y todo automático
```
sudo autonmap 192.168.1.10 -f --fast --pdf-only
```
# Solo escaneo de puertos y servicios, sin preguntas
```
sudo autonmap 192.168.1.10 --no-web --no-smb --no-report -f
```
# Personalizar el PDF
```
sudo autonmap 192.168.1.10 --pdf --title "Pentest Cliente X" --
```
author "N2O"

📂 Estructura del Repositorio
```text
autonmap/
├── autonmap.sh          # Script principal (Bash)
├── autonmap_pdf.py      # Generador de reportes PDF/Markdown
├── whichSystem.py       # Detector de sistema operativo (opcional)
├── install.sh           # Instalador automático
├── LICENSE              # Licencia MIT
└── README.md            # Esta documentación
```
📊 Flujo de Trabajo

```text
1. Validaciones (root, IP, dependencias)
2. Detección de OS (si whichSystem.py está disponible)
3. Escaneo de todos los puertos (nmap -p-)
4. Escaneo de servicios y versiones (nmap -sCV -oA)
5. Reportes (HTML interactivo / PDF profesional)
6. Fingerprinting web (WhatWeb)
7. Enumeración SMB (netexec + smbclient)
```

⚖️ Licencia

Este proyecto está bajo la Licencia MIT. Consulta el archivo LICENSE para más detalles.

🙏 Créditos

N2O – Desarrollo principal.

Basado en herramientas como nmap, WhatWeb, netexec y ReportLab.
