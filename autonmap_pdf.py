#!/usr/bin/env python3
"""
autonmap_pdf.py - All-in-One PDF/Markdown Report Generator for autonmap
========================================================================
Autor: N2O
Version: 2.1.0
Descripcion: Modulo consolidado que combina el parser XML de nmap y el
             generador de reportes PDF/Markdown profesionales.

Uso:
  python3 autonmap_pdf.py -x scan.xml -o report.pdf
  python3 autonmap_pdf.py -x scan.xml -o report.md --format md
  python3 autonmap_pdf.py -x scan.xml --info
  python3 autonmap_pdf.py -x scan.xml -o report.pdf -t "Pentest Cliente X" --author "N2O Security"

Dependencias: pip3 install reportlab
"""

import argparse
import os
import re
import sys
from datetime import datetime
from io import BytesIO
from typing import Optional, Dict, List

import xml.etree.ElementTree as ET

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm, cm
from reportlab.lib.colors import HexColor, Color, white, black
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, KeepTogether, HRFlowable, ListFlowable, ListItem
)
from reportlab.graphics.shapes import Drawing, Rect, String, Circle, Line, Wedge
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics import renderPDF
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont


# ============================================================================
# DATA CLASSES - Parser
# ============================================================================

class NmapHost:
    def __init__(self):
        self.ip: str = ""
        self.hostname: str = ""
        self.mac: str = ""
        self.mac_vendor: str = ""
        self.os_guess: str = ""
        self.os_accuracy: int = 0
        self.state: str = "unknown"
        self.ports: List = []
        self.scan_start: str = ""
        self.scan_end: str = ""
        self.scan_args: str = ""
        self.scanner: str = ""
        self.num_services: int = 0
        self.open_ports: int = 0
        self.filtered_ports: int = 0
        self.closed_ports: int = 0


class NmapPort:
    def __init__(self):
        self.port_id: int = 0
        self.protocol: str = "tcp"
        self.state: str = ""
        self.state_reason: str = ""
        self.service_name: str = ""
        self.service_product: str = ""
        self.service_version: str = ""
        self.service_extrainfo: str = ""
        self.service_os: str = ""
        self.service_device_type: str = ""
        self.script_outputs: Dict[str, str] = {}


# ============================================================================
# PARSER FUNCTIONS
# ============================================================================

def parse_nmap_xml(xml_file: str) -> Optional[NmapHost]:
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError:
        print(f"[!] Error al parsear el XML: {xml_file}")
        return None
    except FileNotFoundError:
        print(f"[!] Archivo no encontrado: {xml_file}")
        return None

    host = NmapHost()

    host.scan_start = root.get("start", "")
    host.scan_end = root.get("startstr", "")
    host.scan_args = root.get("args", "")
    host.scanner = root.get("scanner", "nmap")

    if host.scan_start:
        try:
            ts = int(host.scan_start)
            host.scan_start = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, OSError):
            pass

    host_elem = root.find("host")
    if host_elem is None:
        print("[!] No se encontro elemento <host> en el XML")
        return None

    status_elem = host_elem.find("status")
    if status_elem is not None:
        host.state = status_elem.get("state", "unknown")

    for addr in host_elem.findall("address"):
        addr_type = addr.get("addrtype", "")
        if addr_type == "ipv4":
            host.ip = addr.get("addr", "")
        elif addr_type == "mac":
            host.mac = addr.get("addr", "")
            host.mac_vendor = addr.get("vendor", "Desconocido")

    hostnames_elem = host_elem.find("hostnames")
    if hostnames_elem is not None:
        for hn in hostnames_elem.findall("hostname"):
            name_type = hn.get("type", "")
            if name_type == "user" or (name_type == "PTR" and not host.hostname):
                host.hostname = hn.get("name", "")
        if not host.hostname:
            for hn in hostnames_elem.findall("hostname"):
                host.hostname = hn.get("name", "")
                if host.hostname:
                    break

    os_elem = host_elem.find("os")
    if os_elem is not None:
        for osmatch in os_elem.findall("osmatch"):
            accuracy = int(osmatch.get("accuracy", 0))
            if accuracy > host.os_accuracy:
                host.os_accuracy = accuracy
                host.os_guess = osmatch.get("name", "Desconocido")

    ports_elem = host_elem.find("ports")
    if ports_elem is not None:
        extraports = ports_elem.find("extraports")
        if extraports is not None:
            ep_state = extraports.get("state", "")
            ep_count = int(extraports.get("count", 0))
            if "filtered" in ep_state:
                host.filtered_ports = ep_count
            elif "closed" in ep_state:
                host.closed_ports = ep_count

        for port_elem in ports_elem.findall("port"):
            port = NmapPort()
            port.port_id = int(port_elem.get("portid", 0))
            port.protocol = port_elem.get("protocol", "tcp")

            state_elem = port_elem.find("state")
            if state_elem is not None:
                port.state = state_elem.get("state", "")
                port.state_reason = state_elem.get("reason", "")
                if port.state == "open":
                    host.open_ports += 1

            service_elem = port_elem.find("service")
            if service_elem is not None:
                port.service_name = service_elem.get("name", "")
                port.service_product = service_elem.get("product", "")
                port.service_version = service_elem.get("version", "")
                port.service_extrainfo = service_elem.get("extrainfo", "")
                port.service_os = service_elem.get("ostype", "")
                port.service_device_type = service_elem.get("devicetype", "")

            for script_elem in port_elem.findall("script"):
                script_id = script_elem.get("id", "")
                script_output = script_elem.get("output", "")
                port.script_outputs[script_id] = script_output

            host.ports.append(port)

    host.num_services = len(host.ports)
    return host


def categorize_ports(host: NmapHost) -> Dict[str, List[NmapPort]]:
    categories = {
        "web": [], "database": [], "remote_access": [],
        "file_sharing": [], "mail": [], "dns": [], "other": [],
    }

    web_ports = {80, 443, 8080, 8443, 8000, 8888, 9090, 3000, 5000, 4443}
    db_ports = {3306, 5432, 1433, 1521, 6379, 27017, 5984, 9200, 11211}
    remote_ports = {22, 23, 3389, 5900, 5901, 5902, 2222, 4321}
    file_ports = {21, 69, 111, 139, 445, 2049, 873}
    mail_ports = {25, 110, 143, 465, 587, 993, 995}
    dns_ports = {53, 5353}

    for port in host.ports:
        if port.state != "open":
            continue
        if port.port_id in web_ports or "http" in port.service_name:
            categories["web"].append(port)
        elif port.port_id in db_ports or "mysql" in port.service_name or "postgresql" in port.service_name:
            categories["database"].append(port)
        elif port.port_id in remote_ports or "ssh" in port.service_name or "telnet" in port.service_name:
            categories["remote_access"].append(port)
        elif port.port_id in file_ports or "smb" in port.service_name or "nfs" in port.service_name or "ftp" in port.service_name:
            categories["file_sharing"].append(port)
        elif port.port_id in mail_ports or "smtp" in port.service_name or "imap" in port.service_name:
            categories["mail"].append(port)
        elif port.port_id in dns_ports or "dns" in port.service_name or "domain" in port.service_name:
            categories["dns"].append(port)
        else:
            categories["other"].append(port)
    return categories


def generate_markdown_report(host: NmapHost, output_file: str) -> None:
    categories = categorize_ports(host)
    md = []
    md.append(f"# Reporte de Escaneo - {host.ip}")
    md.append(f"**Fecha:** {host.scan_start}")
    md.append(f"**Estado:** {host.state}")
    md.append(f"**Hostname:** {host.hostname or 'No detectado'}")
    md.append(f"**SO detectado:** {host.os_guess or 'No detectado'} ({host.os_accuracy}%)")
    md.append(f"**MAC:** {host.mac or 'N/A'} ({host.mac_vendor})")
    md.append("")
    md.append(f"## Resumen")
    md.append(f"- Total puertos escaneados: {host.open_ports + host.filtered_ports + host.closed_ports}")
    md.append(f"- Puertos abiertos: **{host.open_ports}**")
    md.append(f"- Puertos filtrados: {host.filtered_ports}")
    md.append(f"- Puertos cerrados: {host.closed_ports}")
    md.append("")
    md.append("## Puertos Abiertos y Servicios")
    md.append("| Puerto | Estado | Protocolo | Servicio | Producto | Version | Info Extra |")
    md.append("|-------:|--------|-----------|----------|----------|---------|------------|")
    for port in host.ports:
        if port.state != "open":
            continue
        md.append(
            f"| {port.port_id} | {port.state} | {port.protocol} | "
            f"{port.service_name or '-'} | {port.service_product or '-'} | "
            f"{port.service_version or '-'} | {port.service_extrainfo or '-'} |"
        )
    md.append("")
    cat_names = {
        "web": "Web",
        "database": "Bases de Datos",
        "remote_access": "Acceso Remoto",
        "file_sharing": "Archivos",
        "mail": "Correo",
        "dns": "DNS",
        "other": "Otros",
    }
    for cat_key, cat_name in cat_names.items():
        ports = categories[cat_key]
        if not ports:
            continue
        md.append(f"### {cat_name}")
        md.append(f"Puertos: {', '.join(str(p.port_id) for p in ports)}")
        md.append("")
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    print(f"[+] Reporte Markdown guardado en: {output_file}")


# ============================================================================
# COLORES Y MAPAS GLOBALES
# ============================================================================
COLORS = {
    "primary": HexColor("#1B2A4A"),
    "secondary": HexColor("#2D4A7A"),
    "accent": HexColor("#E74C3C"),
    "accent2": HexColor("#F39C12"),
    "success": HexColor("#27AE60"),
    "info": HexColor("#3498DB"),
    "dark": HexColor("#1A1A2E"),
    "light": HexColor("#ECF0F1"),
    "gray": HexColor("#95A5A6"),
    "white": HexColor("#FFFFFF"),
    "text": HexColor("#2C3E50"),
    "text_light": HexColor("#7F8C8D"),
    "border": HexColor("#BDC3C7"),
    "table_header": HexColor("#2C3E50"),
    "table_alt": HexColor("#F8F9FA"),
    "risk_critical": HexColor("#C0392B"),
    "risk_high": HexColor("#E74C3C"),
    "risk_medium": HexColor("#F39C12"),
    "risk_low": HexColor("#27AE60"),
    "risk_info": HexColor("#3498DB"),
}

RISK_COLORS = {
    "CRITICO": COLORS["risk_critical"],
    "ALTO": COLORS["risk_high"],
    "MEDIO": COLORS["risk_medium"],
    "BAJO": COLORS["risk_low"],
    "INFO": COLORS["risk_info"],
}

RISK_STYLE_MAP = {
    "CRITICO": "risk_critical",
    "ALTO": "risk_high",
    "MEDIO": "risk_medium",
    "BAJO": "risk_low",
    "INFO": "risk_info",
}

PAGE_W, PAGE_H = A4
MARGIN = 20 * mm


# ============================================================================
# REGISTRO DINÁMICO DE FUENTES
# ============================================================================
def register_fonts():
    dejavu_paths = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
        "/usr/local/share/fonts/dejavu/DejaVuSans.ttf",
        "/Library/Fonts/DejaVuSans.ttf",
    ]
    dejavu_bold_paths = [p.replace("Sans.ttf", "Sans-Bold.ttf") for p in dejavu_paths]
    dejavu_mono_paths = [p.replace("Sans.ttf", "SansMono.ttf") for p in dejavu_paths]

    for normal, bold in zip(dejavu_paths, dejavu_bold_paths):
        if os.path.exists(normal) and os.path.exists(bold):
            try:
                pdfmetrics.registerFont(TTFont("DejaVuSans", normal))
                pdfmetrics.registerFont(TTFont("DejaVuSans-Bold", bold))
                for mono in dejavu_mono_paths:
                    if os.path.exists(mono):
                        pdfmetrics.registerFont(TTFont("DejaVuMono", mono))
                        break
                break
            except Exception:
                pass
    else:
        liberation_paths = [
            "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
            "/usr/share/fonts/liberation/LiberationSans-Regular.ttf",
        ]
        liberation_bold = [p.replace("Regular", "Bold") for p in liberation_paths]
        for normal, bold in zip(liberation_paths, liberation_bold):
            if os.path.exists(normal) and os.path.exists(bold):
                try:
                    pdfmetrics.registerFont(TTFont("DejaVuSans", normal))
                    pdfmetrics.registerFont(TTFont("DejaVuSans-Bold", bold))
                    break
                except Exception:
                    pass


register_fonts()


# ============================================================================
# ESTILOS DE TEXTO
# ============================================================================
def build_styles() -> dict:
    styles = {}
    styles["title"] = ParagraphStyle("CustomTitle", fontName="Helvetica-Bold", fontSize=28, textColor=COLORS["white"], alignment=TA_CENTER, spaceAfter=6*mm, leading=34)
    styles["subtitle"] = ParagraphStyle("CustomSubtitle", fontName="Helvetica", fontSize=14, textColor=HexColor("#AABBCC"), alignment=TA_CENTER, spaceAfter=4*mm)
    styles["h1"] = ParagraphStyle("H1", fontName="Helvetica-Bold", fontSize=20, textColor=COLORS["primary"], spaceBefore=10*mm, spaceAfter=6*mm, borderPadding=(0, 0, 2*mm, 0))
    styles["h2"] = ParagraphStyle("H2", fontName="Helvetica-Bold", fontSize=15, textColor=COLORS["secondary"], spaceBefore=7*mm, spaceAfter=4*mm)
    styles["h3"] = ParagraphStyle("H3", fontName="Helvetica-Bold", fontSize=12, textColor=COLORS["text"], spaceBefore=5*mm, spaceAfter=3*mm)
    styles["body"] = ParagraphStyle("Body", fontName="Helvetica", fontSize=10, textColor=COLORS["text"], alignment=TA_JUSTIFY, spaceAfter=3*mm, leading=15)
    styles["body_bold"] = ParagraphStyle("BodyBold", fontName="Helvetica-Bold", fontSize=10, textColor=COLORS["text"], spaceAfter=3*mm, leading=15)
    styles["small"] = ParagraphStyle("Small", fontName="Helvetica", fontSize=8, textColor=COLORS["text_light"], spaceAfter=2*mm)

    code_font = "DejaVuMono" if "DejaVuMono" in pdfmetrics._fonts else "Courier"
    styles["code"] = ParagraphStyle("Code", fontName=code_font, fontSize=8, textColor=COLORS["dark"], backColor=HexColor("#F5F5F5"), borderPadding=4, spaceAfter=3*mm, leading=12)

    styles["toc_item"] = ParagraphStyle("TOCItem", fontName="Helvetica", fontSize=11, textColor=COLORS["text"], leftIndent=5*mm, spaceAfter=2*mm, leading=18)
    styles["footer"] = ParagraphStyle("Footer", fontName="Helvetica", fontSize=8, textColor=COLORS["gray"], alignment=TA_CENTER)
    styles["risk_critical"] = ParagraphStyle("RiskCritical", fontName="Helvetica-Bold", fontSize=10, textColor=COLORS["risk_critical"], spaceAfter=2*mm)
    styles["risk_high"] = ParagraphStyle("RiskHigh", fontName="Helvetica-Bold", fontSize=10, textColor=COLORS["risk_high"], spaceAfter=2*mm)
    styles["risk_medium"] = ParagraphStyle("RiskMedium", fontName="Helvetica-Bold", fontSize=10, textColor=COLORS["risk_medium"], spaceAfter=2*mm)
    styles["risk_low"] = ParagraphStyle("RiskLow", fontName="Helvetica-Bold", fontSize=10, textColor=COLORS["risk_low"], spaceAfter=2*mm)
    styles["cell"] = ParagraphStyle("Cell", fontName="Helvetica", fontSize=9, textColor=COLORS["text"], leading=12)
    styles["cell_bold"] = ParagraphStyle("CellBold", fontName="Helvetica-Bold", fontSize=9, textColor=COLORS["white"], leading=12)
    return styles


# ============================================================================
# GENERADORES DE ELEMENTOS GRAFICOS
# ============================================================================
def create_section_divider(styles):
    return HRFlowable(width="100%", thickness=1.5, color=COLORS["primary"], spaceBefore=4*mm, spaceAfter=4*mm)


def create_risk_badge(risk_level: str, styles) -> Paragraph:
    risk_map = RISK_STYLE_MAP
    style_key = risk_map.get(risk_level.upper(), "risk_info")
    return Paragraph(f"<b>{risk_level.upper()}</b>", styles[style_key])


def create_summary_card(data_items: list, styles) -> Table:
    cell_w = (PAGE_W - 2 * MARGIN) / max(len(data_items), 1)
    header_row = []
    label_row = []

    for i, (label, value, color) in enumerate(data_items):
        header_style = ParagraphStyle("CardHeader", fontName="Helvetica-Bold", fontSize=20, textColor=COLORS["white"], alignment=TA_CENTER)
        label_style = ParagraphStyle("CardLabel", fontName="Helvetica", fontSize=8, textColor=COLORS["text_light"], alignment=TA_CENTER)
        header_row.append(Paragraph(str(value), header_style))
        label_row.append(Paragraph(label.upper(), label_style))

    data = [header_row, label_row]
    col_widths = [cell_w] * len(data_items)
    table = Table(data, colWidths=col_widths, rowHeights=[18*mm, 8*mm])

    style_cmds = [
        ("BACKGROUND", (0, 1), (-1, 1), COLORS["light"]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, 0), 4*mm),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 3*mm),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]
    for i in range(len(data_items)):
        style_cmds.append(("BACKGROUND", (i, 0), (i, 0), data_items[i][2]))
    table.setStyle(TableStyle(style_cmds))
    return table


def create_pie_chart(categories: dict, styles) -> Drawing:
    chart_w = 200
    chart_h = 150
    d = Drawing(chart_w, chart_h)
    pie = Pie()
    pie.x = 50
    pie.y = 10
    pie.width = 100
    pie.height = 100
    labels = []
    data = []
    color_pairs = [
        (COLORS["info"], "Web"),
        (COLORS["accent"], "DB"),
        (COLORS["success"], "SSH/RDP"),
        (COLORS["accent2"], "Archivos"),
        (COLORS["gray"], "Correo"),
        (COLORS["secondary"], "DNS"),
        (HexColor("#8E44AD"), "Otros"),
    ]
    cat_keys = ["web", "database", "remote_access", "file_sharing", "mail", "dns", "other"]
    for i, key in enumerate(cat_keys):
        count = len(categories.get(key, []))
        if count > 0:
            data.append(count)
            labels.append(color_pairs[i][1])
    if not data:
        d.add(String(100, 75, "Sin datos", fontName="Helvetica", fontSize=12, fillColor=COLORS["gray"], textAnchor="middle"))
        return d
    for i, (c, _) in enumerate(color_pairs[:len(data)]):
        pie.slices[i].fillColor = c
        pie.slices[i].strokeColor = COLORS["white"]
        pie.slices[i].strokeWidth = 2
    pie.data = data
    pie.slices.fontName = "Helvetica"
    pie.slices.fontSize = 8
    d.add(pie)
    y_legend = 130
    for i, label in enumerate(labels):
        x_pos = 10 + (i % 4) * 50
        d.add(Rect(x_pos, y_legend - (i // 4) * 14, 8, 8, fillColor=color_pairs[i][0], strokeColor=None))
        d.add(String(x_pos + 12, y_legend - (i // 4) * 14 - 1, f"{label} ({data[i]})", fontName="Helvetica", fontSize=7, fillColor=COLORS["text"]))
    return d


def create_port_table(host: NmapHost, styles) -> Table:
    s = styles
    headers = [Paragraph("<b>PUERTO</b>", s["cell_bold"]), Paragraph("<b>PROTO</b>", s["cell_bold"]), Paragraph("<b>ESTADO</b>", s["cell_bold"]), Paragraph("<b>SERVICIO</b>", s["cell_bold"]), Paragraph("<b>PRODUCTO</b>", s["cell_bold"]), Paragraph("<b>VERSION</b>", s["cell_bold"]), Paragraph("<b>INFO EXTRA</b>", s["cell_bold"])]
    col_widths = [20*mm, 18*mm, 20*mm, 28*mm, 30*mm, 25*mm, 40*mm]
    data = [headers]
    for i, port in enumerate(host.ports):
        if port.state != "open":
            continue
        state_color = COLORS["success"]
        if port.state == "filtered":
            state_color = COLORS["accent2"]
        elif port.state == "closed":
            state_color = COLORS["gray"]
        state_style = ParagraphStyle(f"State_{i}", fontName="Helvetica-Bold", fontSize=9, textColor=state_color, leading=12)
        row = [Paragraph(str(port.port_id), s["cell"]), Paragraph(port.protocol.upper(), s["cell"]), Paragraph(f"<b>{port.state.upper()}</b>", state_style), Paragraph(port.service_name or "-", s["cell"]), Paragraph(port.service_product or "-", s["cell"]), Paragraph(port.service_version or "-", s["cell"]), Paragraph(port.service_extrainfo or "-", s["cell"])]
        data.append(row)
    table = Table(data, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), COLORS["table_header"]), ("TEXTCOLOR", (0, 0), (-1, 0), COLORS["white"]), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), *[("BACKGROUND", (0, i), (-1, i), COLORS["table_alt"]) for i in range(2, len(data), 2)], ("GRID", (0, 0), (-1, -1), 0.5, COLORS["border"]), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4), ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4), ("TOPPADDING", (0, 0), (-1, 0), 6), ("BOTTOMPADDING", (0, 0), (-1, 0), 6)]))
    return table


def create_findings_table(findings: list, styles) -> Table:
    s = styles
    headers = [Paragraph("<b>#</b>", s["cell_bold"]), Paragraph("<b>HALLAZGO</b>", s["cell_bold"]), Paragraph("<b>SEVERIDAD</b>", s["cell_bold"]), Paragraph("<b>PUERTO/SERVICIO</b>", s["cell_bold"]), Paragraph("<b>RECOMENDACION</b>", s["cell_bold"])]
    col_widths = [10*mm, 42*mm, 22*mm, 30*mm, 77*mm]
    data = [headers]
    for i, finding in enumerate(findings, 1):
        risk = finding.get("risk", "INFO").upper()
        rc = RISK_COLORS.get(risk, COLORS["gray"])
        risk_style = ParagraphStyle(f"Risk_{i}", fontName="Helvetica-Bold", fontSize=8, textColor=rc, leading=11, alignment=TA_CENTER)
        row = [Paragraph(str(i), s["cell"]), Paragraph(finding["title"], s["cell"]), Paragraph(f"<b>{risk}</b>", risk_style), Paragraph(finding.get("port", "-"), s["cell"]), Paragraph(finding.get("recommendation", "-"), s["cell"])]
        data.append(row)
    table = Table(data, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), COLORS["table_header"]), ("TEXTCOLOR", (0, 0), (-1, 0), COLORS["white"]), *[("BACKGROUND", (0, i), (-1, i), COLORS["table_alt"]) for i in range(2, len(data), 2)], ("GRID", (0, 0), (-1, -1), 0.5, COLORS["border"]), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4), ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3)]))
    return table


# ============================================================================
# GENERADOR DE HALLAZGOS AUTOMATICOS
# ============================================================================
def generate_findings(host: NmapHost) -> list:
    findings = []
    open_ports = [p for p in host.ports if p.state == "open"]
    port_ids = {p.port_id for p in open_ports}
    if 23 in port_ids:
        findings.append({"title": "Telnet expuesto sin cifrar", "risk": "CRITICO", "port": "23/tcp (telnet)", "recommendation": "Deshabilitar Telnet y migrar a SSH. Telnet transmite credenciales en texto plano."})
    if 21 in port_ids:
        findings.append({"title": "FTP expuesto - posible transmision de credenciales en claro", "risk": "CRITICO", "port": "21/tcp (ftp)", "recommendation": "Configurar FTPS/SFTP o deshabilitar FTP si no es necesario. Usar SFTP (SSH) para transferencias."})
    if 445 in port_ids:
        findings.append({"title": "SMB expuesto - posible vector de ataque", "risk": "CRITICO", "port": "445/tcp (smb)", "recommendation": "Restringir acceso a SMB mediante firewall. Verificar que no haya recursos compartidos sensibles accesibles. Aplicar parches de seguridad recientes."})
    if 22 in port_ids:
        for p in open_ports:
            if p.port_id == 22:
                if any(v in p.service_version.lower() for v in ["7.2", "7.3", "7.4", "7.5", "7.6", "7.7"]):
                    findings.append({"title": f"SSH con version potencialmente vulnerable ({p.service_version})", "risk": "ALTO", "port": "22/tcp (ssh)", "recommendation": f"Actualizar OpenSSH a la ultima version estable. La version detectada puede tener vulnerabilidades conocidas."})
                    break
                else:
                    findings.append({"title": "SSH expuesto - accesible desde la red", "risk": "ALTO", "port": "22/tcp (ssh)", "recommendation": "Restringir acceso SSH por IP, deshabilitar login de root, usar claves en lugar de contrasenas. Considerar fail2ban."})
                    break
    if 3389 in port_ids:
        findings.append({"title": "RDP (Escritorio Remoto) expuesto", "risk": "ALTO", "port": "3389/tcp (ms-wbt-server)", "recommendation": "Restringir acceso RDP por IP o VPN. Aplicar NLA (Network Level Authentication). Usar contrasenas fuertes."})
    if 5900 in port_ids or 5901 in port_ids:
        vnc_port = 5900 if 5900 in port_ids else 5901
        findings.append({"title": "VNC expuesto sin cifrado nativo", "risk": "ALTO", "port": f"{vnc_port}/tcp (vnc)", "recommendation": "Tunelizar VNC sobre SSH o usar un VPN. VNC no cifra el trafico por defecto."})
    db_services = [(3306, "MySQL", "Restringir acceso a localhost o IPs especificas. Verificar que no tenga contrasena debil."), (5432, "PostgreSQL", "Configurar pg_hba.conf para restringir acceso. Deshabilitar acceso remoto si no es necesario."), (1433, "MSSQL", "Restringir acceso por IP. Encriptar conexiones. Verificar contrasenas fuertes."), (6379, "Redis", "Redis NO deberia estar expuesto. Configurar bind 127.0.0.1 y establecer contrasena."), (27017, "MongoDB", "Habilitar autenticacion. Restringir acceso por IP. No usar configuracion por defecto."), (11211, "Memcached", "Deshabilitar UDP si no es necesario. Restringir acceso por IP. No deberia estar expuesto publicamente."), (5984, "CouchDB", "Configurar bind-address. Habilitar autenticacion. Verificar permisos de administrador.")]
    for port_num, db_name, rec in db_services:
        if port_num in port_ids:
            findings.append({"title": f"{db_name} expuesto a la red", "risk": "MEDIO", "port": f"{port_num}/tcp ({db_name.lower()})", "recommendation": rec})
    if 80 in port_ids and 443 not in port_ids:
        findings.append({"title": "HTTP sin HTTPS - trafico no cifrado", "risk": "MEDIO", "port": "80/tcp (http)", "recommendation": "Implementar HTTPS con certificado TLS valido. Redirigir HTTP a HTTPS."})
    for p in open_ports:
        version = p.service_version.lower()
        product = p.service_product.lower()
        if "apache" in product and version:
            if any(v in version for v in ["2.2", "2.4.29", "2.4.38", "2.4.41"]):
                findings.append({"title": f"Apache con version posiblemente vulnerable ({p.service_version})", "risk": "ALTO", "port": f"{p.port_id}/tcp ({p.service_name})", "recommendation": "Actualizar Apache a la ultima version estable."})
        elif "nginx" in product and version:
            if any(v in version for v in ["1.14", "1.16", "1.18"]):
                findings.append({"title": f"Nginx con version posiblemente antigua ({p.service_version})", "risk": "MEDIO", "port": f"{p.port_id}/tcp ({p.service_name})", "recommendation": "Verificar y actualizar Nginx a la ultima version estable."})
    unusual_high = [p for p in open_ports if p.port_id > 32768]
    if len(unusual_high) > 5:
        findings.append({"title": f"Multiples puertos dinamicos/high-range abiertos ({len(unusual_high)} puertos > 32768)", "risk": "BAJO", "port": ", ".join(str(p.port_id) for p in unusual_high[:5]) + "...", "recommendation": "Investigar si estos puertos son legitimos o indican actividad sospechosa/servicios temporales."})
    return findings


# ============================================================================
# CLASE PRINCIPAL DEL PDF
# ============================================================================
class ReportPDF:
    def __init__(self, output_path: str, metadata: dict = None):
        self.output_path = output_path
        self.styles = build_styles()
        self.metadata = metadata or {}
        self.elements = []
        self.page_number = 0
        self.s = self.styles
        self.doc = SimpleDocTemplate(output_path, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=MARGIN, bottomMargin=MARGIN, title=self.metadata.get("title", "autonmap - Reporte de Escaneo"), author=self.metadata.get("author", "autonmap by N2O"), subject="Reconocimiento de Red", creator="autonmap v2.1")

    def add_header_footer(self, canvas, doc):
        canvas.saveState()
        self.page_number += 1
        canvas.setStrokeColor(COLORS["primary"])
        canvas.setLineWidth(1.5)
        canvas.line(MARGIN, PAGE_H - 12*mm, PAGE_W - MARGIN, PAGE_H - 12*mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(COLORS["gray"])
        canvas.drawString(MARGIN, PAGE_H - 10*mm, "autonmap - The Silent Port Hunter | Reporte de Escaneo")
        canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - 10*mm, "CONFIDENCIAL")
        canvas.setStrokeColor(COLORS["border"])
        canvas.setLineWidth(0.5)
        canvas.line(MARGIN, 14*mm, PAGE_W - MARGIN, 14*mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(COLORS["gray"])
        canvas.drawString(MARGIN, 9*mm, f"Generado: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        canvas.drawCentredString(PAGE_W / 2, 9*mm, f"Pagina {self.page_number}")
        canvas.drawRightString(PAGE_W - MARGIN, 9*mm, "by N2O")
        canvas.setFillColor(COLORS["primary"])
        canvas.rect(MARGIN, 5*mm, PAGE_W - 2*MARGIN, 1.5*mm, fill=True, stroke=False)
        canvas.restoreState()

    def build_cover_page(self, host: NmapHost):
        elements = self.elements
        s = self.s

        elements.append(Spacer(1, 20*mm))

        cover_bar = Table([[""]], colWidths=[PAGE_W - 2*MARGIN], rowHeights=[4*mm])
        cover_bar.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), COLORS["primary"]),
            ("ROUNDEDCORNERS", [2, 2, 0, 0]),
        ]))
        elements.append(cover_bar)
        elements.append(Spacer(1, 15*mm))

        # --- Título y autor dinámicos ---
        custom_title = self.metadata.get("title", "autonmap - Reporte de Escaneo")
        custom_author = self.metadata.get("author", "autonmap by N2O")

        if custom_title == "autonmap - Reporte de Escaneo":
            display_title = "AUTONMAP"
            display_subtitle = "REPORTE DE RECONOCIMIENTO DE RED"
            display_author = ""
        else:
            display_title = custom_title
            display_subtitle = ""
            display_author = custom_author

        title_box = Table(
            [[Paragraph(display_title, s["title"])]],
            colWidths=[PAGE_W - 2*MARGIN]
        )
        title_box.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), COLORS["primary"]),
            ("TOPPADDING", (0, 0), (-1, -1), 15),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("LEFTPADDING", (0, 0), (-1, -1), 20),
            ("ROUNDEDCORNERS", [4, 4, 4, 4]),
        ]))
        elements.append(title_box)
        elements.append(Spacer(1, 5*mm))

        if display_subtitle:
            elements.append(Paragraph(display_subtitle, s["subtitle"]))
        elif display_author:
            author_style = ParagraphStyle(
                "CoverAuthor", fontName="Helvetica", fontSize=14,
                textColor=HexColor("#AABBCC"), alignment=TA_CENTER, spaceAfter=10*mm
            )
            elements.append(Paragraph(display_author, author_style))
        else:
            elements.append(Spacer(1, 10*mm))

        # Información del target
        info_data = [
            [Paragraph("<b>TARGET</b>", ParagraphStyle("IL", fontName="Helvetica-Bold", fontSize=9, textColor=COLORS["text_light"], alignment=TA_CENTER)),
             Paragraph("<b>FECHA</b>", ParagraphStyle("IL2", fontName="Helvetica-Bold", fontSize=9, textColor=COLORS["text_light"], alignment=TA_CENTER)),
             Paragraph("<b>ESTADO</b>", ParagraphStyle("IL3", fontName="Helvetica-Bold", fontSize=9, textColor=COLORS["text_light"], alignment=TA_CENTER))],
            [Paragraph(host.ip or "N/A", ParagraphStyle("IV1", fontName="Helvetica-Bold", fontSize=14, textColor=COLORS["primary"], alignment=TA_CENTER)),
             Paragraph(host.scan_start or "-", ParagraphStyle("IV2", fontName="Helvetica", fontSize=11, textColor=COLORS["text"], alignment=TA_CENTER)),
             Paragraph(host.state.upper() or "UP", ParagraphStyle("IV3", fontName="Helvetica-Bold", fontSize=14, textColor=COLORS["success"], alignment=TA_CENTER))],
        ]

        info_table = Table(info_data, colWidths=[55*mm, 55*mm, 55*mm])
        info_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), COLORS["light"]),
            ("BOX", (0, 0), (-1, -1), 1, COLORS["border"]),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, COLORS["border"]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(info_table)
        elements.append(Spacer(1, 8*mm))

        extra_data = [
            [Paragraph(f"<b>Hostname:</b> {host.hostname or 'No detectado'}", s["body"]),
             Paragraph(f"<b>MAC:</b> {host.mac or 'N/A'}", s["body"])],
            [Paragraph(f"<b>OS:</b> {host.os_guess or 'No detectado'}", s["body"]),
             Paragraph(f"<b>Puertos abiertos:</b> {host.open_ports}", s["body"])],
        ]
        extra_table = Table(extra_data, colWidths=[90*mm, 75*mm])
        extra_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(extra_table)
        elements.append(Spacer(1, 25*mm))

        elements.append(create_section_divider(s))
        elements.append(Spacer(1, 5*mm))

        brand_style = ParagraphStyle(
            "Brand", fontName="Helvetica", fontSize=10,
            textColor=COLORS["gray"], alignment=TA_CENTER
        )
        elements.append(Paragraph("Generado por <b>autonmap</b> | The Silent Port Hunter", brand_style))
        elements.append(Paragraph(f"v2.1 | {datetime.now().strftime('%Y-%m-%d')}", brand_style))

        class_style = ParagraphStyle(
            "Classification", fontName="Helvetica-Bold", fontSize=9,
            textColor=COLORS["accent"], alignment=TA_CENTER, spaceBefore=10*mm
        )
        elements.append(Paragraph("CLASIFICACION: CONFIDENCIAL - USO RESTRINGIDO", class_style))

        elements.append(PageBreak())

    def build_toc(self):
        elements = self.elements
        s = self.s
        elements.append(Paragraph("TABLA DE CONTENIDOS", s["h1"]))
        elements.append(create_section_divider(s))
        toc_items = [("1.", "Resumen Ejecutivo"), ("2.", "Informacion del Objetivo"), ("3.", "Resultados del Escaneo de Puertos"), ("4.", "Analisis de Servicios"), ("5.", "Distribucion de Puertos"), ("6.", "Hallazgos de Seguridad"), ("7.", "Recomendaciones"), ("8.", "Detalles Tecnicos")]
        for num, title in toc_items:
            elements.append(Paragraph(f"<b>{num}</b>&nbsp;&nbsp;&nbsp;{title}", s["toc_item"]))
        elements.append(PageBreak())

    def build_executive_summary(self, host: NmapHost, findings: list):
        elements = self.elements
        s = self.s
        elements.append(Paragraph("1. RESUMEN EJECUTIVO", s["h1"]))
        elements.append(create_section_divider(s))
        card_data = [("Puertos Abiertos", host.open_ports, COLORS["info"]), ("Servicios Detectados", host.num_services, COLORS["success"]), ("Riesgo Alto+", len([f for f in findings if f["risk"].upper() in ("CRITICO", "ALTO")]), COLORS["accent"]), ("Total Hallazgos", len(findings), COLORS["accent2"])]
        elements.append(create_summary_card(card_data, s))
        elements.append(Spacer(1, 8*mm))
        summary_text = f"Se realizo un reconocimiento de red completo sobre el objetivo <b>{host.ip}</b> ({host.hostname or 'sin hostname'}) el {host.scan_start}. El escaneo identifico <b>{host.open_ports} puertos abiertos</b> con servicios activos que representan potenciales vectores de ataque. "
        os_text = f"El sistema operativo detectado es <b>{host.os_guess}</b> con un nivel de confianza del {host.os_accuracy}%. " if host.os_guess else ""
        risk_text = ""
        critical = [f for f in findings if f["risk"].upper() == "CRITICO"]
        high = [f for f in findings if f["risk"].upper() == "ALTO"]
        if critical:
            risk_text = f"Se identificaron <b>{len(critical)} hallazgos criticos</b> que requieren atencion inmediata, incluyendo {', '.join(c['title'].lower() for c in critical[:2])}. "
        elif high:
            risk_text = f"Se identificaron <b>{len(high)} hallazgos de alto riesgo</b> que deberian ser atendidos a la brevedad. "
        conclusion = "Se recomienda revisar los hallazgos detallados en las siguientes secciones y priorizar la mitigacion de las vulnerabilidades de mayor severidad."
        elements.append(Paragraph(summary_text + os_text + risk_text + conclusion, s["body"]))
        elements.append(Spacer(1, 5*mm))

    def build_target_info(self, host: NmapHost):
        elements = self.elements
        s = self.s
        elements.append(Paragraph("2. INFORMACION DEL OBJETIVO", s["h1"]))
        elements.append(create_section_divider(s))
        info_rows = [("Direccion IP", host.ip or "N/A"), ("Hostname", host.hostname or "No detectado"), ("Estado", host.state.upper() or "DESCONOCIDO"), ("Direccion MAC", host.mac or "No detectada"), ("Vendor MAC", host.mac_vendor or "N/A"), ("Sistema Operativo", f"{host.os_guess} ({host.os_accuracy}%)" if host.os_guess else "No detectado"), ("Fecha de Escaneo", host.scan_start or "N/A"), ("Argumentos del Escaneo", host.scan_args or "N/A"), ("Herramienta", host.scanner or "nmap"), ("Puertos Abiertos", str(host.open_ports)), ("Puertos Filtrados", str(host.filtered_ports)), ("Puertos Cerrados", str(host.closed_ports))]
        table_data = []
        for label, value in info_rows:
            table_data.append([Paragraph(f"<b>{label}</b>", ParagraphStyle("IL", fontName="Helvetica-Bold", fontSize=9, textColor=COLORS["secondary"])), Paragraph(str(value), ParagraphStyle("IV", fontName="Helvetica", fontSize=9, textColor=COLORS["text"]))])
        table = Table(table_data, colWidths=[50*mm, 115*mm])
        table.setStyle(TableStyle([*[("BACKGROUND", (0, i), (-1, i), COLORS["table_alt"]) for i in range(0, len(table_data), 2)], ("BOX", (0, 0), (-1, -1), 0.5, COLORS["border"]), ("LINEBELOW", (0, 0), (-1, -2), 0.3, COLORS["border"]), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5), ("LEFTPADDING", (0, 0), (-1, -1), 8)]))
        elements.append(table)
        elements.append(PageBreak())

    def build_port_results(self, host: NmapHost):
        elements = self.elements
        s = self.s
        elements.append(Paragraph("3. RESULTADOS DEL ESCANEO DE PUERTOS", s["h1"]))
        elements.append(create_section_divider(s))
        elements.append(Paragraph("A continuacion se presenta la lista completa de puertos abiertos detectados en el objetivo, junto con los servicios identificados, versiones e informacion adicional proporcionada por el escaneo de versiones (-sCV).", s["body"]))
        elements.append(Spacer(1, 3*mm))
        elements.append(create_port_table(host, s) if host.ports else Paragraph("No se detectaron puertos abiertos.", s["body"]))

    def build_service_analysis(self, host: NmapHost):
        elements = self.elements
        s = self.s
        elements.append(Paragraph("4. ANALISIS DE SERVICIOS", s["h1"]))
        elements.append(create_section_divider(s))
        categories = categorize_ports(host)
        cat_info = {
            "web": ("Servicios Web (HTTP/HTTPS)", COLORS["info"], "Estos puertos estan asociados con servidores web y aplicaciones web. La exposicion de servicios web puede revelar informacion sensible, tecnologias utilizadas y potenciales vulnerabilidades en la aplicacion."),
            "database": ("Bases de Datos", COLORS["accent"], "Las bases de datos expuestas a la red representan uno de los mayores riesgos de seguridad. El acceso no autorizado puede resultar en fuga de datos completa, modificacion o eliminacion de informacion critica."),
            "remote_access": ("Acceso Remoto", COLORS["success"], "Los servicios de acceso remoto permiten la administracion del sistema. Los servicios sin cifrar como Telnet o VNC exponen credenciales en texto plano."),
            "file_sharing": ("Comparticion de Archivos", COLORS["accent2"], "Los servicios de comparticion de archivos pueden exponer datos sensibles si no estan correctamente configurados. SMB en particular ha sido objetivo de numerosos ataques como WannaCry y EternalBlue."),
            "mail": ("Correo Electronico", COLORS["gray"], "Los servidores de correo expuestos pueden ser utilizados para relay de spam, enumeracion de usuarios y otros ataques si no estan correctamente protegidos."),
            "dns": ("DNS", COLORS["secondary"], "Los servidores DNS exponen informacion sobre la infraestructura de red. La transferencia de zona no restringida puede revelar todos los registros DNS."),
            "other": ("Otros Servicios", HexColor("#8E44AD"), "Estos servicios no se categorizaron en los grupos anteriores pero pueden representar riesgos dependiendo de su configuracion y exposicion.")
        }
        cat_keys_order = ["web", "database", "remote_access", "file_sharing", "mail", "dns", "other"]
        for idx, cat_key in enumerate(cat_keys_order, start=1):
            ports = categories.get(cat_key, [])
            if not ports:
                continue
            cat_name, cat_color, cat_desc = cat_info[cat_key]
            elements.append(Paragraph(f"4.{idx} {cat_name.upper()}", s["h2"]))
            badge_style = ParagraphStyle(f"Badge_{cat_key}", fontName="Helvetica-Bold", fontSize=10, textColor=cat_color, spaceAfter=2*mm)
            elements.append(Paragraph(f"{len(ports)} servicio(s) detectado(s)", badge_style))
            elements.append(Paragraph(cat_desc, s["body"]))
            elements.append(Spacer(1, 2*mm))
            mini_headers = [Paragraph("<b>PUERTO</b>", s["cell_bold"]), Paragraph("<b>SERVICIO</b>", s["cell_bold"]), Paragraph("<b>PRODUCTO</b>", s["cell_bold"]), Paragraph("<b>VERSION</b>", s["cell_bold"])]
            mini_data = [mini_headers]
            for p in ports:
                mini_data.append([Paragraph(str(p.port_id), s["cell"]), Paragraph(p.service_name or "-", s["cell"]), Paragraph(p.service_product or "-", s["cell"]), Paragraph(p.service_version or "-", s["cell"])])
            mini_table = Table(mini_data, colWidths=[30*mm, 40*mm, 55*mm, 45*mm])
            mini_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), cat_color), ("TEXTCOLOR", (0, 0), (-1, 0), COLORS["white"]), *[("BACKGROUND", (0, i), (-1, i), COLORS["table_alt"]) for i in range(2, len(mini_data), 2)], ("GRID", (0, 0), (-1, -1), 0.5, COLORS["border"]), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3), ("LEFTPADDING", (0, 0), (-1, -1), 4)]))
            elements.append(mini_table)
            elements.append(Spacer(1, 5*mm))

    def build_distribution(self, host: NmapHost):
        elements = self.elements
        s = self.s
        elements.append(Paragraph("5. DISTRIBUCION DE PUERTOS", s["h1"]))
        elements.append(create_section_divider(s))
        categories = categorize_ports(host)
        elements.append(Paragraph("La siguiente grafica muestra la distribucion de los puertos abiertos por categoria de servicio, permitiendo identificar rapidamente los tipos de servicios predominantes en el objetivo y evaluar la superficie de ataque.", s["body"]))
        elements.append(Spacer(1, 5*mm))
        pie = create_pie_chart(categories, s)
        elements.append(pie)
        elements.append(Spacer(1, 8*mm))
        cat_names = {"web": "Web (HTTP/HTTPS)", "database": "Bases de Datos", "remote_access": "Acceso Remoto", "file_sharing": "Archivos", "mail": "Correo", "dns": "DNS", "other": "Otros"}
        dist_data = [[Paragraph("<b>CATEGORIA</b>", s["cell_bold"]), Paragraph("<b>CANTIDAD</b>", s["cell_bold"]), Paragraph("<b>PUERTOS</b>", s["cell_bold"])]]
        for key, name in cat_names.items():
            ports = categories.get(key, [])
            if ports:
                dist_data.append([Paragraph(name, s["cell"]), Paragraph(str(len(ports)), ParagraphStyle("CN", fontName="Helvetica-Bold", fontSize=9, textColor=COLORS["primary"], alignment=TA_CENTER)), Paragraph(", ".join(str(p.port_id) for p in ports), s["cell"])])
        dist_table = Table(dist_data, colWidths=[55*mm, 25*mm, 90*mm])
        dist_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), COLORS["table_header"]), ("TEXTCOLOR", (0, 0), (-1, 0), COLORS["white"]), *[("BACKGROUND", (0, i), (-1, i), COLORS["table_alt"]) for i in range(2, len(dist_data), 2)], ("GRID", (0, 0), (-1, -1), 0.5, COLORS["border"]), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4), ("LEFTPADDING", (0, 0), (-1, -1), 5)]))
        elements.append(dist_table)

    def build_findings(self, host: NmapHost, findings: list):
        elements = self.elements
        s = self.s
        elements.append(Paragraph("6. HALLAZGOS DE SEGURIDAD", s["h1"]))
        elements.append(create_section_divider(s))
        if not findings:
            elements.append(Paragraph("No se identificaron hallazgos de seguridad significativos.", s["body"]))
            return
        counts = {"CRITICO": 0, "ALTO": 0, "MEDIO": 0, "BAJO": 0, "INFO": 0}
        for f in findings:
            r = f["risk"].upper()
            if r in counts:
                counts[r] += 1
        elements.append(Paragraph("<b>Distribucion por severidad:</b>", s["body"]))
        for risk, count in counts.items():
            if count > 0:
                color = RISK_COLORS.get(risk, COLORS["gray"])
                badge = Paragraph(f"&nbsp;&nbsp;<b>{risk}: {count}</b>&nbsp;&nbsp;", ParagraphStyle(f"SB_{risk}", fontName="Helvetica-Bold", fontSize=10, textColor=COLORS["white"], backColor=color, borderPadding=4, spaceBefore=2, spaceAfter=2, leftIndent=5, rightIndent=5))
                elements.append(badge)
        elements.append(Spacer(1, 8*mm))
        elements.append(Paragraph("A continuacion se detallan los hallazgos identificados durante el reconocimiento, ordenados por severidad.", s["body"]))
        elements.append(Spacer(1, 3*mm))
        elements.append(create_findings_table(findings, s))

    def build_recommendations(self, host: NmapHost, findings: list):
        elements = self.elements
        s = self.s
        elements.append(Paragraph("7. RECOMENDACIONES", s["h1"]))
        elements.append(create_section_divider(s))
        elements.append(Paragraph("Las siguientes recomendaciones estan organizadas por prioridad.", s["body"]))
        elements.append(Spacer(1, 4*mm))
        general_recs = [("Actualizacion de Sistemas", "Mantener el sistema operativo y todos los servicios actualizados con los ultimos parches de seguridad."), ("Principio de Minimo Exposicion", "Deshabilitar todos los servicios que no sean estrictamente necesarios."), ("Firewall y Segmentacion", "Implementar reglas de firewall restrictivas."), ("Autenticacion Fuerte", "Exigir autenticacion robusta en todos los servicios."), ("Monitoreo y Logs", "Implementar monitoreo continuo de accesos."), ("Cifrado de Comunicaciones", "Migrar todos los servicios a sus versiones cifradas.")]
        for i, (title, desc) in enumerate(general_recs, 1):
            elements.append(Paragraph(f"<b>7.{i} {title}</b>", s["h3"]))
            elements.append(Paragraph(desc, s["body"]))
        if findings:
            elements.append(Spacer(1, 5*mm))
            elements.append(Paragraph("7.7 Acciones Especificas por Hallazgo", s["h3"]))
            for i, f in enumerate(findings, 1):
                if f["risk"].upper() in ("CRITICO", "ALTO"):
                    risk_color = RISK_COLORS.get(f["risk"].upper(), COLORS["gray"])
                    rec_style = ParagraphStyle(f"Rec_{i}", fontName="Helvetica", fontSize=9, textColor=COLORS["text"], leftIndent=8*mm, spaceAfter=2*mm, leading=13, bulletIndent=2*mm)
                    elements.append(Paragraph(f'<bullet color="{risk_color.hexval()}">&bull;</bullet> <b>[{f["risk"].upper()}]</b> {f["recommendation"]}', rec_style))

    def build_technical_details(self, host: NmapHost):
        elements = self.elements
        s = self.s
        elements.append(Paragraph("8. DETALLES TECNICOS", s["h1"]))
        elements.append(create_section_divider(s))
        elements.append(Paragraph("<b>Comandos Ejecutados</b>", s["h2"]))
        cmds = [f"nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn {host.ip} -oA ports_{host.ip}", f"nmap -sCV -p<puertos_abiertos> {host.ip} -oA services_{host.ip}"]
        for cmd in cmds:
            elements.append(Paragraph(f"$ {cmd}", s["code"]))
        elements.append(Spacer(1, 5*mm))
        elements.append(Paragraph("<b>Herramientas Utilizadas</b>", s["h2"]))
        tools_data = [[Paragraph("<b>Herramienta</b>", s["cell_bold"]), Paragraph("<b>Version</b>", s["cell_bold"]), Paragraph("<b>Proposito</b>", s["cell_bold"])], [Paragraph("nmap", s["cell"]), Paragraph("-", s["cell"]), Paragraph("Escaneo de puertos y deteccion de servicios", s["cell"])], [Paragraph("autonmap", s["cell"]), Paragraph("2.1.0", s["cell"]), Paragraph("Automatizacion del flujo de reconocimiento", s["cell"])]]
        for p in host.ports:
            if p.port_id in (80, 443, 8080, 8443):
                tools_data.append([Paragraph("WhatWeb", s["cell"]), Paragraph("-", s["cell"]), Paragraph("Fingerprinting de tecnologias web", s["cell"])])
                break
        if any(p.port_id == 445 for p in host.ports):
            tools_data.append([Paragraph("netexec / smbclient", s["cell"]), Paragraph("-", s["cell"]), Paragraph("Enumeracion SMB y acceso a recursos compartidos", s["cell"])])
        tools_table = Table(tools_data, colWidths=[40*mm, 25*mm, 105*mm])
        tools_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), COLORS["table_header"]), ("TEXTCOLOR", (0, 0), (-1, 0), COLORS["white"]), *[("BACKGROUND", (0, i), (-1, i), COLORS["table_alt"]) for i in range(2, len(tools_data), 2)], ("GRID", (0, 0), (-1, -1), 0.5, COLORS["border"]), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
        elements.append(tools_table)
        elements.append(Spacer(1, 8*mm))
        elements.append(Paragraph("<b>Acerca de este Reporte</b>", s["h2"]))
        elements.append(Paragraph("Este reporte fue generado automaticamente por <b>autonmap v2.1</b>. Los resultados presentados se basan exclusivamente en tecnicas pasivas y de enumeracion sin explotacion activa.", s["body"]))

    def build_all(self, xml_file: str, extra_data: dict = None):
        host = parse_nmap_xml(xml_file)
        if host is None:
            print(f"[!] Error: No se pudo parsear {xml_file}")
            sys.exit(1)
        findings = generate_findings(host)
        self.build_cover_page(host)
        self.build_toc()
        self.build_executive_summary(host, findings)
        self.build_target_info(host)
        self.build_port_results(host)
        self.build_service_analysis(host)
        self.build_distribution(host)
        self.build_findings(host, findings)
        self.build_recommendations(host, findings)
        self.build_technical_details(host)
        try:
            self.doc.build(self.elements, onFirstPage=self.add_header_footer, onLaterPages=self.add_header_footer)
            print(f"[+] Reporte PDF generado exitosamente: {self.output_path}")
        except Exception as e:
            print(f"[!] Error al generar el PDF: {e}")
            sys.exit(1)
        return host


# ============================================================================
# CLI - Interfaz de linea de comandos
# ============================================================================
def show_info(host: NmapHost):
    print("=" * 60)
    print(f"  AUTONMAP - Informacion del Escaneo")
    print("=" * 60)
    print(f"  IP:            {host.ip or 'N/A'}")
    print(f"  Hostname:      {host.hostname or 'No detectado'}")
    print(f"  Estado:        {host.state}")
    print(f"  MAC:           {host.mac or 'N/A'} ({host.mac_vendor})")
    print(f"  OS:            {host.os_guess or 'No detectado'} ({host.os_accuracy}%)")
    print(f"  Fecha:         {host.scan_start}")
    print(f"  Scanner:       {host.scanner}")
    print(f"  Args:          {host.scan_args}")
    print("-" * 60)
    print(f"  Puertos abiertos:  {host.open_ports}")
    print(f"  Puertos filtrados: {host.filtered_ports}")
    print(f"  Puertos cerrados:  {host.closed_ports}")
    print(f"  Total servicios:   {host.num_services}")
    print("-" * 60)
    open_ports = [p for p in host.ports if p.state == "open"]
    if open_ports:
        print(f"  {'PORT':<8} {'PROTO':<8} {'SERVICE':<16} {'PRODUCT':<25} {'VERSION'}")
        print(f"  {'-'*8} {'-'*8} {'-'*16} {'-'*25} {'-'*15}")
        for p in open_ports:
            print(f"  {p.port_id:<8} {p.protocol.upper():<8} {p.service_name or '-':<16} {p.service_product or '-':<25} {p.service_version or '-'}")
    else:
        print("  No se detectaron puertos abiertos.")
    findings = generate_findings(host)
    print("-" * 60)
    if findings:
        print(f"  Hallazgos de seguridad: {len(findings)}")
        for f in findings:
            print(f"    [{f['risk'].upper():<8}] {f['title']}")
    else:
        print("  No se identificaron hallazgos de seguridad.")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="autonmap PDF Report Generator - Generador de reportes PDF/Markdown profesionales")
    parser.add_argument("-x", "--xml", required=True, help="Archivo XML de nmap (-oX)")
    parser.add_argument("-o", "--output", default="autonmap_report.pdf", help="Archivo de salida (PDF o MD)")
    parser.add_argument("-t", "--title", default="autonmap - Reporte de Escaneo", help="Titulo del reporte")
    parser.add_argument("--author", default="autonmap by N2O", help="Autor del reporte")
    parser.add_argument("--format", default="pdf", choices=["pdf", "md"], help="Formato de salida: pdf o md (default: pdf)")
    parser.add_argument("--info", action="store_true", help="Mostrar informacion del escaneo sin generar reporte")
    args = parser.parse_args()

    if not os.path.exists(args.xml):
        print(f"[!] Archivo XML no encontrado: {args.xml}")
        sys.exit(1)

    host = parse_nmap_xml(args.xml)
    if host is None:
        sys.exit(1)

    if args.info:
        show_info(host)
        return

    if args.format == "md":
        generate_markdown_report(host, args.output)
        return

    metadata = {"title": args.title, "author": args.author, "subject": "Reconocimiento de Red"}
    report = ReportPDF(args.output, metadata)
    report.build_all(args.xml)


if __name__ == "__main__":
    main()