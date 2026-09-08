"""
Report writers for OwlScan: JSON, JSON Lines, Markdown, Markmap mindmap,
and (optionally) Excel via openpyxl.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from . import __version__
from .config import ScanConfig
from .engine import findings, sort_key_ip
from .log import console, log

try:
    import openpyxl
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.utils import get_column_letter
    HAS_OPENPYXL = True
except ImportError:
    HAS_OPENPYXL = False


def _meta(cfg: ScanConfig) -> dict:
    return {
        "tool": "OwlScan",
        "version": __version__,
        "scan_started": cfg.scan_start.strftime("%Y-%m-%d %H:%M:%S") if cfg.scan_start else "—",
        "scan_ended": cfg.scan_end.strftime("%Y-%m-%d %H:%M:%S") if cfg.scan_end else "—",
        "scan_duration": cfg.scan_duration,
        "evasion_profile": cfg.evasion_profile,
        "masscan_rate": cfg.masscan_rate,
        "nmap_threads": cfg.nmap_threads,
        "nmap_timeout": cfg.nmap_timeout,
    }


def generate_json(out_dir: Path, cfg: ScanConfig) -> Path:
    data = {**_meta(cfg), "hosts": findings}
    path = out_dir / "owlscan_findings.json"
    path.write_text(json.dumps(data, indent=2))
    log("ok", f"JSON report → {path}")
    return path


def generate_jsonl(out_dir: Path, cfg: ScanConfig, target_label: str) -> Path:
    """One JSON object per host, one line per host — always written."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target_label.replace("/", "_").replace(":", "_")
    path = out_dir / f"{safe_target}_{ts}.jsonl"
    with open(path, "w") as f:
        for ip, data in sorted(findings.items(), key=lambda x: sort_key_ip(x[0])):
            services = {p.split("/")[0]: data["services"].get(p.split("/")[0], "") for p in data["ports"]}
            record = {
                "ip": ip,
                "open_ports": sorted(int(p.split("/")[0]) for p in data["ports"]),
                "services": services,
                "honeypot": data["honeypot"],
                "evasion": cfg.evasion_profile,
                "timestamp": datetime.now().isoformat(timespec="seconds"),
            }
            f.write(json.dumps(record) + "\n")
    log("ok", f"JSON Lines report → {path}")
    return path


def print_json_console(cfg: ScanConfig) -> None:
    """Dump one big JSON array to the console instead of the rich table."""
    records = []
    for ip, data in sorted(findings.items(), key=lambda x: sort_key_ip(x[0])):
        services = {p.split("/")[0]: data["services"].get(p.split("/")[0], "") for p in data["ports"]}
        records.append({
            "ip": ip,
            "open_ports": sorted(int(p.split("/")[0]) for p in data["ports"]),
            "services": services,
            "honeypot": data["honeypot"],
        })
    console.print_json(json.dumps(records))


def generate_markdown(out_dir: Path, cfg: ScanConfig) -> Path:
    ts = cfg.scan_start.strftime("%Y-%m-%d %H:%M:%S") if cfg.scan_start else "—"
    lines = [
        f"# OwlScan — Findings Report",
        "",
        f"**Scan started:** {ts}  ",
        f"**Scan duration:** {cfg.scan_duration}  ",
        f"**Evasion profile:** {cfg.evasion_profile}  ",
        f"**Masscan rate:** {cfg.masscan_rate} pps  ",
        f"**Nmap threads:** {cfg.nmap_threads}  ",
        f"**Nmap timeout:** {cfg.nmap_timeout}s per host  ",
        "",
        "---",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Hosts discovered | {len(findings)} |",
        f"| Suspected honeypots | {sum(1 for v in findings.values() if v['honeypot'])} |",
        f"| Total open ports | {sum(len(v['ports']) for v in findings.values())} |",
        "",
        "---",
        "",
        "## Host Details",
        "",
    ]
    for ip, data in sorted(findings.items(), key=lambda x: sort_key_ip(x[0])):
        honey = "  ⚠️ **Suspected Honeypot**" if data["honeypot"] else ""
        lines.append(f"### {ip}{honey}")
        lines.append("")
        lines.append("| Port | Service / Banner |")
        lines.append("|------|-------------------|")
        for port in sorted(data["ports"], key=lambda p: int(p.split("/")[0])):
            port_num = port.split("/")[0]
            svc = data["services"].get(port_num, "—")
            lines.append(f"| `{port}` | {svc} |")
        lines.append("")

    path = out_dir / "owlscan_report.md"
    path.write_text("\n".join(lines))
    log("ok", f"Markdown report → {path}")
    return path


def generate_mindmap(out_dir: Path, cfg: ScanConfig) -> Path:
    ts = cfg.scan_start.strftime("%Y-%m-%d %H:%M:%S") if cfg.scan_start else "—"
    lines = [
        "---",
        "markmap:",
        "  colorFreezeLevel: 2",
        "---",
        "",
        f"# OwlScan  ({ts})",
        "",
        f"## Profile: {cfg.evasion_profile}",
        f"## Duration: {cfg.scan_duration}",
        "",
        f"## Hosts ({len(findings)} discovered)",
        "",
    ]
    for ip, data in sorted(findings.items(), key=lambda x: sort_key_ip(x[0])):
        honey_tag = " ⚠️" if data["honeypot"] else ""
        lines.append(f"### {ip}{honey_tag}")
        for port in sorted(data["ports"], key=lambda p: int(p.split("/")[0])):
            port_num = port.split("/")[0]
            svc = data["services"].get(port_num, "")
            svc_label = f" — {svc}" if svc else ""
            lines.append(f"#### {port}{svc_label}")
    lines.append("")

    path = out_dir / "owlscan_mindmap.md"
    path.write_text("\n".join(lines))
    log("ok", f"Mind-map (Markmap) → {path}")
    return path


def generate_xlsx(out_dir: Path, cfg: ScanConfig) -> Optional[Path]:
    if not HAS_OPENPYXL:
        log("warn", "openpyxl not installed — skipping Excel output. Install with: pip install owlscan[excel]")
        return None

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Findings"
    headers = ["Host", "Port", "Protocol", "Service / Version", "Honeypot", "Raw Nmap Line"]
    widths = [18, 10, 12, 40, 12, 50]
    for col_idx, (h, w) in enumerate(zip(headers, widths), 1):
        ws.column_dimensions[get_column_letter(col_idx)].width = w
        cell = ws.cell(row=1, column=col_idx, value=h)
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor="1A1A2E")
        cell.alignment = Alignment(horizontal="center")

    row = 2
    for ip, data in sorted(findings.items(), key=lambda x: sort_key_ip(x[0])):
        for port in sorted(data["ports"], key=lambda p: int(p.split("/")[0])):
            port_num, proto = (port.split("/") + ["tcp"])[:2]
            svc = data["services"].get(port_num, "")
            ws.cell(row=row, column=1, value=ip)
            ws.cell(row=row, column=2, value=int(port_num))
            ws.cell(row=row, column=3, value=proto)
            ws.cell(row=row, column=4, value=svc)
            ws.cell(row=row, column=5, value="YES" if data["honeypot"] else "")
            ws.cell(row=row, column=6, value=svc)
            row += 1

    path = out_dir / "owlscan_report.xlsx"
    wb.save(str(path))
    log("ok", f"Excel report → {path}")
    return path


def generate_outputs(out_dir: Path, cfg: ScanConfig, target_label: str) -> None:
    if not findings:
        log("warn", "No findings to report — output files skipped")
        return
    out_dir.mkdir(parents=True, exist_ok=True)

    # JSON Lines is always written, per host, regardless of --output-formats
    generate_jsonl(out_dir, cfg, target_label)

    for fmt in cfg.output_formats:
        if fmt == "json":
            generate_json(out_dir, cfg)
        elif fmt == "md":
            generate_markdown(out_dir, cfg)
        elif fmt == "mindmap":
            generate_mindmap(out_dir, cfg)
        elif fmt == "xlsx":
            generate_xlsx(out_dir, cfg)

    if cfg.excel and "xlsx" not in cfg.output_formats:
        generate_xlsx(out_dir, cfg)