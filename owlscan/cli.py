"""
OwlScan command-line interface.

    owlscan scan --target 10.0.0.0/24 --ports 1-65535 --evasion stealth --output ./reports/
    owlscan honeypot --input report.json
    owlscan config show
    owlscan config set evasion=paranoid
    owlscan version

Interactive mode (the original prompt-driven wizard) is still available as
a hidden fallback via `owlscan --interactive`, or automatically when `scan`
is invoked with no --target.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import signal
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from . import __version__
from .config import DEFAULTS, EVASION_PROFILES, ScanConfig, resolve_defaults, resolve_masscan_rate
from .engine import check_tools, findings, get_network_size, is_root, reset_findings, run_masscan, sort_key_ip
from .log import banner, console, log, setup_file_logger
from .output import generate_outputs, print_json_console

# ── Exit codes ────────────────────────────────────────────────────────────
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_HONEYPOT = 2
EXIT_NO_OPEN_PORTS = 3
EXIT_INTERRUPTED = 4


# ─────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────
def _write_config_toml(path: Path, data: dict) -> None:
    lines = ["[scan]"]
    for k, v in data.items():
        if k.startswith("_"):
            continue
        if isinstance(v, str):
            lines.append(f'{k} = "{v}"')
        elif isinstance(v, bool):
            lines.append(f"{k} = {'true' if v else 'false'}")
        elif isinstance(v, list):
            rendered = ", ".join(f'"{x}"' for x in v)
            lines.append(f"{k} = [{rendered}]")
        elif v is None:
            continue
        else:
            lines.append(f"{k} = {v}")
    path.write_text("\n".join(lines) + "\n")


def _build_config(
    config_path: Optional[Path],
    target: Optional[str],
    ports: Optional[str],
    evasion: Optional[str],
    output: Optional[str],
    threads: Optional[int],
    timeout: Optional[int],
    honeypot_threshold: Optional[int],
    decoys: Optional[str],
    interface: Optional[str],
    formats: Optional[str],
    masscan_rate: Optional[int],
    log_file: Optional[str],
    json_console: bool,
    excel: bool,
    docker: bool,
) -> ScanConfig:
    merged = resolve_defaults(config_path)

    evasion_final = evasion or merged["evasion"]
    if evasion_final not in EVASION_PROFILES:
        raise click.ClickException(
            f"Unknown evasion profile '{evasion_final}'. Choices: {', '.join(EVASION_PROFILES)}"
        )

    rate_final = masscan_rate if masscan_rate is not None else merged["masscan_rate"]
    rate_final = resolve_masscan_rate(evasion_final, rate_final)

    formats_final = [f.strip() for f in formats.split(",")] if formats else merged["output_formats"]

    cfg = ScanConfig(
        ranges=[target] if target else [],
        ports=ports or "",
        interface=interface or merged["interface"],
        evasion_profile=evasion_final,
        masscan_rate=rate_final,
        nmap_threads=threads or merged["nmap_threads"],
        nmap_timeout=timeout or merged["nmap_timeout"],
        honeypot_threshold=honeypot_threshold or merged["honeypot_threshold"],
        decoy_list=decoys or merged["decoy_list"],
        output_formats=formats_final,
        output_dir=Path(output or merged["output_dir"]),
        log_file=Path(log_file) if log_file else (Path(merged["log_file"]) if merged["log_file"] else None),
        json_console=json_console,
        excel=excel,
        docker=docker,
    )
    return cfg


def _root_hint() -> None:
    if not is_root():
        if sys.platform == "win32":
            log("warn", "Not running as Administrator — raw-socket scans (masscan, nmap -sS) need it.")
        else:
            log("warn", "Not running as root — masscan and nmap -sS require it. Re-run with sudo.")


def _maybe_run_via_docker(cfg: ScanConfig, argv: list[str]) -> Optional[int]:
    """If --docker was requested (or tools are missing and docker is available),
    re-exec the scan inside the bundled container. Returns an exit code, or
    None if the caller should continue running natively."""
    if not cfg.docker:
        return None
    if not check_tools() == []:
        pass  # tools missing natively is exactly why --docker was passed
    if not _tool_on_path("docker"):
        raise click.ClickException("--docker was requested but the `docker` binary is not on PATH.")

    image = "owlscan:local"
    cwd = str(Path.cwd())
    cmd = [
        "docker", "run", "--rm", "--cap-add=NET_RAW", "--cap-add=NET_ADMIN",
        "--network", "host",
        "-v", f"{cwd}:/app/reports",
        image,
    ] + [a for a in argv if a != "--docker"]
    log("info", f"Delegating to Docker image {image} …")
    result = subprocess.run(cmd)
    return result.returncode


def _tool_on_path(name: str) -> bool:
    from shutil import which
    return which(name) is not None


# ─────────────────────────────────────────────
# CLI group
# ─────────────────────────────────────────────
@click.group(invoke_without_command=True)
@click.option("--interactive", is_flag=True, help="Force the legacy interactive wizard instead of a subcommand.")
@click.pass_context
def cli(ctx: click.Context, interactive: bool) -> None:
    """OwlScan — internal pentest network segmentation scanner (masscan + nmap)."""
    if ctx.invoked_subcommand is None:
        if interactive:
            ctx.exit(_run_interactive_wizard())
        click.echo(ctx.get_help())
        ctx.exit(EXIT_OK)


@cli.command()
def version() -> None:
    """Print the OwlScan version."""
    click.echo(f"owlscan {__version__}")


# ─────────────────────────────────────────────
# scan
# ─────────────────────────────────────────────
@cli.command()
@click.option("--target", help="Target CIDR to scan, e.g. 10.0.0.0/24. Omit to fall back to the interactive wizard.")
@click.option("--ports", help="Ports for masscan discovery, e.g. 1-65535 or 22,80,443.")
@click.option("--evasion", type=click.Choice(list(EVASION_PROFILES)), help="Evasion profile to use.")
@click.option("--output", "output_dir", help="Directory to write reports and raw scan files into.")
@click.option("--threads", type=int, help="Concurrent nmap worker threads.")
@click.option("--timeout", type=int, help="Per-host nmap timeout in seconds.")
@click.option("--honeypot-threshold", type=int, help="Open-port count above which a host is flagged as a honeypot.")
@click.option("--decoys", help="Comma-separated nmap decoy IPs (-D), e.g. 10.0.0.1,10.0.0.2,ME.")
@click.option("--interface", help="Network interface for masscan to bind to.")
@click.option("--formats", help="Comma-separated report formats to generate: json,md,mindmap,xlsx.")
@click.option("--masscan-rate", type=int, help="Override the evasion profile's masscan packet rate (pps).")
@click.option("--config", "config_path", type=click.Path(path_type=Path), help="Path to an owlscan.toml config file.")
@click.option("--log-file", help="Write a DEBUG-level session log to this path.")
@click.option("--json", "json_console", is_flag=True, help="Print console output as one JSON array instead of a table.")
@click.option("--excel", is_flag=True, help="Also write an .xlsx report (requires openpyxl).")
@click.option("--docker", is_flag=True, help="Run masscan/nmap inside the bundled Docker image instead of natively.")
@click.option("--yes", "-y", is_flag=True, help="Skip the confirmation prompt.")
@click.pass_context
def scan(
    ctx: click.Context,
    target: Optional[str],
    ports: Optional[str],
    evasion: Optional[str],
    output_dir: Optional[str],
    threads: Optional[int],
    timeout: Optional[int],
    honeypot_threshold: Optional[int],
    decoys: Optional[str],
    interface: Optional[str],
    formats: Optional[str],
    masscan_rate: Optional[int],
    config_path: Optional[Path],
    log_file: Optional[str],
    json_console: bool,
    excel: bool,
    docker: bool,
    yes: bool,
) -> None:
    """Discover hosts with masscan, then deep-scan each with nmap."""
    if not target:
        sys.exit(_run_interactive_wizard())

    try:
        ipaddress.ip_network(target, strict=False)
    except ValueError:
        raise click.ClickException(f"'{target}' is not a valid CIDR (e.g. 10.0.0.0/24).")

    cfg = _build_config(
        config_path, target, ports, evasion, output_dir, threads, timeout,
        honeypot_threshold, decoys, interface, formats, masscan_rate, log_file,
        json_console, excel, docker,
    )
    if not cfg.ports:
        raise click.ClickException("--ports is required, e.g. --ports 1-1000")

    if cfg.docker:
        code = _maybe_run_via_docker(cfg, sys.argv[1:])
        if code is not None:
            sys.exit(code)
    else:
        missing = check_tools()
        if missing:
            log("err", f"Missing tools: {', '.join(missing)}")
            log("info", f"Install: sudo apt install {' '.join(missing)}")
            log("info", "…or re-run this command with --docker to use the bundled image.")
            sys.exit(EXIT_ERROR)

    setup_file_logger(cfg.log_file)
    banner(target, cfg.evasion_profile, __version__)
    _root_hint()
    reset_findings()

    log("info", f"Ports          : {cfg.ports}")
    log("info", f"Evasion profile: {cfg.evasion_profile}  ({EVASION_PROFILES[cfg.evasion_profile]['description']})")
    log("info", f"Masscan rate   : {cfg.masscan_rate} pps")
    log("info", f"Nmap threads   : {cfg.nmap_threads}")
    log("info", f"Output dir     : {cfg.output_dir}")

    if not yes:
        if not click.confirm("\nStart scan?", default=True):
            log("info", "Aborted by user.")
            sys.exit(EXIT_OK)

    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    cfg.scan_start = datetime.now()

    exit_code = EXIT_OK
    try:
        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TimeElapsedColumn(), console=console, transient=False,
        ) as progress:
            task = progress.add_task(f"Scanning {target}", total=None)
            result = run_masscan(target, cfg.ports, cfg)
            progress.update(task, completed=1, total=1)

        if result.error:
            exit_code = EXIT_ERROR
        elif result.paused:
            exit_code = EXIT_INTERRUPTED
        elif not findings:
            log("warn", "No open ports found.")
            exit_code = EXIT_NO_OPEN_PORTS
        elif any(v["honeypot"] for v in findings.values()):
            exit_code = EXIT_HONEYPOT
    except KeyboardInterrupt:
        log("warn", "Interrupted by user.")
        exit_code = EXIT_INTERRUPTED

    cfg.scan_end = datetime.now()
    log("ok", f"Scan finished in {cfg.scan_duration}")

    generate_outputs(cfg.output_dir, cfg, target)

    if cfg.json_console:
        print_json_console(cfg)
    else:
        _print_summary_table()

    sys.exit(exit_code)


def _print_summary_table() -> None:
    table = Table(title="OwlScan Results")
    table.add_column("Host")
    table.add_column("Open Ports")
    table.add_column("Services")
    table.add_column("Honeypot?")
    for ip, data in sorted(findings.items(), key=lambda x: sort_key_ip(x[0])):
        ports_str = ", ".join(sorted(data["ports"], key=lambda p: int(p.split("/")[0])))
        services_str = ", ".join(f"{p}:{s}" for p, s in list(data["services"].items())[:3]) or "—"
        table.add_row(ip, ports_str or "—", services_str, "⚠️ YES" if data["honeypot"] else "—")
    console.print(table)


# ─────────────────────────────────────────────
# honeypot — re-run heuristics on a saved report
# ─────────────────────────────────────────────
@cli.command()
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, path_type=Path),
              help="A previously written owlscan_findings.json report.")
@click.option("--threshold", type=int, default=None, help="Override the honeypot open-port threshold.")
def honeypot(input_path: Path, threshold: Optional[int]) -> None:
    """Re-run honeypot heuristics against a saved JSON report."""
    data = json.loads(input_path.read_text())
    hosts = data.get("hosts", {})
    limit = threshold if threshold is not None else DEFAULTS["honeypot_threshold"]

    table = Table(title=f"Honeypot re-check (threshold={limit})")
    table.add_column("Host")
    table.add_column("Open Ports")
    table.add_column("Flagged?")

    flagged_any = False
    for ip, entry in sorted(hosts.items()):
        count = len(entry.get("ports", []))
        flagged = count > limit
        flagged_any = flagged_any or flagged
        table.add_row(ip, str(count), "⚠️ YES" if flagged else "—")
    console.print(table)
    sys.exit(EXIT_HONEYPOT if flagged_any else EXIT_OK)


# ─────────────────────────────────────────────
# config
# ─────────────────────────────────────────────
@cli.group()
def config() -> None:
    """View or edit OwlScan configuration."""


@config.command("show")
@click.option("--config", "config_path", type=click.Path(path_type=Path), help="Path to an owlscan.toml config file.")
def config_show(config_path: Optional[Path]) -> None:
    """Print the resolved configuration (defaults <- file <- env)."""
    merged = resolve_defaults(config_path)
    used = merged.pop("_config_file_used", None)
    console.print(f"Config file: [cyan]{used or '(none found — using built-in defaults)'}[/cyan]")
    table = Table(title="Resolved Configuration")
    table.add_column("Key")
    table.add_column("Value")
    for k, v in merged.items():
        table.add_row(k, str(v))
    console.print(table)

    table2 = Table(title="Evasion Profiles")
    table2.add_column("Profile")
    table2.add_column("Masscan Rate")
    table2.add_column("Nmap Timing")
    table2.add_column("Description")
    for name, p in EVASION_PROFILES.items():
        table2.add_row(name, str(p["masscan_rate"]), f"T{p['nmap_timing']}", p["description"])
    console.print(table2)


@config.command("set")
@click.argument("keyvalue")
@click.option("--config", "config_path", type=click.Path(path_type=Path), default=None,
              help="Config file to write to (defaults to ./owlscan.toml).")
def config_set(keyvalue: str, config_path: Optional[Path]) -> None:
    """Set a config value, e.g. `owlscan config set evasion=paranoid`."""
    if "=" not in keyvalue:
        raise click.ClickException("Expected KEY=VALUE, e.g. evasion=paranoid")
    key, value = keyvalue.split("=", 1)
    key = key.strip()
    value = value.strip()
    if key not in DEFAULTS:
        raise click.ClickException(f"Unknown config key '{key}'. Valid keys: {', '.join(DEFAULTS)}")

    target_path = config_path or (Path.cwd() / "owlscan.toml")
    merged = resolve_defaults(target_path if target_path.exists() else None)
    merged.pop("_config_file_used", None)

    if key in {"masscan_rate", "nmap_threads", "nmap_timeout", "honeypot_threshold"}:
        merged[key] = int(value)
    elif key == "output_formats":
        merged[key] = [v.strip() for v in value.split(",")]
    else:
        merged[key] = value

    _write_config_toml(target_path, merged)
    log("ok", f"Set {key} = {value} in {target_path}")


# ─────────────────────────────────────────────
# Interactive fallback (legacy wizard, condensed)
# ─────────────────────────────────────────────
def _run_interactive_wizard() -> int:
    console.print("[bold]OwlScan interactive wizard[/bold]  (no --target given; falling back to prompts)\n")
    try:
        raw_ranges = click.prompt("Target CIDR(s), comma-separated")
        ranges = []
        for r in [x.strip() for x in raw_ranges.split(",") if x.strip()]:
            try:
                ipaddress.ip_network(r, strict=False)
                ranges.append(r)
            except ValueError:
                log("warn", f"Invalid CIDR skipped: {r}")
        if not ranges:
            log("err", "No valid ranges provided.")
            return EXIT_ERROR

        ports = click.prompt("Ports (e.g. 1-1000 or 22,80,443)")
        evasion_choice = click.prompt(
            "Evasion profile", type=click.Choice(list(EVASION_PROFILES)), default="none"
        )
        output_dir = click.prompt("Output directory", default="owl_hunts")
        threads = click.prompt("Nmap threads", default=10, type=int)
        timeout = click.prompt("Nmap per-host timeout (s)", default=600, type=int)
        honeypot_thresh = click.prompt("Honeypot port-count threshold", default=100, type=int)
    except (click.Abort, EOFError, KeyboardInterrupt):
        console.print()
        return EXIT_INTERRUPTED

    cfg = ScanConfig(
        ranges=ranges, ports=ports, evasion_profile=evasion_choice,
        masscan_rate=EVASION_PROFILES[evasion_choice]["masscan_rate"],
        nmap_threads=threads, nmap_timeout=timeout, honeypot_threshold=honeypot_thresh,
        output_formats=["json"], output_dir=Path(output_dir),
    )

    missing = check_tools()
    if missing:
        log("err", f"Missing tools: {', '.join(missing)}")
        return EXIT_ERROR

    setup_file_logger(None)
    _root_hint()
    reset_findings()
    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    cfg.scan_start = datetime.now()

    exit_code = EXIT_OK
    for cidr in cfg.ranges:
        log("scan", f"Processing range: {cidr}")
        result = run_masscan(cidr, cfg.ports, cfg)
        if result.error:
            exit_code = EXIT_ERROR
        elif result.paused:
            exit_code = EXIT_INTERRUPTED

    cfg.scan_end = datetime.now()
    if exit_code == EXIT_OK:
        if not findings:
            exit_code = EXIT_NO_OPEN_PORTS
        elif any(v["honeypot"] for v in findings.values()):
            exit_code = EXIT_HONEYPOT

    generate_outputs(cfg.output_dir, cfg, "_".join(cfg.ranges))
    _print_summary_table()
    return exit_code


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────
def main() -> None:
    try:
        cli(standalone_mode=False)
    except click.ClickException as e:
        e.show()
        sys.exit(e.exit_code if hasattr(e, "exit_code") else EXIT_ERROR)
    except click.exceptions.Exit as e:
        sys.exit(e.exit_code)
    except KeyboardInterrupt:
        log("warn", "Interrupted.")
        sys.exit(EXIT_INTERRUPTED)


if __name__ == "__main__":
    main()