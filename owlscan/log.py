"""
Console and file logging for OwlScan.

- `console` (rich.console.Console) drives all human-facing stdout: coloured
  tags, progress bars, and the final results table.
- `loguru`'s logger drives the DEBUG-level file sink, so the on-disk log has
  timestamps, levels, and full detail regardless of what's printed to screen.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from loguru import logger
from rich.console import Console

console = Console()

_TAGS = {
    "info": "[bold blue][*][/bold blue]",
    "ok": "[bold green][+][/bold green]",
    "warn": "[bold yellow][!][/bold yellow]",
    "err": "[bold red][-][/bold red]",
    "scan": "[bold magenta][~][/bold magenta]",
    "nmap": "[bold cyan][N][/bold cyan]",
}

_LOGURU_LEVELS = {
    "info": "INFO",
    "ok": "SUCCESS",
    "warn": "WARNING",
    "err": "ERROR",
    "scan": "DEBUG",
    "nmap": "DEBUG",
}

_configured = False


def setup_file_logger(log_path: Optional[Path]) -> Optional[Path]:
    """Attach a DEBUG-level loguru sink writing to log_path. No-op if None."""
    global _configured
    logger.remove()  # clear any default stderr sink
    if log_path is None:
        _configured = True
        return None

    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger.add(
        str(log_path),
        level="DEBUG",
        format="{time:YYYY-MM-DD HH:mm:ss}  {level: <8}  {message}",
        enqueue=True,
        backtrace=False,
        diagnose=False,
    )
    _configured = True
    return log_path


def log(level: str, msg: str) -> None:
    """
    Print a tagged, coloured line to the rich console and mirror a plain
    (markup-stripped) copy to the loguru file sink, if configured.
    """
    tag = _TAGS.get(level, "[bold white][?][/bold white]")
    console.print(f"{tag} {msg}", highlight=False)

    if _configured:
        plain = console.render_str(msg).plain
        loguru_level = _LOGURU_LEVELS.get(level, "DEBUG")
        logger.log(loguru_level, f"[{level.upper()}] {plain}")


def banner(target: str, evasion: str, version: str) -> None:
    console.print(f"[bold red]owlscan[/bold red] v{version}  "
                  f"(target: [yellow]{target}[/yellow], evasion: [yellow]{evasion}[/yellow])")