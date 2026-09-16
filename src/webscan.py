"""
Web-service classification and dirsearch launching.

A host/port is treated as "web" based on nmap's own service-detection
output (-sV), not a fixed port whitelist — any service token or version
string containing "http" is considered web, with "ssl"/"tls"/"https"
indicating TLS. This catches web services on non-standard ports (8000,
9443, 8834, custom management UIs, etc.) the same way it catches :80/:443.

Dirsearch is launched either as its own tmux window (so results can be
followed live with `tmux attach -t <session>`) or, if tmux isn't
available, as a detached background process whose output is captured to
a log file.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Optional

from .config import ScanConfig
from .log import log

_warned_missing: set[str] = set()
_warn_lock = threading.Lock()


def _warn_once(key: str, message: str) -> None:
    with _warn_lock:
        if key in _warned_missing:
            return
        _warned_missing.add(key)
    log("warn", message)


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def classify_web_service(service: str, extra: str = "") -> Optional[bool]:
    """
    Inspect nmap's detected service name + version/banner string.
    Returns None if this isn't a web service, otherwise True/False for
    whether it looks TLS-wrapped (i.e. should be probed as https://).
    """
    s = (service or "").lower()
    e = (extra or "").lower()
    haystack = f"{s} {e}"

    if "http" not in haystack:
        return None

    is_tls = any(tok in haystack for tok in ("ssl/http", "https", "ssl", "tls"))
    return is_tls


def check_optional_tools(cfg: ScanConfig) -> None:
    """Warn once, up front, about any optional tooling that's missing."""
    if not cfg.dirsearch:
        return
    if not tool_available(cfg.dirsearch_bin):
        _warn_once(
            "dirsearch_bin",
            f"'{cfg.dirsearch_bin}' not found on PATH — web hosts will be detected but not "
            f"dirsearch'd. Install with: pip install dirsearch",
        )
    if cfg.dirsearch_tmux and not tool_available("tmux"):
        _warn_once(
            "tmux",
            "tmux not found — dirsearch runs will fall back to background processes "
            "(no live view). Install tmux to follow scans as they run: sudo apt install tmux",
        )


def build_dirsearch_command(url: str, cfg: ScanConfig, out_file: Path) -> list[str]:
    return [
        cfg.dirsearch_bin,
        "-u", url,
        "--user-agent", cfg.dirsearch_user_agent,
        "-w", cfg.dirsearch_wordlist,
        "-t", str(cfg.dirsearch_threads),
        "-e", cfg.dirsearch_extensions,
        "-r",
        "--exclude-status", cfg.dirsearch_exclude_status,
        "--max-rate", str(cfg.dirsearch_max_rate),
        "-o", str(out_file),
        "--format", "plain",
    ]


def _ensure_tmux_session(session: str) -> None:
    has = subprocess.run(
        ["tmux", "has-session", "-t", session],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if has.returncode != 0:
        subprocess.run(
            ["tmux", "new-session", "-d", "-s", session, "-n", "owlscan"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )


def launch_dirsearch(ip: str, port: str, is_tls: bool, cfg: ScanConfig) -> Optional[str]:
    """
    Fire off a dirsearch run against ip:port. Returns a short status string
    describing where to find it ("tmux:<session>:<window>" or a log file
    path), or None if dirsearch couldn't be launched at all.
    """
    if not tool_available(cfg.dirsearch_bin):
        check_optional_tools(cfg)  # emits the "install dirsearch" warning once
        return None

    scheme = "https" if is_tls else "http"
    url = f"{scheme}://{ip}:{port}/"

    out_dir = cfg.output_dir / "dirsearch"
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_ip = ip.replace(":", "_")  # IPv6-safe
    out_file = out_dir / f"{safe_ip}_{port}.txt"
    cmd = build_dirsearch_command(url, cfg, out_file)

    if cfg.dirsearch_tmux and tool_available("tmux"):
        # tmux target strings use "session:window.pane" — a "." in the window
        # name (e.g. a bare IPv4 address) makes tmux misparse the target when
        # addressing the window directly, so dashes replace dots here.
        window_name = f"{safe_ip}_{port}"[:40].replace(".", "-")
        _ensure_tmux_session(cfg.dirsearch_session)
        dirsearch_cmd = " ".join(shlex.quote(c) for c in cmd)
        # tmux closes a window the instant its pane's process exits, which
        # would yank the results off-screen the moment dirsearch finishes.
        # Wrap it so the window stays open (with a clear banner) until the
        # user dismisses it.
        shell_cmd = (
            f"{dirsearch_cmd}; "
            f"echo; echo '--- dirsearch finished ({url}) — results also saved to {out_file} ---'; "
            f"echo 'Press Enter to close this window.'; read _"
        )
        subprocess.run(
            ["tmux", "new-window", "-t", cfg.dirsearch_session, "-n", window_name, "bash", "-c", shell_cmd],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        log("ok", f"dirsearch → [bold cyan]{url}[/bold cyan]  "
                   f"(tmux: attach with `tmux attach -t {cfg.dirsearch_session}`, window '{window_name}')")
        return f"tmux:{cfg.dirsearch_session}:{window_name}"

    if cfg.dirsearch_tmux:
        check_optional_tools(cfg)  # emits the "tmux not found" warning once

    log_file = out_dir / f"{safe_ip}_{port}.log"
    try:
        with open(log_file, "w") as fh:
            subprocess.Popen(
                cmd, stdout=fh, stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        log("ok", f"dirsearch → [bold cyan]{url}[/bold cyan]  (background, log: {log_file})")
        return f"bg:{log_file}"
    except FileNotFoundError:
        log("err", f"Failed to launch dirsearch for {url}: '{cfg.dirsearch_bin}' not found")
        return None
    except Exception as e:
        log("err", f"Failed to launch dirsearch for {url}: {e}")
        return None