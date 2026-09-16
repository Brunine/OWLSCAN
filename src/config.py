"""
Configuration system for OwlScan.

Resolution order (highest priority first):
  1. Explicit CLI flags (applied by the caller, in cli.py)
  2. --config <path> file
  3. ./owlscan.toml in the current working directory
  4. ~/.config/owlscan/owlscan.toml
  5. Built-in defaults (EVASION_PROFILES + DEFAULTS below)

Environment variables (OWLSCAN_*) override the config file but are
themselves overridden by explicit CLI flags.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Optional

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]

# ─────────────────────────────────────────────
# Evasion profiles (built-in defaults)
# ─────────────────────────────────────────────
EVASION_PROFILES: dict[str, dict[str, Any]] = {
    "none": {
        "masscan_rate": 1000,
        "nmap_timing": 4,
        "nmap_extra": [],
        "description": "No evasion — fast, noisy (default)",
    },
    "stealth": {
        "masscan_rate": 200,
        "nmap_timing": 2,
        "nmap_extra": [
            "-f",
            "--data-length", "24",
            "--randomize-hosts",
            "--source-port", "53",
            "--ttl", "64",
        ],
        "description": "Fragmented + padded packets, DNS source-port, T2 timing",
    },
    "paranoid": {
        "masscan_rate": 50,
        "nmap_timing": 1,
        "nmap_extra": [
            "-f", "-f",
            "--data-length", "48",
            "--randomize-hosts",
            "--source-port", "443",
            "--ttl", "128",
            "--scan-delay", "500ms",
        ],
        "description": "Double-fragmented, HTTPS source-port, 500ms probe delay, T1 timing",
    },
    "docker": {
        "masscan_rate": 500,
        "nmap_timing": 3,
        "nmap_extra": [
            "-Pn",
            "--defeat-rst-ratelimit",
            "-sT",
        ],
        "description": "Docker-optimised: -Pn, TCP-connect, defeat RST rate-limit",
    },
}

# Non-evasion defaults
DEFAULTS: dict[str, Any] = {
    "evasion": "none",
    "masscan_rate": None,          # None => use the profile's own rate
    "nmap_threads": 10,
    "nmap_timeout": 600,
    "honeypot_threshold": 100,
    "decoy_list": None,
    "output_dir": "owl_hunts",
    "output_formats": ["json"],
    "interface": None,
    "log_file": None,
    # Dirsearch (web content discovery), auto-triggered off nmap's own
    # service detection rather than a fixed port list.
    "dirsearch": True,
    "dirsearch_bin": "dirsearch",
    "dirsearch_wordlist": "/usr/share/wordlists/dirbuster_wordlist/directory-list-2.3-medium.txt",
    "dirsearch_threads": 5,
    "dirsearch_extensions": "html,json,js,txt,bkp,php,jsp,asp,aspx",
    "dirsearch_exclude_status": "404,400",
    "dirsearch_max_rate": 100,
    "dirsearch_user_agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36 (Pentest Access Security)"
    ),
    "dirsearch_tmux": True,
    "dirsearch_session": "owlscan",
}

_ENV_PREFIX = "OWLSCAN_"

# Maps OWLSCAN_<KEY> (upper snake case, minus prefix) -> DEFAULTS key
_ENV_KEYS = {
    "EVASION": "evasion",
    "MASSCAN_RATE": "masscan_rate",
    "NMAP_THREADS": "nmap_threads",
    "NMAP_TIMEOUT": "nmap_timeout",
    "HONEYPOT_THRESHOLD": "honeypot_threshold",
    "DECOY_LIST": "decoy_list",
    "OUTPUT_DIR": "output_dir",
    "INTERFACE": "interface",
    "LOG_FILE": "log_file",
    "DIRSEARCH": "dirsearch",
    "DIRSEARCH_BIN": "dirsearch_bin",
    "DIRSEARCH_WORDLIST": "dirsearch_wordlist",
    "DIRSEARCH_THREADS": "dirsearch_threads",
    "DIRSEARCH_EXTENSIONS": "dirsearch_extensions",
    "DIRSEARCH_EXCLUDE_STATUS": "dirsearch_exclude_status",
    "DIRSEARCH_MAX_RATE": "dirsearch_max_rate",
    "DIRSEARCH_USER_AGENT": "dirsearch_user_agent",
    "DIRSEARCH_TMUX": "dirsearch_tmux",
    "DIRSEARCH_SESSION": "dirsearch_session",
}

_INT_KEYS = {
    "masscan_rate", "nmap_threads", "nmap_timeout", "honeypot_threshold",
    "dirsearch_threads", "dirsearch_max_rate",
}
_BOOL_KEYS = {"dirsearch", "dirsearch_tmux"}


@dataclass
class ScanConfig:
    """Fully-resolved runtime configuration for a scan."""

    ranges: list[str] = field(default_factory=list)
    ports: str = ""
    interface: Optional[str] = None
    evasion_profile: str = "none"
    masscan_rate: int = 1000
    nmap_threads: int = 10
    nmap_timeout: int = 600
    honeypot_threshold: int = 100
    decoy_list: Optional[str] = None
    output_formats: list[str] = field(default_factory=lambda: ["json"])
    output_dir: Path = Path("owl_hunts")
    log_file: Optional[Path] = None
    json_console: bool = False
    excel: bool = False
    docker: bool = False
    dirsearch: bool = True
    dirsearch_bin: str = "dirsearch"
    dirsearch_wordlist: str = "/usr/share/wordlists/dirbuster_wordlist/directory-list-2.3-medium.txt"
    dirsearch_threads: int = 5
    dirsearch_extensions: str = "html,json,js,txt,bkp,php,jsp,asp,aspx"
    dirsearch_exclude_status: str = "404,400"
    dirsearch_max_rate: int = 100
    dirsearch_user_agent: str = ""
    dirsearch_tmux: bool = True
    dirsearch_session: str = "owlscan"
    scan_start: Optional[object] = None
    scan_end: Optional[object] = None

    @property
    def scan_duration(self) -> str:
        if self.scan_start and self.scan_end:
            delta = self.scan_end - self.scan_start
            h, rem = divmod(int(delta.total_seconds()), 3600)
            m, s = divmod(rem, 60)
            return f"{h:02d}:{m:02d}:{s:02d}"
        return "—"


def _candidate_config_paths(explicit: Optional[Path]) -> list[Path]:
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    candidates.append(Path.cwd() / "owlscan.toml")
    candidates.append(Path.home() / ".config" / "owlscan" / "owlscan.toml")
    return candidates


def load_config_file(explicit: Optional[Path] = None) -> tuple[dict[str, Any], Optional[Path]]:
    """Find and parse the first available owlscan.toml. Returns (data, path_used)."""
    for path in _candidate_config_paths(explicit):
        if path.is_file():
            with open(path, "rb") as fh:
                data = tomllib.load(fh)
            return data, path
        if explicit is not None and path == Path(explicit):
            # user explicitly pointed at a file that doesn't exist
            raise FileNotFoundError(f"Config file not found: {path}")
    return {}, None


def load_env_overrides() -> dict[str, Any]:
    overrides: dict[str, Any] = {}
    for env_suffix, key in _ENV_KEYS.items():
        raw = os.environ.get(f"{_ENV_PREFIX}{env_suffix}")
        if raw is None:
            continue
        if key in _INT_KEYS:
            try:
                overrides[key] = int(raw)
            except ValueError:
                continue
        elif key in _BOOL_KEYS:
            overrides[key] = raw.strip().lower() in {"1", "true", "yes", "on"}
        else:
            overrides[key] = raw
    return overrides


def resolve_defaults(config_path: Optional[Path] = None) -> dict[str, Any]:
    """
    Merge built-in defaults <- config file <- environment variables.
    CLI flags are applied on top of this by cli.py (highest priority).
    """
    merged = dict(DEFAULTS)

    file_data, used_path = load_config_file(config_path)
    if "scan" in file_data:
        merged.update(file_data["scan"])
    else:
        merged.update({k: v for k, v in file_data.items() if k in DEFAULTS})

    global EVASION_PROFILES
    if "evasion_profiles" in file_data:
        EVASION_PROFILES = {**EVASION_PROFILES, **file_data["evasion_profiles"]}

    merged.update(load_env_overrides())
    merged["_config_file_used"] = str(used_path) if used_path else None
    return merged


def resolve_masscan_rate(evasion_profile: str, explicit_rate: Optional[int]) -> int:
    if explicit_rate is not None:
        return explicit_rate
    return EVASION_PROFILES[evasion_profile]["masscan_rate"]