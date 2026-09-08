"""
OwlScan — Internal Pentest Network Segmentation Tool.

Wraps masscan (fast port discovery) and nmap (deep service/version
scanning) behind a single CLI, with configurable evasion profiles and
honeypot-detection heuristics.

Platform support: Linux, macOS (Intel & Apple Silicon), Windows (limited —
raw-socket scans require Npcap and an elevated/administrator shell).
"""

from importlib.metadata import PackageNotFoundError, version as _version

try:
    __version__ = _version("owlscan")
except PackageNotFoundError:  # pragma: no cover - running from source tree
    __version__ = "2.0.0-dev"

__all__ = ["__version__"]