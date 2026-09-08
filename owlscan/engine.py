"""
Scan engine for OwlScan: masscan discovery, nmap full + deep scans,
evasion-flag injection, and honeypot heuristics.

The subprocess mechanics (line-streaming masscan/nmap through a file sink,
SIGINT-driven pause/resume, per-host timeouts) are preserved from the
original interactive script; only the surrounding plumbing (config,
logging, cross-platform root/stdbuf handling) has changed.
"""

from __future__ import annotations

import ipaddress
import platform
import queue
import re
import shutil
import signal
import subprocess
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from .config import EVASION_PROFILES, ScanConfig
from .log import log

# ─────────────────────────────────────────────
# Platform helpers
# ─────────────────────────────────────────────
def is_root() -> bool:
    """Cross-platform administrator/root check."""
    if platform.system() == "Windows":
        import ctypes
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(__import__("os"), "geteuid") and __import__("os").geteuid() == 0


def _stdbuf_prefix() -> list[str]:
    """
    masscan/nmap buffer stdout when not attached to a TTY; `stdbuf -oL`
    forces line buffering on Linux/macOS. Fall back to no prefix (and rely
    on subprocess text-mode line iteration) where stdbuf isn't available,
    e.g. Windows or minimal containers.
    """
    if platform.system() == "Windows":
        return []
    if shutil.which("stdbuf"):
        return ["stdbuf", "-oL"]
    return []


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def check_tools(use_docker: bool = False) -> list[str]:
    """Return the list of missing required tools. Empty list = all present."""
    if use_docker:
        return []
    missing = [t for t in ("masscan", "nmap") if not tool_available(t)]
    return missing


# ─────────────────────────────────────────────
# Findings store
# ─────────────────────────────────────────────
findings_lock = threading.Lock()
findings: dict[str, dict] = {}


def reset_findings() -> None:
    with findings_lock:
        findings.clear()


def record_open_port(ip: str, port: str, proto: str = "tcp") -> None:
    with findings_lock:
        entry = findings.setdefault(ip, {"ports": [], "services": {}, "honeypot": False})
        tag = f"{port}/{proto}"
        if tag not in entry["ports"]:
            entry["ports"].append(tag)


def record_service(ip: str, port: str, banner: str) -> None:
    with findings_lock:
        entry = findings.setdefault(ip, {"ports": [], "services": {}, "honeypot": False})
        entry["services"][port] = banner


def mark_honeypot(ip: str) -> None:
    with findings_lock:
        if ip in findings:
            findings[ip]["honeypot"] = True


def sort_key_ip(ip: str):
    try:
        return [int(n) for n in ip.split(".")]
    except (ValueError, AttributeError):
        return [0, 0, 0, 0]


# ─────────────────────────────────────────────
# Path helpers
# ─────────────────────────────────────────────
def cidr_to_safe(cidr: str) -> str:
    return cidr.replace("/", "_").replace(".", "-")


def get_range_dir(base_dir: Path, cidr: str) -> Path:
    return base_dir / cidr_to_safe(cidr)


def get_masscan_file(base_dir: Path, cidr: str) -> Path:
    return base_dir / f"masscan_range_{cidr_to_safe(cidr)}.txt"


def get_nmap_file(base_dir: Path, cidr: str, ip: str) -> Path:
    return get_range_dir(base_dir, cidr) / f"nmap_{ip}.txt"


def get_honeypot_log(base_dir: Path, cidr: str) -> Path:
    return get_range_dir(base_dir, cidr) / "honeypots.txt"


def get_paused_conf(base_dir: Path, cidr: str) -> Path:
    return base_dir / f"masscan_range_{cidr_to_safe(cidr)}.paused.conf"


def get_network_size(cidr: str) -> int:
    try:
        return ipaddress.ip_network(cidr, strict=False).num_addresses
    except ValueError:
        return 0


# ─────────────────────────────────────────────
# Interrupt handling (SIGINT + SIGTERM, the latter for `docker stop`)
# ─────────────────────────────────────────────
class InterruptState:
    def __init__(self) -> None:
        self.event = threading.Event()
        self._proc: Optional[subprocess.Popen] = None
        self._old_sigint = None
        self._old_sigterm = None

    def attach(self, proc: subprocess.Popen) -> None:
        self._proc = proc

    def _handler(self, sig, frame):
        if not self.event.is_set():
            self.event.set()
            if self._proc and self._proc.poll() is None:
                self._proc.send_signal(signal.SIGINT)

    def __enter__(self) -> "InterruptState":
        self._old_sigint = signal.signal(signal.SIGINT, self._handler)
        try:
            self._old_sigterm = signal.signal(signal.SIGTERM, self._handler)
        except (ValueError, OSError):
            self._old_sigterm = None  # not available on this platform/thread
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        signal.signal(signal.SIGINT, self._old_sigint)
        if self._old_sigterm is not None:
            signal.signal(signal.SIGTERM, self._old_sigterm)


# ─────────────────────────────────────────────
# Honeypot flagging
# ─────────────────────────────────────────────
def flag_honeypot(base_dir: Path, ip: str, cidr: str, port_count: int, threshold: int) -> None:
    get_range_dir(base_dir, cidr).mkdir(parents=True, exist_ok=True)
    honey_file = get_honeypot_log(base_dir, cidr)
    entry = f"{datetime.now().strftime('%H:%M:%S')}  {ip}  ({port_count} open ports)\n"
    with open(honey_file, "a") as f:
        f.write(entry)
    mark_honeypot(ip)
    log("warn", f"[bold red]HONEYPOT?[/bold red]  {ip} has [red]{port_count}[/red] open ports "
                f"(threshold {threshold}) — skipping deep scan. Logged to {honey_file.name}")


def build_nmap_evasion_flags(evasion_profile: str, decoy_list: Optional[str]) -> list[str]:
    profile = EVASION_PROFILES[evasion_profile]
    flags = [f"-T{profile['nmap_timing']}"] + list(profile["nmap_extra"])
    if decoy_list:
        flags += ["-D", decoy_list]
    return flags


# ─────────────────────────────────────────────
# Subprocess runner with timeout
# ─────────────────────────────────────────────
def _run_subprocess_with_timeout(
    cmd: list[str], timeout: int, output_file, on_line: Optional[Callable[[str], Optional[str]]] = None
) -> tuple[int, bool]:
    """
    Run a subprocess, stream stdout line-by-line to output_file and
    optionally call on_line(line) for each line. Kills the process if the
    timeout is exceeded. Returns (returncode, timed_out).
    """
    timed_out_flag = {"v": False}
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        def _on_timeout():
            timed_out_flag["v"] = True
            proc.kill()

        timer = threading.Timer(timeout, _on_timeout)
        timer.start()
        try:
            for line in proc.stdout:
                output_file.write(line)
                if on_line:
                    result = on_line(line)
                    if result == "STOP":
                        proc.terminate()
                        break
            proc.wait()
        finally:
            timer.cancel()
        return proc.returncode, timed_out_flag["v"]
    except Exception as e:
        log("err", f"Subprocess error: {e}")
        return -1, False


# ─────────────────────────────────────────────
# Nmap full + deep scans
# ─────────────────────────────────────────────
def run_nmap_deep(ip: str, ports: str, base_output: Path, cfg: ScanConfig) -> None:
    profile = EVASION_PROFILES[cfg.evasion_profile]
    evasion_flags = build_nmap_evasion_flags(cfg.evasion_profile, cfg.decoy_list)
    scan_type = "-sT" if "-sT" in profile["nmap_extra"] else "-sV"
    evasion_flags = [f for f in evasion_flags if f != "-sT"]
    cmd_deep = ["nmap", scan_type, "-A", "-v", f"-p{ports}"] + evasion_flags + [ip]

    try:
        with open(base_output, "a") as f:
            f.write(f"\n\n# ─── Deep Service Scan: {ip} ports {ports} ───\n")
            f.write(f"# Started: {datetime.now()}\n\n")

            def on_line(line: str) -> None:
                svc_match = re.match(r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
                if svc_match:
                    port, service, extra = svc_match.groups()
                    record_service(ip, port, f"{service} {extra}".strip())
                return None

            rc, timed_out = _run_subprocess_with_timeout(cmd_deep, cfg.nmap_timeout, f, on_line)

        if timed_out:
            log("warn", f"Deep nmap timed out on {ip} after {cfg.nmap_timeout}s")
        else:
            log("ok", f"Deep scan complete for {ip} → {base_output.name}")

    except Exception as e:
        log("err", f"Deep nmap error on {ip}: {e}")


def run_nmap_full(ip: str, cidr: str, cfg: ScanConfig) -> None:
    get_range_dir(cfg.output_dir, cidr).mkdir(parents=True, exist_ok=True)
    output_file = get_nmap_file(cfg.output_dir, cidr, ip)
    profile = EVASION_PROFILES[cfg.evasion_profile]
    evasion_flags = build_nmap_evasion_flags(cfg.evasion_profile, cfg.decoy_list)

    scan_type = "-sT" if "-sT" in profile["nmap_extra"] else "-sS"
    evasion_flags = [f for f in evasion_flags if f != "-sT"]

    cmd_full = ["nmap", scan_type, "-p-", "-v", "--open"] + evasion_flags + [ip]
    log("nmap", f"Full port scan started: {ip}")

    open_ports: list[str] = []
    honeypot_tripped = False

    try:
        with open(output_file, "w") as f:
            f.write(f"# Full port scan: {ip}\n# Started: {datetime.now()}\n\n")

            def on_line(line: str) -> Optional[str]:
                nonlocal honeypot_tripped
                m = re.match(r"^(\d+)/tcp\s+open\s+", line)
                if m:
                    port = m.group(1)
                    open_ports.append(port)
                    record_open_port(ip, port, "tcp")
                    log("ok", f"  {ip} → port [green]{port}/tcp open[/green]")
                    if not honeypot_tripped and len(open_ports) > cfg.honeypot_threshold:
                        honeypot_tripped = True
                        f.write(f"\n# !! Honeypot threshold ({cfg.honeypot_threshold}) exceeded — scan aborted\n")
                        return "STOP"
                return None

            rc, timed_out = _run_subprocess_with_timeout(cmd_full, cfg.nmap_timeout, f, on_line)

        if timed_out:
            log("warn", f"Nmap timed out on {ip} after {cfg.nmap_timeout}s — moving on")
            return

        if honeypot_tripped:
            flag_honeypot(cfg.output_dir, ip, cidr, len(open_ports), cfg.honeypot_threshold)
            return

        if open_ports:
            ports_str = ",".join(open_ports)
            log("nmap", f"Deep scan started: {ip} ports [{ports_str}]")
            run_nmap_deep(ip, ports_str, output_file, cfg)
        else:
            log("warn", f"No open ports found on {ip} during full scan")

    except FileNotFoundError:
        log("err", "nmap not found in PATH")
    except Exception as e:
        log("err", f"nmap error on {ip}: {e}")


# ─────────────────────────────────────────────
# Nmap worker pool
# ─────────────────────────────────────────────
class NmapPool:
    def __init__(self, cfg: ScanConfig) -> None:
        self.cfg = cfg
        self.queue: "queue.Queue" = queue.Queue()
        self.scanned_hosts: set[str] = set()
        self.scanned_lock = threading.Lock()
        self._workers: list[threading.Thread] = []

    def _worker(self) -> None:
        while True:
            job = self.queue.get()
            if job is None:
                break
            ip, cidr = job
            try:
                run_nmap_full(ip, cidr, self.cfg)
            except Exception as e:
                log("err", f"Unhandled error scanning {ip}: {e}")
            finally:
                self.queue.task_done()

    def start(self) -> None:
        for _ in range(self.cfg.nmap_threads):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            self._workers.append(t)

    def submit_if_new(self, ip: str, cidr: str) -> bool:
        with self.scanned_lock:
            if ip in self.scanned_hosts:
                return False
            self.scanned_hosts.add(ip)
        self.queue.put((ip, cidr))
        return True

    def reset_scanned(self) -> None:
        with self.scanned_lock:
            self.scanned_hosts.clear()

    def drain(self) -> None:
        deadline = (
            datetime.now().timestamp()
            + self.cfg.nmap_timeout * self.cfg.nmap_threads + 60
        )
        while not self.queue.empty():
            if datetime.now().timestamp() > deadline:
                log("warn", "Nmap queue drain timed out — some hosts may be incomplete")
                break
            threading.Event().wait(1.0)

    def stop(self, timeout: float = 10.0) -> None:
        for _ in self._workers:
            self.queue.put(None)
        for t in self._workers:
            t.join(timeout=timeout)
            if t.is_alive():
                log("warn", "A worker thread did not exit cleanly — continuing anyway")


# ─────────────────────────────────────────────
# Masscan
# ─────────────────────────────────────────────
_MASSCAN_UNSUPPORTED_OPTS = {
    "nocapture", "servername", "router-mac-ipv6",
    "pcap-payloads", "hello", "hello-timeout",
}


def sanitize_paused_conf(path: Path) -> bool:
    try:
        lines = path.read_text().splitlines(keepends=True)
        clean, stripped = [], []
        for line in lines:
            key = line.split("=")[0].strip().lstrip("-")
            if key in _MASSCAN_UNSUPPORTED_OPTS:
                stripped.append(line.rstrip())
            else:
                clean.append(line)
        if stripped:
            path.write_text("".join(clean))
            log("info", f"Stripped unsupported options from {path.name}: {', '.join(stripped)}")
        return bool(stripped)
    except Exception as e:
        log("warn", f"Could not sanitize {path.name}: {e}")
        return False


@dataclass
class RangeResult:
    cidr: str
    paused: bool = False
    error: Optional[str] = None


def run_masscan(cidr: str, ports: str, cfg: ScanConfig, on_host_progress: Optional[Callable[[str], None]] = None) -> RangeResult:
    """Run masscan for one CIDR and feed discovered hosts into the nmap pool."""
    masscan_out = get_masscan_file(cfg.output_dir, cidr)
    paused_conf = get_paused_conf(cfg.output_dir, cidr)
    paused_local = Path("paused.conf")

    pool = NmapPool(cfg)
    pool.reset_scanned()

    resuming = paused_conf.exists()
    if resuming:
        sanitize_paused_conf(paused_conf)
        cmd = ["masscan", "--resume", str(paused_conf), "-oL", "-"]
        log("warn", f"Resuming previous scan for {cidr} from {paused_conf.name}")
    else:
        cmd = ["masscan", cidr, f"-p{ports}", "--rate", str(cfg.masscan_rate), "--open-only", "-oL", "-"]

    if cfg.interface:
        cmd += ["-e", cfg.interface]

    action = "Resuming" if resuming else "Starting"
    log("scan", f"{action} Masscan on {cidr}  ports: {ports}" +
        (f"  interface: {cfg.interface}" if cfg.interface else ""))
    log("info", f"Output → {masscan_out}")

    pool.start()
    interrupt = InterruptState()
    result = RangeResult(cidr=cidr)

    try:
        with interrupt:
            file_mode = "a" if resuming else "w"
            cfg.output_dir.mkdir(parents=True, exist_ok=True)
            with open(masscan_out, file_mode, buffering=1) as mf:
                if not resuming:
                    mf.write(f"# Masscan output for {cidr}\n# Ports: {ports}\n# Started: {datetime.now()}\n\n")
                else:
                    mf.write(f"\n# Resumed: {datetime.now()}\n\n")
                mf.flush()

                full_cmd = _stdbuf_prefix() + cmd
                proc = subprocess.Popen(
                    full_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1,
                )
                interrupt.attach(proc)

                def stream_stderr() -> None:
                    for line in proc.stderr:
                        line = line.rstrip()
                        if line.strip() and not line.startswith("#"):
                            log("scan", line)

                threading.Thread(target=stream_stderr, daemon=True).start()

                for line in proc.stdout:
                    line = line.rstrip()
                    if not line or line.startswith("#"):
                        continue
                    mf.write(line + "\n")
                    mf.flush()
                    m = re.match(r"^open\s+(\w+)\s+(\d+)\s+(\d+\.\d+\.\d+\.\d+)", line)
                    if m:
                        proto, port, ip = m.group(1), m.group(2), m.group(3)
                        log("ok", f"[bold green]OPEN[/bold green]  {ip}:{port}/{proto}")
                        record_open_port(ip, port, proto)
                        if pool.submit_if_new(ip, cidr):
                            log("nmap", f"Queuing full scan → {ip}")
                        if on_host_progress:
                            on_host_progress(ip)

                proc.wait()

    except FileNotFoundError:
        log("err", "masscan not found. Install: sudo apt install masscan")
        pool.stop()
        result.error = "masscan_not_found"
        return result
    except PermissionError:
        log("err", "masscan needs elevated privileges. Run with sudo/administrator rights.")
        pool.stop()
        result.error = "permission_denied"
        return result

    paused_by_user = interrupt.event.is_set()
    if paused_by_user:
        for _ in range(30):
            if paused_local.exists():
                break
            threading.Event().wait(0.1)
        if paused_local.exists():
            shutil.move(str(paused_local), str(paused_conf))
            log("ok", f"Paused state saved → {paused_conf}")
            log("info", "Resume by re-running the same `owlscan scan` command.")
            result.paused = True
        else:
            log("warn", "masscan did not write paused.conf (interrupted too early — nothing to resume)")
    else:
        for f in (paused_conf, paused_local):
            if Path(f).exists():
                Path(f).unlink()

    log("ok", f"Masscan done for {cidr}. Draining Nmap queue…")
    pool.drain()
    pool.stop(timeout=cfg.nmap_timeout + 5)
    log("ok", f"All scans complete for {cidr}")
    return result