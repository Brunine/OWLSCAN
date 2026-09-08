# OwlScan

Internal pentest / network-segmentation scanner. Wraps **masscan** (fast port
discovery) and **nmap** (deep service/version scanning) behind a single CLI,
with configurable evasion profiles and honeypot-detection heuristics.

## Install

```bash
# Native (requires nmap + masscan on PATH)
pip install .
pip install ".[excel]"   # adds Excel (.xlsx) report support

# Or containerized (bundles nmap + masscan, no host install needed)
docker build -t owlscan:local .
```

## Quick start

```bash
sudo owlscan scan --target 10.0.0.0/24 --ports 1-1000 --evasion stealth --output ./reports/
```

```bash
docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN --network host \
  -v $(pwd)/reports:/app/reports owlscan:local \
  scan --target 10.0.0.0/24 --ports 1-1000 --evasion stealth --output /app/reports
```

## Commands

| Command | Purpose |
|---|---|
| `owlscan scan` | Run a masscan discovery + nmap deep-scan against a target CIDR |
| `owlscan honeypot --input report.json` | Re-run honeypot heuristics against a saved report |
| `owlscan config show` | Print resolved config (defaults ← file ← env) |
| `owlscan config set KEY=VALUE` | Persist a setting to `owlscan.toml` |
| `owlscan version` | Print the installed version |
| `owlscan --interactive` | Fall back to the legacy prompt-driven wizard |

## `scan` flag reference

| Flag | Description |
|---|---|
| `--target` | Target CIDR, e.g. `10.0.0.0/24` |
| `--ports` | Ports for masscan discovery, e.g. `1-65535` or `22,80,443` |
| `--evasion` | `none` \| `stealth` \| `paranoid` \| `docker` |
| `--output` | Directory for reports and raw scan files |
| `--threads` | Concurrent nmap worker threads |
| `--timeout` | Per-host nmap timeout (seconds) |
| `--honeypot-threshold` | Open-port count above which a host is flagged |
| `--decoys` | Comma-separated nmap decoy IPs (`-D`) |
| `--interface` | Network interface for masscan |
| `--formats` | Report formats to generate: `json,md,mindmap,xlsx` |
| `--masscan-rate` | Override the evasion profile's packet rate |
| `--config` | Path to an `owlscan.toml` file |
| `--log-file` | DEBUG-level session log path |
| `--json` | Console output as one JSON array instead of a table |
| `--excel` | Also write an `.xlsx` report |
| `--docker` | Run masscan/nmap inside the bundled image instead of natively |
| `-y`, `--yes` | Skip the confirmation prompt |

## Evasion profiles

| Profile | Masscan rate | Nmap timing | Description |
|---|---|---|---|
| `none` | 1000 pps | T4 | No evasion — fast, noisy (default) |
| `stealth` | 200 pps | T2 | Fragmented + padded packets, DNS source-port |
| `paranoid` | 50 pps | T1 | Double-fragmented, HTTPS source-port, 500ms delay |
| `docker` | 500 pps | T3 | `-Pn`, TCP-connect, defeats RST rate-limiting |

## Configuration

Resolution order (highest wins): CLI flags → `--config` file → `./owlscan.toml`
→ `~/.config/owlscan/owlscan.toml` → built-in defaults.

Environment overrides: `OWLSCAN_EVASION`, `OWLSCAN_OUTPUT_DIR`,
`OWLSCAN_NMAP_THREADS`, `OWLSCAN_NMAP_TIMEOUT`, `OWLSCAN_HONEYPOT_THRESHOLD`,
`OWLSCAN_DECOY_LIST`, `OWLSCAN_INTERFACE`, `OWLSCAN_LOG_FILE`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success — scan completed, report written |
| 1 | Generic error (bad args, no target, missing tools) |
| 2 | Honeypot detected |
| 3 | No open ports found |
| 4 | User interrupted (SIGINT/SIGTERM) |

## Docker usage

`docker-compose.yml` mounts `./reports` and an optional `owlscan.toml`, and
runs with `network_mode: host` plus `NET_RAW`/`NET_ADMIN` capabilities so
masscan can transmit raw packets:

```bash
docker compose run --rm owlscan scan --target 10.0.0.0/24 --ports 1-1000
```

## Known limitations

- **Windows**: raw-socket scans (`masscan`, `nmap -sS`) require
  [Npcap](https://npcap.com/) and an elevated shell. Without it, fall back to
  the `docker` evasion profile (`-sT`/TCP-connect) or run inside WSL2/Docker.
- **Licensing**: this tool orchestrates `nmap` and `masscan`, both licensed
  under GPLv2. Distributing a bundled image (as the provided `Dockerfile`
  does) means you are redistributing GPLv2 binaries — review your
  organization's obligations under that license before shipping the image
  externally.
- Only run this tool against networks you are authorized to scan.