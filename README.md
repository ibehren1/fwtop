# fwtop

A real-time **router / firewall** traffic visualizer for the terminal, inspired by [btop](https://github.com/aristocratos/btop).

Where a host monitor shows your machine's own traffic, `fwtop` is built for the box that sits *between* networks — an edge router or firewall. It reads kernel state directly (near-zero overhead, no packet capture) to show **per-interface throughput** (split into WAN/LAN zones), the live **connection-tracking table** (including NAT), and **firewall rule counters** with a smoke→fire **drops heatmap** that surfaces spikes at a glance.

Built with [Textual](https://github.com/Textualize/textual), [Plotext](https://github.com/piccolomo/plotext), and [psutil](https://github.com/giampaolo/psutil).

## Features

- **Per-interface flows** — RX/TX rates, cumulative totals, and error/drop counters for every interface, so forwarded (through) traffic is visible per link
- **Conntrack view** — live netfilter connection table: protocol & TCP-state breakdown, NAT translations, and table-capacity gauge
- **Firewall drops** — nftables (or iptables) rule counters with per-rule packet/byte rates; drops and rejects sorted to the top
- **Drops heatmap** — a ticking grid, one row per drop/reject rule, colored smoke→fire (gray low, red high) so spikes light up at a glance
- **Zone categorization** — label each interface WAN / WAN-Tunnel / LAN / LAN-Tunnel / other; saved to a config file and editable at runtime
- Side-by-side rolling 60-second throughput charts — **WAN in red shades, LAN in green shades**, each overlaying its physical link and its tunnel (WireGuard/GRE/IPsec) traffic, braille-dot plotted
- **Two-column connections view** — WAN-facing flows (NAT'd/public) on the left, internal LAN flows on the right
- CPU usage panel (user / system / total / fwtop process)
- Optional reverse-DNS resolution of IPs, toggleable at runtime
- `--demo` mode with synthetic data — runs anywhere, no kernel access or root needed
- btop-inspired dark theme with rounded borders and color-coded panels
- Reads kernel counters only: no `libpcap`, no per-packet overhead on busy routers

## Data sources

All sources are read-only and Linux-native. Each degrades gracefully: if a
facility is missing, its panel shows *why* instead of crashing.

| View | Source | Notes |
|------|--------|-------|
| Interfaces | `/proc/net/dev` | Always present on Linux |
| Conntrack  | `/proc/net/nf_conntrack` | Requires the `nf_conntrack` module (loaded on any NAT/stateful box). Per-flow byte/packet counts need `nf_conntrack_acct` |
| Firewall   | `nft -j list ruleset`, fallback `iptables -L -v -n -x` | Per-rule counters require a `counter` statement on the rule (nftables) |

## Installation

### Pre-built binaries

Download the latest binary for your platform from [GitHub Releases](../../releases):

| Platform | Architecture | Download |
|----------|-------------|----------|
| Linux    | x86_64      | `fwtop-linux-x86_64` |
| Linux    | ARM64       | `fwtop-linux-arm64` |
| macOS    | ARM64       | `fwtop-macos-arm64` (demo/dev only) |

```bash
chmod +x fwtop-*
sudo ./fwtop-linux-x86_64
```

### From source with uv

```bash
git clone https://github.com/ibehren1/fwtop.git
cd fwtop
uv sync
sudo uv run fwtop          # live
uv run fwtop --demo        # synthetic data, no root
```

## Usage

```
usage: fwtop [-h] [-v] [-n INTERVAL] [-r] [--demo] [-c PATH]

options:
  -h, --help            show this help message and exit
  -v, --version         Show the version and exit
  -n, --interval        Screen refresh interval in seconds (default: 1.0)
  -r, --resolve         Reverse-DNS resolve IPs, showing hostnames when available
  --demo                Run with synthetic data (no kernel access / root needed)
  -c, --config PATH     Config file for interface zone assignments
                        (default: $XDG_CONFIG_HOME/fwtop/config.json)
```

### Examples

```bash
# Live monitoring on a Linux router (requires root for conntrack & nft)
sudo fwtop

# Try it anywhere with synthetic data
fwtop --demo

# Resolve IPs to hostnames, refresh twice a second
sudo fwtop -r -n 0.5
```

### Keybindings

| Key | Action |
|-----|--------|
| `q` | Quit |
| `p` | Pause / resume display |
| `r` | Toggle reverse-DNS resolution of IPs |
| `n` | Cycle refresh interval (0.5 → 1 → 2 → 5s) |
| `z` | Assign interface zones (WAN / WAN-Tunnel / LAN / LAN-Tunnel / other) |
| `1` | Overview tab |
| `2` | Connections tab |
| `3` | Firewall tab |

## Dashboard

### Overview tab

A two-column layout. The left column stacks **Summary** (aggregate
throughput, tracked connections, drop rate, uptime), **CPU**, and a
**Conntrack** breakdown (capacity bar, per-protocol bars, top TCP states).
The right column shows two side-by-side rolling throughput charts — **WAN**
(red shades) and **LAN** (green shades) — then a **Drops Heatmap**, then the
**Interfaces** table.

The throughput charts each plot up to four lines: the physical link's down/up
plus its tunnel's down/up.

The **Drops Heatmap** is a ticking grid with one row per firewall drop/reject
rule and one column per refresh tick, scrolling left as time advances. Each
cell's color runs **smoke→fire** — faint gray at low drop rates, warming
through embers to bright red at the peak — scaled to the busiest cell on
screen, so a spike in dropped traffic (a scan, a brute-force burst) lights up
at a glance. The newest tick is the right-hand column; a footer shows the
smoke→fire legend and the current peak rate the color scale maps to. The grid
expands and contracts with the window.

The **Interfaces** table groups rows into zone sections (WAN → WAN-Tunnel →
LAN → LAN-Tunnel → other), each under a heading; rows keep a stable order and
update their values in place rather than re-sorting each tick. The table
expands and contracts with the window.

### Connections tab

The heaviest conntrack flows, one row per connection: protocol, original
source → destination, the NAT reply address when translation is in effect,
TCP state, and per-flow packet/byte volume.

Flows are split into two side-by-side columns. Conntrack entries carry no
interface label, so the split is inferred: **WAN / WAN-Tunnel** traffic on the
left (flows that were NAT'd out or touch a public address) and **LAN / Other**
internal flows on the right (purely private endpoint to private endpoint, no
NAT). Each heading shows the live count for that side.

### Firewall tab

Every firewall rule counter, with **drops and rejects sorted to the top** and
color-coded by verdict. Shows per-rule packet/byte rates so a spike in
dropped traffic (a scan, a brute-force attempt, a misconfig) jumps out.

## Interface zones

Each interface is categorized into one of five zones:

| Zone | Chart | Typical interfaces |
|------|-------|--------------------|
| **WAN**        | red (bright)  | uplink: `eth0`, `ppp0`, `*wan*` |
| **WAN-Tunnel** | red (orange)  | WireGuard/IPsec/GRE over the WAN: `wg0`, `tun0`, `ipsec0` |
| **LAN**        | green (bright)| local: `br-lan`, `vlan*`, `*lan*` |
| **LAN-Tunnel** | green (lime)  | tunnels bridged into the LAN: `gre-lan`, `wg-lan` |
| **other**      | neither       | loopback, management, unclassified |

WAN and WAN-Tunnel feed the red chart; LAN and LAN-Tunnel feed the green
chart. `other` is excluded from both.

On first run, zones are guessed from interface names (tunnel hints like `wg`,
`tun`, `tap`, `gre`, `ipsec` take priority and resolve to a `*-Tunnel` zone —
WAN-side unless the name also looks LAN-side). Press **`z`** to open the
assignment screen and cycle any interface through WAN → WAN-Tunnel → LAN →
LAN-Tunnel → other; the choice is saved immediately to the config file and
applied on the next refresh.

The config is a small JSON file (default
`$XDG_CONFIG_HOME/fwtop/config.json`, override with `-c`):

```json
{
  "zones": {
    "eth0": "wan",
    "wg0": "wan_tunnel",
    "br-lan": "lan",
    "gre-lan": "lan_tunnel"
  }
}
```

## Building binaries

### Local build

```bash
uv sync --dev
uv run pyinstaller fwtop.spec --clean --noconfirm
# Binary at dist/fwtop
```

### CI/CD

The GitHub Actions workflow (`.github/workflows/build.yml`) builds binaries
for Linux x86_64, Linux ARM64, and macOS ARM64. Push a tag to cut a release:

```bash
make release VERSION=0.1.0
# or: git tag v0.1.0 && git push origin v0.1.0
```

This builds all binaries, generates SHA256 checksums, and creates a GitHub
Release with the artifacts attached.

## Requirements

- Python >= 3.10
- Linux (for live data); any platform for `--demo`
- Root privileges to read conntrack and the firewall ruleset
- A terminal emulator with 256-color support

## Platform notes

### Linux

Works out of the box with `sudo`. The conntrack panel needs the
`nf_conntrack` module loaded (automatic on any box doing NAT or stateful
filtering). For per-flow byte/packet accounting:

```bash
sysctl -w net.netfilter.nf_conntrack_acct=1
```

For per-rule firewall counters under nftables, add a `counter` statement to
the rules you want to track.

### macOS / other

The kernel sources are Linux-specific, so live mode has nothing to read. Use
`fwtop --demo` to explore the interface with synthetic data — this is the
intended path for development on non-Linux machines.

## License

MIT — Copyright © 2026 Isaac B. Behrens. All rights reserved.
