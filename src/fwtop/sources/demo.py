from __future__ import annotations

import math
import random
from time import monotonic

from fwtop.models import (
    Connection,
    ConntrackSummary,
    FirewallCounter,
    InterfaceStat,
    SourceStatus,
)

# A small fixed cast of interfaces and hosts so the demo looks like a real
# edge router: a WAN uplink, a LAN bridge and VLAN, a WireGuard WAN tunnel,
# and a GRE tunnel bridged into the LAN.
_IFACES = ("eth0", "br-lan", "vlan10", "wg0", "gre-lan")
_LAN_HOSTS = ("192.168.1.10", "192.168.1.42", "192.168.1.77", "10.0.10.5")
_WAN_HOSTS = ("203.0.113.9", "198.51.100.23", "8.8.8.8", "1.1.1.1", "140.82.121.4")
_WAN_IP = "203.0.113.2"  # the router's public address (NAT egress)

# Friendly names for the synthetic hosts, mimicking a router's local DNS /
# DHCP lease table. Private LAN addresses have no public PTR record, so
# without these the demo could never show source/LAN-side resolution.
DEMO_STATIC_NAMES = {
    "192.168.1.10": "desktop.lan",
    "192.168.1.42": "laptop.lan",
    "192.168.1.77": "nas.lan",
    "10.0.10.5": "iot-hub.lan",
    "203.0.113.2": "router.wan",
    "203.0.113.9": "vpn-peer.example.net",
    "198.51.100.23": "mail.example.org",
}


class DemoSource:
    """Synthetic data source producing plausible, time-varying router metrics.

    Used on non-Linux dev machines and via ``--demo`` so the dashboard can be
    exercised without a live kernel to read. It mimics the public surface of
    the three real sources (interfaces / conntrack / firewall) closely enough
    that the app code path is identical.
    """

    def __init__(self, seed: int = 1337) -> None:
        self._rng = random.Random(seed)
        self._start = monotonic()
        # Cumulative counters we advance every poll.
        self._iface_acc = {
            name: dict(rx_b=0, tx_b=0, rx_p=0, tx_p=0, rx_e=0, tx_e=0, rx_d=0, tx_d=0)
            for name in _IFACES
        }
        self._fw_acc = {
            ("inet filter", "input", "drop ssh bruteforce", "drop"): [0, 0],
            ("inet filter", "input", "drop invalid ct state", "drop"): [0, 0],
            ("inet filter", "forward", "reject smb to wan", "reject"): [0, 0],
            ("inet filter", "input", "accept established", "accept"): [0, 0],
            ("inet filter", "forward", "accept lan to wan", "accept"): [0, 0],
        }
        self._available = SourceStatus(True, "demo / synthetic data")

    @property
    def status(self) -> SourceStatus:
        return self._available

    def _wave(self, period: float, phase: float = 0.0) -> float:
        """A 0..1 sinusoid so rates breathe over time instead of being flat."""
        t = monotonic() - self._start
        return 0.5 + 0.5 * math.sin(2 * math.pi * (t / period) + phase)

    # ── interfaces ────────────────────────────────────────────────────────

    def poll_interfaces(self) -> list[InterfaceStat]:
        stats: list[InterfaceStat] = []
        for i, name in enumerate(_IFACES):
            acc = self._iface_acc[name]
            # WAN/LAN carry the bulk of traffic; tunnels & VLANs are lighter.
            scale = (12_000_000 if name in ("eth0", "br-lan") else 2_000_000)
            rx_bps = scale * self._wave(20, i) * self._rng.uniform(0.6, 1.0)
            tx_bps = scale * 0.7 * self._wave(17, i + 1) * self._rng.uniform(0.6, 1.0)
            rx_pps = rx_bps / 800.0
            tx_pps = tx_bps / 800.0
            acc["rx_b"] += int(rx_bps)
            acc["tx_b"] += int(tx_bps)
            acc["rx_p"] += int(rx_pps)
            acc["tx_p"] += int(tx_pps)
            if self._rng.random() < 0.05:
                acc["rx_d"] += self._rng.randint(1, 3)
            stats.append(InterfaceStat(
                name=name,
                rx_bytes=acc["rx_b"], tx_bytes=acc["tx_b"],
                rx_packets=acc["rx_p"], tx_packets=acc["tx_p"],
                rx_errors=acc["rx_e"], tx_errors=acc["tx_e"],
                rx_dropped=acc["rx_d"], tx_dropped=acc["tx_d"],
                rx_bps=rx_bps, tx_bps=tx_bps, rx_pps=rx_pps, tx_pps=tx_pps,
            ))
        stats.sort(key=lambda s: s.total_bps, reverse=True)
        return stats

    # ── conntrack ─────────────────────────────────────────────────────────

    def poll_conntrack(self) -> tuple[list[Connection], ConntrackSummary]:
        conns: list[Connection] = []
        n = 40 + int(60 * self._wave(30))
        states = ["ESTABLISHED"] * 6 + ["TIME_WAIT", "SYN_SENT", "CLOSE_WAIT", "FIN_WAIT"]
        for _ in range(n):
            proto = self._rng.choices(["tcp", "udp", "icmp"], weights=[7, 4, 1])[0]
            sport = self._rng.randint(1024, 65535)
            state = self._rng.choice(states) if proto == "tcp" else ""
            # ~70% of flows leave the WAN (NAT'd); the rest are internal
            # LAN↔LAN traffic so the Connections tab's right column populates.
            if self._rng.random() < 0.70:
                lan = self._rng.choice(_LAN_HOSTS)
                wan = self._rng.choice(_WAN_HOSTS)
                dport = self._rng.choice([80, 443, 53, 22, 123, 3478, 51820])
                conns.append(Connection(
                    protocol=proto, state=state,
                    src=lan, dst=wan, sport=sport, dport=dport,
                    # SNAT/masquerade: reply comes back to the router's WAN IP.
                    reply_src=wan, reply_dst=_WAN_IP,
                    packets=self._rng.randint(1, 5000),
                    bytes=self._rng.randint(64, 5_000_000),
                ))
            else:
                src = self._rng.choice(_LAN_HOSTS)
                dst = self._rng.choice([h for h in _LAN_HOSTS if h != src])
                dport = self._rng.choice([445, 139, 53, 5353, 1883, 8006, 32400])
                conns.append(Connection(
                    protocol=proto, state=state,
                    src=src, dst=dst, sport=sport, dport=dport,
                    # No NAT for internal flows: reply tuple is the mirror.
                    reply_src=dst, reply_dst=src,
                    packets=self._rng.randint(1, 5000),
                    bytes=self._rng.randint(64, 5_000_000),
                ))
        from collections import Counter
        by_proto = Counter(c.protocol for c in conns)
        by_state = Counter(c.state for c in conns if c.state)
        summary = ConntrackSummary(
            total=len(conns),
            by_protocol=dict(by_proto.most_common()),
            by_state=dict(by_state.most_common()),
            nat_count=sum(1 for c in conns if c.is_nat),
            max_entries=262144,
        )
        conns.sort(key=lambda c: c.bytes, reverse=True)
        return conns, summary

    # ── firewall ──────────────────────────────────────────────────────────

    def poll_firewall(self) -> list[FirewallCounter]:
        out: list[FirewallCounter] = []
        for (table, chain, label, verdict), acc in self._fw_acc.items():
            if verdict in ("drop", "reject"):
                rate = self._rng.uniform(0, 40) * self._wave(15)
            else:
                rate = self._rng.uniform(200, 2000)
            pps = rate
            bps = rate * self._rng.uniform(60, 600)
            acc[0] += int(pps)
            acc[1] += int(bps)
            out.append(FirewallCounter(
                table=table, chain=chain, label=label, verdict=verdict,
                packets=acc[0], bytes=acc[1], pps=pps, bps=bps,
            ))
        return out
