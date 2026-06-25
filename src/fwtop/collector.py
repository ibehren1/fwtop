from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from fwtop.config import Config
from fwtop.models import (
    Connection,
    ConntrackSummary,
    FirewallCounter,
    InterfaceStat,
    SourceStatus,
)
from fwtop.sources import (
    ConntrackSource,
    DemoSource,
    FirewallSource,
    InterfaceSource,
)

HISTORY_SIZE = 60
# Time columns retained for the drops heatmap (one per tick). Kept generous so
# the heatmap can fill very wide terminals; the widget slices this down to its
# actual on-screen width each render, so it also looks right on narrow ones.
HEATMAP_WIDTH = 320


@dataclass
class Snapshot:
    """Everything the UI needs for a single refresh tick."""

    interfaces: list[InterfaceStat] = field(default_factory=list)
    connections: list[Connection] = field(default_factory=list)
    conntrack: ConntrackSummary = field(
        default_factory=lambda: ConntrackSummary(0, {}, {}, 0, None)
    )
    firewall: list[FirewallCounter] = field(default_factory=list)
    # Aggregate router throughput (bytes/s) summed across all interfaces.
    total_rx_bps: float = 0.0
    total_tx_bps: float = 0.0
    total_drops_pps: float = 0.0  # firewall drop/reject packets per second
    # Per-zone aggregate throughput (bytes/s) for the WAN/LAN charts.
    wan_rx_bps: float = 0.0
    wan_tx_bps: float = 0.0
    wan_tun_rx_bps: float = 0.0
    wan_tun_tx_bps: float = 0.0
    lan_rx_bps: float = 0.0
    lan_tx_bps: float = 0.0
    lan_tun_rx_bps: float = 0.0
    lan_tun_tx_bps: float = 0.0


class Collector:
    """Drives the data sources each tick and maintains rolling history.

    A single switch (``demo``) selects between the real kernel-backed sources
    and the synthetic :class:`DemoSource`, keeping the rest of the app blind to
    which is in use. History deques feed the time-series charts.
    """

    def __init__(self, demo: bool = False, config: Config | None = None) -> None:
        self.demo = demo
        self.config = config or Config()
        self._demo_source: DemoSource | None = None
        self._iface: InterfaceSource | None = None
        self._conntrack: ConntrackSource | None = None
        self._firewall: FirewallSource | None = None

        if demo:
            self._demo_source = DemoSource()
        else:
            self._iface = InterfaceSource()
            self._conntrack = ConntrackSource()
            self._firewall = FirewallSource()

        # Rolling history for the throughput charts (bytes/s).
        def _hist() -> "deque[float]":
            return deque([0.0] * HISTORY_SIZE, maxlen=HISTORY_SIZE)

        self.rx_history = _hist()
        self.tx_history = _hist()
        self.drops_history = _hist()
        # Separate per-zone histories feed the WAN (red) and LAN (green) charts;
        # each chart overlays its physical zone and its tunnel zone.
        self.wan_rx_history = _hist()
        self.wan_tx_history = _hist()
        self.wan_tun_rx_history = _hist()
        self.wan_tun_tx_history = _hist()
        self.lan_rx_history = _hist()
        self.lan_tx_history = _hist()
        self.lan_tun_rx_history = _hist()
        self.lan_tun_tx_history = _hist()

        # Per drop-rule scrolling history of packets/s, for the drops heatmap.
        # Keyed by rule label; each value is a deque of the last HEATMAP_WIDTH
        # ticks (oldest left, newest right). Rules are kept in first-seen order.
        self.drop_rule_order: list[str] = []
        self.drop_rule_history: dict[str, deque[float]] = {}

    # ── source availability (for the status bar / empty panels) ──────────

    @property
    def interface_status(self) -> SourceStatus:
        if self._demo_source:
            return self._demo_source.status
        assert self._iface is not None
        return self._iface.status

    @property
    def conntrack_status(self) -> SourceStatus:
        if self._demo_source:
            return self._demo_source.status
        assert self._conntrack is not None
        return self._conntrack.status

    @property
    def firewall_status(self) -> SourceStatus:
        if self._demo_source:
            return self._demo_source.status
        assert self._firewall is not None
        return self._firewall.status

    @property
    def firewall_backend(self) -> str:
        if self._demo_source:
            return "demo"
        assert self._firewall is not None
        return self._firewall.backend or "none"

    # ── per-tick collection ──────────────────────────────────────────────

    def poll(self) -> Snapshot:
        if self._demo_source is not None:
            interfaces = self._demo_source.poll_interfaces()
            connections, conntrack = self._demo_source.poll_conntrack()
            firewall = self._demo_source.poll_firewall()
        else:
            assert self._iface and self._conntrack and self._firewall
            interfaces = self._iface.poll()
            connections, conntrack = self._conntrack.poll()
            firewall = self._firewall.poll()

        # Tag each interface with its configured (or guessed) zone.
        interfaces = [s._replace(zone=self.config.zone_for(s.name)) for s in interfaces]

        # Sum RX/TX per zone in a single pass.
        def zone_sum(zone: str) -> tuple[float, float]:
            rx = sum(s.rx_bps for s in interfaces if s.zone == zone)
            tx = sum(s.tx_bps for s in interfaces if s.zone == zone)
            return rx, tx

        total_rx = sum(s.rx_bps for s in interfaces)
        total_tx = sum(s.tx_bps for s in interfaces)
        wan_rx, wan_tx = zone_sum("wan")
        wan_tun_rx, wan_tun_tx = zone_sum("wan_tunnel")
        lan_rx, lan_tx = zone_sum("lan")
        lan_tun_rx, lan_tun_tx = zone_sum("lan_tunnel")
        drops_pps = sum(c.pps for c in firewall if c.verdict in ("drop", "reject"))

        self.rx_history.append(total_rx)
        self.tx_history.append(total_tx)
        self.drops_history.append(drops_pps)
        self.wan_rx_history.append(wan_rx)
        self.wan_tx_history.append(wan_tx)
        self.wan_tun_rx_history.append(wan_tun_rx)
        self.wan_tun_tx_history.append(wan_tun_tx)
        self.lan_rx_history.append(lan_rx)
        self.lan_tx_history.append(lan_tx)
        self.lan_tun_rx_history.append(lan_tun_rx)
        self.lan_tun_tx_history.append(lan_tun_tx)

        self._tick_drop_heatmap(firewall)

        return Snapshot(
            interfaces=interfaces,
            connections=connections,
            conntrack=conntrack,
            firewall=firewall,
            total_rx_bps=total_rx,
            total_tx_bps=total_tx,
            total_drops_pps=drops_pps,
            wan_rx_bps=wan_rx,
            wan_tx_bps=wan_tx,
            wan_tun_rx_bps=wan_tun_rx,
            wan_tun_tx_bps=wan_tun_tx,
            lan_rx_bps=lan_rx,
            lan_tx_bps=lan_tx,
            lan_tun_rx_bps=lan_tun_rx,
            lan_tun_tx_bps=lan_tun_tx,
        )

    def _tick_drop_heatmap(self, firewall: list[FirewallCounter]) -> None:
        """Advance the per-rule drops heatmap by one time column.

        Every drop/reject rule's current packets/s is pushed onto its row's
        history (newest on the right). Rules seen for the first time backfill
        with zeros so all rows stay column-aligned, and a rule that stops
        reporting still scrolls (its row fills with zeros) until it ages out.
        """
        current: dict[str, float] = {}
        for c in firewall:
            if c.verdict not in ("drop", "reject"):
                continue
            # Distinguish identically-labeled rules in different chains.
            key = f"{c.chain}: {c.label}" if c.chain else c.label
            current[key] = current.get(key, 0.0) + c.pps

        for key in current:
            if key not in self.drop_rule_history:
                self.drop_rule_order.append(key)
                self.drop_rule_history[key] = deque(
                    [0.0] * HEATMAP_WIDTH, maxlen=HEATMAP_WIDTH
                )

        # Push this tick's value (0 for rules that didn't report) onto each row.
        for key in self.drop_rule_order:
            self.drop_rule_history[key].append(current.get(key, 0.0))
