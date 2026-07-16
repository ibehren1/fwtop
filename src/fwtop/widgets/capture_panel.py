from __future__ import annotations

from collections import deque
from time import monotonic

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widget import Widget
from textual.widgets import DataTable, Label, RichLog

from fwtop.config import ZONE_LABELS
from fwtop.models import Packet
from fwtop.stats import format_bytes, format_mbps
from fwtop.widgets.throughput_chart import (
    LAN_RX_COLOR,
    WAN_RX_COLOR,
    Series,
    ThroughputChart,
)

# Rolling history length, matching the Overview charts (collector.HISTORY_SIZE).
_HISTORY = 60

_ZONE_STYLE = {
    "wan": "bold #ff5050",
    "wan_tunnel": "bold #ff9664",
    "lan": "bold #50ffa0",
    "lan_tunnel": "bold #a0ff50",
    "other": "bold #8080a0",
}

_PROTO_COLORS = {
    "tcp": "#50a0ff",
    "udp": "#50ffa0",
    "icmp": "#ffa050",
}


class CapturePanel(Widget):
    """Filtered-traffic view, laid out like Overview: separate stacked panels.

    Fed by :class:`fwtop.sources.CaptureSource`. Top: two charts plotting the
    matched flow's bytes/s split by zone (reusing the Overview chart colors).
    Middle: a per-interface table breaking the same matched flow down by link.
    Bottom: a live tcpdump-style packet list — the same lines tcpdump prints,
    scrolling as packets arrive. All three update together each tick.

    Throughput here is derived from captured frame lengths, so it approximates
    (rather than exactly matches) the kernel's interface counters.
    """

    DEFAULT_CSS = """
    CapturePanel {
        height: 100%;
        layout: vertical;
    }
    CapturePanel #cap-status {
        height: 1;
        color: #8080a0;
        padding: 0 1;
    }
    CapturePanel #cap-charts {
        height: 16;
        layout: horizontal;
    }
    CapturePanel #cap-wan, CapturePanel #cap-lan {
        width: 1fr;
        height: 100%;
        border: round #303050;
        border-title-align: left;
        background: #0e0e20;
    }
    CapturePanel #cap-wan {
        border-title-color: #ff5050;
    }
    CapturePanel #cap-lan {
        border-title-color: #50ffa0;
    }
    CapturePanel #cap-ifaces {
        height: 1fr;
        min-height: 5;
        border: round #303050;
        border-title-color: #50a0ff;
        border-title-align: left;
        background: #0e0e20;
    }
    CapturePanel #cap-packets {
        height: 2fr;
        min-height: 6;
        border: round #303050;
        border-title-color: #a050ff;
        border-title-align: left;
        background: #0a0a1a;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        # Rolling bytes/s histories for the two zone charts.
        self._wan_hist: deque[float] = deque([0.0] * _HISTORY, maxlen=_HISTORY)
        self._lan_hist: deque[float] = deque([0.0] * _HISTORY, maxlen=_HISTORY)
        # Previous cumulative totals + timestamp, for delta→rate computation.
        self._prev_zone: dict[str, tuple[int, int]] = {}
        self._prev_iface: dict[str, tuple[int, int]] = {}
        self._prev_ts: float | None = None

    def compose(self) -> ComposeResult:
        yield Label("Capture idle — press 'f' to set a filter and start", id="cap-status")
        with Horizontal(id="cap-charts"):
            yield ThroughputChart("WAN matched (Mb/s)", id="cap-wan")
            yield ThroughputChart("LAN matched (Mb/s)", id="cap-lan")
        yield DataTable(id="cap-ifaces")
        yield RichLog(id="cap-packets", wrap=False, markup=False, max_lines=1000, auto_scroll=True)

    def on_mount(self) -> None:
        self.query_one("#cap-wan").border_title = "WAN matched"
        self.query_one("#cap-lan").border_title = "LAN matched"
        self.query_one("#cap-ifaces").border_title = "Interfaces (matched)"
        self.query_one("#cap-packets").border_title = "Packets"
        dt = self.query_one("#cap-ifaces", DataTable)
        dt.cursor_type = "row"
        dt.zebra_stripes = True
        dt.add_columns("Interface", "Zone", "Pkt/s", "Bytes/s", "Total Pkts", "Total Bytes")

    def reset(self) -> None:
        """Clear histories, deltas, and the packet list when a capture starts."""
        self._wan_hist = deque([0.0] * _HISTORY, maxlen=_HISTORY)
        self._lan_hist = deque([0.0] * _HISTORY, maxlen=_HISTORY)
        self._prev_zone = {}
        self._prev_iface = {}
        self._prev_ts = None
        try:
            self.query_one("#cap-packets", RichLog).clear()
        except Exception:
            pass

    def set_status(self, text: str, style: str = "#8080a0") -> None:
        try:
            self.query_one("#cap-status", Label).update(Text(text, style=style))
        except Exception:
            pass

    def update_stats(
        self,
        packets: list[Packet],
        iface_totals: dict[str, tuple[int, int]],
        zone_totals: dict[str, tuple[int, int]],
    ) -> None:
        """Push a drain's worth of packets + cumulative (packets, bytes) totals.

        Rates are the per-second deltas against the previous drain; the WAN and
        LAN charts scroll one column per call and the new packets append to the
        live list.
        """
        now = monotonic()
        dt = (now - self._prev_ts) if self._prev_ts is not None else 0.0
        self._prev_ts = now

        def rate(prev: dict[str, tuple[int, int]], key: str, cur: tuple[int, int]) -> tuple[float, float]:
            pp, pb = prev.get(key, (cur[0], cur[1]))
            if dt <= 0:
                return 0.0, 0.0
            return max(0.0, (cur[0] - pp) / dt), max(0.0, (cur[1] - pb) / dt)

        # Zone charts: WAN family (wan + wan_tunnel), LAN family (lan + lan_tunnel).
        wan_bps = lan_bps = 0.0
        for zone, cur in zone_totals.items():
            _, bps = rate(self._prev_zone, zone, cur)
            if zone in ("wan", "wan_tunnel"):
                wan_bps += bps
            elif zone in ("lan", "lan_tunnel"):
                lan_bps += bps
        self._prev_zone = dict(zone_totals)
        self._wan_hist.append(wan_bps)
        self._lan_hist.append(lan_bps)

        self._render_charts()
        self._render_table(iface_totals, rate)
        self._prev_iface = dict(iface_totals)
        self._render_packets(packets)

    def _render_charts(self) -> None:
        try:
            self.query_one("#cap-wan", ThroughputChart).update_series(
                [Series("matched", list(self._wan_hist), WAN_RX_COLOR)]
            )
            self.query_one("#cap-lan", ThroughputChart).update_series(
                [Series("matched", list(self._lan_hist), LAN_RX_COLOR)]
            )
        except Exception:
            pass

    def _render_table(self, iface_totals: dict[str, tuple[int, int]], rate) -> None:
        try:
            dt = self.query_one("#cap-ifaces", DataTable)
        except Exception:
            return
        dt.clear()
        # Busiest interface (by cumulative bytes) first.
        for iface in sorted(iface_totals, key=lambda k: iface_totals[k][1], reverse=True):
            pkts, byts = iface_totals[iface]
            pps, bps = rate(self._prev_iface, iface, (pkts, byts))
            zone = self._zone_of(iface)
            dt.add_row(
                Text(iface, style="bold #50a0ff"),
                Text(ZONE_LABELS.get(zone, zone), style=_ZONE_STYLE.get(zone, "#8080a0")),
                Text(f"{pps:,.0f}", style="#c0c0d0" if pps else "#606080"),
                Text(format_mbps(bps), style="#50ffa0" if bps else "#606080"),
                f"{pkts:,}",
                format_bytes(byts),
            )

    def _render_packets(self, packets: list[Packet]) -> None:
        if not packets:
            return
        try:
            log = self.query_one("#cap-packets", RichLog)
        except Exception:
            return
        for p in packets:
            log.write(self._format_packet(p))

    @staticmethod
    def _format_packet(p: Packet) -> Text:
        # Show tcpdump's own line verbatim; just tint it by protocol. Fall back
        # to a minimal line if a packet somehow lacks captured text.
        color = _PROTO_COLORS.get(p.proto, "#c0c0d0")
        if p.text:
            return Text(p.text, style=color)
        src = f"{p.src}.{p.sport}" if p.sport else p.src
        dst = f"{p.dst}.{p.dport}" if p.dport else p.dst
        return Text(f"{p.ts:.6f} {p.iface} IP {src} > {dst}: length {p.length}", style=color)

    # The panel doesn't know an interface's zone directly; the app sets the
    # current interface→zone mapping (from the config) via set_iface_zones.
    _iface_zone: dict[str, str] = {}

    def set_iface_zones(self, mapping: dict[str, str]) -> None:
        self._iface_zone = dict(mapping)

    def _zone_of(self, iface: str) -> str:
        return self._iface_zone.get(iface, "other")
