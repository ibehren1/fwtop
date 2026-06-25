from __future__ import annotations

from time import monotonic

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Footer, Header, Label, ListItem, ListView, TabbedContent, TabPane

from fwtop import __version__
from fwtop.collector import Collector
from fwtop.config import ZONE_CYCLE, Config
from fwtop.resolve import Resolver
from fwtop.widgets import (
    ConnectionsTable,
    ConntrackPanel,
    CpuPanel,
    DropsHeatmap,
    FirewallPanel,
    InterfaceTable,
    SummaryPanel,
    ThroughputChart,
)
from fwtop.widgets.throughput_chart import (
    LAN_RX_COLOR,
    LAN_TUN_RX_COLOR,
    LAN_TUN_TX_COLOR,
    LAN_TX_COLOR,
    WAN_RX_COLOR,
    WAN_TUN_RX_COLOR,
    WAN_TUN_TX_COLOR,
    WAN_TX_COLOR,
    Series,
)


class ZoneScreen(ModalScreen[None]):
    """Assign each interface to a zone (WAN / LAN / other).

    Pressing Enter (or space) on a row cycles its zone and persists the choice
    immediately via the shared :class:`Config`. The change takes effect on the
    next refresh tick, repopulating the WAN/LAN charts accordingly.
    """

    DEFAULT_CSS = """
    ZoneScreen {
        align: center middle;
        background: rgba(0, 0, 0, 0.7);
    }
    #zone-dialog {
        width: 56;
        height: auto;
        max-height: 80%;
        border: round #50a0ff;
        background: #1a1a2e;
        padding: 1 2;
    }
    #zone-dialog Label {
        color: #c0c0d0;
        margin-bottom: 1;
    }
    #zone-dialog .hint {
        color: #606080;
        margin-top: 1;
    }
    #zone-dialog ListView {
        height: auto;
        max-height: 16;
        background: #0e0e20;
        border: tall #303050;
    }
    #zone-dialog ListView:focus {
        border: tall #50a0ff;
    }
    #zone-dialog ListItem {
        background: #0e0e20;
        color: #c0c0d0;
        padding: 0 1;
    }
    #zone-dialog ListItem.-highlight {
        background: #303060;
        text-style: bold;
    }
    """

    _ZONE_MARK = {
        "wan": "[#ff5050]WAN[/]",
        "wan_tunnel": "[#ff9664]WAN-Tun[/]",
        "lan": "[#50ffa0]LAN[/]",
        "lan_tunnel": "[#a0ff50]LAN-Tun[/]",
        "other": "[#8080a0]other[/]",
    }

    def __init__(self, interfaces: list[str], config: Config) -> None:
        super().__init__()
        self._interfaces = interfaces
        self._config = config

    def compose(self) -> ComposeResult:
        with Vertical(id="zone-dialog"):
            yield Label("Assign interface zones:")
            yield ListView(*self._build_items(), id="zone-list")
            yield Label("Enter/Space to cycle WAN → LAN → other, Escape to close", classes="hint")

    def _build_items(self) -> list[ListItem]:
        items = []
        for iface in self._interfaces:
            zone = self._config.zone_for(iface)
            items.append(ListItem(Label(self._row_text(iface, zone))))
        return items

    def _row_text(self, iface: str, zone: str) -> str:
        return f"{iface:<14} {self._ZONE_MARK.get(zone, zone)}"

    def on_mount(self) -> None:
        self.query_one("#zone-list", ListView).focus()

    def _cycle_current(self) -> None:
        lv = self.query_one("#zone-list", ListView)
        idx = lv.index
        if idx is None:
            return
        iface = self._interfaces[idx]
        new_zone = self._config.cycle_zone(iface)
        # Re-render just this row's label in place.
        item = lv.children[idx]
        label = item.query_one(Label)
        label.update(self._row_text(iface, new_zone))

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        self._cycle_current()

    def key_space(self) -> None:
        self._cycle_current()

    def key_escape(self) -> None:
        self.dismiss(None)


class FwTopApp(App):
    CSS_PATH = "fwtop.tcss"
    TITLE = f"fwtop v{__version__}"

    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("p", "toggle_pause", "Pause"),
        Binding("r", "toggle_resolve", "Resolve"),
        Binding("n", "change_interval", "Interval"),
        Binding("z", "assign_zones", "Zones"),
        Binding("1", "show_tab('overview')", "Overview"),
        Binding("2", "show_tab('connections')", "Connections"),
        Binding("3", "show_tab('firewall')", "Firewall"),
        Binding("4", "show_tab('drops')", "Drops"),
        Binding("w", "conns_sub('sub-wan')", "WAN conns"),
        Binding("l", "conns_sub('sub-lan')", "LAN conns"),
    ]

    def __init__(
        self,
        interval: float = 1.0,
        demo: bool = False,
        resolve: bool = False,
        config: Config | None = None,
        nameservers: list[str] | None = None,
    ) -> None:
        super().__init__()
        self.refresh_interval = interval
        self.config = config or Config.load()
        self.collector = Collector(demo=demo, config=self.config)
        self.resolver: Resolver | None = None
        self.resolve_enabled = resolve
        self.nameservers = nameservers
        self.paused = False
        self._start_time = 0.0
        self._timer = None
        self._last_interfaces: list[str] = []

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent(initial="overview", id="main-tabs"):
            with TabPane("Overview", id="overview"):
                with Horizontal(id="main-row"):
                    with Vertical(id="left-col"):
                        yield SummaryPanel(id="summary")
                        yield CpuPanel(id="cpu-panel")
                        yield ConntrackPanel(id="conntrack")
                    with Vertical(id="right-col"):
                        with Horizontal(id="charts-row"):
                            yield ThroughputChart("WAN throughput (Mb/s)", id="wan-chart")
                            yield ThroughputChart("LAN throughput (Mb/s)", id="lan-chart")
                        yield InterfaceTable(id="interfaces")
            with TabPane("Connections", id="connections"):
                yield ConnectionsTable(id="conns-table")
            with TabPane("Firewall", id="firewall"):
                yield FirewallPanel(id="fw-table")
            with TabPane("Drops", id="drops"):
                yield DropsHeatmap(id="drops-heatmap")
        yield Label("", id="status-label", markup=False)
        yield Footer()

    def _make_resolver(self) -> Resolver:
        # Resolution always goes through real DNS, in-process via dnspython,
        # against the host's discovered upstream servers (or --dns overrides).
        # Demo mode is no different: its traffic uses real LAN subnets, so
        # whichever addresses have PTR records on the host's DNS resolve for
        # real, exactly as in production.
        return Resolver(nameservers=self.nameservers)

    def on_mount(self) -> None:
        if self.resolve_enabled:
            self.resolver = self._make_resolver()
        self._start_time = monotonic()
        self._update_subtitle()

        self.query_one("#summary").border_title = "Summary"
        self.query_one("#cpu-panel").border_title = "CPU"
        self.query_one("#conntrack").border_title = "Conntrack"
        self.query_one("#wan-chart").border_title = "WAN"
        self.query_one("#lan-chart").border_title = "LAN"
        self.query_one("#drops-heatmap").border_title = "Drops Heatmap"
        self.query_one("#interfaces").border_title = "Interfaces"
        self.query_one("#conns-table").border_title = "Connections"
        self.query_one("#fw-table").border_title = "Firewall Counters"

        self._timer = self.set_interval(self.refresh_interval, self._refresh)
        self._refresh()

    def _refresh(self) -> None:
        try:
            status = self.query_one("#status-label", Label)
        except Exception:
            return

        if self.paused:
            status.update(" capture: paused — press 'p' to resume")
            return

        snap = self.collector.poll()
        self._last_interfaces = [s.name for s in snap.interfaces]
        uptime = int(monotonic() - self._start_time)

        # Status bar reflects which sources are live vs degraded.
        status.update(" " + self._status_line())

        self.query_one("#summary", SummaryPanel).update_stats(snap, uptime)
        self.query_one("#cpu-panel", CpuPanel).poll()
        self.query_one("#conntrack", ConntrackPanel).update_stats(
            snap.conntrack,
            "" if self.collector.conntrack_status.available
            else self.collector.conntrack_status.detail,
        )
        c = self.collector
        self.query_one("#wan-chart", ThroughputChart).update_series([
            Series("down", c.wan_rx_history, WAN_RX_COLOR),
            Series("up", c.wan_tx_history, WAN_TX_COLOR),
            Series("tun down", c.wan_tun_rx_history, WAN_TUN_RX_COLOR),
            Series("tun up", c.wan_tun_tx_history, WAN_TUN_TX_COLOR),
        ])
        self.query_one("#lan-chart", ThroughputChart).update_series([
            Series("down", c.lan_rx_history, LAN_RX_COLOR),
            Series("up", c.lan_tx_history, LAN_TX_COLOR),
            Series("tun down", c.lan_tun_rx_history, LAN_TUN_RX_COLOR),
            Series("tun up", c.lan_tun_tx_history, LAN_TUN_TX_COLOR),
        ])
        self.query_one("#drops-heatmap", DropsHeatmap).update_stats(
            c,
            "" if self.collector.firewall_status.available
            else self.collector.firewall_status.detail,
        )
        self.query_one("#interfaces", InterfaceTable).update_stats(snap.interfaces)

        conns = self.query_one("#conns-table", ConnectionsTable)
        conns.set_resolver(self.resolver if self.resolve_enabled else None)
        conns.update_stats(snap.connections)
        self.query_one("#fw-table", FirewallPanel).update_stats(snap.firewall)

    def _status_line(self) -> str:
        def mark(name: str, st) -> str:
            return f"{name}:{'ok' if st.available else 'n/a'}"

        parts = [
            mark("iface", self.collector.interface_status),
            mark("conntrack", self.collector.conntrack_status),
            f"fw:{self.collector.firewall_backend}",
        ]
        if self.collector.demo:
            parts.insert(0, "DEMO")
        return " | ".join(parts)

    def _update_subtitle(self) -> None:
        flags = []
        if self.collector.demo:
            flags.append("DEMO")
        if self.resolve_enabled:
            flags.append("DNS")
        if self.paused:
            flags.append("PAUSED")
        suffix = f" [{' '.join(flags)}]" if flags else ""
        self.sub_title = f"{self.refresh_interval:.1f}s{suffix}"

    # ── actions ──────────────────────────────────────────────────────────

    def action_show_tab(self, tab: str) -> None:
        self.query_one("#main-tabs", TabbedContent).active = tab

    def action_conns_sub(self, sub: str) -> None:
        # Jump to the Connections tab and select the WAN/LAN sub-tab.
        self.query_one("#main-tabs", TabbedContent).active = "connections"
        self.query_one("#conns-table", ConnectionsTable).show_sub(sub)

    def action_toggle_pause(self) -> None:
        self.paused = not self.paused
        self._update_subtitle()

    def action_toggle_resolve(self) -> None:
        self.resolve_enabled = not self.resolve_enabled
        if self.resolve_enabled and self.resolver is None:
            self.resolver = self._make_resolver()
        self._update_subtitle()

    def action_change_interval(self) -> None:
        # Cycle through a few sensible refresh rates.
        choices = [0.5, 1.0, 2.0, 5.0]
        try:
            idx = choices.index(self.refresh_interval)
        except ValueError:
            idx = -1
        self.refresh_interval = choices[(idx + 1) % len(choices)]
        if self._timer is not None:
            self._timer.stop()
        self._timer = self.set_interval(self.refresh_interval, self._refresh)
        self._update_subtitle()

    def action_assign_zones(self) -> None:
        # Offer the interfaces seen on the most recent tick.
        if not self._last_interfaces:
            return
        self.push_screen(ZoneScreen(list(self._last_interfaces), self.config))

    def on_unmount(self) -> None:
        if self.resolver is not None:
            self.resolver.stop()
