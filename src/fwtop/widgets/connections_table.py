from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import DataTable, TabbedContent, TabPane

from fwtop.models import Connection
from fwtop.stats import format_bytes


class ConnectionsTable(Widget):
    """Top conntrack flows, split into WAN and LAN sub-tabs.

    Conntrack entries carry no interface label, so flows are split by
    :attr:`Connection.is_wan_facing`: NAT'd or public-touching flows (WAN and
    WAN-Tunnel traffic) under the WAN sub-tab, purely internal flows under LAN.
    Each sub-tab is a full-width table; both source and destination addresses
    are reverse-DNS resolved when resolution is enabled.
    """

    DEFAULT_CSS = """
    ConnectionsTable {
        height: 100%;
    }
    ConnectionsTable TabbedContent {
        height: 100%;
    }
    ConnectionsTable DataTable {
        height: 1fr;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._resolver = None

    def set_resolver(self, resolver) -> None:
        self._resolver = resolver

    def show_sub(self, sub: str) -> None:
        """Activate a sub-tab ('sub-wan' or 'sub-lan')."""
        try:
            self.query_one("#conns-subtabs", TabbedContent).active = sub
        except Exception:
            pass

    def compose(self) -> ComposeResult:
        with TabbedContent(initial="sub-wan", id="conns-subtabs"):
            with TabPane("WAN", id="sub-wan"):
                yield DataTable(id="dt-conns-wan")
            with TabPane("LAN", id="sub-lan"):
                yield DataTable(id="dt-conns-lan")

    # Columns with a fixed width; the remaining horizontal space is divided
    # among the variable-length address columns (Source/Destination/NAT) so
    # the table always fills the full terminal width.
    _FIXED_WIDTHS = {
        "Proto": 6,
        "State": 12,
        "Packets": 11,
        "Bytes": 11,
    }
    _FLEX_COLUMNS = ("Source", "Destination", "NAT →")
    # Roughly how to divide leftover space among the flex columns: source and
    # destination get the lion's share, the NAT reply a bit less.
    _FLEX_WEIGHTS = {"Source": 4, "Destination": 4, "NAT →": 3}

    def on_mount(self) -> None:
        for table_id in ("#dt-conns-wan", "#dt-conns-lan"):
            dt = self.query_one(table_id, DataTable)
            dt.cursor_type = "row"
            dt.zebra_stripes = True
            dt.add_columns(
                "Proto", "Source", "Destination", "NAT →", "State", "Packets", "Bytes"
            )
            for col in dt.columns.values():
                col.auto_width = False
        self._resize_columns()

    def on_resize(self) -> None:
        self._resize_columns()

    def _resize_columns(self) -> None:
        for table_id in ("#dt-conns-wan", "#dt-conns-lan"):
            try:
                dt = self.query_one(table_id, DataTable)
            except Exception:
                continue
            if not dt.columns:
                continue
            # Each column also consumes 2 * cell_padding of horizontal space.
            padding_total = 2 * dt.cell_padding * len(dt.columns)
            available = dt.size.width - padding_total
            fixed_total = sum(self._FIXED_WIDTHS.values())
            flex_space = max(available - fixed_total, len(self._FLEX_COLUMNS) * 12)
            weight_total = sum(self._FLEX_WEIGHTS.values())
            # Hand out flex space by weight, giving any rounding remainder to
            # the last flex column so the row exactly fills the width.
            assigned = 0
            flex_widths: dict[str, int] = {}
            for i, name in enumerate(self._FLEX_COLUMNS):
                if i == len(self._FLEX_COLUMNS) - 1:
                    flex_widths[name] = flex_space - assigned
                else:
                    w = flex_space * self._FLEX_WEIGHTS[name] // weight_total
                    flex_widths[name] = w
                    assigned += w
            for col in dt.columns.values():
                name = col.label.plain
                col.auto_width = False
                col.width = self._FIXED_WIDTHS.get(name, flex_widths.get(name, col.width))
            dt.refresh()

    def update_stats(self, connections: list[Connection], limit: int = 200) -> None:
        wan = [c for c in connections if c.is_wan_facing]
        lan = [c for c in connections if not c.is_wan_facing]
        self._fill("#dt-conns-wan", wan, limit)
        self._fill("#dt-conns-lan", lan, limit)
        # Reflect live counts in the sub-tab labels.
        try:
            tabs = self.query_one("#conns-subtabs", TabbedContent)
            tabs.get_tab("sub-wan").label = f"WAN ({len(wan)})"
            tabs.get_tab("sub-lan").label = f"LAN ({len(lan)})"
        except Exception:
            pass

    def _fill(self, table_id: str, connections: list[Connection], limit: int) -> None:
        try:
            dt = self.query_one(table_id, DataTable)
        except Exception:
            return
        dt.clear()
        for c in connections[:limit]:
            # Resolve both endpoints (and the NAT reply address) when enabled.
            src = f"{self._host(c.src)}:{c.sport}"
            dst = f"{self._host(c.dst)}:{c.dport}"
            nat = self._host(c.reply_dst) if c.is_nat else "—"
            dt.add_row(
                Text(c.protocol.upper(), style=self._proto_color(c.protocol)),
                Text(src, style="#50a0ff"),
                Text(dst, style="#c0c0d0"),
                Text(nat, style="#c080ff" if c.is_nat else "#404060"),
                Text(c.state or "—", style=self._state_color(c.state)),
                f"{c.packets:,}" if c.packets else "—",
                format_bytes(c.bytes) if c.bytes else "—",
            )

    def _host(self, ip: str) -> str:
        if self._resolver is not None:
            return self._resolver.display(ip)
        return ip

    @staticmethod
    def _proto_color(proto: str) -> str:
        return {
            "tcp": "#50a0ff",
            "udp": "#50ffa0",
            "icmp": "#ffa050",
        }.get(proto.lower(), "#808080")

    @staticmethod
    def _state_color(state: str) -> str:
        if state == "ESTABLISHED":
            return "#50ffa0"
        if state in ("TIME_WAIT", "CLOSE_WAIT", "FIN_WAIT"):
            return "#ffa050"
        if not state:
            return "#404060"
        return "#8080a0"
