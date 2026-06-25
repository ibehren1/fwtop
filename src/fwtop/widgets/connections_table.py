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

    def on_mount(self) -> None:
        for table_id in ("#dt-conns-wan", "#dt-conns-lan"):
            dt = self.query_one(table_id, DataTable)
            dt.cursor_type = "row"
            dt.zebra_stripes = True
            dt.add_columns(
                "Proto", "Source", "Destination", "NAT →", "State", "Packets", "Bytes"
            )

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
