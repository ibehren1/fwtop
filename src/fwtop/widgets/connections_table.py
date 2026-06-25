from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widget import Widget
from textual.widgets import DataTable, Label

from fwtop.models import Connection
from fwtop.stats import format_bytes


class ConnectionsTable(Widget):
    """Top conntrack flows in two columns.

    Conntrack entries carry no interface label, so flows are split by
    :attr:`Connection.is_wan_facing`: NAT'd or public-touching flows (WAN and
    WAN-Tunnel traffic) on the left, purely internal flows on the right.
    """

    DEFAULT_CSS = """
    ConnectionsTable {
        height: 100%;
    }
    ConnectionsTable #conns-split {
        height: 100%;
        layout: horizontal;
    }
    ConnectionsTable .conns-col {
        width: 1fr;
        height: 100%;
    }
    ConnectionsTable .conns-col-left {
        margin-right: 1;
    }
    ConnectionsTable .conns-heading {
        height: 1;
        text-style: bold;
        padding: 0 1;
    }
    ConnectionsTable #heading-wan {
        color: #ff5050;
    }
    ConnectionsTable #heading-other {
        color: #50ffa0;
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

    def compose(self) -> ComposeResult:
        with Horizontal(id="conns-split"):
            with Vertical(classes="conns-col conns-col-left"):
                yield Label("WAN / WAN-Tunnel", classes="conns-heading", id="heading-wan")
                yield DataTable(id="dt-conns-wan")
            with Vertical(classes="conns-col"):
                yield Label("LAN / Other", classes="conns-heading", id="heading-other")
                yield DataTable(id="dt-conns-other")

    def on_mount(self) -> None:
        for table_id in ("#dt-conns-wan", "#dt-conns-other"):
            dt = self.query_one(table_id, DataTable)
            dt.cursor_type = "row"
            dt.zebra_stripes = True
            dt.add_columns(
                "Proto", "Source", "Destination", "NAT →", "State", "Packets", "Bytes"
            )

    def update_stats(self, connections: list[Connection], limit: int = 50) -> None:
        wan = [c for c in connections if c.is_wan_facing]
        other = [c for c in connections if not c.is_wan_facing]
        self._fill("#dt-conns-wan", wan, limit)
        self._fill("#dt-conns-other", other, limit)
        # Show live counts in the headings.
        try:
            self.query_one("#heading-wan", Label).update(f"WAN / WAN-Tunnel  ({len(wan)})")
            self.query_one("#heading-other", Label).update(f"LAN / Other  ({len(other)})")
        except Exception:
            pass

    def _fill(self, table_id: str, connections: list[Connection], limit: int) -> None:
        try:
            dt = self.query_one(table_id, DataTable)
        except Exception:
            return
        dt.clear()
        for c in connections[:limit]:
            src = f"{self._host(c.src)}:{c.sport}"
            dst = f"{self._host(c.dst)}:{c.dport}"
            nat = f"{self._host(c.reply_dst)}" if c.is_nat else "—"
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
