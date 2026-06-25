from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import DataTable

from fwtop.models import FirewallCounter
from fwtop.stats import format_bytes

_VERDICT_COLORS = {
    "drop": "#ff5050",
    "reject": "#ff9020",
    "accept": "#50ffa0",
}


class FirewallPanel(Widget):
    """Firewall rule counters, drops/rejects sorted to the top.

    Shows per-rule packet/byte rates so spikes in dropped traffic (scans,
    brute-force, misconfig) are obvious at a glance.
    """

    DEFAULT_CSS = """
    FirewallPanel {
        height: 100%;
    }
    FirewallPanel DataTable {
        height: 100%;
    }
    """

    def compose(self) -> ComposeResult:
        yield DataTable(id="dt-fw")

    def on_mount(self) -> None:
        dt = self.query_one("#dt-fw", DataTable)
        dt.cursor_type = "row"
        dt.zebra_stripes = True
        dt.add_columns("Verdict", "Chain", "Rule", "Pkt/s", "Bytes/s", "Total Pkts", "Total Bytes")

    def update_stats(self, counters: list[FirewallCounter], limit: int = 40) -> None:
        try:
            dt = self.query_one("#dt-fw", DataTable)
        except Exception:
            return
        dt.clear()

        # Drops and rejects first (and within that, by current packet rate),
        # then everything else by rate — the operator cares about drops most.
        def sort_key(c: FirewallCounter) -> tuple:
            is_drop = c.verdict in ("drop", "reject")
            return (not is_drop, -c.pps, -c.packets)

        for c in sorted(counters, key=sort_key)[:limit]:
            color = _VERDICT_COLORS.get(c.verdict, "#808080")
            dt.add_row(
                Text(c.verdict.upper() or "—", style=f"bold {color}"),
                Text(f"{c.table}/{c.chain}", style="#8080a0"),
                Text(c.label, style="#c0c0d0"),
                Text(f"{c.pps:,.0f}", style=color if c.pps else "#606080"),
                Text(format_bytes(c.bps), style=color if c.bps else "#606080"),
                f"{c.packets:,}",
                format_bytes(c.bytes),
            )
