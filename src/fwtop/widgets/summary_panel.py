from __future__ import annotations

from rich.text import Text
from textual.widget import Widget

from fwtop.collector import Snapshot
from fwtop.stats import format_bits_rate, format_count


class SummaryPanel(Widget):
    """At-a-glance router health: aggregate throughput, connections, drops."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._snap: Snapshot | None = None
        self._uptime = 0

    def update_stats(self, snap: Snapshot, uptime: int) -> None:
        self._snap = snap
        self._uptime = uptime
        self.refresh()

    def render(self) -> Text:
        text = Text()
        snap = self._snap

        mins, secs = divmod(self._uptime, 60)
        hrs, mins = divmod(mins, 60)
        text.append("  UPTIME ", style="bold #a0a0a0")
        text.append(f"{hrs:02d}:{mins:02d}:{secs:02d}\n\n", style="bold white")

        if snap is None:
            text.append("  Waiting for data...\n", style="#606060")
            return text

        text.append("  THROUGHPUT ", style="bold #50a0ff")
        text.append(f"{'─' * 16}\n", style="#404060")
        text.append("    down  ", style="#808080")
        text.append(f"{format_bits_rate(snap.total_rx_bps):>14}\n", style="#50a0ff")
        text.append("    up    ", style="#808080")
        text.append(f"{format_bits_rate(snap.total_tx_bps):>14}\n", style="#50ffa0")
        text.append("    total ", style="#808080")
        text.append(
            f"{format_bits_rate(snap.total_rx_bps + snap.total_tx_bps):>14}\n",
            style="bold white",
        )

        text.append("\n")
        text.append("  CONNECTIONS ", style="bold #a050ff")
        text.append(f"{'─' * 15}\n", style="#404060")
        ct = snap.conntrack
        text.append("    tracked ", style="#808080")
        cap = ""
        if ct.max_entries:
            pct = ct.total / ct.max_entries * 100
            cap = f"  ({pct:.1f}% of {format_count(ct.max_entries)})"
        text.append(f"{ct.total:>6,}", style="#a050ff")
        text.append(f"{cap}\n", style="#606080")
        text.append("    NAT'd   ", style="#808080")
        text.append(f"{ct.nat_count:>6,}\n", style="#c080ff")

        text.append("\n")
        text.append("  FIREWALL ", style="bold #ff5050")
        text.append(f"{'─' * 17}\n", style="#404060")
        text.append("    drops ", style="#808080")
        text.append(f"{snap.total_drops_pps:>8,.0f} pkt/s\n", style="#ff5050")

        return text
