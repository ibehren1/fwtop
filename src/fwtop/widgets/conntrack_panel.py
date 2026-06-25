from __future__ import annotations

from rich.text import Text
from textual.widget import Widget

from fwtop.models import ConntrackSummary

# Per-protocol bar colors, matching the rest of the theme.
_PROTO_COLORS = {
    "tcp": "#50a0ff",
    "udp": "#50ffa0",
    "icmp": "#ffa050",
    "icmpv6": "#ff50a0",
    "sctp": "#a050ff",
}


class ConntrackPanel(Widget):
    """Connection-tracking summary: table fill, protocol & state breakdown."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._summary: ConntrackSummary | None = None
        self._detail = ""

    def update_stats(self, summary: ConntrackSummary, detail: str = "") -> None:
        self._summary = summary
        self._detail = detail
        self.refresh()

    def render(self) -> Text:
        text = Text()
        s = self._summary

        if s is None or (s.total == 0 and self._detail):
            text.append(f"  {self._detail or 'Waiting for data...'}\n", style="#606060")
            return text

        # Capacity bar.
        bar_width = max(self.size.width - 22, 10)
        if s.max_entries:
            frac = min(s.total / s.max_entries, 1.0)
            filled = int(frac * bar_width)
            color = "#ff5050" if frac > 0.8 else "#ffa050" if frac > 0.5 else "#50ffa0"
            text.append("  table  ", style="#808080")
            text.append("█" * filled, style=color)
            text.append("░" * (bar_width - filled), style="#303030")
            text.append(f" {frac:>5.1%}\n", style=color)
        text.append("  total  ", style="#808080")
        text.append(f"{s.total:,}", style="bold white")
        text.append("   NAT ", style="#808080")
        text.append(f"{s.nat_count:,}\n\n", style="#c080ff")

        # Protocol breakdown bars.
        total = s.total or 1
        for proto, count in list(s.by_protocol.items())[:5]:
            pct = count / total
            color = _PROTO_COLORS.get(proto.lower(), "#808080")
            pbar = max(self.size.width - 24, 8)
            filled = int(pct * pbar)
            text.append(f"  {proto.upper():<7}", style=f"bold {color}")
            text.append("█" * filled, style=color)
            text.append("░" * (pbar - filled), style="#303030")
            text.append(f" {count:>5,}\n", style="#808080")

        # Top TCP states on one line.
        if s.by_state:
            text.append("\n  states  ", style="#808080")
            parts = [f"{st}={n}" for st, n in list(s.by_state.items())[:4]]
            text.append("  ".join(parts) + "\n", style="#8080a0")

        return text
