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
# Fixed protocol display order so rows never reshuffle as counts change;
# protocols not listed here are appended (sorted) after these.
_PROTO_ORDER = ("tcp", "udp", "icmp", "icmpv6", "sctp")

# TCP-state bar colors, consistent with the Connections tab's state coloring:
# healthy ESTABLISHED green, transient/closing states orange.
_STATE_COLORS = {
    "ESTABLISHED": "#50ffa0",
    "SYN_SENT": "#50a0ff",
    "FIN_WAIT": "#ffa050",
    "TIME_WAIT": "#ffa050",
    "CLOSE_WAIT": "#ffa050",
}
_STATE_DEFAULT_COLOR = "#8080a0"
# Fixed set of states shown, in this order, always — only the bar lengths
# change tick to tick (a state with no connections renders an empty bar).
_STATE_ORDER = ("ESTABLISHED", "SYN_SENT", "FIN_WAIT", "TIME_WAIT", "CLOSE_WAIT")

# Shared field geometry so the protocol and state bar graphs line up: a
# fixed-width label column (wide enough for "ESTABLISHED") and a count column.
_LABEL_WIDTH = 11
_COUNT_WIDTH = 7


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

        # Both bar graphs share the same field widths so they line up: the
        # bar fills the space left after the fixed label and count columns.
        bar = max(self.size.width - (_LABEL_WIDTH + _COUNT_WIDTH + 6), 8)

        # Protocol breakdown bars, in fixed order (known protocols first, then
        # any extras), scaled to the total so widths read as a share of all.
        text.append("  Protocols\n", style="#808080")
        proto_max = max(s.by_protocol.values(), default=1) or 1
        for proto in self._ordered_keys(s.by_protocol, _PROTO_ORDER):
            count = s.by_protocol.get(proto, 0)
            color = _PROTO_COLORS.get(proto.lower(), "#808080")
            self._bar_row(text, proto.upper(), count, count / proto_max, color, bar)

        # TCP-state breakdown bars, in fixed order — only the bar lengths
        # change tick to tick. Scaled to the busiest state so the mix is
        # readable even when one state dominates.
        if s.by_state:
            text.append("\n  States\n", style="#808080")
            state_max = max(s.by_state.values(), default=1) or 1
            for state in _STATE_ORDER:
                count = s.by_state.get(state, 0)
                color = _STATE_COLORS.get(state, _STATE_DEFAULT_COLOR)
                self._bar_row(text, state, count, count / state_max, color, bar)

        return text

    @staticmethod
    def _ordered_keys(counts: dict[str, int], preferred: tuple[str, ...]) -> list[str]:
        """Keys in ``preferred`` order first, then any extras sorted by count."""
        ordered = [k for k in preferred if k in counts]
        extras = sorted(
            (k for k in counts if k not in preferred),
            key=lambda k: counts[k],
            reverse=True,
        )
        return ordered + extras

    @staticmethod
    def _bar_row(text: Text, label: str, count: int, frac: float, color: str, bar: int) -> None:
        filled = max(0, min(int(frac * bar), bar))
        text.append(f"  {label:<{_LABEL_WIDTH}} ", style=f"bold {color}")
        text.append("█" * filled, style=color)
        text.append("░" * (bar - filled), style="#303030")
        text.append(f" {count:>{_COUNT_WIDTH},}\n", style="#808080")
