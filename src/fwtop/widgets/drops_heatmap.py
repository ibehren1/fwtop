from __future__ import annotations

from rich.text import Text
from textual.widget import Widget

from fwtop.collector import Collector

# "Smoke to fire" ramp: faint gray smoke at low drop rates warming through
# embers into bright red fire at the peak. Index 0 is reserved for "exactly
# zero" and rendered as a near-black wisp so empty time still reads as a grid
# rather than blank space.
_RAMP = (
    "#151515",  # 0  — no drops this tick (cold ash)
    "#3a3a3a",  # faint smoke
    "#5a5a5a",  # gray smoke
    "#7a7670",  # warming smoke
    "#8a6a55",  # smoldering
    "#a55a3a",  # embers
    "#c64822",  # kindling
    "#e63010",  # flame
    "#ff2020",  # peak fire
)
_CELL = "█"


class DropsHeatmap(Widget):
    """A ticking heatmap of firewall drops: one row per drop/reject rule,
    one column per refresh tick, scrolling left as time advances.

    Cell color encodes that rule's packets/s on a shared cold→hot ramp scaled
    to the busiest cell currently on screen, so a spike in any rule lights up
    relative to the rest. Newest activity is on the right edge.
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._collector: Collector | None = None
        self._detail = ""

    def update_stats(self, collector: Collector, detail: str = "") -> None:
        self._collector = collector
        self._detail = detail
        self.refresh()

    def on_resize(self) -> None:
        # render() reads self.size.width, so re-render as soon as we resize
        # instead of waiting for the next refresh tick.
        self.refresh()

    def render(self) -> Text:
        text = Text()
        col = self._collector
        if col is None:
            return Text("  Waiting for data...", style="#606060")

        order = col.drop_rule_order
        if not order:
            msg = self._detail or "No drop/reject rules with counters yet."
            return Text(f"  {msg}", style="#606060")

        # Label column width: cap so the heat strip always has room.
        avail = max(self.size.width, 20)
        label_w = min(max(len(k) for k in order) + 1, max(avail // 3, 10))
        strip_w = max(avail - label_w - 1, 8)

        # Shared scale: the peak across all visible cells (last strip_w ticks).
        peak = 0.0
        for key in order:
            for v in list(col.drop_rule_history[key])[-strip_w:]:
                if v > peak:
                    peak = v

        for key in order:
            hist = list(col.drop_rule_history[key])[-strip_w:]
            label = key if len(key) <= label_w - 1 else key[: label_w - 2] + "…"
            text.append(f"  {label:<{label_w - 1}}", style="#c0c0d0")
            for v in hist:
                text.append(_CELL, style=self._heat(v, peak))
            text.append("\n")

        # Footer: smoke→fire legend plus the current peak the scale maps to.
        text.append("  smoke ", style="#5a5a5a")
        text.append("░▒▓█", style="#a55a3a")
        text.append(" fire", style="#ff2020")
        text.append(f"   0 → {peak:,.0f} pkt/s\n", style="#808080")
        return text

    @staticmethod
    def _heat(value: float, peak: float) -> str:
        if value <= 0 or peak <= 0:
            return _RAMP[0]
        # Map (0, peak] across ramp buckets 1..len-1.
        frac = min(value / peak, 1.0)
        idx = 1 + int(frac * (len(_RAMP) - 2) + 0.999)
        idx = min(idx, len(_RAMP) - 1)
        return _RAMP[idx]
