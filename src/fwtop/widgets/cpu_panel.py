from __future__ import annotations

import os

import psutil
from rich.text import Text
from textual.widget import Widget


class CpuPanel(Widget):
    """Compact CPU utilization bars: user / system / total / fwtop process."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._user_pct = 0.0
        self._system_pct = 0.0
        self._total_pct = 0.0
        self._process_pct = 0.0
        self._num_cpus = psutil.cpu_count() or 1
        self._process = psutil.Process(os.getpid())
        # Prime both so the first real poll returns meaningful deltas.
        psutil.cpu_times_percent(percpu=False)
        self._process.cpu_percent()

    def poll(self) -> None:
        times = psutil.cpu_times_percent(percpu=False)
        self._user_pct = times.user
        self._system_pct = times.system
        self._total_pct = self._user_pct + self._system_pct
        # Normalize from per-core (0..N*100) to system-wide (0..100).
        self._process_pct = self._process.cpu_percent() / self._num_cpus
        self.refresh()

    def render(self) -> Text:
        text = Text()
        bar_width = max(self.size.width - 18, 10)
        rows = [
            ("User", self._user_pct, "#50a0ff"),
            ("System", self._system_pct, "#a050ff"),
            ("Total", self._total_pct, "#50ffa0"),
            ("fwtop", self._process_pct, "#ffa050"),
        ]
        for label, pct, bar_color in rows:
            text.append(f"  {label:<8}", style=f"bold {bar_color}")
            self._draw_bar(text, pct, bar_width, bar_color, "#303030")
            text.append(f" {pct:>5.1f}%\n", style=self._color(pct))
        return text

    @staticmethod
    def _draw_bar(text: Text, pct: float, width: int, fg: str, bg: str) -> None:
        filled = min(int(pct / 100 * width), width)
        text.append("█" * filled, style=fg)
        text.append("░" * (width - filled), style=bg)

    @staticmethod
    def _color(pct: float) -> str:
        if pct > 80:
            return "bold #ff5050"
        if pct > 50:
            return "#ffa050"
        return "#50ffa0"
