from __future__ import annotations

from typing import NamedTuple, Sequence

from textual_plotext import PlotextPlot

BYTES_TO_MBITS = 8 / 1_000_000

# Per-zone line colors (RGB). WAN family is reds, LAN family is greens; within
# each family the physical link is the bright shade and the tunnel a separate
# hue so all four series stay distinguishable on one chart.
WAN_RX_COLOR = (255, 80, 80)    # bright red    — physical WAN down
WAN_TX_COLOR = (150, 30, 30)    # dark red      — physical WAN up
WAN_TUN_RX_COLOR = (255, 150, 100)  # orange-red — WAN tunnel down
WAN_TUN_TX_COLOR = (190, 90, 40)    # burnt orange — WAN tunnel up

LAN_RX_COLOR = (80, 255, 120)   # bright green  — physical LAN down
LAN_TX_COLOR = (30, 130, 60)    # dark green    — physical LAN up
LAN_TUN_RX_COLOR = (160, 255, 80)   # lime green — LAN tunnel down
LAN_TUN_TX_COLOR = (90, 170, 40)    # olive green — LAN tunnel up


class Series(NamedTuple):
    label: str
    data: Sequence[float]
    color: tuple[int, int, int]


class ThroughputChart(PlotextPlot):
    """Rolling 60-second throughput chart plotting one or more colored series.

    Each chart renders a family of lines (e.g. physical WAN down/up plus WAN
    tunnel down/up) so the red/green zone split stays intact while tunnel
    traffic is visible as separate lines.
    """

    def __init__(self, title: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self._title = title

    def update_series(self, series: Sequence[Series]) -> None:
        plt = self.plt
        plt.clear_figure()
        plt.theme("dark")
        plt.title(self._title)
        plt.plot_size(None, None)

        n = 0
        for s in series:
            scaled = [v * BYTES_TO_MBITS for v in s.data]
            n = len(scaled)
            xs = list(range(n))
            plt.plot(xs, scaled, label=s.label, color=s.color, marker="braille")

        plt.xlabel("seconds ago")
        plt.ylabel("Mb/s")
        if n > 1:
            plt.xticks(
                [0, n // 4, n // 2, 3 * n // 4, n - 1],
                [f"-{n}s", f"-{3 * n // 4}s", f"-{n // 2}s", f"-{n // 4}s", "now"],
            )

        self.refresh()
