from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import DataTable

from fwtop.config import ZONE_LABELS
from fwtop.models import InterfaceStat
from fwtop.stats import format_bytes, format_mbps

# Zones are always shown in this order, each as its own headed section.
_ZONE_ORDER = ("wan", "wan_tunnel", "lan", "lan_tunnel", "other")

# Fixed column widths so cells never resize as values grow. The rate columns
# are sized for "100,000.00 Mbps" (100 Gbps); totals for values up to "999.9
# PB"; the rest for large comma-grouped counts.
_COL_WIDTHS = {
    "Interface": 16,
    "RX rate": 16,
    "TX rate": 16,
    "RX total": 12,
    "TX total": 12,
    "Errors": 11,
    "Drops": 11,
}


class InterfaceTable(Widget):
    """Per-interface RX/TX rates, totals, and error/drop counters.

    This is the core router view: each physical/virtual interface shown
    separately so forwarded (through) traffic is visible per link, not just
    host-local traffic.

    Rows are grouped into zone sections (WAN, WAN-Tunnel, LAN, LAN-Tunnel,
    other), each under a heading, and ordered stably by name within a section.
    The row layout is only rebuilt when the set of interfaces or their zones
    changes; on every other tick the existing cells are updated in place so
    rows never jump around as traffic fluctuates.
    """

    DEFAULT_CSS = """
    InterfaceTable {
        height: 100%;
    }
    InterfaceTable DataTable {
        height: 100%;
    }
    """

    # Zone heading colors, matching the WAN(red)/LAN(green) chart scheme;
    # tunnels use the lighter shade from their family.
    _ZONE_STYLE = {
        "wan": "bold #ff5050",
        "wan_tunnel": "bold #ff9664",
        "lan": "bold #50ffa0",
        "lan_tunnel": "bold #a0ff50",
        "other": "bold #8080a0",
    }

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._col_keys: list = []
        # Signature of the current row layout: ((zone, (name, ...)), ...).
        # When it changes we rebuild; otherwise we update cells in place.
        self._sig: tuple = ()

    def compose(self) -> ComposeResult:
        yield DataTable(id="dt-ifaces")

    def on_mount(self) -> None:
        dt = self.query_one("#dt-ifaces", DataTable)
        dt.cursor_type = "row"
        # Zebra striping is off so the zone heading rows read cleanly as
        # separators rather than blending into alternating row colors.
        dt.zebra_stripes = False
        self._col_keys = dt.add_columns(*_COL_WIDTHS.keys())
        # Pin each column to a fixed width so cells never resize as values
        # grow (e.g. a link ramping from idle to 100 Gbps).
        for col in dt.columns.values():
            col.auto_width = False
            col.width = _COL_WIDTHS.get(col.label.plain, col.width)

    def update_stats(self, interfaces: list[InterfaceStat]) -> None:
        try:
            dt = self.query_one("#dt-ifaces", DataTable)
        except Exception:
            return

        # Group interfaces by zone in the fixed order, stable-sorted by name.
        groups: list[tuple[str, list[InterfaceStat]]] = []
        for zone in _ZONE_ORDER:
            members = sorted(
                (s for s in interfaces if s.zone == zone), key=lambda s: s.name
            )
            if members:
                groups.append((zone, members))

        sig = tuple((zone, tuple(s.name for s in members)) for zone, members in groups)

        if sig != self._sig:
            self._rebuild(dt, groups)
            self._sig = sig
        else:
            for _, members in groups:
                for s in members:
                    self._update_row(dt, s)

    # ── layout ───────────────────────────────────────────────────────────

    def _rebuild(self, dt: DataTable, groups: list[tuple[str, list[InterfaceStat]]]) -> None:
        dt.clear()
        blanks = [""] * (len(self._col_keys) - 1)
        for zone, members in groups:
            dt.add_row(
                Text(ZONE_LABELS.get(zone, zone), style=self._ZONE_STYLE.get(zone, "#8080a0")),
                *blanks,
                key=f"__hdr_{zone}",
            )
            for s in members:
                dt.add_row(*self._cells(s), key=f"if_{s.name}")

    def _update_row(self, dt: DataTable, s: InterfaceStat) -> None:
        row_key = f"if_{s.name}"
        cells = self._cells(s)
        # Skip column 0 (the interface name) — it never changes for a row.
        for col_key, value in zip(self._col_keys[1:], cells[1:]):
            try:
                # update_width=False keeps the pinned column widths static.
                dt.update_cell(row_key, col_key, value, update_width=False)
            except Exception:
                # Row vanished between ticks (race with a rebuild) — ignore;
                # the next tick's signature check will reconcile the layout.
                return

    def _cells(self, s: InterfaceStat) -> tuple:
        errs = s.rx_errors + s.tx_errors
        drops = s.rx_dropped + s.tx_dropped
        return (
            Text(f"  {s.name}", style="bold #50a0ff"),
            Text(format_mbps(s.rx_bps), style="#50a0ff"),
            Text(format_mbps(s.tx_bps), style="#50ffa0"),
            format_bytes(s.rx_bytes),
            format_bytes(s.tx_bytes),
            Text(f"{errs:,}", style="#ffa050" if errs else "#606080"),
            Text(f"{drops:,}", style="#ff5050" if drops else "#606080"),
        )
