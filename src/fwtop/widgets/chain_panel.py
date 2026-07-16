from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widget import Widget
from textual.widgets import DataTable, Label, ListItem, ListView

from fwtop.models import FirewallCounter
from fwtop.stats import format_bytes

_VERDICT_COLORS = {
    "drop": "#ff5050",
    "reject": "#ff9020",
    "accept": "#50ffa0",
}


class ChainPanel(Widget):
    """Pick a firewall chain and inspect every rule's counter within it.

    Unlike the drops-first :class:`FirewallPanel`, this view keeps rules in
    their natural ruleset order under the chain the operator selects, so it
    reads like ``nft list chain`` / ``iptables -L <chain>``: rule position,
    verdict, and live packet/byte rates side by side.
    """

    DEFAULT_CSS = """
    ChainPanel {
        height: 100%;
        layout: horizontal;
    }
    ChainPanel #chain-list {
        width: 32;
        height: 100%;
        background: #0e0e20;
        border-right: tall #303050;
    }
    ChainPanel #chain-list > ListItem {
        background: #0e0e20;
        color: #c0c0d0;
        padding: 0 1;
    }
    ChainPanel #chain-list > ListItem.-highlight {
        background: #303060;
        text-style: bold;
    }
    ChainPanel #chain-list:focus > ListItem.-highlight {
        background: #405080;
    }
    ChainPanel #chain-rules {
        width: 1fr;
        height: 100%;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._counters: list[FirewallCounter] = []
        self._chain_keys: list[str] = []
        self._selected: str | None = None

    def compose(self) -> ComposeResult:
        yield ListView(id="chain-list")
        yield DataTable(id="chain-rules")

    def on_mount(self) -> None:
        dt = self.query_one("#chain-rules", DataTable)
        dt.cursor_type = "row"
        dt.zebra_stripes = True
        dt.add_columns("#", "Verdict", "Rule", "Pkt/s", "Bytes/s", "Total Pkts", "Total Bytes")

    # ── chain grouping ────────────────────────────────────────────────────

    @staticmethod
    def _key(c: FirewallCounter) -> str:
        return f"{c.table}/{c.chain}"

    def _rules_for(self, key: str) -> list[FirewallCounter]:
        return [c for c in self._counters if self._key(c) == key]

    def _chain_label(self, key: str) -> Text:
        rules = self._rules_for(key)
        drops = sum(c.pps for c in rules if c.verdict in ("drop", "reject"))
        color = "#ff5050" if drops > 0 else "#c0c0d0"
        text = Text(key, style=color)
        text.append(f"  ({len(rules)})", style="#606080")
        return text

    # ── refresh ───────────────────────────────────────────────────────────

    def update_stats(self, counters: list[FirewallCounter]) -> None:
        self._counters = counters

        keys: list[str] = []
        seen: set[str] = set()
        for c in counters:
            k = self._key(c)
            if k not in seen:
                seen.add(k)
                keys.append(k)
        keys.sort()

        if keys != self._chain_keys:
            self._rebuild_list(keys)
        else:
            self._refresh_list_labels()

        self._fill_rules()

    def _rebuild_list(self, keys: list[str]) -> None:
        try:
            lv = self.query_one("#chain-list", ListView)
        except Exception:
            return
        self._chain_keys = keys
        # Keep the current selection if that chain still exists, else default
        # to the first chain so the rules pane is never blank.
        if self._selected not in keys:
            self._selected = keys[0] if keys else None
        lv.clear()
        for key in keys:
            lv.append(ListItem(Label(self._chain_label(key))))
        if self._selected is not None:
            lv.index = keys.index(self._selected)

    def _refresh_list_labels(self) -> None:
        try:
            lv = self.query_one("#chain-list", ListView)
        except Exception:
            return
        for item, key in zip(lv.children, self._chain_keys):
            try:
                item.query_one(Label).update(self._chain_label(key))
            except Exception:
                continue

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        idx = event.list_view.index
        if idx is None or idx >= len(self._chain_keys):
            return
        self._selected = self._chain_keys[idx]
        self._fill_rules()

    def _fill_rules(self) -> None:
        try:
            dt = self.query_one("#chain-rules", DataTable)
        except Exception:
            return
        dt.clear()
        if self._selected is None:
            return
        for i, c in enumerate(self._rules_for(self._selected), start=1):
            color = _VERDICT_COLORS.get(c.verdict, "#808080")
            dt.add_row(
                Text(str(i), style="#606080"),
                Text(c.verdict.upper() or "—", style=f"bold {color}"),
                Text(c.label, style="#c0c0d0"),
                Text(f"{c.pps:,.0f}", style=color if c.pps else "#606080"),
                Text(format_bytes(c.bps), style=color if c.bps else "#606080"),
                f"{c.packets:,}",
                format_bytes(c.bytes),
            )
