from __future__ import annotations

from time import monotonic

from fwtop.models import InterfaceStat, SourceStatus

# Pseudo / virtual interfaces that are rarely interesting on a router view.
_DEFAULT_HIDDEN_PREFIXES = ("lo",)


class InterfaceSource:
    """Reads per-interface counters from ``/proc/net/dev``.

    On each :meth:`poll` it parses the raw cumulative counters and computes
    per-second rates by comparing against the previous sample's wall-clock
    timestamp, so rates stay correct regardless of the UI refresh interval.

    Linux-only. On other platforms :attr:`status` reports unavailable and
    :meth:`poll` returns an empty list.
    """

    PATH = "/proc/net/dev"

    def __init__(self, hidden_prefixes: tuple[str, ...] = _DEFAULT_HIDDEN_PREFIXES) -> None:
        self._hidden = hidden_prefixes
        # name -> (timestamp, rx_bytes, tx_bytes, rx_packets, tx_packets)
        self._prev: dict[str, tuple[float, int, int, int, int]] = {}
        self._status = self._probe()

    @property
    def status(self) -> SourceStatus:
        return self._status

    def _probe(self) -> SourceStatus:
        try:
            with open(self.PATH, "r"):
                pass
        except OSError as exc:
            return SourceStatus(False, f"{self.PATH} unavailable ({exc.__class__.__name__})")
        return SourceStatus(True, "")

    def _is_hidden(self, name: str) -> bool:
        return any(name.startswith(p) for p in self._hidden)

    def poll(self) -> list[InterfaceStat]:
        if not self._status.available:
            return []
        try:
            with open(self.PATH, "r") as fh:
                lines = fh.readlines()
        except OSError as exc:
            self._status = SourceStatus(False, f"read failed ({exc.__class__.__name__})")
            return []

        now = monotonic()
        stats: list[InterfaceStat] = []

        # The first two lines are headers; data rows look like:
        #   eth0: <rx_bytes> <rx_packets> <rx_errs> <rx_drop> ... <tx_bytes> ...
        for line in lines[2:]:
            if ":" not in line:
                continue
            name, _, rest = line.partition(":")
            name = name.strip()
            if self._is_hidden(name):
                continue
            fields = rest.split()
            if len(fields) < 16:
                continue
            f = [int(x) for x in fields[:16]]
            rx_bytes, rx_packets, rx_errs, rx_drop = f[0], f[1], f[2], f[3]
            tx_bytes, tx_packets, tx_errs, tx_drop = f[8], f[9], f[10], f[11]

            rx_bps = tx_bps = rx_pps = tx_pps = 0.0
            prev = self._prev.get(name)
            if prev is not None:
                pt, p_rxb, p_txb, p_rxp, p_txp = prev
                dt = now - pt
                if dt > 0:
                    # Counters can wrap or reset (iface down/up); clamp negatives.
                    rx_bps = max(0.0, (rx_bytes - p_rxb) / dt)
                    tx_bps = max(0.0, (tx_bytes - p_txb) / dt)
                    rx_pps = max(0.0, (rx_packets - p_rxp) / dt)
                    tx_pps = max(0.0, (tx_packets - p_txp) / dt)
            self._prev[name] = (now, rx_bytes, tx_bytes, rx_packets, tx_packets)

            stats.append(InterfaceStat(
                name=name,
                rx_bytes=rx_bytes,
                tx_bytes=tx_bytes,
                rx_packets=rx_packets,
                tx_packets=tx_packets,
                rx_errors=rx_errs,
                tx_errors=tx_errs,
                rx_dropped=rx_drop,
                tx_dropped=tx_drop,
                rx_bps=rx_bps,
                tx_bps=tx_bps,
                rx_pps=rx_pps,
                tx_pps=tx_pps,
            ))

        stats.sort(key=lambda s: s.total_bps, reverse=True)
        return stats
