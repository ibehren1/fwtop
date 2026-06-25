from __future__ import annotations

import json
import shutil
import subprocess
from time import monotonic

from fwtop.models import FirewallCounter, SourceStatus

# Verdicts we care to surface, in priority order for the "drops" view.
_DROP_VERDICTS = ("drop", "reject")


class FirewallSource:
    """Reads firewall rule counters, preferring nftables, falling back to iptables.

    Strategy:
      * ``nft -j list ruleset`` gives structured JSON including per-rule
        ``counter`` expressions (when a rule has ``counter`` set) and named
        counter objects. We extract those with their packets/bytes and the
        rule's verdict so the UI can highlight drops.
      * If ``nft`` is absent we try ``iptables -L -v -n -x`` (and the v6
        variant) and parse the per-rule packet/byte columns.

    Per-tick deltas (pps/bps) are computed against the previous sample keyed by
    a stable rule identity. Linux-only; requires root to read the ruleset.
    """

    def __init__(self) -> None:
        self._backend: str | None = None
        self._prev: dict[str, tuple[float, int, int]] = {}  # key -> (ts, pkts, bytes)
        self._status = self._probe()

    @property
    def status(self) -> SourceStatus:
        return self._status

    @property
    def backend(self) -> str | None:
        return self._backend

    def _probe(self) -> SourceStatus:
        if shutil.which("nft"):
            self._backend = "nftables"
            return SourceStatus(True, "nftables")
        if shutil.which("iptables"):
            self._backend = "iptables"
            return SourceStatus(True, "iptables (no nft found)")
        return SourceStatus(False, "neither nft nor iptables found")

    def poll(self) -> list[FirewallCounter]:
        if not self._status.available:
            return []
        if self._backend == "nftables":
            counters = self._poll_nft()
        else:
            counters = self._poll_iptables()
        return self._apply_rates(counters)

    # ── nftables ──────────────────────────────────────────────────────────

    def _poll_nft(self) -> list[FirewallCounter]:
        try:
            out = subprocess.run(
                ["nft", "-j", "list", "ruleset"],
                capture_output=True, text=True, timeout=5,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            self._status = SourceStatus(False, f"nft failed ({exc.__class__.__name__})")
            return []
        if out.returncode != 0:
            # Most commonly: not running as root.
            detail = out.stderr.strip() or f"nft exit {out.returncode}"
            self._status = SourceStatus(False, detail)
            return []
        try:
            data = json.loads(out.stdout)
        except json.JSONDecodeError:
            return []

        counters: list[FirewallCounter] = []
        for item in data.get("nftables", []):
            rule = item.get("rule")
            if not rule:
                continue
            counter = self._find_counter(rule.get("expr", []))
            if counter is None:
                continue
            pkts, byts = counter
            verdict = self._find_verdict(rule.get("expr", []))
            comment = rule.get("comment") or f"handle {rule.get('handle', '?')}"
            counters.append(FirewallCounter(
                table=rule.get("table", ""),
                chain=rule.get("chain", ""),
                label=comment,
                verdict=verdict,
                packets=pkts,
                bytes=byts,
            ))
        return counters

    @staticmethod
    def _find_counter(exprs: list) -> tuple[int, int] | None:
        for e in exprs:
            if isinstance(e, dict) and "counter" in e:
                c = e["counter"]
                if isinstance(c, dict):
                    return int(c.get("packets", 0)), int(c.get("bytes", 0))
        return None

    @staticmethod
    def _find_verdict(exprs: list) -> str:
        for e in exprs:
            if not isinstance(e, dict):
                continue
            for v in _DROP_VERDICTS + ("accept",):
                if v in e:
                    return v
        return ""

    # ── iptables fallback ─────────────────────────────────────────────────

    def _poll_iptables(self) -> list[FirewallCounter]:
        counters: list[FirewallCounter] = []
        for cmd, family in (("iptables", "ip4"), ("ip6tables", "ip6")):
            if not shutil.which(cmd):
                continue
            try:
                out = subprocess.run(
                    [cmd, "-L", "-v", "-n", "-x"],
                    capture_output=True, text=True, timeout=5,
                )
            except (OSError, subprocess.SubprocessError):
                continue
            if out.returncode != 0:
                if not counters:
                    self._status = SourceStatus(False, out.stderr.strip() or "iptables failed")
                continue
            counters.extend(self._parse_iptables(out.stdout, family))
        return counters

    @staticmethod
    def _parse_iptables(text: str, family: str) -> list[FirewallCounter]:
        counters: list[FirewallCounter] = []
        chain = ""
        for line in text.splitlines():
            line = line.rstrip()
            if line.startswith("Chain "):
                chain = line.split()[1]
                continue
            if not line or line.lstrip().startswith("pkts"):
                continue  # header row
            fields = line.split()
            if len(fields) < 3 or not fields[0].isdigit():
                continue
            pkts = int(fields[0])
            byts = int(fields[1])
            target = fields[2]
            verdict = {"DROP": "drop", "REJECT": "reject", "ACCEPT": "accept"}.get(target, "")
            counters.append(FirewallCounter(
                table=family,
                chain=chain,
                label=f"{target} {' '.join(fields[3:6])}".strip(),
                verdict=verdict,
                packets=pkts,
                bytes=byts,
            ))
        return counters

    # ── rate computation ────────────────────────────────────────────────

    def _apply_rates(self, counters: list[FirewallCounter]) -> list[FirewallCounter]:
        now = monotonic()
        out: list[FirewallCounter] = []
        seen: dict[str, tuple[float, int, int]] = {}
        for c in counters:
            key = f"{c.table}/{c.chain}/{c.label}/{c.verdict}"
            pps = bps = 0.0
            prev = self._prev.get(key)
            if prev is not None:
                pt, pp, pb = prev
                dt = now - pt
                if dt > 0:
                    pps = max(0.0, (c.packets - pp) / dt)
                    bps = max(0.0, (c.bytes - pb) / dt)
            seen[key] = (now, c.packets, c.bytes)
            out.append(c._replace(pps=pps, bps=bps))
        self._prev = seen
        return out
