from __future__ import annotations

import os
from collections import Counter

from fwtop.models import Connection, ConntrackSummary, SourceStatus

# Candidate paths, in order of preference. The nf_conntrack file carries per
# flow accounting (packets/bytes) when nf_conntrack_acct is enabled; the older
# ip_conntrack path is kept as a fallback on legacy kernels.
_PATHS = ("/proc/net/nf_conntrack", "/proc/net/ip_conntrack")
_MAX_PATH = "/proc/sys/net/netfilter/nf_conntrack_max"


def _parse_kv(tokens: list[str]) -> dict[str, str]:
    """Split ``key=value`` tokens into a dict, ignoring bare flags."""
    out: dict[str, str] = {}
    for tok in tokens:
        if "=" in tok:
            k, _, v = tok.partition("=")
            # Original and reply tuples reuse the same keys (src=, dst=, ...);
            # keep the first occurrence (original direction) for those.
            out.setdefault(k, v)
    return out


class ConntrackSource:
    """Reads the netfilter connection-tracking table from procfs.

    Each line describes one tracked flow with an original tuple and a reply
    tuple; when they disagree, NAT is in effect. Per-flow packet/byte counts
    are only present when ``nf_conntrack_acct`` is enabled in the kernel.

    Linux-only and requires the ``nf_conntrack`` module to be loaded (it is on
    any box doing NAT/stateful firewalling).
    """

    def __init__(self) -> None:
        self._path: str | None = None
        self._status = self._probe()
        self._max = self._read_max()

    @property
    def status(self) -> SourceStatus:
        return self._status

    def _probe(self) -> SourceStatus:
        for path in _PATHS:
            if os.path.exists(path):
                try:
                    with open(path, "r"):
                        pass
                except OSError as exc:
                    return SourceStatus(False, f"{path} not readable ({exc.__class__.__name__})")
                self._path = path
                return SourceStatus(True, "")
        return SourceStatus(False, "nf_conntrack not present (module not loaded or non-Linux)")

    def _read_max(self) -> int | None:
        try:
            with open(_MAX_PATH, "r") as fh:
                return int(fh.read().strip())
        except (OSError, ValueError):
            return None

    def poll(self) -> tuple[list[Connection], ConntrackSummary]:
        empty = ConntrackSummary(0, {}, {}, 0, self._max)
        if not self._status.available or self._path is None:
            return [], empty
        try:
            with open(self._path, "r") as fh:
                lines = fh.readlines()
        except OSError as exc:
            self._status = SourceStatus(False, f"read failed ({exc.__class__.__name__})")
            return [], empty

        conns: list[Connection] = []
        by_proto: Counter[str] = Counter()
        by_state: Counter[str] = Counter()
        nat_count = 0

        for line in lines:
            conn = self._parse_line(line)
            if conn is None:
                continue
            conns.append(conn)
            by_proto[conn.protocol] += 1
            if conn.state:
                by_state[conn.state] += 1
            if conn.is_nat:
                nat_count += 1

        summary = ConntrackSummary(
            total=len(conns),
            by_protocol=dict(by_proto.most_common()),
            by_state=dict(by_state.most_common()),
            nat_count=nat_count,
            max_entries=self._max,
        )
        # Heaviest flows first (by original-direction bytes).
        conns.sort(key=lambda c: c.bytes, reverse=True)
        return conns, summary

    @staticmethod
    def _parse_line(line: str) -> Connection | None:
        # Format (nf_conntrack):
        #   <l3proto> <l3num> <l4proto> <l4num> [timeout] [STATE] \
        #     src=.. dst=.. sport=.. dport=.. [packets=.. bytes=..] \
        #     src=.. dst=.. sport=.. dport=.. (reply tuple) ...
        parts = line.split()
        if len(parts) < 5:
            return None
        l4proto = parts[2]

        # State is an uppercase word appearing before the first key=value pair
        # (only present for stateful protocols like TCP/SCTP/DCCP).
        state = ""
        for tok in parts[3:]:
            if "=" in tok:
                break
            if tok.isupper() and tok.isalpha():
                state = tok
                break

        kv_tokens = [t for t in parts if "=" in t]
        if not kv_tokens:
            return None
        first = _parse_kv(kv_tokens)

        # The reply tuple repeats src=/dst=; grab the second occurrence.
        reply_src = reply_dst = ""
        seen_src = seen_dst = False
        for tok in kv_tokens:
            k, _, v = tok.partition("=")
            if k == "src":
                if seen_src:
                    reply_src = v
                seen_src = True
            elif k == "dst":
                if seen_dst:
                    reply_dst = v
                seen_dst = True

        def _int(key: str) -> int:
            try:
                return int(first.get(key, "0"))
            except ValueError:
                return 0

        return Connection(
            protocol=l4proto,
            state=state,
            src=first.get("src", ""),
            dst=first.get("dst", ""),
            sport=_int("sport"),
            dport=_int("dport"),
            reply_src=reply_src or first.get("dst", ""),
            reply_dst=reply_dst or first.get("src", ""),
            packets=_int("packets"),
            bytes=_int("bytes"),
        )
