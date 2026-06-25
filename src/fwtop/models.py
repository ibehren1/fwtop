from __future__ import annotations

from typing import NamedTuple, Optional

# Layer-4 protocol numbers we name; everything else is shown as "Other(N)".
PROTOCOL_NAMES: dict[int, str] = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    132: "SCTP",
}


def protocol_name(proto: int | str) -> str:
    """Normalize a protocol identifier (number or conntrack name) to a label."""
    if isinstance(proto, str):
        return proto.upper()
    return PROTOCOL_NAMES.get(proto, f"Other({proto})")


def is_private_ip(ip: str) -> bool:
    """True for RFC1918 / link-local / ULA / loopback addresses.

    Used to tell internal (LAN-side) endpoints from public ones without a
    routing table. Anything we can't confidently call private is treated as
    public, so a flow touching it counts as WAN-facing.
    """
    if not ip:
        return False
    if ":" in ip:  # IPv6
        low = ip.lower()
        # Unique-local (fc00::/7), link-local (fe80::/10), loopback (::1).
        return low.startswith(("fc", "fd", "fe8", "fe9", "fea", "feb")) or low in ("::1", "::")
    parts = ip.split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return False
    a, b = int(parts[0]), int(parts[1])
    if a == 10 or a == 127:
        return True
    if a == 192 and b == 168:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 169 and b == 254:  # link-local
        return True
    return False


class SourceStatus(NamedTuple):
    """Availability of a data source on the current host.

    ``available`` is False when the underlying kernel facility is missing
    (e.g. running on macOS, or conntrack not loaded). ``detail`` carries a
    short human-readable reason shown in the UI so the panel can explain why
    it is empty rather than silently showing nothing.
    """

    available: bool
    detail: str = ""


class InterfaceStat(NamedTuple):
    """A single interface's counters and derived per-second rates.

    Byte/packet fields are cumulative since boot (straight from the kernel);
    the ``*_bps`` / ``*_pps`` fields are deltas computed over the last tick.
    """

    name: str
    rx_bytes: int
    tx_bytes: int
    rx_packets: int
    tx_packets: int
    rx_errors: int
    tx_errors: int
    rx_dropped: int
    tx_dropped: int
    rx_bps: float = 0.0
    tx_bps: float = 0.0
    rx_pps: float = 0.0
    tx_pps: float = 0.0
    zone: str = "other"  # wan / lan / other (assigned from Config)

    @property
    def total_bps(self) -> float:
        return self.rx_bps + self.tx_bps


class Connection(NamedTuple):
    """A single conntrack flow (one logical connection / NAT mapping)."""

    protocol: str          # tcp, udp, icmp, ...
    state: str             # ESTABLISHED, TIME_WAIT, "" for stateless protos
    src: str               # original source ip
    dst: str               # original dest ip
    sport: int
    dport: int
    # Reply tuple — differs from the original tuple when NAT is in play.
    reply_src: str
    reply_dst: str
    packets: int           # original-direction packets (0 if unaccounted)
    bytes: int             # original-direction bytes (0 if unaccounted)

    @property
    def is_nat(self) -> bool:
        # When the reply destination differs from the original source, the
        # source address was translated (SNAT/masquerade); likewise dest.
        return self.reply_dst != self.src or self.reply_src != self.dst

    @property
    def is_wan_facing(self) -> bool:
        """True if this flow crosses the WAN edge.

        Conntrack entries have no interface label, so we infer it: a flow is
        WAN-facing if it was NAT'd out (masquerade) or if either original
        endpoint is a public address. Purely internal LAN↔LAN flows are not.
        """
        if self.is_nat:
            return True
        return not is_private_ip(self.src) or not is_private_ip(self.dst)


class FirewallCounter(NamedTuple):
    """A named firewall rule/chain counter (nftables or iptables).

    ``packets`` / ``bytes`` are cumulative; ``pps`` / ``bps`` are per-tick
    deltas filled in by the collector.
    """

    table: str
    chain: str
    label: str             # comment, rule handle, or verdict descriptor
    verdict: str           # drop, accept, reject, "" if unknown
    packets: int
    bytes: int
    pps: float = 0.0
    bps: float = 0.0


class ConntrackSummary(NamedTuple):
    total: int
    by_protocol: dict[str, int]
    by_state: dict[str, int]
    nat_count: int
    max_entries: Optional[int]  # conntrack table capacity, if known
