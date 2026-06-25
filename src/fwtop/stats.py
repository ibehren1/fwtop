from __future__ import annotations


def format_bytes(n: float) -> str:
    """Human-readable byte size (binary units)."""
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            if unit == "B":
                return f"{n:.0f} {unit}"
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def format_rate(n: float) -> str:
    """Bytes-per-second as a human-readable rate."""
    return f"{format_bytes(n)}/s"


def format_bits_rate(bytes_per_sec: float) -> str:
    """Bits-per-second (network convention) from a bytes/s input."""
    bits = bytes_per_sec * 8
    for unit in ("bps", "Kbps", "Mbps", "Gbps"):
        if abs(bits) < 1000:
            if unit == "bps":
                return f"{bits:.0f} {unit}"
            return f"{bits:.1f} {unit}"
        bits /= 1000
    return f"{bits:.1f} Tbps"


# Width of the numeric field in format_mbps: enough for "100,000.00"
# (100 Gbps) so the column never has to grow.
MBPS_FIELD_WIDTH = 10


def format_mbps(bytes_per_sec: float) -> str:
    """Always-Mbps rate in a fixed-width field so table columns stay static.

    The numeric part is right-justified to :data:`MBPS_FIELD_WIDTH`, which
    accommodates values up to ``100,000.00`` Mbps (100 Gbps); the trailing
    unit keeps the full string a constant width regardless of magnitude.
    """
    mbps = bytes_per_sec * 8 / 1_000_000
    return f"{mbps:>{MBPS_FIELD_WIDTH},.2f} Mbps"


def format_count(n: float) -> str:
    """Compact count formatting (1.2K, 3.4M)."""
    n = float(n)
    for unit in ("", "K", "M", "G"):
        if abs(n) < 1000:
            if unit == "":
                return f"{n:.0f}"
            return f"{n:.1f}{unit}"
        n /= 1000
    return f"{n:.1f}T"
