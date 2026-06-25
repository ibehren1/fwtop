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
