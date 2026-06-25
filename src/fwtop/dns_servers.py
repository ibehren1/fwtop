from __future__ import annotations

import ipaddress
import re
import subprocess


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def _parse_resolv_conf(path: str) -> list[str]:
    """Return non-loopback ``nameserver`` IPs from a resolv.conf-style file.

    Loopback entries are dropped on purpose: on a systemd-resolved host
    ``/etc/resolv.conf`` points at the ``127.0.0.53`` stub, and querying the
    stub directly is exactly the path that fails to resolve private (RFC1918)
    reverse lookups. We want the real upstream servers, not the stub.
    """
    servers: list[str] = []
    try:
        with open(path, "r") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith(";"):
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    ip = parts[1]
                    if not _is_loopback(ip):
                        servers.append(ip)
    except OSError:
        pass
    return servers


def _macos_nameservers() -> list[str]:
    """Discover resolvers on macOS via ``scutil --dns``.

    macOS does not keep the active resolvers in ``/etc/resolv.conf``; they live
    in the dynamic store, surfaced by ``scutil --dns`` as ``nameserver[N] : IP``
    lines. Used for development on macOS (live mode is Linux-only anyway).
    """
    try:
        out = subprocess.run(
            ["scutil", "--dns"], capture_output=True, text=True, timeout=3
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if out.returncode != 0:
        return []
    servers: list[str] = []
    for m in re.finditer(r"nameserver\[\d+\]\s*:\s*(\S+)", out.stdout):
        ip = m.group(1)
        if not _is_loopback(ip) and ip not in servers:
            servers.append(ip)
    return servers


def discover_nameservers() -> list[str]:
    """Best-effort list of the host's real upstream DNS servers.

    Resolution order:
      1. ``/run/systemd/resolve/resolv.conf`` — systemd-resolved writes the
         actual upstream servers here, while ``/etc/resolv.conf`` is the stub.
      2. ``/etc/resolv.conf`` — classic Linux resolver config.
      3. ``scutil --dns`` — macOS dynamic store.
    Loopback/stub addresses are excluded throughout. Returns an empty list if
    nothing usable is found, in which case the caller falls back to dnspython's
    own default configuration.
    """
    for path in ("/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"):
        servers = _parse_resolv_conf(path)
        if servers:
            return servers
    return _macos_nameservers()
