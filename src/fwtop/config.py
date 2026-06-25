from __future__ import annotations

import json
import os
from pathlib import Path

# Valid zone labels. The four real zones split into the WAN charts (red) and
# LAN charts (green); "other" covers loopback-ish, management, or unclassified
# links that count toward neither chart. The "*_tunnel" zones are for overlay
# interfaces (WireGuard, GRE, IPsec, tun/tap) carried over the WAN or bridged
# into the LAN.
ZONES = ("wan", "wan_tunnel", "lan", "lan_tunnel", "other")
ZONE_CYCLE = ("wan", "wan_tunnel", "lan", "lan_tunnel", "other")

# Short human-readable labels for the table and zone-assignment screen.
ZONE_LABELS = {
    "wan": "WAN",
    "wan_tunnel": "WAN-Tun",
    "lan": "LAN",
    "lan_tunnel": "LAN-Tun",
    "other": "other",
}

# Name fragments used to guess a zone the first time an interface is seen, so
# the charts are populated out of the box. The user can override any guess via
# the zone-assignment screen (key 'z'), which persists the choice to disk.
_WAN_HINTS = ("wan", "ppp", "pppoe", "wwan")
_WAN_EXACT = ("eth0",)
_LAN_HINTS = ("lan", "br", "vlan", "switch")
_LAN_EXACT = ("eth1", "eth2", "eth3")
# Tunnel/overlay interface name fragments. A tunnel that also looks LAN-side
# (e.g. "wg-lan") is classed lan_tunnel; otherwise tunnels default to the WAN
# side, which is where WireGuard/IPsec links usually terminate.
_TUNNEL_HINTS = ("wg", "wireguard", "tun", "tap", "gre", "gretap", "vti", "ipsec", "tunnel")


def config_path() -> Path:
    """Resolve the config file location.

    Honors ``$FWTOP_CONFIG`` first, then ``$XDG_CONFIG_HOME``, falling back to
    ``~/.config/fwtop/config.json``. Under ``sudo`` this is root's home, which
    is the right place for a box-wide router config.
    """
    env = os.environ.get("FWTOP_CONFIG")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "fwtop" / "config.json"


def guess_zone(name: str) -> str:
    """Best-effort zone for an interface not yet present in the config."""
    lower = name.lower()
    # Tunnels take priority: a name like "wg0" or "gre-lan" is an overlay first.
    if any(h in lower for h in _TUNNEL_HINTS):
        if any(h in lower for h in _LAN_HINTS):
            return "lan_tunnel"
        return "wan_tunnel"
    if lower in _WAN_EXACT or any(h in lower for h in _WAN_HINTS):
        return "wan"
    if lower in _LAN_EXACT or any(h in lower for h in _LAN_HINTS):
        return "lan"
    return "other"


class Config:
    """Persisted fwtop settings — currently the interface→zone mapping.

    Explicit assignments live in ``self.zones``; interfaces absent from it fall
    back to :func:`guess_zone`. Writes are atomic-ish (write + replace) so a
    crash mid-save can't truncate the file.
    """

    def __init__(self, zones: dict[str, str] | None = None, path: Path | None = None) -> None:
        self.zones: dict[str, str] = zones or {}
        self.path: Path = path or config_path()

    @classmethod
    def load(cls, path: Path | None = None) -> "Config":
        path = path or config_path()
        try:
            with open(path, "r") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return cls(zones={}, path=path)
        raw = data.get("zones", {}) if isinstance(data, dict) else {}
        zones = {k: v for k, v in raw.items() if v in ZONES}
        return cls(zones=zones, path=path)

    def save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            with open(tmp, "w") as fh:
                json.dump({"zones": self.zones}, fh, indent=2, sort_keys=True)
            os.replace(tmp, self.path)
        except OSError:
            # Read-only filesystem or permission issue — keep running with the
            # in-memory mapping rather than crashing the UI.
            pass

    def zone_for(self, name: str) -> str:
        return self.zones.get(name) or guess_zone(name)

    def set_zone(self, name: str, zone: str) -> None:
        if zone not in ZONES:
            return
        self.zones[name] = zone
        self.save()

    def cycle_zone(self, name: str) -> str:
        current = self.zone_for(name)
        try:
            nxt = ZONE_CYCLE[(ZONE_CYCLE.index(current) + 1) % len(ZONE_CYCLE)]
        except ValueError:
            nxt = ZONE_CYCLE[0]
        self.set_zone(name, nxt)
        return nxt
