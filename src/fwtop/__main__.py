from __future__ import annotations

import argparse
import os
import sys


def main() -> None:
    from fwtop import __version__

    parser = argparse.ArgumentParser(
        prog="fwtop",
        description="Real-time router/firewall traffic visualizer "
                    "(interfaces, conntrack, firewall drops)",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Show the version and exit",
    )
    parser.add_argument(
        "-n", "--interval",
        type=float,
        default=1.0,
        help="Screen refresh interval in seconds (default: 1.0)",
    )
    parser.add_argument(
        "-r", "--resolve",
        action="store_true",
        help="Reverse-DNS resolve IPs, showing hostnames when available",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run with synthetic data (no kernel access needed); useful for "
             "demos and non-Linux development",
    )
    parser.add_argument(
        "-c", "--config",
        metavar="PATH",
        help="Path to the config file storing interface zone assignments "
             "(default: $XDG_CONFIG_HOME/fwtop/config.json)",
    )
    parser.add_argument(
        "--dns",
        metavar="SERVER",
        action="append",
        help="DNS server to use for reverse lookups (repeatable). Overrides "
             "the servers auto-discovered from the host; resolution is always "
             "done in-process via dnspython, never the system resolver",
    )
    args = parser.parse_args()

    # Real data sources read privileged kernel files (conntrack, nft ruleset).
    # Demo mode needs nothing, so skip the root check there.
    if not args.demo and hasattr(os, "geteuid") and os.geteuid() != 0:
        print(
            "Error: fwtop requires root to read conntrack and firewall state.\n"
            "Run with: sudo fwtop   (or try: fwtop --demo)",
            file=sys.stderr,
        )
        sys.exit(1)

    from pathlib import Path

    from fwtop.app import FwTopApp
    from fwtop.config import Config

    config = Config.load(Path(args.config) if args.config else None)

    app = FwTopApp(
        interval=args.interval,
        demo=args.demo,
        resolve=args.resolve,
        config=config,
        nameservers=args.dns,
    )
    app.run()


if __name__ == "__main__":
    main()
