from __future__ import annotations

import random
import re
import shutil
import subprocess
import threading
from collections import defaultdict
from time import localtime, monotonic, strftime, time
from typing import Callable

from fwtop.models import Packet, SourceStatus

# How many interfaces we'll spawn a tcpdump process for. A router has a
# handful; this caps runaway process fan-out on a box with many veths.
MAX_CAPTURE_IFACES = 12

# Ring buffer of recently-captured packets handed to the log modal. Bounded so
# a busy filter can't grow memory without limit between UI drains.
_BUFFER_LIMIT = 2000

# Matches an IPv4 "addr.port > addr.port" endpoint pair in a tcpdump line.
_V4_PAIR = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})\.(\d+)\s+>\s+(\d{1,3}(?:\.\d{1,3}){3})\.(\d+)"
)
# IPv4 pair without ports (e.g. ICMP): "addr > addr:".
_V4_NOPORT = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})\s+>\s+(\d{1,3}(?:\.\d{1,3}){3}):"
)
# The frame length tcpdump prints with -e, ending the link-layer preamble:
# "... ethertype IPv4 (0x0800), length 74: <ip payload>". We capture the
# offset so we can strip the -e MAC/ethertype preamble and keep the classic
# IP-layer payload verbatim.
_LENGTH = re.compile(r"\blength (\d+): ")


class CaptureSource:
    """Live packet capture for a user-specified port/protocol filter.

    This is fwtop's only packet-capture source — every other source reads
    kernel counters. It shells out to the system ``tcpdump`` binary (one
    process per interface, matching how :class:`FirewallSource` shells out to
    ``nft``/``iptables``) so it needs no extra Python dependency, and it only
    runs while the Capture tab is active, preserving the app's low-overhead
    promise everywhere else.

    Each per-interface reader runs on a daemon thread that parses tcpdump's
    line output and appends into a lock-guarded ring buffer plus cumulative
    per-interface / per-zone byte & packet counters. Threads never touch the
    UI; the timer-driven refresh calls :meth:`drain` to read the counters and
    the new-packet batch, mirroring the :class:`fwtop.resolve.Resolver`
    threading model.
    """

    def __init__(self, demo: bool = False) -> None:
        self.demo = demo
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._procs: list[subprocess.Popen] = []
        self._threads: list[threading.Thread] = []
        self._running = False
        self._bpf = ""
        self._ifaces: list[str] = []
        self._zone_for: Callable[[str], str] = lambda name: "other"
        # ip/proto for demo synthesis (set from the active filter).
        self._demo_ports: tuple[int, ...] = ()
        self._demo_proto = "any"

        # Shared, lock-guarded state populated by reader threads.
        self._buffer: list[Packet] = []
        self._pkts_iface: dict[str, int] = defaultdict(int)
        self._bytes_iface: dict[str, int] = defaultdict(int)
        self._pkts_zone: dict[str, int] = defaultdict(int)
        self._bytes_zone: dict[str, int] = defaultdict(int)

        self._status = self._probe()

    @property
    def status(self) -> SourceStatus:
        return self._status

    @property
    def running(self) -> bool:
        return self._running

    def _probe(self) -> SourceStatus:
        if self.demo:
            return SourceStatus(True, "demo / synthetic packets")
        if shutil.which("tcpdump"):
            return SourceStatus(True, "tcpdump")
        return SourceStatus(False, "tcpdump not found")

    # ── lifecycle ─────────────────────────────────────────────────────────

    def start(
        self,
        bpf: str,
        interfaces: list[str],
        zone_for: Callable[[str], str],
    ) -> None:
        """(Re)start capture with a BPF filter across the given interfaces.

        Safe to call repeatedly; each call tears down any prior capture first.
        """
        self.stop()
        self._stop = threading.Event()
        self._bpf = bpf
        self._zone_for = zone_for
        self._ifaces = list(interfaces)[:MAX_CAPTURE_IFACES]
        self._reset_counters()
        self._running = True

        if self.demo:
            # No processes; drain() synthesizes packets on demand.
            return
        if not self._status.available:
            self._running = False
            return

        for iface in self._ifaces:
            proc = self._spawn(iface, bpf)
            if proc is None:
                continue
            self._procs.append(proc)
            t = threading.Thread(target=self._reader, args=(iface, proc), daemon=True)
            t.start()
            self._threads.append(t)

    def _spawn(self, iface: str, bpf: str) -> subprocess.Popen | None:
        # -n no DNS, -l line-buffered, -tt epoch ts, -e link header (frame
        # length), -Q inout both directions, -i the single interface.
        cmd = ["tcpdump", "-i", iface, "-n", "-l", "-tt", "-e", "-Q", "inout"]
        if bpf:
            cmd += bpf.split(" ")
        try:
            return subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
        except (OSError, ValueError) as exc:
            self._status = SourceStatus(False, f"tcpdump failed ({exc.__class__.__name__})")
            return None

    def stop(self) -> None:
        self._stop.set()
        for proc in self._procs:
            try:
                proc.terminate()
            except OSError:
                pass
        self._procs = []
        self._threads = []
        self._running = False

    def _reset_counters(self) -> None:
        with self._lock:
            self._buffer.clear()
            self._pkts_iface.clear()
            self._bytes_iface.clear()
            self._pkts_zone.clear()
            self._bytes_zone.clear()

    # ── reader thread ─────────────────────────────────────────────────────

    def _reader(self, iface: str, proc: subprocess.Popen) -> None:
        stream = proc.stdout
        if stream is None:
            return
        for line in stream:
            if self._stop.is_set():
                break
            pkt = self._parse_line(iface, line)
            if pkt is not None:
                self._record(pkt)
        # Process ended (interface down, tcpdump error, or we terminated it).

    def _parse_line(self, iface: str, line: str) -> Packet | None:
        m_len = _LENGTH.search(line)
        if m_len is None:
            return None
        length = int(m_len.group(1))

        ts = time()
        head = line.split(None, 1)
        if head:
            try:
                ts = float(head[0])
            except ValueError:
                pass

        proto = self._infer_proto(line)
        m = _V4_PAIR.search(line)
        if m is not None:
            src, sport, dst, dport = m.group(1), int(m.group(2)), m.group(3), int(m.group(4))
        else:
            mnp = _V4_NOPORT.search(line)
            if mnp is None:
                return None
            src, sport, dst, dport = mnp.group(1), 0, mnp.group(2), 0

        zone = self._zone_for(iface)
        text = self._display_line(ts, iface, line, m_len.end())
        return Packet(
            ts=ts, iface=iface, zone=zone, proto=proto,
            src=src, sport=sport, dst=dst, dport=dport, length=length, text=text,
        )

    @staticmethod
    def _display_line(ts: float, iface: str, raw: str, ip_start: int) -> str:
        """Reconstruct the classic (non-``-e``) tcpdump display line.

        We run tcpdump with ``-e`` to get the frame length for the throughput
        charts, but ``-e`` prepends MAC/ethertype noise. The text after the
        ``length NN: `` marker is the verbatim IP-layer payload tcpdump would
        print without ``-e``; we prefix it with the same ``HH:MM:SS.ffffff IP``
        header tcpdump uses by default, tagged with the interface.
        """
        payload = raw[ip_start:].rstrip()
        frac = f"{ts - int(ts):.6f}"[2:]  # 6-digit microseconds
        stamp = strftime("%H:%M:%S", localtime(ts)) + "." + frac
        return f"{stamp} {iface} IP {payload}"

    @staticmethod
    def _infer_proto(line: str) -> str:
        low = line.lower()
        # tcpdump prints "Flags [..]" for TCP, "UDP," for UDP, "ICMP" for ICMP.
        if "flags [" in low or " tcp " in low:
            return "tcp"
        if "udp" in low:
            return "udp"
        if "icmp" in low:
            return "icmp"
        return "ip"

    def _record(self, pkt: Packet) -> None:
        with self._lock:
            self._buffer.append(pkt)
            if len(self._buffer) > _BUFFER_LIMIT:
                # Drop the oldest half in one slice rather than popping per-append.
                del self._buffer[: len(self._buffer) - _BUFFER_LIMIT]
            self._pkts_iface[pkt.iface] += 1
            self._bytes_iface[pkt.iface] += pkt.length
            self._pkts_zone[pkt.zone] += 1
            self._bytes_zone[pkt.zone] += pkt.length

    # ── drain (called on the UI thread each active tick) ──────────────────

    def drain(self) -> tuple[list[Packet], dict[str, tuple[int, int]], dict[str, tuple[int, int]]]:
        """Return (new packets since last drain, per-iface totals, per-zone totals).

        Totals are cumulative (packets, bytes) since :meth:`start`; the panel
        computes per-second rates from their deltas. The packet batch is for
        the live log; it is cleared out on each drain.
        """
        if self.demo and self._running:
            self._synthesize()
        with self._lock:
            batch = self._buffer
            self._buffer = []
            iface_totals = {k: (self._pkts_iface[k], self._bytes_iface[k]) for k in self._pkts_iface}
            zone_totals = {k: (self._pkts_zone[k], self._bytes_zone[k]) for k in self._pkts_zone}
        return batch, iface_totals, zone_totals

    # ── demo synthesis ────────────────────────────────────────────────────

    _DEMO_IFACES = ("eth0", "br-lan", "vlan3", "wg0")
    _DEMO_LAN = ("10.1.1.10", "10.1.1.42", "10.1.3.20", "10.1.24.11")
    _DEMO_WAN = ("203.0.113.9", "8.8.8.8", "1.1.1.1", "140.82.121.4")

    def set_demo_filter(self, ports: tuple[int, ...], proto: str) -> None:
        self._demo_ports = ports
        self._demo_proto = proto

    def _synthesize(self) -> None:
        # Produce a burst of plausible packets matching the active filter so
        # the tab is fully exercisable without root or a live network.
        rng = random
        proto = self._demo_proto if self._demo_proto != "any" else rng.choice(["tcp", "udp"])
        ports = self._demo_ports or (443,)
        n = rng.randint(20, 120)
        now = time()
        for _ in range(n):
            iface = rng.choice([i for i in self._DEMO_IFACES if i in self._ifaces] or list(self._ifaces) or ["eth0"])
            wan_facing = rng.random() < 0.6
            if wan_facing:
                src, dst = rng.choice(self._DEMO_LAN), rng.choice(self._DEMO_WAN)
            else:
                src = rng.choice(self._DEMO_LAN)
                dst = rng.choice([h for h in self._DEMO_LAN if h != src])
            port = rng.choice(ports)
            # Randomly orient which side holds the well-known port.
            if rng.random() < 0.5:
                sport, dport = rng.randint(1024, 65535), port
            else:
                sport, dport = port, rng.randint(1024, 65535)
            length = rng.randint(60, 1500)
            zone = self._zone_for(iface)
            text = self._demo_text(now, iface, proto, src, sport, dst, dport, length, rng)
            self._record(Packet(
                ts=now, iface=iface, zone=zone, proto=proto,
                src=src, sport=sport, dst=dst, dport=dport, length=length, text=text,
            ))

    @staticmethod
    def _demo_text(ts, iface, proto, src, sport, dst, dport, length, rng) -> str:
        # Mirror the real tcpdump-style line _display_line produces.
        frac = f"{ts - int(ts):.6f}"[2:]
        stamp = strftime("%H:%M:%S", localtime(ts)) + "." + frac
        if proto == "tcp":
            flag = rng.choice(["S", "S.", ".", "P.", "F.", "R"])
            seq = rng.randint(1, 4_000_000_000)
            body = f"{src}.{sport} > {dst}.{dport}: Flags [{flag}], seq {seq}, win 64240, length {max(0, length - 66)}"
        elif proto == "udp":
            body = f"{src}.{sport} > {dst}.{dport}: UDP, length {max(0, length - 42)}"
        else:
            body = f"{src} > {dst}: ICMP echo request, id {rng.randint(1, 65535)}, seq {rng.randint(1, 9999)}, length {max(0, length - 34)}"
        return f"{stamp} {iface} IP {body}"
