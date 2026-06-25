from __future__ import annotations

import queue
import socket
import threading
from typing import Callable, Optional


def _ptr_lookup(ip: str) -> str:
    """Resolve ``ip`` to a hostname via the system resolver (reverse DNS).

    Returns the IP unchanged when there is no PTR record or the lookup fails.
    This goes through the OS resolver, so on a router whose local DNS serves
    PTR records for its DHCP leases, private addresses resolve here too — no
    hosts file or static map required.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip


class Resolver:
    """Background reverse-DNS resolver with a program-local cache.

    ``display(ip)`` returns the resolved hostname if it is already cached,
    otherwise the IP itself while scheduling a lookup in the background so a
    later call can show the name. Lookups never block the caller — the UI keeps
    showing the raw IP until the PTR record (if any) comes back. Every result
    (including "no PTR -> the IP itself") is cached in an in-memory map, so each
    address is looked up at most once.

    All resolution goes through DNS via ``lookup`` (the system resolver by
    default). The hook exists only so tests and the synthetic ``--demo`` mode
    can stand in a fake DNS backend for addresses that don't exist for real; it
    is not a static names table.
    """

    def __init__(
        self,
        max_workers: int = 4,
        lookup: Optional[Callable[[str], str]] = None,
    ) -> None:
        self._cache: dict[str, str] = {}  # ip -> hostname (or ip if no PTR)
        self._pending: set[str] = set()
        self._lookup = lookup or _ptr_lookup
        self._lock = threading.Lock()
        self._queue: queue.Queue[str] = queue.Queue()
        self._stop = threading.Event()
        self._workers: list[threading.Thread] = []
        for _ in range(max_workers):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            self._workers.append(t)

    def display(self, ip: str) -> str:
        if not ip:
            return ip
        with self._lock:
            name = self._cache.get(ip)
            if name is not None:
                return name
            if ip in self._pending:
                return ip
            self._pending.add(ip)
        self._queue.put(ip)
        return ip

    def _worker(self) -> None:
        while not self._stop.is_set():
            try:
                ip = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            host = self._lookup(ip)
            with self._lock:
                self._cache[ip] = host
                self._pending.discard(ip)

    def stop(self) -> None:
        self._stop.set()
