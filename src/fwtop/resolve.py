from __future__ import annotations

import queue
import socket
import threading


class Resolver:
    """Background reverse-DNS resolver with a cache.

    ``display(ip)`` returns the resolved hostname if it is already known,
    otherwise the IP itself while scheduling a lookup in the background so a
    later call can show the name. Lookups never block the caller — the UI keeps
    showing the raw IP until the PTR record (if any) comes back.
    """

    def __init__(self, max_workers: int = 4) -> None:
        self._cache: dict[str, str] = {}  # ip -> hostname (or ip if no PTR)
        self._pending: set[str] = set()
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
            try:
                host = socket.gethostbyaddr(ip)[0]
            except Exception:
                host = ip  # no PTR record or lookup failed -> fall back to IP
            with self._lock:
                self._cache[ip] = host
                self._pending.discard(ip)

    def stop(self) -> None:
        self._stop.set()
