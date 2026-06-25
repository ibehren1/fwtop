from __future__ import annotations

import queue
import threading
import time
from typing import Callable, Optional

import dns.exception
import dns.resolver
import dns.reversename

from fwtop.dns_servers import discover_nameservers


class Resolver:
    """Background reverse-DNS resolver: all lookups go through dnspython.

    ``display(ip)`` returns the resolved hostname if it is already cached,
    otherwise the IP itself while scheduling a lookup in the background so a
    later call can show the name. Lookups never block the caller — the UI keeps
    showing the raw IP until the PTR record (if any) comes back.

    Resolution is performed entirely in-process with dnspython against an
    explicit set of nameservers (discovered from the host, see
    :func:`fwtop.dns_servers.discover_nameservers`, or passed in). The host's
    own resolver (``getaddrinfo`` / NSS / ``/etc/hosts``) is never consulted.

    Caching:
      * A resolved hostname is cached for the session.
      * A *transient* failure (timeout, no reachable server) is cached only
        briefly, then retried — so a momentary glitch doesn't pin an address
        to its raw IP forever when it really does have a PTR.
      * An *authoritative* "no PTR" (NXDOMAIN / no answer) is cached for a
        long interval so we don't hammer DNS for addresses with no record.

    The ``lookup`` hook overrides the DNS backend entirely; it exists only as
    a seam for unit tests. Demo mode does NOT use it — demo traffic uses real
    RFC1918 subnets and resolves through the host's DNS like production.
    """

    # Per-query limits so a slow/unreachable server can't stall a worker.
    _TIMEOUT = 2.0
    _LIFETIME = 4.0
    # How long to suppress re-querying after a failure, by failure kind.
    _RETRY_TRANSIENT = 30.0    # timeout / no server reachable -> retry soon
    _RETRY_NO_RECORD = 300.0   # authoritative "no PTR" -> retry rarely

    def __init__(
        self,
        max_workers: int = 8,
        lookup: Optional[Callable[[str], str]] = None,
        nameservers: Optional[list[str]] = None,
    ) -> None:
        # ip -> hostname, for successful lookups (kept for the session).
        self._cache: dict[str, str] = {}
        # ip -> monotonic time before which we won't re-query (negative cache).
        self._suppress_until: dict[str, float] = {}
        self._pending: set[str] = set()
        self._lock = threading.Lock()
        self._queue: queue.Queue[str] = queue.Queue()
        self._stop = threading.Event()

        # A test backend short-circuits real DNS entirely.
        self._custom_lookup = lookup
        self._dns = None if lookup else self._build_dns(nameservers)

        self._workers: list[threading.Thread] = []
        for _ in range(max_workers):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            self._workers.append(t)

    def _build_dns(self, nameservers: Optional[list[str]]) -> dns.resolver.Resolver:
        # Use the caller-supplied servers, else discover the host's real
        # upstreams, else fall back to dnspython's own resolv.conf parsing.
        servers = nameservers or discover_nameservers()
        resolver = dns.resolver.Resolver(configure=not servers)
        if servers:
            resolver.nameservers = servers
        resolver.timeout = self._TIMEOUT
        resolver.lifetime = self._LIFETIME
        self.nameservers = list(resolver.nameservers)
        return resolver

    def display(self, ip: str) -> str:
        if not ip:
            return ip
        now = time.monotonic()
        with self._lock:
            name = self._cache.get(ip)
            if name is not None:
                return name
            if ip in self._pending:
                return ip
            # Within a negative-cache window: don't re-query yet.
            until = self._suppress_until.get(ip)
            if until is not None and now < until:
                return ip
            self._pending.add(ip)
        self._queue.put(ip)
        return ip

    def _resolve(self, ip: str) -> tuple[Optional[str], float]:
        """Reverse-resolve ``ip``.

        Returns ``(hostname, 0)`` on success, or ``(None, retry_after)`` on
        failure, where ``retry_after`` is how long to suppress re-querying.
        """
        if self._custom_lookup is not None:
            try:
                result = self._custom_lookup(ip)
            except Exception:
                return None, self._RETRY_TRANSIENT
            # A custom backend returns the IP itself when it has no name.
            return (result, 0.0) if result and result != ip else (None, self._RETRY_NO_RECORD)
        try:
            rev = dns.reversename.from_address(ip)
            answer = self._dns.resolve(rev, "PTR")
            if answer:
                # PTR targets are absolute names with a trailing dot.
                return str(answer[0]).rstrip("."), 0.0
            return None, self._RETRY_NO_RECORD
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None, self._RETRY_NO_RECORD  # authoritative: no PTR record
        except (dns.resolver.NoNameservers, dns.exception.Timeout):
            return None, self._RETRY_TRANSIENT  # transient: retry sooner
        except Exception:
            return None, self._RETRY_TRANSIENT

    def _worker(self) -> None:
        while not self._stop.is_set():
            try:
                ip = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            name, retry_after = self._resolve(ip)
            now = time.monotonic()
            with self._lock:
                if name is not None:
                    self._cache[ip] = name
                    self._suppress_until.pop(ip, None)
                else:
                    # No name yet: suppress re-querying until the window passes,
                    # then display() will schedule another attempt.
                    self._suppress_until[ip] = now + retry_after
                self._pending.discard(ip)

    def stop(self) -> None:
        self._stop.set()
