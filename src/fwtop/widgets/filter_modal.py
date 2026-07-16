from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Input, Label, Select

from fwtop.models import CaptureFilter

_PROTOS = ("any", "tcp", "udp", "icmp")


class FilterModal(ModalScreen[CaptureFilter | None]):
    """Prompt for a capture filter: a list of ports and an L4 protocol.

    Dismisses with a :class:`CaptureFilter` on submit, or ``None`` on cancel.
    This is the app's first value-returning modal (pushed with a callback);
    styling mirrors ZoneScreen for visual consistency.
    """

    DEFAULT_CSS = """
    FilterModal {
        align: center middle;
        background: rgba(0, 0, 0, 0.7);
    }
    #filter-dialog {
        width: 60;
        height: auto;
        border: round #50a0ff;
        background: #1a1a2e;
        padding: 1 2;
    }
    #filter-dialog Label {
        color: #c0c0d0;
        margin-bottom: 1;
    }
    #filter-dialog Input {
        background: #0e0e20;
        border: tall #303050;
        margin-bottom: 1;
    }
    #filter-dialog Input:focus {
        border: tall #50a0ff;
    }
    #filter-dialog Select {
        margin-bottom: 1;
    }
    #filter-dialog .hint {
        color: #606080;
        margin-top: 1;
        margin-bottom: 0;
    }
    """

    # Select value standing in for "capture on every interface". Select can't
    # hold an empty string as a value, so we use this sentinel and map it back
    # to CaptureFilter.iface="" on submit.
    _ALL_IFACES = "\x00all"

    def __init__(
        self,
        current: CaptureFilter | None = None,
        interfaces: list[str] | None = None,
    ) -> None:
        super().__init__()
        self._current = current or CaptureFilter()
        self._interfaces = list(interfaces or [])

    def compose(self) -> ComposeResult:
        ports = ", ".join(str(p) for p in self._current.ports)
        iface_options = [("all interfaces", self._ALL_IFACES)]
        iface_options += [(name, name) for name in self._interfaces]
        # Preselect the current interface if it's still present, else "all".
        iface_value = self._current.iface if self._current.iface in self._interfaces else self._ALL_IFACES
        with Vertical(id="filter-dialog"):
            yield Label("Capture filter")
            yield Input(
                value=ports,
                placeholder="ports, e.g. 80, 443, 53  (blank = all)",
                id="filter-ports",
            )
            yield Input(
                value=self._current.src,
                placeholder="source address  (blank = any)",
                id="filter-src",
            )
            yield Input(
                value=self._current.dst,
                placeholder="destination address  (blank = any)",
                id="filter-dst",
            )
            yield Select(
                [(p, p) for p in _PROTOS],
                value=self._current.proto,
                allow_blank=False,
                id="filter-proto",
            )
            yield Select(
                iface_options,
                value=iface_value,
                allow_blank=False,
                id="filter-iface",
            )
            yield Label("Enter to start capture · Escape to cancel", classes="hint")

    def on_mount(self) -> None:
        self.query_one("#filter-ports", Input).focus()

    def _submit(self) -> None:
        raw = self.query_one("#filter-ports", Input).value
        ports: list[int] = []
        for tok in raw.replace(",", " ").split():
            try:
                n = int(tok)
            except ValueError:
                continue
            if 0 < n < 65536 and n not in ports:
                ports.append(n)
        proto = self.query_one("#filter-proto", Select).value
        if not isinstance(proto, str):
            proto = "any"
        iface = self.query_one("#filter-iface", Select).value
        if not isinstance(iface, str) or iface == self._ALL_IFACES:
            iface = ""
        src = self.query_one("#filter-src", Input).value.strip()
        dst = self.query_one("#filter-dst", Input).value.strip()
        self.dismiss(CaptureFilter(
            ports=tuple(ports), proto=proto, iface=iface, src=src, dst=dst,
        ))

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._submit()

    def key_enter(self) -> None:
        self._submit()

    def key_escape(self) -> None:
        self.dismiss(None)
