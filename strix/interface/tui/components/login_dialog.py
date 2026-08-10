"""Interactive login dialog for the Strix TUI.

Displays real-time session detection status while waiting for the user to
authenticate in the managed browser window.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import TYPE_CHECKING, Any, ClassVar

from textual.binding import Binding
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import Label, Static


if TYPE_CHECKING:
    from textual.app import ComposeResult

    from strix.mcp.server import MCPServer

logger = logging.getLogger(__name__)


_HELP_TEXT = (
    "[bold green]\\[C][/] Continue (session detected)  "
    "[bold yellow]\\[S][/] Skip auth (unauthenticated)  "
    "[bold red]\\[Q][/] Quit"
)

_CSS = """
LoginDialog {
    align: center middle;
}

#dialog-container {
    width: 70;
    height: auto;
    border: double $accent;
    padding: 1 2;
    background: $surface;
}

#dialog-title {
    text-align: center;
    text-style: bold;
    color: $accent;
    padding-bottom: 1;
}

#status-line {
    color: $text-muted;
}

#help-bar {
    margin-top: 1;
    text-align: center;
}
"""


class LoginDialog(ModalScreen[str]):
    """Modal screen that guides the user through interactive browser login.

    Returns one of:
    * ``"continue"``  — user confirmed they are logged in
    * ``"skip"``      — user wants to proceed unauthenticated
    * ``"quit"``      — user wants to abort the scan

    Usage::

        result = await app.push_screen_wait(LoginDialog(mcp_server=server, target="https://app.com"))
    """

    DEFAULT_CSS = _CSS

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("c", "continue_login", "Continue", show=True),
        Binding("s", "skip_login", "Skip", show=True),
        Binding("q", "quit_scan", "Quit", show=True),
    ]

    # Reactive attributes drive live UI updates
    elapsed: reactive[int] = reactive(0)
    request_count: reactive[int] = reactive(0)
    cookie_count: reactive[int] = reactive(0)
    session_detected: reactive[bool] = reactive(default=False)
    status_text: reactive[str] = reactive("Waiting for authenticated session...")

    def __init__(
        self,
        mcp_server: MCPServer,
        target: str = "",
        timeout: int = 300,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._mcp_server = mcp_server
        self._target = target
        self._timeout = timeout
        self._update_task: asyncio.Task[None] | None = None

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        browser_url = self._mcp_server.get_browser_url() or "http://localhost:9222"
        with Static(id="dialog-container"):
            yield Label("INTERACTIVE LOGIN", id="dialog-title")
            yield Label(f"Browser URL: [bold]{browser_url}[/]")
            yield Label(f"Target:      [bold]{self._target or '(not set)'}[/]")
            yield Label("")
            yield Label(id="status-line")
            yield Label("")
            yield Label(id="traffic-line")
            yield Label("")
            yield Static(_HELP_TEXT, id="help-bar")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        self._update_task = asyncio.ensure_future(self._poll_loop())

    def on_unmount(self) -> None:
        if self._update_task is not None:
            self._update_task.cancel()

    # ------------------------------------------------------------------
    # Background polling
    # ------------------------------------------------------------------

    async def _poll_loop(self) -> None:
        while True:
            try:
                traffic = self._mcp_server.get_proxy_traffic()
                self.request_count = traffic.get("request_count", 0)
                self.session_detected = bool(traffic.get("session_detected", False))

                if self.session_detected:
                    self.status_text = "✅ Session detected! Press [C] to continue."
                else:
                    self.status_text = (
                        f"No session detected yet "
                        f"({self.elapsed}s / {self._timeout}s)"
                    )

                captured = self._mcp_server.get_captured_session()
                self.cookie_count = len(captured.get("cookies", {}))

                self.elapsed += 2
                if self.elapsed >= self._timeout:
                    self.status_text = "⏰ Timeout reached. Press [S] to continue unauthenticated."
                    break
            except Exception:
                logger.debug("LoginDialog poll error", exc_info=True)
            await asyncio.sleep(2)

    # ------------------------------------------------------------------
    # Reactive watchers
    # ------------------------------------------------------------------

    def watch_status_text(self, value: str) -> None:
        with contextlib.suppress(Exception):
            self.query_one("#status-line", Label).update(value)

    def watch_request_count(self, value: int) -> None:
        with contextlib.suppress(Exception):
            self.query_one("#traffic-line", Label).update(
                f"Traffic: {value} requests captured  |  "
                f"Cookies: {self.cookie_count} auth cookies found"
            )

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_continue_login(self) -> None:
        self._mcp_server.confirm_session()
        self.dismiss("continue")

    def action_skip_login(self) -> None:
        self._mcp_server.skip_authentication()
        self.dismiss("skip")

    def action_quit_scan(self) -> None:
        self.dismiss("quit")


__all__ = ["LoginDialog"]
