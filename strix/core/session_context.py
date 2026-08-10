"""Session context management — bridges captured sessions to agent requests."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from strix.mcp.session_capture import (
    AuthenticatedSession,
    format_session_for_prompt,
    inject_session_headers,
)


if TYPE_CHECKING:
    from strix.mcp.server import MCPServer


logger = logging.getLogger(__name__)


class SessionContext:
    """Manages an authenticated session and its injection into agent requests.

    Instances are created by the runner when ``--enable-interactive-login``
    is active, and threaded through the agent factory so every agent (root
    and children) has access to the captured credentials.
    """

    def __init__(self) -> None:
        self._session: AuthenticatedSession | None = None
        self._mcp_server: MCPServer | None = None

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    async def capture_from_browser(
        self,
        *,
        mcp_server: MCPServer,
        timeout: int = 300,
    ) -> AuthenticatedSession | None:
        """Attach to the MCP server and wait for an authenticated session.

        This coroutine blocks until either:
        * The user has authenticated in the browser (session detected), or
        * ``timeout`` seconds have elapsed.

        Returns the session on success, ``None`` on timeout.
        """
        self._mcp_server = mcp_server
        session = await mcp_server.wait_for_authentication(timeout=timeout)
        if session is not None:
            self._session = session
            logger.info("SessionContext: authenticated session captured")
        else:
            logger.warning("SessionContext: no session captured within timeout")
        return session

    def set_session(self, session: AuthenticatedSession) -> None:
        """Directly assign a pre-built session (e.g., from manual confirmation)."""
        self._session = session

    def clear(self) -> None:
        """Remove the current session."""
        self._session = None

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def session(self) -> AuthenticatedSession | None:
        return self._session

    @property
    def is_authenticated(self) -> bool:
        return self._session is not None and self._session.is_authenticated

    # ------------------------------------------------------------------
    # Integration helpers
    # ------------------------------------------------------------------

    def inject_into_request_headers(
        self, headers: dict[str, str]
    ) -> dict[str, str]:
        """Return a copy of *headers* augmented with session cookies/tokens.

        If no authenticated session is available the original dict is returned
        unchanged.
        """
        if self._session is None or not self._session.is_authenticated:
            return headers
        return inject_session_headers(headers, self._session)

    def get_session_summary(self) -> str:
        """Return a human-readable summary for logging / agent context."""
        if self._session is None:
            return "No authenticated session."
        return self._session.summary()

    def build_system_prompt_block(self) -> str:
        """Return the authenticated-session block to prepend to agent prompts.

        Returns an empty string when no authenticated session is available.
        """
        if self._session is None:
            return ""
        return format_session_for_prompt(self._session)

    def to_scan_config_dict(self) -> dict[str, Any]:
        """Serialise the current session for inclusion in ``scan_config``."""
        if self._session is None:
            return {}
        return {
            "cookies": self._session.cookies,
            "headers": self._session.headers,
            "jwt_tokens": self._session.jwt_tokens,
            "session_id": self._session.session_id,
            "source": self._session.source,
            "notes": self._session.notes,
        }


__all__ = ["SessionContext"]
