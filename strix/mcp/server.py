"""MCP server exposing browser/session tools for Strix interactive login.

This module implements the Model Context Protocol (MCP) surface that allows
Strix agents to interact with the captured browser session.  Tools exposed:

* ``get_captured_session``   — returns cookies, tokens, headers from proxy
* ``inject_session_into_scan`` — prepares session for agent injection
* ``wait_for_authentication``  — polls until session detected or timeout
* ``get_browser_url``          — returns the browser debug/access URL
* ``get_proxy_traffic``        — inspect captured traffic counts for debug
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from strix.mcp.browser_manager import BrowserManager, BrowserSession
from strix.mcp.proxy_middleware import ProxyMiddleware
from strix.mcp.session_capture import AuthenticatedSession, SessionCapture


logger = logging.getLogger(__name__)

_POLL_INTERVAL: float = 2.0  # seconds between session-detection checks


class MCPServer:
    """Facade that binds together the browser, proxy middleware, and capture.

    Typical lifecycle::

        server = MCPServer(proxy_port=8888)
        session = server.launch_browser(browser="auto", target_url="https://app.com")
        auth = await server.wait_for_authentication(timeout=300)
        captured = server.get_captured_session()
        server.shutdown(keep_browser=False)
    """

    def __init__(self, proxy_port: int = 8888) -> None:
        self._proxy_port = proxy_port
        self._capture = SessionCapture()
        self._middleware = ProxyMiddleware(self._capture)
        self._browser_manager = BrowserManager(proxy_port=proxy_port)
        self._browser_session: BrowserSession | None = None
        self._authenticated_session: AuthenticatedSession | None = None

    # ------------------------------------------------------------------
    # Browser tools
    # ------------------------------------------------------------------

    def launch_browser(
        self,
        browser: str = "auto",
        target_url: str = "",
        remote_debugging_port: int = 9222,
    ) -> BrowserSession:
        """Launch a managed browser for the user to authenticate in."""
        self._browser_session = self._browser_manager.launch(
            browser=browser,
            target_url=target_url,
            remote_debugging_port=remote_debugging_port,
        )
        logger.info(
            "MCPServer: browser launched, debug_url=%s",
            self._browser_session.debug_url,
        )
        return self._browser_session

    def get_browser_url(self) -> str:
        """Return the browser's remote debugging URL, or empty string."""
        if self._browser_session is None:
            return ""
        return self._browser_session.debug_url or ""

    # ------------------------------------------------------------------
    # Proxy / traffic tools
    # ------------------------------------------------------------------

    @property
    def middleware(self) -> ProxyMiddleware:
        """The proxy middleware addon; register with mitmproxy or call directly."""
        return self._middleware

    def get_proxy_traffic(self) -> dict[str, Any]:
        """Return traffic statistics for debugging."""
        return {
            "flow_count": self._middleware.flow_count,
            "auth_event_count": self._middleware.auth_event_count,
            "request_count": self._capture.request_count,
            "session_detected": self._capture.has_session(),
        }

    # ------------------------------------------------------------------
    # Session tools
    # ------------------------------------------------------------------

    def get_captured_session(self) -> dict[str, Any]:
        """Return the currently captured session data as a plain dict."""
        session = self._authenticated_session or self._capture.build_session()
        return {
            "cookies": session.cookies,
            "headers": session.headers,
            "jwt_tokens": session.jwt_tokens,
            "session_id": session.session_id,
            "is_authenticated": session.is_authenticated,
            "notes": session.notes,
            "detected_at": session.detected_at.isoformat(),
            "source": session.source,
        }

    def inject_session_into_scan(self) -> dict[str, Any]:
        """Finalise the captured session and prepare it for agent injection.

        Returns the session dict plus an ``injected`` flag indicating success.
        """
        session = self._capture.build_session()
        if not session.is_authenticated:
            logger.warning("inject_session_into_scan called but no session detected yet")
            return {"injected": False, "reason": "No authenticated session data captured."}

        self._authenticated_session = session
        logger.info(
            "MCPServer: session injected — cookies=%d, headers=%d, jwts=%d",
            len(session.cookies),
            len(session.headers),
            len(session.jwt_tokens),
        )
        return {
            "injected": True,
            "cookies": list(session.cookies.keys()),
            "headers": list(session.headers.keys()),
            "jwt_count": len(session.jwt_tokens),
            "session_id": session.session_id,
        }

    async def wait_for_authentication(self, timeout: int = 300) -> AuthenticatedSession | None:
        """Poll until an authenticated session is detected or timeout expires.

        Returns the :class:`AuthenticatedSession` on success, ``None`` on timeout.
        """
        elapsed = 0.0
        logger.info("MCPServer: waiting for authentication (timeout=%ds)", timeout)
        while elapsed < timeout:
            if self._capture.has_session():
                session = self._capture.build_session()
                self._authenticated_session = session
                logger.info(
                    "MCPServer: authentication detected after %.1fs",
                    elapsed,
                )
                return session
            await asyncio.sleep(_POLL_INTERVAL)
            elapsed += _POLL_INTERVAL

        logger.warning("MCPServer: authentication wait timed out after %ds", timeout)
        return None

    def confirm_session(self) -> AuthenticatedSession:
        """Explicitly snapshot the current capture as the final session.

        Call this when the user presses 'C' to confirm they've logged in.
        """
        session = self._capture.build_session()
        self._authenticated_session = session
        return session

    def skip_authentication(self) -> None:
        """Record that the user chose to skip authentication."""
        self._authenticated_session = AuthenticatedSession(
            source="skipped",
            notes=["User chose to skip authentication"],
        )
        logger.info("MCPServer: authentication skipped by user")

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def shutdown(self, *, keep_browser: bool = False) -> None:
        """Tear down browser and proxy resources."""
        if not keep_browser:
            self._browser_manager.cleanup_all()
        logger.info("MCPServer: shutdown complete (keep_browser=%s)", keep_browser)

    # ------------------------------------------------------------------
    # Direct capture feed (for testing / Caido integration)
    # ------------------------------------------------------------------

    def feed_request(self, headers: dict[str, str]) -> None:
        """Feed request headers directly to the capture layer."""
        self._capture.ingest_request_headers(headers)

    def feed_response(
        self,
        headers: dict[str, str],
        body: str = "",
        status_code: int = 200,
        path: str = "",
    ) -> None:
        """Feed response data directly to the capture layer."""
        self._capture.ingest_response_headers(headers)
        if body:
            self._capture.ingest_response_body(body)
        self._middleware.process_flow(
            request_headers={},
            response_headers=headers,
            status_code=status_code,
            path=path,
            response_body=body,
        )

    def feed_cookies(self, cookies: dict[str, str]) -> None:
        """Feed cookies directly to the capture layer (e.g., from browser CDP)."""
        self._capture.ingest_cookies_dict(cookies)


__all__ = ["MCPServer"]
