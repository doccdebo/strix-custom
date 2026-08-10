"""HTTP proxy middleware for intercepting and tagging authentication traffic.

This module provides a *non-invasive* middleware layer that hooks into the
mitmproxy / Caido traffic pipeline.  It observes requests and responses,
passes them to the SessionCapture layer, and never modifies the traffic.
"""

from __future__ import annotations

import contextlib
import logging
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from strix.mcp.session_capture import SessionCapture


logger = logging.getLogger(__name__)


# HTTP status codes that strongly suggest an authentication event
_AUTH_STATUS_CODES: frozenset[int] = frozenset({200, 201, 302})

# Path fragments that suggest auth-related endpoints
_AUTH_PATH_HINTS: tuple[str, ...] = (
    "/login",
    "/signin",
    "/auth",
    "/oauth",
    "/token",
    "/session",
    "/sso",
    "/callback",
    "/saml",
    "/oidc",
)


def _is_auth_endpoint(path: str) -> bool:
    lower = path.lower()
    return any(hint in lower for hint in _AUTH_PATH_HINTS)


class ProxyMiddleware:
    """Observes HTTP flows, feeds auth signals to :class:`SessionCapture`.

    Usage with mitmproxy addon API::

        capture = SessionCapture()
        addon = ProxyMiddleware(capture)
        mitmdump.run(options=["-p", "8888"], addons=[addon])

    Usage with raw dicts (e.g., testing, Caido webhook)::

        middleware.process_flow(request_headers, response_headers, status_code, path)
    """

    def __init__(self, capture: SessionCapture) -> None:
        self._capture = capture
        self._flow_count: int = 0
        self._auth_event_count: int = 0

    # ------------------------------------------------------------------
    # mitmproxy addon interface
    # ------------------------------------------------------------------

    def request(self, flow: Any) -> None:
        """mitmproxy hook: called for each outgoing request."""
        try:
            headers = dict(flow.request.headers)
            self._capture.ingest_request_headers(headers)
            self._flow_count += 1
        except Exception:
            logger.debug("ProxyMiddleware.request: error processing flow", exc_info=True)

    def response(self, flow: Any) -> None:
        """mitmproxy hook: called for each incoming response."""
        try:
            headers = dict(flow.response.headers)
            self._capture.ingest_response_headers(headers)

            # Opportunistically scan small response bodies for JWTs
            content_type = headers.get("content-type", "")
            if "json" in content_type or "text" in content_type:
                with contextlib.suppress(Exception):
                    body = flow.response.get_text(strict=False) or ""
                    if body:
                        self._capture.ingest_response_body(body)

            path = getattr(flow.request, "path", "")
            status = getattr(flow.response, "status_code", 0)
            if _is_auth_endpoint(path) and status in _AUTH_STATUS_CODES:
                self._auth_event_count += 1
                logger.debug(
                    "Auth event detected at %s (status=%d)", path, status
                )
        except Exception:
            logger.debug("ProxyMiddleware.response: error processing flow", exc_info=True)

    # ------------------------------------------------------------------
    # Direct (non-mitmproxy) processing interface
    # ------------------------------------------------------------------

    def process_flow(
        self,
        request_headers: dict[str, str],
        response_headers: dict[str, str],
        status_code: int = 200,
        path: str = "",
        response_body: str = "",
    ) -> None:
        """Process a flow given raw dicts.  Used by tests and non-mitmproxy proxies."""
        self._capture.ingest_request_headers(request_headers)
        self._capture.ingest_response_headers(response_headers)
        if response_body:
            self._capture.ingest_response_body(response_body)
        self._flow_count += 1
        if _is_auth_endpoint(path) and status_code in _AUTH_STATUS_CODES:
            self._auth_event_count += 1

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------

    @property
    def flow_count(self) -> int:
        return self._flow_count

    @property
    def auth_event_count(self) -> int:
        return self._auth_event_count

    def reset_counters(self) -> None:
        self._flow_count = 0
        self._auth_event_count = 0


__all__ = ["ProxyMiddleware"]
