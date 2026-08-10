"""Session extraction and capture from proxy traffic."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from urllib.parse import urlparse


if TYPE_CHECKING:
    from http.cookiejar import CookieJar


logger = logging.getLogger(__name__)

# Common session cookie names to detect
_SESSION_COOKIE_NAMES: frozenset[str] = frozenset(
    {
        "jsessionid",
        "phpsessid",
        "asp.net_sessionid",
        "connect.sid",
        "session",
        "sessionid",
        "sess",
        "auth",
        "token",
        "access_token",
        "id_token",
        "refresh_token",
        "csrf_token",
        "xsrf-token",
        "__cfduid",
        "_ga",
    }
)

# Headers that indicate authenticated state
_AUTH_HEADER_NAMES: frozenset[str] = frozenset(
    {
        "authorization",
        "x-auth-token",
        "x-access-token",
        "x-api-key",
        "x-csrf-token",
        "x-xsrf-token",
        "x-session-token",
    }
)

# JWT pattern: three base64url-encoded segments separated by dots
_JWT_PATTERN = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
)


@dataclass
class AuthenticatedSession:
    """Captured authenticated session from browser/proxy."""

    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    jwt_tokens: list[str] = field(default_factory=list)
    session_id: str | None = None
    detected_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    source: str = "browser_proxy"
    notes: list[str] = field(default_factory=list)

    @property
    def is_authenticated(self) -> bool:
        """Return True when at least one auth signal has been captured."""
        return bool(self.cookies or self.headers or self.jwt_tokens)

    def summary(self) -> str:
        """Human-readable summary for embedding in agent system prompts."""
        parts: list[str] = []
        if self.cookies:
            parts.append(f"Cookies: {', '.join(self.cookies.keys())}")
        if self.headers:
            parts.append(f"Auth headers: {', '.join(self.headers.keys())}")
        if self.jwt_tokens:
            parts.append(f"JWT tokens: {len(self.jwt_tokens)} found")
        if self.session_id:
            parts.append(f"Session ID: {self.session_id}")
        if not parts:
            return "No authenticated session data captured."
        return "\n".join(parts)


class SessionCapture:
    """Extract and accumulate session data from intercepted HTTP traffic."""

    def __init__(self) -> None:
        self._cookies: dict[str, str] = {}
        self._headers: dict[str, str] = {}
        self._jwt_tokens: list[str] = []
        self._notes: list[str] = []
        self._request_count: int = 0

    # ------------------------------------------------------------------
    # Feed-methods — called by the proxy middleware or test harness
    # ------------------------------------------------------------------

    def ingest_request_headers(self, headers: dict[str, str]) -> None:
        """Process outgoing request headers for auth signals."""
        for name, value in headers.items():
            lower = name.lower()
            if lower in _AUTH_HEADER_NAMES:
                self._headers[name] = value
                logger.debug("Captured auth header: %s", name)
                jwts = _JWT_PATTERN.findall(value)
                for jwt in jwts:
                    if jwt not in self._jwt_tokens:
                        self._jwt_tokens.append(jwt)
                        self._notes.append(f"JWT found in request header '{name}'")
        self._request_count += 1

    def ingest_response_headers(self, headers: dict[str, str]) -> None:
        """Process response headers (e.g., Set-Cookie) for session signals."""
        set_cookie = headers.get("set-cookie") or headers.get("Set-Cookie")
        if set_cookie:
            self._parse_set_cookie(set_cookie)

    def ingest_cookie_jar(self, jar: CookieJar) -> None:
        """Import cookies directly from a cookiejar object."""
        for cookie in jar:
            self._cookies[cookie.name] = cookie.value or ""
            if cookie.name.lower() in _SESSION_COOKIE_NAMES:
                self._notes.append(f"Session cookie detected: {cookie.name}")

    def ingest_cookies_dict(self, cookies: dict[str, str]) -> None:
        """Import cookies from a plain dict (e.g., from browser CDP)."""
        for name, value in cookies.items():
            self._cookies[name] = value
            if name.lower() in _SESSION_COOKIE_NAMES:
                self._notes.append(f"Session cookie detected: {name}")

    def ingest_response_body(self, body: str) -> None:
        """Scan a response body for embedded JWTs."""
        jwts = _JWT_PATTERN.findall(body)
        for jwt in jwts:
            if jwt not in self._jwt_tokens:
                self._jwt_tokens.append(jwt)
                self._notes.append("JWT found in response body")

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def request_count(self) -> int:
        return self._request_count

    def has_session(self) -> bool:
        """Return True when at least one auth signal has been captured."""
        auth_cookies = {
            k for k in self._cookies if k.lower() in _SESSION_COOKIE_NAMES
        }
        return bool(auth_cookies or self._headers or self._jwt_tokens)

    def build_session(self) -> AuthenticatedSession:
        """Snapshot the current capture state as an immutable AuthenticatedSession."""
        session_id: str | None = None
        for name in self._cookies:
            if name.lower() in ("jsessionid", "phpsessid", "asp.net_sessionid"):
                session_id = self._cookies[name]
                break

        return AuthenticatedSession(
            cookies=dict(self._cookies),
            headers=dict(self._headers),
            jwt_tokens=list(self._jwt_tokens),
            session_id=session_id,
            detected_at=datetime.now(UTC),
            source="browser_proxy",
            notes=list(self._notes),
        )

    def clear(self) -> None:
        """Reset all captured data."""
        self._cookies.clear()
        self._headers.clear()
        self._jwt_tokens.clear()
        self._notes.clear()
        self._request_count = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_set_cookie(self, header_value: str) -> None:
        """Parse a Set-Cookie header and store the cookie name/value."""
        # Only take the first part (name=value), ignore attributes
        first_pair = header_value.split(";", maxsplit=1)[0].strip()
        if "=" in first_pair:
            name, _, value = first_pair.partition("=")
            name = name.strip()
            value = value.strip()
            self._cookies[name] = value
            if name.lower() in _SESSION_COOKIE_NAMES:
                self._notes.append(f"Session cookie set via Set-Cookie: {name}")

    @staticmethod
    def extract_target_domain(url: str) -> str:
        """Return the netloc of a URL for scope filtering."""
        parsed = urlparse(url)
        return parsed.netloc or url


def extract_jwts_from_text(text: str) -> list[str]:
    """Utility: find all JWT strings in an arbitrary text blob."""
    return _JWT_PATTERN.findall(text)


def is_session_cookie(name: str) -> bool:
    """Return True when ``name`` matches a known session cookie pattern."""
    return name.lower() in _SESSION_COOKIE_NAMES


def is_auth_header(name: str) -> bool:
    """Return True when ``name`` matches a known authentication header."""
    return name.lower() in _AUTH_HEADER_NAMES


def build_cookie_header(cookies: dict[str, str]) -> str:
    """Format a cookies dict as a Cookie: header value."""
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


def inject_session_headers(
    request_headers: dict[str, str],
    session: AuthenticatedSession,
) -> dict[str, str]:
    """Return a *new* headers dict with session cookies/tokens injected."""
    merged = dict(request_headers)

    if session.cookies:
        existing_cookie = merged.get("Cookie", "")
        session_cookie_str = build_cookie_header(session.cookies)
        merged["Cookie"] = (
            f"{existing_cookie}; {session_cookie_str}" if existing_cookie else session_cookie_str
        )

    merged.update(session.headers)

    return merged


def format_session_for_prompt(session: AuthenticatedSession) -> str:
    """Format session data as an authenticated-session block for agent prompts."""
    if not session.is_authenticated:
        return ""

    lines: list[str] = [
        "[Authenticated Session Detected]",
        "This scan uses an authenticated user session captured from browser login.",
    ]
    if session.cookies:
        lines.append(f"- Cookies: {', '.join(session.cookies.keys())}")
    if session.headers:
        lines.append(f"- Auth headers: {', '.join(session.headers.keys())}")
    if session.jwt_tokens:
        lines.append(f"- JWT tokens: {len(session.jwt_tokens)} found")
    if session.session_id:
        lines.append(f"- Session ID: {session.session_id}")
    lines.append("")
    lines.append(
        "All your HTTP requests will automatically include this authentication."
    )
    lines.append(
        "Focus on testing authenticated functionality, authorization flaws, "
        "and privilege escalation."
    )
    if session.notes:
        lines.append("")
        lines.append("Detection notes:")
        lines.extend(f"  - {note}" for note in session.notes)

    return "\n".join(lines)


# Re-export public dataclass so callers can import from session_capture
__all__ = [
    "AuthenticatedSession",
    "SessionCapture",
    "build_cookie_header",
    "extract_jwts_from_text",
    "format_session_for_prompt",
    "inject_session_headers",
    "is_auth_header",
    "is_session_cookie",
]
