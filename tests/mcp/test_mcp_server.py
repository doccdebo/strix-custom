"""Tests for strix.mcp.server (MCPServer)."""

from __future__ import annotations

import asyncio
import base64
from unittest.mock import MagicMock, patch

import pytest

from strix.mcp.browser_manager import BrowserInfo, BrowserSession
from strix.mcp.server import MCPServer
from strix.mcp.session_capture import AuthenticatedSession


def _b64url(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


_JWT_HEADER = _b64url('{"alg":"none","typ":"JWT"}')
_JWT_PAYLOAD = _b64url('{"sub":"1234567890"}')
_JWT_SIG = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
_FAKE_JWT = f"{_JWT_HEADER}.{_JWT_PAYLOAD}.{_JWT_SIG}"


class TestMCPServerTools:
    def test_get_browser_url_no_session(self):
        server = MCPServer()
        assert server.get_browser_url() == ""

    def test_get_captured_session_empty(self):
        server = MCPServer()
        result = server.get_captured_session()
        assert result["is_authenticated"] is False
        assert result["cookies"] == {}

    def test_get_proxy_traffic(self):
        server = MCPServer()
        traffic = server.get_proxy_traffic()
        assert "flow_count" in traffic
        assert "request_count" in traffic
        assert "session_detected" in traffic

    def test_inject_session_into_scan_no_session(self):
        server = MCPServer()
        result = server.inject_session_into_scan()
        assert result["injected"] is False

    def test_inject_session_into_scan_with_session(self):
        server = MCPServer()
        server.feed_cookies({"JSESSIONID": "abc123"})
        result = server.inject_session_into_scan()
        assert result["injected"] is True
        assert result["session_id"] == "abc123"

    def test_feed_request_captures_auth_header(self):
        server = MCPServer()
        server.feed_request({"Authorization": f"******"})
        session = server.get_captured_session()
        assert "Authorization" in session["headers"]

    def test_feed_cookies_captures_session(self):
        server = MCPServer()
        server.feed_cookies({"session": "tok"})
        traffic = server.get_proxy_traffic()
        assert traffic["session_detected"] is True

    def test_confirm_session_snapshots(self):
        server = MCPServer()
        server.feed_cookies({"JSESSIONID": "abc"})
        session = server.confirm_session()
        assert isinstance(session, AuthenticatedSession)
        assert session.cookies["JSESSIONID"] == "abc"

    def test_skip_authentication(self):
        server = MCPServer()
        server.skip_authentication()
        result = server.get_captured_session()
        assert result["source"] == "skipped"


class TestMCPServerWait:
    @pytest.mark.asyncio
    async def test_wait_for_authentication_detects_session(self):
        server = MCPServer()

        async def feed_after_delay():
            await asyncio.sleep(0.1)
            server.feed_cookies({"JSESSIONID": "tok123"})

        asyncio.ensure_future(feed_after_delay())
        session = await server.wait_for_authentication(timeout=5)
        assert session is not None
        assert session.cookies["JSESSIONID"] == "tok123"

    @pytest.mark.asyncio
    async def test_wait_for_authentication_timeout(self):
        server = MCPServer()
        # Don't feed any cookies — should time out quickly
        session = await server.wait_for_authentication(timeout=1)
        assert session is None


class TestMCPServerLaunch:
    def test_launch_browser_sets_session(self):
        server = MCPServer()
        from pathlib import Path

        fake_info = BrowserInfo(name="chrome", executable="/usr/bin/google-chrome")
        fake_proc = MagicMock()
        fake_proc.pid = 1234
        fake_proc.poll.return_value = None
        fake_session = BrowserSession(
            info=fake_info,
            profile_dir=Path("/tmp/fake"),
            proxy_port=8888,
            process=fake_proc,
            debug_url="http://localhost:9222",
        )

        with patch.object(server._browser_manager, "launch", return_value=fake_session):
            returned = server.launch_browser(browser="chrome", target_url="https://app.com")

        assert returned.debug_url == "http://localhost:9222"
        assert server.get_browser_url() == "http://localhost:9222"

    def test_shutdown_calls_cleanup(self):
        server = MCPServer()
        with patch.object(server._browser_manager, "cleanup_all") as mock_cleanup:
            server.shutdown(keep_browser=False)
            mock_cleanup.assert_called_once()

    def test_shutdown_keep_browser(self):
        server = MCPServer()
        with patch.object(server._browser_manager, "cleanup_all") as mock_cleanup:
            server.shutdown(keep_browser=True)
            mock_cleanup.assert_not_called()
