"""Tests for strix.mcp.browser_manager."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from strix.mcp.browser_manager import BrowserInfo, BrowserManager, BrowserSession


class TestBrowserDetection:
    def test_detect_browsers_returns_list(self):
        result = BrowserManager.detect_browsers()
        assert isinstance(result, list)
        for item in result:
            assert isinstance(item, BrowserInfo)
            assert item.name
            assert item.executable

    def test_preferred_browser_auto_no_browsers(self):
        with patch.object(BrowserManager, "detect_browsers", return_value=[]):
            result = BrowserManager.preferred_browser("auto")
            assert result is None

    def test_preferred_browser_auto_returns_chrome_first(self):
        browsers = [
            BrowserInfo(name="firefox", executable="/usr/bin/firefox"),
            BrowserInfo(name="chrome", executable="/usr/bin/google-chrome"),
        ]
        with patch.object(BrowserManager, "detect_browsers", return_value=browsers):
            result = BrowserManager.preferred_browser("auto")
            assert result is not None
            assert result.name == "chrome"

    def test_preferred_browser_explicit_match(self):
        browsers = [
            BrowserInfo(name="firefox", executable="/usr/bin/firefox"),
            BrowserInfo(name="chrome", executable="/usr/bin/google-chrome"),
        ]
        with patch.object(BrowserManager, "detect_browsers", return_value=browsers):
            result = BrowserManager.preferred_browser("firefox")
            assert result is not None
            assert result.name == "firefox"

    def test_preferred_browser_explicit_no_match(self):
        browsers = [
            BrowserInfo(name="firefox", executable="/usr/bin/firefox"),
        ]
        with patch.object(BrowserManager, "detect_browsers", return_value=browsers):
            result = BrowserManager.preferred_browser("edge")
            assert result is None

    def test_preferred_browser_auto_fallback_order(self):
        # If only edge is available it should be returned
        browsers = [BrowserInfo(name="edge", executable="/usr/bin/msedge")]
        with patch.object(BrowserManager, "detect_browsers", return_value=browsers):
            result = BrowserManager.preferred_browser("auto")
            assert result is not None
            assert result.name == "edge"


class TestBrowserSession:
    def _make_session(self, running: bool = True) -> BrowserSession:
        proc = MagicMock(spec=subprocess.Popen)
        proc.poll.return_value = None if running else 0
        return BrowserSession(
            info=BrowserInfo(name="chrome", executable="/usr/bin/chrome"),
            profile_dir=Path("/tmp/test-profile"),
            proxy_port=8888,
            process=proc,
            debug_url="http://localhost:9222",
        )

    def test_is_running_true(self):
        session = self._make_session(running=True)
        assert session.is_running is True

    def test_is_running_false(self):
        session = self._make_session(running=False)
        assert session.is_running is False

    def test_is_running_no_process(self):
        session = BrowserSession(
            info=BrowserInfo(name="chrome", executable="/usr/bin/chrome"),
            profile_dir=Path("/tmp/test-profile"),
            proxy_port=8888,
        )
        assert session.is_running is False

    def test_terminate_calls_process_terminate(self):
        session = self._make_session(running=True)
        session.terminate()
        session.process.terminate.assert_called_once()

    def test_terminate_no_process(self):
        session = BrowserSession(
            info=BrowserInfo(name="chrome", executable="/usr/bin/chrome"),
            profile_dir=Path("/tmp/test-profile"),
            proxy_port=8888,
        )
        session.terminate()  # Should not raise


class TestBrowserManagerLaunch:
    def test_launch_raises_when_no_browser(self):
        manager = BrowserManager(proxy_port=8888)
        with patch.object(BrowserManager, "preferred_browser", return_value=None):
            with pytest.raises(RuntimeError, match="No supported browser found"):
                manager.launch(browser="auto")

    def test_launch_starts_process(self, tmp_path):
        manager = BrowserManager(proxy_port=8888)
        fake_info = BrowserInfo(name="chrome", executable="/usr/bin/google-chrome")
        fake_proc = MagicMock(spec=subprocess.Popen)
        fake_proc.pid = 1234
        fake_proc.poll.return_value = None

        with (
            patch.object(BrowserManager, "preferred_browser", return_value=fake_info),
            patch("tempfile.mkdtemp", return_value=str(tmp_path)),
            patch("subprocess.Popen", return_value=fake_proc),
            patch("time.sleep"),
        ):
            session = manager.launch(browser="auto", target_url="https://example.com")

        assert session.info.name == "chrome"
        assert session.proxy_port == 8888
        assert session.debug_url == "http://localhost:9222"

    def test_cleanup_terminates_session(self):
        manager = BrowserManager(proxy_port=8888)
        mock_session = MagicMock(spec=BrowserSession)
        mock_session.profile_dir = Path("/tmp/fake-profile")
        manager._active_sessions.append(mock_session)

        with patch("shutil.rmtree"):
            manager.cleanup(mock_session)

        mock_session.terminate.assert_called_once()
        assert mock_session not in manager._active_sessions
