"""Browser lifecycle management for interactive login sessions."""

from __future__ import annotations

import contextlib
import logging
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


_BROWSER_EXECUTABLES: dict[str, list[str]] = {
    "chrome": [
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
        "chrome",
        # macOS
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        # Windows
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ],
    "firefox": [
        "firefox",
        "firefox-esr",
        # macOS
        "/Applications/Firefox.app/Contents/MacOS/firefox",
        # Windows
        r"C:\Program Files\Mozilla Firefox\firefox.exe",
        r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe",
    ],
    "edge": [
        "msedge",
        "microsoft-edge",
        "microsoft-edge-stable",
        # macOS
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        # Windows
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    ],
    "safari": [
        # macOS only
        "/Applications/Safari.app/Contents/MacOS/Safari",
    ],
}


@dataclass
class BrowserInfo:
    """Metadata about a detected browser installation."""

    name: str
    executable: str
    version: str | None = None


@dataclass
class BrowserSession:
    """Runtime state of a managed browser process."""

    info: BrowserInfo
    profile_dir: Path
    proxy_port: int
    process: Any = field(default=None, repr=False)
    debug_url: str | None = None

    @property
    def is_running(self) -> bool:
        if self.process is None:
            return False
        return self.process.poll() is None

    def terminate(self) -> None:
        if self.process is not None and self.is_running:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except Exception:  # noqa: BLE001
                with contextlib.suppress(Exception):
                    self.process.kill()


class BrowserManager:
    """Detect installed browsers, launch isolated sessions, manage cleanup.

    Example::

        manager = BrowserManager(proxy_port=8888)
        session = manager.launch(browser="auto", target_url="https://example.com")
        # ... wait for user to log in ...
        manager.cleanup(session)
    """

    def __init__(self, proxy_port: int = 8888) -> None:
        self._proxy_port = proxy_port
        self._active_sessions: list[BrowserSession] = []
        self._tmp_dirs: list[Path] = []

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    @staticmethod
    def detect_browsers() -> list[BrowserInfo]:
        """Return a list of installed browsers on the current system."""
        found: list[BrowserInfo] = []
        for name, candidates in _BROWSER_EXECUTABLES.items():
            for exe in candidates:
                resolved = shutil.which(exe) or (Path(exe).exists() and exe) or None
                if resolved:
                    found.append(BrowserInfo(name=name, executable=str(resolved)))
                    break
        return found

    @staticmethod
    def preferred_browser(
        browser: str = "auto",
    ) -> BrowserInfo | None:
        """Return the best available browser matching the preference."""
        available = BrowserManager.detect_browsers()
        if not available:
            return None
        if browser == "auto":
            # Prefer Chrome > Firefox > Edge > Safari
            order = ["chrome", "firefox", "edge", "safari"]
            for preferred in order:
                for info in available:
                    if info.name == preferred:
                        return info
            return available[0]
        for info in available:
            if info.name == browser:
                return info
        return None

    # ------------------------------------------------------------------
    # Launch
    # ------------------------------------------------------------------

    def launch(
        self,
        browser: str = "auto",
        target_url: str = "",
        remote_debugging_port: int = 9222,
    ) -> BrowserSession:
        """Launch a browser in an isolated profile with proxy configuration.

        Returns a :class:`BrowserSession` whose ``debug_url`` points to the
        remote debugging interface.  The caller should poll
        :attr:`BrowserSession.is_running` and call :meth:`cleanup` when done.
        """
        info = self.preferred_browser(browser)
        if info is None:
            raise RuntimeError(
                f"No supported browser found (requested: {browser!r}). "
                "Install Chrome, Firefox, or Edge and retry."
            )

        profile_dir = Path(tempfile.mkdtemp(prefix="strix-browser-"))
        self._tmp_dirs.append(profile_dir)

        logger.info(
            "Launching %s (exe=%s, proxy=127.0.0.1:%d, profile=%s)",
            info.name,
            info.executable,
            self._proxy_port,
            profile_dir,
        )

        process = self._start_process(
            info=info,
            profile_dir=profile_dir,
            target_url=target_url,
            remote_debugging_port=remote_debugging_port,
        )

        session = BrowserSession(
            info=info,
            profile_dir=profile_dir,
            proxy_port=self._proxy_port,
            process=process,
            debug_url=f"http://localhost:{remote_debugging_port}",
        )
        self._active_sessions.append(session)

        # Brief pause to let the browser initialise
        time.sleep(1)
        logger.info(
            "Browser launched (pid=%s, debug_url=%s)",
            process.pid if process else "N/A",
            session.debug_url,
        )
        return session

    def _start_process(
        self,
        info: BrowserInfo,
        profile_dir: Path,
        target_url: str,
        remote_debugging_port: int,
    ) -> subprocess.Popen[bytes]:
        """Build the command line and start the browser process."""
        firefox_env: dict[str, str] | None = None

        if info.name in ("chrome", "edge"):
            cmd = [
                info.executable,
                f"--user-data-dir={profile_dir}",
                f"--proxy-server=http://127.0.0.1:{self._proxy_port}",
                "--proxy-bypass-list=<-loopback>",
                f"--remote-debugging-port={remote_debugging_port}",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-extensions",
                "--disable-sync",
                "--safebrowsing-disable-auto-update",
                "--ignore-certificate-errors",
                "--disable-background-timer-throttling",
                "--disable-renderer-backgrounding",
            ]
            if target_url:
                cmd.append(target_url)

        elif info.name == "firefox":
            cmd = [
                info.executable,
                "--no-remote",
                "--profile",
                str(profile_dir),
                "--start-debugger-server",
                str(remote_debugging_port),
            ]
            # Write Firefox proxy preferences to user.js in the profile dir
            proxy_host = "127.0.0.1"
            proxy_port = self._proxy_port
            user_js = profile_dir / "user.js"
            user_js.write_text(
                f'user_pref("network.proxy.type", 1);\n'
                f'user_pref("network.proxy.http", "{proxy_host}");\n'
                f'user_pref("network.proxy.http_port", {proxy_port});\n'
                f'user_pref("network.proxy.ssl", "{proxy_host}");\n'
                f'user_pref("network.proxy.ssl_port", {proxy_port});\n'
                f'user_pref("network.proxy.no_proxies_on", "localhost,127.0.0.1");\n'
            )
            # Scope proxy env vars to the subprocess only (don't pollute os.environ)
            firefox_env = os.environ.copy()
            firefox_env["http_proxy"] = f"http://{proxy_host}:{proxy_port}"
            firefox_env["https_proxy"] = f"http://{proxy_host}:{proxy_port}"
            if target_url:
                cmd.append(target_url)

        else:
            # Generic fallback: just open the URL
            cmd = [info.executable]
            if target_url:
                cmd.append(target_url)

        logger.debug("Browser command: %s", cmd)
        return subprocess.Popen(  # noqa: S603
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=firefox_env,
        )

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def cleanup(self, session: BrowserSession | None = None) -> None:
        """Terminate a browser session and remove its temporary profile."""
        targets = [session] if session else list(self._active_sessions)
        for s in targets:
            try:
                s.terminate()
            except Exception:
                logger.debug("Error terminating browser", exc_info=True)
            try:
                shutil.rmtree(s.profile_dir, ignore_errors=True)
            except Exception:
                logger.debug("Error removing profile dir %s", s.profile_dir, exc_info=True)
            if s in self._active_sessions:
                self._active_sessions.remove(s)
        logger.info("Browser cleanup complete (%d session(s) cleaned)", len(targets))

    def cleanup_all(self) -> None:
        """Terminate all active browser sessions."""
        self.cleanup()
        for tmp_dir in self._tmp_dirs:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        self._tmp_dirs.clear()


__all__ = ["BrowserInfo", "BrowserManager", "BrowserSession"]
