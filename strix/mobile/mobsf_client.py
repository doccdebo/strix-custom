"""MobSF REST API client for Strix mobile security integration."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

import requests


if TYPE_CHECKING:
    pass


logger = logging.getLogger(__name__)


class MobSFConnectionError(Exception):
    """Raised when the MobSF server is unreachable."""


class MobSFAPIError(Exception):
    """Raised when the MobSF API returns a non-2xx response."""


class MobSFClient:
    """Thin client for a self-hosted MobSF instance."""

    def __init__(self, base_url: str, api_key: str, timeout: int = 120) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        self._headers = {"X-Mobsf-Api-Key": api_key}

    def _post(self, endpoint: str, **kwargs: Any) -> requests.Response:
        url = f"{self._base_url}{endpoint}"
        try:
            response = requests.post(url, headers=self._headers, timeout=self._timeout, **kwargs)
        except requests.exceptions.ConnectionError as exc:
            raise MobSFConnectionError(f"Cannot connect to MobSF at {self._base_url}") from exc
        except requests.exceptions.Timeout as exc:
            raise MobSFConnectionError(f"Timeout connecting to MobSF at {self._base_url}") from exc
        if not response.ok:
            raise MobSFAPIError(
                f"MobSF API error {response.status_code} from {endpoint}: {response.text[:200]}"
            )
        return response

    def upload(self, binary_path: Path) -> str:
        """Upload an APK or IPA; return the scan hash."""
        logger.info("Uploading binary %s to MobSF", binary_path)
        with binary_path.open("rb") as fh:
            response = self._post("/api/v1/upload", files={"file": (binary_path.name, fh)})
        data: dict[str, Any] = response.json()
        scan_hash: str = data["hash"]
        logger.info("Upload complete, scan hash: %s", scan_hash)
        return scan_hash

    def scan(self, scan_hash: str, file_name: str) -> None:
        """Trigger static analysis for the given scan hash."""
        logger.info("Triggering MobSF static analysis for hash %s", scan_hash)
        suffix = Path(file_name).suffix.lower()
        scan_type = "apk" if suffix == ".apk" else "ipa"
        self._post(
            "/api/v1/scan",
            data={"scan_type": scan_type, "file_name": file_name, "hash": scan_hash},
        )
        logger.info("Scan triggered for hash %s", scan_hash)

    def get_report(self, scan_hash: str) -> dict[str, Any]:
        """Fetch the full JSON report for a completed scan."""
        logger.info("Fetching MobSF report for hash %s", scan_hash)
        response = self._post("/api/v1/report_json", data={"hash": scan_hash})
        report: dict[str, Any] = response.json()
        return report
