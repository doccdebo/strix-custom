"""Unit tests for MobSFClient."""

from __future__ import annotations

import io
import json
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests

from strix.mobile.mobsf_client import MobSFAPIError, MobSFClient, MobSFConnectionError


class TestMobSFClientUpload(unittest.TestCase):
    def _make_client(self) -> MobSFClient:
        return MobSFClient(base_url="http://localhost:8000", api_key="testkey", timeout=30)

    def test_upload_returns_hash(self) -> None:
        client = self._make_client()
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.json.return_value = {"hash": "abc123", "scan_type": "apk"}

        with (
            patch("strix.mobile.mobsf_client.requests.post", return_value=mock_response) as mock_post,
            patch("pathlib.Path.open", unittest.mock.mock_open(read_data=b"binarydata")),
        ):
            tmp = Path("/tmp/test.apk")
            result = client.upload(tmp)

        self.assertEqual(result, "abc123")
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        self.assertIn("/api/v1/upload", call_kwargs.args[0])
        self.assertIn("X-Mobsf-Api-Key", call_kwargs.kwargs["headers"])
        self.assertEqual(call_kwargs.kwargs["headers"]["X-Mobsf-Api-Key"], "testkey")

    def test_upload_raises_connection_error(self) -> None:
        client = self._make_client()
        with (
            patch(
                "strix.mobile.mobsf_client.requests.post",
                side_effect=requests.exceptions.ConnectionError("refused"),
            ),
            patch("pathlib.Path.open", unittest.mock.mock_open(read_data=b"")),
        ):
            with self.assertRaises(MobSFConnectionError):
                client.upload(Path("/tmp/test.apk"))

    def test_upload_raises_api_error_on_non_2xx(self) -> None:
        client = self._make_client()
        mock_response = MagicMock()
        mock_response.ok = False
        mock_response.status_code = 403
        mock_response.text = "Forbidden"

        with (
            patch("strix.mobile.mobsf_client.requests.post", return_value=mock_response),
            patch("pathlib.Path.open", unittest.mock.mock_open(read_data=b"")),
        ):
            with self.assertRaises(MobSFAPIError):
                client.upload(Path("/tmp/test.apk"))


class TestMobSFClientScan(unittest.TestCase):
    def test_scan_sends_correct_fields(self) -> None:
        client = MobSFClient(base_url="http://localhost:8000", api_key="key", timeout=30)
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.json.return_value = {}

        with patch("strix.mobile.mobsf_client.requests.post", return_value=mock_response) as mp:
            client.scan("myhash", "app.apk")

        mp.assert_called_once()
        call_kwargs = mp.call_args
        self.assertIn("/api/v1/scan", call_kwargs.args[0])
        sent_data = call_kwargs.kwargs["data"]
        self.assertEqual(sent_data["hash"], "myhash")
        self.assertEqual(sent_data["file_name"], "app.apk")
        self.assertEqual(sent_data["scan_type"], "apk")

    def test_scan_ipa_type(self) -> None:
        client = MobSFClient(base_url="http://localhost:8000", api_key="key", timeout=30)
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.json.return_value = {}

        with patch("strix.mobile.mobsf_client.requests.post", return_value=mock_response) as mp:
            client.scan("hash2", "myapp.ipa")

        sent_data = mp.call_args.kwargs["data"]
        self.assertEqual(sent_data["scan_type"], "ipa")


class TestMobSFClientGetReport(unittest.TestCase):
    def test_get_report_returns_dict(self) -> None:
        client = MobSFClient(base_url="http://localhost:8000", api_key="key", timeout=30)
        expected = {"app_name": "TestApp", "hash": "xyz"}
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.json.return_value = expected

        with patch("strix.mobile.mobsf_client.requests.post", return_value=mock_response):
            result = client.get_report("xyz")

        self.assertEqual(result, expected)


if __name__ == "__main__":
    unittest.main()
