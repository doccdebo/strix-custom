"""Unit tests for strix.tools.sanitizer."""

from __future__ import annotations

import json
import unittest

from strix.tools.sanitizer import sanitize_tool_output


class TestSecuritySignalPreservation(unittest.TestCase):
    """Critical security signals must NEVER be removed."""

    def test_sql_error_preserved(self) -> None:
        raw = "\n".join(["Status: 404"] * 50) + "\nMySQL error: syntax error in SQL near 'x'"
        result = sanitize_tool_output("ffuf", raw, max_chars=200)
        self.assertIn("syntax error in SQL", result)

    def test_ora_error_preserved(self) -> None:
        raw = "\n".join(["Status: 404"] * 50) + "\nORA-00942: table or view does not exist"
        result = sanitize_tool_output("ffuf", raw, max_chars=200)
        self.assertIn("ORA-00942", result)

    def test_stack_trace_preserved(self) -> None:
        raw = "lots of noise\n" * 100 + "Traceback (most recent call last):\n  File test.py line 1"
        result = sanitize_tool_output("curl", raw, max_chars=500)
        self.assertIn("Traceback (most recent call last)", result)

    def test_500_preserved(self) -> None:
        raw = "noise\n" * 100 + "HTTP/1.1 500 Internal Server Error\nContent-Type: text/html"
        result = sanitize_tool_output("curl", raw, max_chars=300)
        self.assertIn("500 Internal Server Error", result)

    def test_set_cookie_header_preserved(self) -> None:
        raw = "noise\n" * 50 + "Set-Cookie: session=abc123; HttpOnly; Secure"
        result = sanitize_tool_output("curl", raw, max_chars=100)
        self.assertIn("Set-Cookie:", result)

    def test_jwt_token_preserved(self) -> None:
        raw = "noise\n" * 50 + "Authorization: ******"
        result = sanitize_tool_output("curl", raw, max_chars=100)
        self.assertIn("Authorization:", result)

    def test_401_preserved(self) -> None:
        raw = "noise\n" * 30 + "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Basic"
        result = sanitize_tool_output("curl", raw, max_chars=200)
        self.assertIn("401", result)


class TestNoiseStripping(unittest.TestCase):
    """Repetitive 404/closed lines should be stripped."""

    def test_ffuf_404_flood_reduced(self) -> None:
        lines = ["[Status: 404, Size: 100, Words: 3, Lines: 5]"] * 200
        lines.append("[Status: 200, Size: 4500, Words: 300, Lines: 100] /admin")
        raw = "\n".join(lines)
        result = sanitize_tool_output("ffuf", raw, max_chars=5000)
        count_404 = result.count("Status: 404")
        self.assertLess(count_404, 10, "Repetitive 404 lines should be stripped")
        self.assertIn("200", result)

    def test_nmap_closed_ports_stripped(self) -> None:
        lines = [f"{p}/tcp closed unknown" for p in range(1, 200)]
        lines.append("80/tcp open  http Apache httpd 2.4")
        raw = "\n".join(lines)
        result = sanitize_tool_output("nmap", raw, max_chars=5000)
        self.assertNotIn("closed", result)
        self.assertIn("80/tcp open", result)

    def test_nmap_filtered_ports_stripped(self) -> None:
        raw = "443/tcp filtered https\n22/tcp open  ssh OpenSSH 8.2"
        result = sanitize_tool_output("nmap", raw, max_chars=5000)
        self.assertNotIn("filtered", result)
        self.assertIn("22/tcp open", result)


class TestSmartTruncation(unittest.TestCase):
    """Truncation must respect max_chars and insert the structural banner."""

    def test_output_within_limit_unchanged(self) -> None:
        raw = "A" * 500
        result = sanitize_tool_output("curl", raw, max_chars=1000)
        self.assertEqual(result, raw)

    def test_truncation_honours_max_chars(self) -> None:
        raw = "X" * 10_000
        result = sanitize_tool_output("curl", raw, max_chars=2000)
        self.assertLessEqual(len(result), 2000 + 200)  # banner adds ~150 chars

    def test_truncation_inserts_banner(self) -> None:
        raw = "X" * 10_000
        result = sanitize_tool_output("curl", raw, max_chars=2000)
        self.assertIn("TRUNCATED", result)
        self.assertIn("SECURITY ARTIFACTS PRESERVED", result)

    def test_truncation_preserves_head_and_tail(self) -> None:
        head = "HEAD_MARKER " + "A" * 1000
        tail = "B" * 1000 + " TAIL_MARKER"
        raw = head + "C" * 50_000 + tail
        result = sanitize_tool_output("curl", raw, max_chars=2000)
        self.assertIn("HEAD_MARKER", result)
        self.assertIn("TAIL_MARKER", result)


class TestJsonSummarisation(unittest.TestCase):
    """Large JSON arrays should be summarised."""

    def test_large_json_array_summarised(self) -> None:
        data = [{"id": i, "value": "x" * 100} for i in range(500)]
        raw = json.dumps(data)
        result = sanitize_tool_output("curl", raw, max_chars=500)
        self.assertIn("500 items", result)

    def test_small_json_not_altered(self) -> None:
        data = {"key": "value"}
        raw = json.dumps(data)
        result = sanitize_tool_output("curl", raw, max_chars=5000)
        self.assertIn("key", result)


if __name__ == "__main__":
    unittest.main()
