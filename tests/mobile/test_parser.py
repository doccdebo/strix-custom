"""Unit tests for MobSFReportParser."""

from __future__ import annotations

import unittest

from strix.mobile.parser import MobSFReportParser, ParsedMobileReport


_MINIMAL_REPORT: dict = {
    "app_name": "TestApp",
    "package_name": "com.example.test",
    "platform": "Android",
}

_FULL_REPORT: dict = {
    "app_name": "MyApp",
    "package_name": "com.myapp",
    "platform": "Android",
    "urls": [
        {"url": "http://api.myapp.com/v1/login"},
        {"url": "https://api.myapp.com/v2/users"},
        {"url": "https://googletagmanager.com/gtm.js"},  # filtered
    ],
    "domains": [
        {"domain": "api.myapp.com"},
        {"domain": "googleapis.com"},  # filtered
    ],
    "firebase_urls": ["https://myapp.firebaseio.com/data.json"],
    "secrets": [
        {
            "title": "AWS Access Key",
            "severity": "high",
            "description": "Hardcoded AWS key detected",
            "file_path": "com/myapp/Config.java",
            "code": "AKIAIOSFODNN7EXAMPLE",
        }
    ],
    "binary_analysis": [
        {
            "title": "MD5 usage",
            "severity": "medium",
            "description": "MD5 hash algorithm is weak",
        }
    ],
}


class TestParserUrlExtraction(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = MobSFReportParser()

    def test_extracts_urls(self) -> None:
        result = self.parser.parse(_FULL_REPORT)
        self.assertIn("http://api.myapp.com/v1/login", result.discovered_urls)
        self.assertIn("https://api.myapp.com/v2/users", result.discovered_urls)

    def test_filters_cdn_hosts(self) -> None:
        result = self.parser.parse(_FULL_REPORT)
        for url in result.discovered_urls:
            self.assertNotIn("googletagmanager.com", url)
            self.assertNotIn("googleapis.com", url)
            self.assertNotIn("firebaseio.com", url)

    def test_domains_added_as_https(self) -> None:
        result = self.parser.parse(_FULL_REPORT)
        self.assertIn("https://api.myapp.com", result.discovered_urls)

    def test_no_duplicate_urls(self) -> None:
        result = self.parser.parse(_FULL_REPORT)
        self.assertEqual(len(result.discovered_urls), len(set(result.discovered_urls)))


class TestParserApiRoutes(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = MobSFReportParser()

    def test_api_routes_contain_path_patterns(self) -> None:
        result = self.parser.parse(_FULL_REPORT)
        # /v1/ and /v2/ qualify as API routes
        api_route_urls = result.discovered_api_routes
        self.assertTrue(
            any("/v1/" in u or "/v2/" in u for u in api_route_urls),
            f"No API routes found in {api_route_urls}",
        )

    def test_non_api_urls_excluded(self) -> None:
        report = {
            "app_name": "A",
            "package_name": "p",
            "platform": "android",
            "urls": [{"url": "https://myapp.com/home"}],
        }
        result = self.parser.parse(report)
        self.assertEqual(result.discovered_api_routes, [])


class TestParserFindings(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = MobSFReportParser()

    def test_secret_finding_extracted(self) -> None:
        result = self.parser.parse(_FULL_REPORT)
        secret_findings = [f for f in result.findings if f.category == "hardcoded_secret"]
        self.assertEqual(len(secret_findings), 1)
        self.assertEqual(secret_findings[0].severity, "high")

    def test_weak_crypto_finding_extracted(self) -> None:
        result = self.parser.parse(_FULL_REPORT)
        crypto_findings = [f for f in result.findings if f.category == "weak_crypto"]
        self.assertTrue(len(crypto_findings) >= 1)

    def test_severity_mapping(self) -> None:
        report = {
            "app_name": "A",
            "package_name": "p",
            "platform": "android",
            "secrets": [{"title": "Key", "severity": "WARNING", "description": "x"}],
        }
        result = self.parser.parse(report)
        self.assertEqual(result.findings[0].severity, "medium")


class TestParserMinimalReport(unittest.TestCase):
    def test_minimal_report_does_not_crash(self) -> None:
        parser = MobSFReportParser()
        result = parser.parse(_MINIMAL_REPORT)
        self.assertIsInstance(result, ParsedMobileReport)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.discovered_urls, [])
        self.assertEqual(result.discovered_api_routes, [])

    def test_empty_report_does_not_crash(self) -> None:
        parser = MobSFReportParser()
        result = parser.parse({})
        self.assertIsInstance(result, ParsedMobileReport)


if __name__ == "__main__":
    unittest.main()
