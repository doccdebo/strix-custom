"""Parse MobSF JSON reports into structured findings and discovered URLs."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


logger = logging.getLogger(__name__)

# Hosts that are CDN / analytics infrastructure and not worth scanning directly
_FILTERED_HOSTS: frozenset[str] = frozenset(
    [
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "googletagmanager.com",
        "firebase.google.com",
        "firebaseapp.com",
        "firebaseio.com",
        "crashlytics.com",
        "amazonaws.com",
        "cloudfront.net",
        "fastly.net",
        "akamaihd.net",
        "facebook.com",
        "twitter.com",
        "instagram.com",
        "apple.com",
        "microsoft.com",
        "azure.com",
        "doubleclick.net",
        "ggpht.com",
        "youtube.com",
        "schema.org",
        "w3.org",
        "example.com",
    ]
)

_WEAK_CRYPTO_PATTERNS: tuple[str, ...] = ("MD5", "SHA1", "DES", "RC2", "ECB")


def _is_filtered_host(url: str) -> bool:
    """Return True when *url* belongs to a well-known CDN / analytics host."""
    try:
        hostname = urlparse(url).hostname or ""
    except ValueError:
        return False
    return any(hostname == h or hostname.endswith("." + h) for h in _FILTERED_HOSTS)


def _looks_like_api_route(url: str) -> bool:
    """Return True when *url* looks like an API endpoint worth scanning."""
    api_path_patterns = (
        "/api/",
        "/v1/",
        "/v2/",
        "/v3/",
        "/graphql",
        "/rest/",
        "/rpc/",
    )
    lower = url.lower()
    parsed = urlparse(lower)
    if any(p in parsed.path for p in api_path_patterns):
        return True
    if parsed.query:
        return True
    hostname = parsed.hostname or ""
    if re.match(r"^api[.\-]", hostname):
        return True
    return False


@dataclass
class MobileFinding:
    category: str
    title: str
    severity: str
    description: str
    file_path: str | None
    evidence: str | None


@dataclass
class ParsedMobileReport:
    app_name: str
    package_name: str
    platform: str
    findings: list[MobileFinding]
    discovered_urls: list[str]
    discovered_api_routes: list[str]


class MobSFReportParser:
    """Ingest a raw MobSF JSON report and extract findings + discovered URLs."""

    def parse(self, report: dict[str, Any]) -> ParsedMobileReport:
        app_name: str = report.get("app_name") or report.get("file_name") or "unknown"
        package_name: str = (
            report.get("package_name") or report.get("bundle_id") or "unknown"
        )
        platform_raw: str = (report.get("platform") or "").lower()
        platform = "ios" if "ios" in platform_raw else "android"

        findings: list[MobileFinding] = []
        findings.extend(self._extract_secrets(report))
        findings.extend(self._extract_insecure_endpoints(report))
        findings.extend(self._extract_weak_crypto(report))
        findings.extend(self._extract_network_security(report))

        discovered_urls = self._collect_urls(report)
        discovered_api_routes = [u for u in discovered_urls if _looks_like_api_route(u)]

        logger.info(
            "Parsed report for %s: %d findings, %d URLs (%d API routes)",
            app_name,
            len(findings),
            len(discovered_urls),
            len(discovered_api_routes),
        )
        return ParsedMobileReport(
            app_name=app_name,
            package_name=package_name,
            platform=platform,
            findings=findings,
            discovered_urls=discovered_urls,
            discovered_api_routes=discovered_api_routes,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _extract_secrets(self, report: dict[str, Any]) -> list[MobileFinding]:
        findings: list[MobileFinding] = []
        secrets_section = report.get("secrets") or []
        for item in secrets_section:
            if not isinstance(item, dict):
                continue
            findings.append(
                MobileFinding(
                    category="hardcoded_secret",
                    title=item.get("title") or "Hardcoded Secret / API Key",
                    severity=_normalise_severity(item.get("severity") or "high"),
                    description=item.get("description") or item.get("issue") or "",
                    file_path=item.get("file_path") or item.get("file"),
                    evidence=item.get("code") or item.get("evidence"),
                )
            )
        return findings

    def _extract_insecure_endpoints(self, report: dict[str, Any]) -> list[MobileFinding]:
        findings: list[MobileFinding] = []
        urls_section: list[Any] = report.get("urls") or []
        for entry in urls_section:
            if not isinstance(entry, dict):
                continue
            url: str = entry.get("url") or ""
            if url.startswith("http://"):
                findings.append(
                    MobileFinding(
                        category="insecure_endpoint",
                        title="Insecure HTTP Endpoint",
                        severity="medium",
                        description=f"Plain-HTTP URL found in binary: {url}",
                        file_path=None,
                        evidence=url,
                    )
                )
        return findings

    def _extract_weak_crypto(self, report: dict[str, Any]) -> list[MobileFinding]:
        findings: list[MobileFinding] = []

        def _check_section(section: Any) -> None:
            entries: list[Any] = []
            if isinstance(section, dict):
                entries = list(section.values())
            elif isinstance(section, list):
                entries = section
            for item in entries:
                if not isinstance(item, dict):
                    continue
                title: str = item.get("title") or item.get("issue") or ""
                desc: str = item.get("description") or item.get("cvss_desc") or ""
                combined = f"{title} {desc}"
                if any(p.upper() in combined.upper() for p in _WEAK_CRYPTO_PATTERNS):
                    findings.append(
                        MobileFinding(
                            category="weak_crypto",
                            title=title or "Weak Cryptography",
                            severity=_normalise_severity(
                                item.get("severity") or item.get("level") or "medium"
                            ),
                            description=desc or combined,
                            file_path=item.get("file_path") or item.get("file"),
                            evidence=item.get("code") or item.get("evidence"),
                        )
                    )

        _check_section(report.get("binary_analysis"))
        _check_section(report.get("code_analysis"))
        return findings

    def _extract_network_security(self, report: dict[str, Any]) -> list[MobileFinding]:
        findings: list[MobileFinding] = []
        for section_key in ("network_security", "manifest_analysis"):
            section = report.get(section_key)
            entries: list[Any] = []
            if isinstance(section, dict):
                entries = list(section.values())
            elif isinstance(section, list):
                entries = section
            for item in entries:
                if not isinstance(item, dict):
                    continue
                severity_raw: str = item.get("severity") or item.get("level") or ""
                if not severity_raw:
                    continue
                findings.append(
                    MobileFinding(
                        category="network_security_config",
                        title=item.get("title") or item.get("issue") or "Network Security Misconfiguration",
                        severity=_normalise_severity(severity_raw),
                        description=item.get("description") or item.get("cvss_desc") or "",
                        file_path=item.get("file_path") or item.get("file"),
                        evidence=item.get("evidence"),
                    )
                )
        return findings

    def _collect_urls(self, report: dict[str, Any]) -> list[str]:
        raw: set[str] = set()

        def _add(val: Any) -> None:
            if isinstance(val, str) and val.startswith(("http://", "https://")):
                raw.add(val.strip())

        for entry in report.get("urls") or []:
            if isinstance(entry, dict):
                _add(entry.get("url"))
            elif isinstance(entry, str):
                _add(entry)

        for entry in report.get("domains") or []:
            if isinstance(entry, dict):
                domain = entry.get("domain") or entry.get("url")
                if domain:
                    if not domain.startswith("http"):
                        domain = f"https://{domain}"
                    _add(domain)
            elif isinstance(entry, str):
                _add(f"https://{entry}" if not entry.startswith("http") else entry)

        for entry in report.get("exported_activities") or []:
            if isinstance(entry, dict):
                _add(entry.get("url"))
            elif isinstance(entry, str):
                _add(entry)

        for url in report.get("firebase_urls") or []:
            _add(url)

        filtered = [u for u in sorted(raw) if not _is_filtered_host(u)]
        return filtered


def _normalise_severity(raw: str) -> str:
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "warning": "medium",
        "low": "low",
        "info": "info",
        "information": "info",
        "note": "info",
        "secure": "info",
    }
    return mapping.get(raw.lower(), "medium")
