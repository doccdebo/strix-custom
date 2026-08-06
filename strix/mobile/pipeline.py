"""Mobile security pipeline: orchestrate MobSF upload → scan → parse → inject."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

from strix.mobile.mobsf_client import MobSFClient, MobSFConnectionError
from strix.mobile.parser import MobSFReportParser


logger = logging.getLogger(__name__)

_POLL_INTERVAL = 10
_MAX_POLLS = 30


async def run_mobile_pipeline(
    binary_path: Path,
    mobsf_url: str,
    mobsf_api_key: str,
    scan_config: dict[str, Any],
) -> dict[str, Any]:
    """
    1. Upload the binary to MobSF and trigger static analysis.
    2. Poll for the report (simple retry loop with sleep).
    3. Parse the report.
    4. Inject discovered_urls + discovered_api_routes into scan_config["targets"]
       as web_application entries (deduplicating against existing targets).
    5. Prepend a MobSF findings summary to scan_config["user_instructions"].
    6. Return the mutated scan_config.
    """
    client = MobSFClient(base_url=mobsf_url, api_key=mobsf_api_key)

    try:
        scan_hash = await asyncio.to_thread(client.upload, binary_path)
        await asyncio.to_thread(client.scan, scan_hash, binary_path.name)
    except MobSFConnectionError as exc:
        existing_targets = scan_config.get("targets") or []
        if not existing_targets:
            raise
        logger.warning("MobSF is offline – continuing with original targets. Reason: %s", exc)
        return scan_config

    report: dict[str, Any] | None = None
    for attempt in range(1, _MAX_POLLS + 1):
        try:
            report = await asyncio.to_thread(client.get_report, scan_hash)
            logger.info("Report ready after %d poll(s)", attempt)
            break
        except Exception as exc:  # noqa: BLE001
            logger.debug("Poll %d/%d failed: %s", attempt, _MAX_POLLS, exc)
            await asyncio.sleep(_POLL_INTERVAL)

    if report is None:
        existing_targets = scan_config.get("targets") or []
        if not existing_targets:
            raise RuntimeError(
                f"MobSF report not available after {_MAX_POLLS} attempts for hash {scan_hash}"
            )
        logger.warning("MobSF report unavailable after polling – continuing with original targets.")
        return scan_config

    parser = MobSFReportParser()
    parsed = parser.parse(report)

    # Inject discovered URLs
    existing_targets: list[dict[str, Any]] = scan_config.get("targets") or []
    existing_urls: set[str] = {
        t.get("details", {}).get("target_url", "") for t in existing_targets
    }

    new_urls = set(parsed.discovered_urls) | set(parsed.discovered_api_routes)
    for url in sorted(new_urls):
        if url and url not in existing_urls:
            existing_targets.append(
                {"type": "web_application", "details": {"target_url": url}, "original": url}
            )
            existing_urls.add(url)
            logger.debug("Injected URL into scan targets: %s", url)

    scan_config["targets"] = existing_targets

    # Prepend MobSF findings summary to user_instructions
    summary_lines = [
        f"## MobSF Static Analysis — {parsed.app_name} ({parsed.platform.upper()})",
        f"Package: {parsed.package_name}",
        f"Findings: {len(parsed.findings)} ({len(parsed.discovered_urls)} URLs discovered)",
        "",
    ]
    for finding in parsed.findings:
        summary_lines.append(
            f"- [{finding.severity.upper()}] {finding.category}: {finding.title}"
        )
    summary = "\n".join(summary_lines)

    existing_instructions: str = scan_config.get("user_instructions") or ""
    scan_config["user_instructions"] = (
        f"{summary}\n\n{existing_instructions}" if existing_instructions else summary
    )

    logger.info(
        "Mobile pipeline complete: injected %d new targets for %s",
        len(new_urls - {t.get("details", {}).get("target_url", "") for t in existing_targets}),
        parsed.app_name,
    )
    return scan_config
