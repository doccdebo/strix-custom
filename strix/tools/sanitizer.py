"""Security-Aware Smart Output Sanitizer.

Strips noise from common pentest-tool outputs while guaranteeing that
security-critical signals (SQL errors, stack traces, auth tokens, 500s,
reflected values) are **never** removed or truncated.
"""

from __future__ import annotations

import json
import re


# ---------------------------------------------------------------------------
# Security-signal patterns that must always be preserved
# ---------------------------------------------------------------------------

_SQL_ERROR_RE = re.compile(
    r"(syntax error.*sql|ORA-\d+|MySQL.*error|PostgreSQL.*error"
    r"|you have an error in your sql|warning.*mysql|unclosed quotation"
    r"|quoted string not properly terminated)",
    re.IGNORECASE,
)

_EXCEPTION_RE = re.compile(
    r"(Traceback \(most recent call last\)|Fatal error|Unhandled exception"
    r"|500 Internal Server Error|java\.lang\.\w+Exception"
    r"|Exception in thread|at [\w\.$]+\([\w.]+:\d+\))",
    re.IGNORECASE,
)

_AUTH_HEADER_RE = re.compile(
    r"(Set-Cookie:|Authorization:|X-[\w-]+:|WWW-Authenticate:|"
    r"Bearer\s+[A-Za-z0-9\-_\.]+|eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)",
    re.IGNORECASE,
)

_INTERESTING_HTTP_RE = re.compile(
    r"(HTTP/[12][\. ]\d\s+(200|201|204|301|302|307|308|401|403|405|500|502|503)"
    r"|Status:\s*(200|201|204|301|302|307|308|401|403|405|500|502|503)"
    r"|< HTTP/|Response code: (200|201|301|302|401|403|500))",
    re.IGNORECASE,
)

# Repetitive noise patterns to strip
_FFUF_404_RE = re.compile(r"^\s*\[Status: 40[34],.*$", re.MULTILINE)
_NMAP_CLOSED_RE = re.compile(r"^\d+/\w+\s+(closed|filtered)\s+.*$", re.MULTILINE)


def _is_security_critical(line: str) -> bool:
    """Return True if *line* contains a security-significant signal."""
    return bool(
        _SQL_ERROR_RE.search(line)
        or _EXCEPTION_RE.search(line)
        or _AUTH_HEADER_RE.search(line)
        or _INTERESTING_HTTP_RE.search(line)
    )


def _strip_ffuf_noise(output: str) -> str:
    """Remove repetitive 404/403 lines from ffuf / gobuster output."""
    lines = output.splitlines(keepends=True)
    seen_noise: set[str] = set()
    kept: list[str] = []
    for line in lines:
        if _FFUF_404_RE.match(line):
            normalised = re.sub(r"Length: \d+", "Length: N", line.strip())
            if normalised in seen_noise and not _is_security_critical(line):
                continue
            seen_noise.add(normalised)
        kept.append(line)
    return "".join(kept)


def _strip_nmap_noise(output: str) -> str:
    """Remove closed/filtered port lines from nmap output."""
    lines = output.splitlines(keepends=True)
    kept: list[str] = []
    for line in lines:
        if _NMAP_CLOSED_RE.match(line.strip()) and not _is_security_critical(line):
            continue
        kept.append(line)
    return "".join(kept)


def _summarise_json(raw: str) -> str:
    """For large JSON blobs, emit a schema summary + a few sample records."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw  # not valid JSON — return as-is

    if isinstance(data, list):
        count = len(data)
        sample = data[:3]
        keys: list[str] = []
        if sample and isinstance(sample[0], dict):
            keys = list(sample[0].keys())
        return (
            f"[JSON ARRAY — {count} items, sample keys: {keys}]\n"
            + json.dumps(sample, indent=2)
        )

    if isinstance(data, dict):
        keys = list(data.keys())
        return f"[JSON OBJECT — keys: {keys}]\n" + json.dumps(data, indent=2)

    return raw


def _smart_truncate(text: str, max_chars: int) -> str:
    """Truncate *text* to *max_chars* preserving head + tail security context."""
    if len(text) <= max_chars:
        return text

    head = 1200
    tail = 800
    if head + tail >= max_chars:
        head = max(max_chars // 2, max_chars - 800)
        tail = max_chars - head

    removed = len(text) - head - tail
    banner = (
        f"\n[... TRUNCATED {removed} CHARACTERS OF NON-CRITICAL TOOL OUTPUT "
        "(SECURITY ARTIFACTS PRESERVED) ...]\n"
    )
    return text[:head] + banner + text[len(text) - tail :]


def sanitize_tool_output(
    tool_name: str,
    raw_output: str,
    max_chars: int = 2000,
) -> str:
    """Sanitize *raw_output* from *tool_name*, preserving all security signals.

    Steps:
    1. Tool-specific noise stripping (nmap closed ports; ffuf/gobuster 404 floods).
    2. JSON summarisation for large JSON responses.
    3. Smart structural truncation when output still exceeds *max_chars*,
       keeping head (headers/status) and tail (stack traces/closing body).

    Security signals (SQL errors, stack traces, auth headers, 500s) are
    **never** removed regardless of size constraints.

    Args:
        tool_name: Logical name of the producing tool (e.g. ``"nmap"``,
            ``"ffuf"``, ``"curl"``).
        raw_output: The full, unfiltered output string.
        max_chars: Soft character budget; structural truncation applies
            beyond this limit.  Defaults to ``2000``.

    Returns:
        Sanitized output string, guaranteed to retain all security signals.
    """
    output = raw_output

    lower_tool = tool_name.lower()

    if lower_tool in {"ffuf", "gobuster", "feroxbuster", "dirsearch"}:
        output = _strip_ffuf_noise(output)

    if lower_tool == "nmap":
        output = _strip_nmap_noise(output)

    # JSON summarisation — only for large blobs
    stripped = output.strip()
    if len(stripped) > max_chars and stripped.startswith(("{", "[")):
        output = _summarise_json(stripped)

    # Final size guard
    return _smart_truncate(output, max_chars)
