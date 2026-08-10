"""Performance-Preserving Escalation Engine.

Detects when the local model is struggling and routes a high-density,
isolated single-turn prompt to a cloud LLM (e.g. Claude Sonnet via
Copilot Bridge) rather than re-sending the full conversation history.

Usage
-----
Typical integration inside an agent tool-execution loop::

    escalator = Escalator(endpoint=settings.escalation.endpoint)

    result = await run_local_tool(tool_call)
    if result.is_failure:
        escalator.record_failure()
    else:
        escalator.reset_failures()

    if escalator.should_escalate(task_description):
        payload = await escalator.escalate(
            hypothesis="Possible SQL injection at /login",
            context_snippet=last_http_response,
            request="Generate a standalone Python exploit script.",
        )
        # Inject payload back as a successful tool result and continue locally.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)


_COMPLEX_TASK_RE = re.compile(
    r"(jwt|json web token|jku|kid|alg none|rsa|hmac|ec key"
    r"|js reverse|deobfuscat|business logic|multi.?stage|csrf chain"
    r"|oauth|saml|xmldsig|x509|pkcs|asymmetric)",
    re.IGNORECASE,
)

_FAILURE_THRESHOLD = 3


class EscalationResult:
    """Result returned by :meth:`Escalator.escalate`."""

    def __init__(self, success: bool, payload: str, model_used: str) -> None:
        self.success = success
        self.payload = payload
        self.model_used = model_used

    def __repr__(self) -> str:
        status = "ok" if self.success else "failed"
        return f"EscalationResult({status}, model={self.model_used!r}, len={len(self.payload)})"


class Escalator:
    """Dynamic fallback mechanism to escalate complex tasks to a cloud LLM.

    Args:
        endpoint: URL of the escalation endpoint (e.g. Copilot Bridge).
            When ``None`` escalation is disabled and :meth:`escalate` raises
            :exc:`RuntimeError`.
        failure_threshold: Number of consecutive local failures before
            automatic escalation is triggered.
    """

    def __init__(
        self,
        endpoint: str | None = None,
        failure_threshold: int = _FAILURE_THRESHOLD,
    ) -> None:
        self.endpoint = endpoint
        self.failure_threshold = failure_threshold
        self._consecutive_failures: int = 0

    # ------------------------------------------------------------------
    # Failure tracking
    # ------------------------------------------------------------------

    def record_failure(self) -> None:
        """Increment the consecutive-failure counter."""
        self._consecutive_failures += 1
        logger.debug(
            "escalator: consecutive failures = %d / %d",
            self._consecutive_failures,
            self.failure_threshold,
        )

    def reset_failures(self) -> None:
        """Reset the consecutive-failure counter after a successful step."""
        self._consecutive_failures = 0

    # ------------------------------------------------------------------
    # Escalation decision
    # ------------------------------------------------------------------

    def should_escalate(self, task_description: str = "") -> bool:
        """Return ``True`` when escalation to the cloud model is warranted.

        Triggers:
        - Consecutive local failures ≥ ``failure_threshold``.
        - Task description matches the complex-task classifier pattern.
        """
        if self._consecutive_failures >= self.failure_threshold:
            logger.info(
                "escalator: triggering escalation due to %d consecutive failures",
                self._consecutive_failures,
            )
            return True
        if task_description and _COMPLEX_TASK_RE.search(task_description):
            logger.info(
                "escalator: triggering escalation due to complex task pattern: %s",
                task_description[:80],
            )
            return True
        return False

    # ------------------------------------------------------------------
    # Escalation execution
    # ------------------------------------------------------------------

    async def escalate(
        self,
        hypothesis: str,
        context_snippet: str,
        request: str,
        extra_headers: dict[str, str] | None = None,
    ) -> EscalationResult:
        """Send a **high-density isolated single-turn prompt** to the cloud model.

        The prompt contains only:
        - The vulnerability hypothesis / target endpoint.
        - Relevant HTTP response / error trace snippet.
        - A specific, bounded request (e.g. "generate a Python exploit script").

        The full conversation history is intentionally **not** sent.

        Args:
            hypothesis: Short description of the vulnerability being tested
                (e.g. ``"SQL injection at POST /login via 'username' parameter"``).
            context_snippet: The minimal relevant context — HTTP response body,
                error trace, or request/response pair.  Keep concise.
            request: Exact ask for the cloud model (e.g. ``"Generate a
                standalone Python script to exploit this."``).
            extra_headers: Optional additional HTTP headers for the request.

        Returns:
            :class:`EscalationResult` with ``success``, ``payload``, and
            ``model_used`` attributes.

        Raises:
            RuntimeError: If no escalation endpoint is configured.
        """
        if not self.endpoint:
            raise RuntimeError(
                "Escalation requested but STRIX_ESCALATION_ENDPOINT is not configured."
            )

        prompt = _build_escalation_prompt(hypothesis, context_snippet, request)

        logger.info(
            "escalator: sending isolated %d-char prompt to %s",
            len(prompt),
            self.endpoint,
        )

        return await _post_escalation(
            endpoint=self.endpoint,
            prompt=prompt,
            extra_headers=extra_headers,
            on_success=self.reset_failures,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_escalation_prompt(
    hypothesis: str,
    context_snippet: str,
    request: str,
) -> str:
    return (
        "You are a senior penetration tester.\n\n"
        f"**Vulnerability Hypothesis:**\n{hypothesis}\n\n"
        f"**Relevant Context (HTTP response / error trace):**\n```\n{context_snippet}\n```\n\n"
        f"**Task:**\n{request}\n\n"
        "Respond with only the requested output — no commentary, no preamble."
    )


def _extract_content(body: dict[str, object]) -> str:
    """Extract the text payload from an OpenAI-compatible chat response."""
    try:
        choices = body.get("choices") or []
        if choices and isinstance(choices, list):
            message = choices[0].get("message") or {}
            return str(message.get("content", ""))
    except (AttributeError, IndexError, KeyError):
        pass
    return str(body)


async def _post_escalation(
    *,
    endpoint: str,
    prompt: str,
    extra_headers: dict[str, str] | None,
    on_success: Callable[[], Any],
) -> EscalationResult:
    """Send the escalation prompt to *endpoint* and return an :class:`EscalationResult`.

    Uses :mod:`urllib` (stdlib) for the HTTP POST so that ``httpx`` is not a
    required dependency.  The ``on_success`` callable is invoked on HTTP 2xx.
    """
    import json  # noqa: PLC0415
    import urllib.error  # noqa: PLC0415
    import urllib.request  # noqa: PLC0415

    body_bytes = json.dumps({"messages": [{"role": "user", "content": prompt}]}).encode()
    req = urllib.request.Request(  # noqa: S310
        endpoint,
        data=body_bytes,
        headers={"Content-Type": "application/json", **(extra_headers or {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310
            body = json.loads(resp.read())
            content = _extract_content(body)
            on_success()
            return EscalationResult(
                success=True,
                payload=content,
                model_used=str(body.get("model", "cloud")),
            )
    except urllib.error.URLError:
        logger.exception("escalator: HTTP request failed")
        return EscalationResult(success=False, payload="HTTP request failed", model_used="cloud")
