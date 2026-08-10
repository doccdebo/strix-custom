"""Local LLM adapter for Ollama / LiteLLM endpoints.

Auto-detects when Strix is pointed at a local model and applies:
- JSON schema enforcement (``response_format={"type": "json_object"}``).
- Deterministic sampling overrides (``temperature``, ``top_p``, ``min_p``).
- System-prompt injection that suppresses conversational filler.

Usage
-----
Call :func:`apply_local_mode_overrides` after loading settings to patch
the LiteLLM module-level defaults and set the required env vars::

    from strix.llm.local_adapter import apply_local_mode_overrides
    from strix.config.loader import load_settings

    settings = load_settings()
    apply_local_mode_overrides(settings)
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from strix.config.settings import Settings


logger = logging.getLogger(__name__)

# Prefixes that unambiguously identify a local inference endpoint.
_LOCAL_MODEL_PREFIXES = frozenset(
    {"ollama/", "local/", "lmstudio/", "vllm/", "llamacpp/"}
)

# Injected at the end of every local system prompt.
_LOCAL_SYSTEM_PROMPT_SUFFIX = (
    "\nOutput valid, raw JSON tool calls strictly. "
    "Never add conversational filler, greetings, or post-execution commentary "
    "before or after JSON payloads."
)

# LiteLLM env var that enforces JSON output mode.
_RESPONSE_FORMAT_ENV = "LITELLM_RESPONSE_FORMAT"

_LOCAL_SAMPLING: dict[str, float] = {
    "temperature": 0.05,
    "top_p": 0.85,
    "min_p": 0.05,
}


def is_local_endpoint(settings: Settings) -> bool:
    """Return ``True`` when the configured model targets a local LLM.

    Detection logic (first match wins):
    1. ``STRIX_ENABLE_LOCAL_MODE=1`` env var / config flag.
    2. Model name starts with a known local prefix (``ollama/``, ``vllm/`` …).
    3. ``api_base`` points to localhost / 127.x / host.docker.internal.
    """
    if getattr(getattr(settings, "budget", None), "enable_local_mode", False):
        return True

    model = (settings.llm.model or "").strip().lower()
    if any(model.startswith(p) for p in _LOCAL_MODEL_PREFIXES):
        return True

    api_base = (settings.llm.api_base or "").lower()
    _local_hosts = ("localhost", "127.0.", "::1", "host.docker.internal", "0.0.0.0")
    return any(host in api_base for host in _local_hosts)


def apply_local_mode_overrides(settings: Settings) -> None:
    """Configure LiteLLM / env vars for local model operation.

    This is a **no-op** when the configured endpoint is not local.  It is
    safe to call unconditionally at startup.

    Applies:
    - ``LITELLM_RESPONSE_FORMAT`` → ``{"type": "json_object"}``
    - LiteLLM module-level ``temperature``, ``top_p``, ``min_p``.
    - Logs the system-prompt suffix that should be appended by callers.

    Args:
        settings: The loaded :class:`~strix.config.settings.Settings` instance.
    """
    if not is_local_endpoint(settings):
        return

    logger.info(
        "local_adapter: local endpoint detected (%s) — applying schema & sampling overrides",
        settings.llm.model or settings.llm.api_base,
    )

    # Enforce JSON output mode via env var
    if _RESPONSE_FORMAT_ENV not in os.environ:
        os.environ[_RESPONSE_FORMAT_ENV] = '{"type": "json_object"}'
        logger.debug("local_adapter: set %s", _RESPONSE_FORMAT_ENV)

    # Apply sampling overrides via LiteLLM module-level defaults
    try:
        import litellm  # type: ignore[import-untyped]  # noqa: PLC0415

        for param, value in _LOCAL_SAMPLING.items():
            current = getattr(litellm, param, None)
            if current is None:
                setattr(litellm, param, value)
                logger.debug("local_adapter: set litellm.%s = %s", param, value)
    except ImportError:
        logger.warning("local_adapter: litellm not installed; skipping sampling overrides")


def get_local_system_prompt_suffix() -> str:
    """Return the suffix to append to system prompts when in local mode.

    Callers should append this to the agent system prompt when
    :func:`is_local_endpoint` returns ``True``::

        if is_local_endpoint(settings):
            system_prompt += get_local_system_prompt_suffix()
    """
    return _LOCAL_SYSTEM_PROMPT_SUFFIX
