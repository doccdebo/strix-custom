"""SDK model configuration helpers."""

from __future__ import annotations

import logging
import os
from ipaddress import ip_address
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from agents import set_default_openai_api, set_default_openai_key
from agents.retry import (
    ModelRetryBackoffSettings,
    ModelRetrySettings,
    retry_policies,
)


if TYPE_CHECKING:
    from strix.config.settings import Settings


_SDK_PREFIXES = {"any-llm", "litellm", "openai"}
_PUBLIC_MODEL_PREFIXES = {
    "anthropic/",
    "azure/",
    "bedrock/",
    "deepseek/",
    "gemini/",
    "groq/",
    "mistral/",
    "novita/",
    "openai/",
    "openrouter/",
    "vertex",
    "vertex_ai/",
    "xai/",
}
logger = logging.getLogger(__name__)


DEFAULT_MODEL_RETRY = ModelRetrySettings(
    max_retries=5,
    backoff=ModelRetryBackoffSettings(
        initial_delay=2.0,
        max_delay=90.0,
        multiplier=2.0,
        jitter=False,
    ),
    policy=retry_policies.any(
        retry_policies.provider_suggested(),
        retry_policies.network_error(),
        retry_policies.http_status((429, 500, 502, 503, 504)),
    ),
)


def configure_sdk_model_defaults(settings: Settings) -> None:
    """Apply Strix config to SDK-native defaults.

    OpenAI-compatible base URLs are handled by the SDK OpenAI provider.
    Non-OpenAI providers should use the SDK's native ``litellm/`` or
    ``any-llm/`` routing, produced by :func:`normalize_model_name`.
    """
    llm = settings.llm
    _enforce_private_llm_defaults(settings)
    _configure_litellm_compatibility()
    api_base = (llm.api_base or "").strip()
    if llm.api_key:
        set_default_openai_key(llm.api_key, use_for_tracing=False)
        _configure_litellm_default("api_key", llm.api_key)
    if api_base:
        os.environ["OPENAI_BASE_URL"] = api_base
        _configure_litellm_default("api_base", api_base)
        logger.info("Configured custom OpenAI-compatible api_base: %s", api_base)
        set_default_openai_api("chat_completions")
    else:
        set_default_openai_api("responses")


def _enforce_private_llm_defaults(settings: Settings) -> None:
    llm = settings.llm
    if not settings.security.private_mode:
        return

    resolved_model = normalize_model_name(llm.model or "")
    public_api_base = _is_public_api_base(llm.api_base)
    public_model_route = _is_public_model_route(resolved_model)
    external_usage = public_api_base if llm.api_base else public_model_route

    if external_usage and not llm.allow_public_endpoints:
        raise RuntimeError(
            "Strix private mode blocked external/public LLM usage. "
            "Set STRIX_ALLOW_PUBLIC_LLM=1 only if you deliberately permit egress to this provider.",
        )
    if external_usage and llm.allow_public_endpoints:
        logger.warning(
            "Public/external LLM endpoint explicitly enabled via STRIX_ALLOW_PUBLIC_LLM=1; "
            "prompts and scan metadata may leave your environment",
        )


def _is_public_api_base(api_base: str | None) -> bool:
    if not api_base:
        return False
    parsed = urlparse(api_base)
    host = (parsed.hostname or "").strip().lower()
    if not host:
        return False
    if host in {"localhost", "host.docker.internal"}:
        return False
    if host.endswith((".local", ".internal", ".corp", ".lan")):
        return False
    try:
        ip = ip_address(host)
    except ValueError:
        return True
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified
    )


def _is_public_model_route(model_name: str) -> bool:
    model = model_name.strip().lower()
    if not model:
        return False
    if model.startswith(("local/", "ollama/", "lmstudio/", "vllm/", "any-llm/")):
        return False
    return model.startswith(tuple(_PUBLIC_MODEL_PREFIXES))


def _configure_litellm_compatibility() -> None:
    """Enable LiteLLM's permissive param-handling mode."""
    import litellm

    litellm.drop_params = True
    litellm.modify_params = True


def _configure_litellm_default(name: str, value: str) -> None:
    """Set LiteLLM's module-level defaults without adding a provider wrapper."""
    import litellm

    setattr(litellm, name, value)


def normalize_model_name(model_name: str) -> str:
    """Normalize friendly Strix model names to SDK-native model ids."""
    model = model_name.strip()
    if not model:
        return model

    if "/" in model:
        prefix = model.split("/", 1)[0].lower()
        if prefix in _SDK_PREFIXES:
            return model
        return f"litellm/{model}"

    lower = model.lower()
    if lower.startswith("claude"):
        return f"litellm/anthropic/{model}"
    if lower.startswith("gemini"):
        return f"litellm/gemini/{model}"

    return model


def uses_chat_completions_tool_schema(model_name: str, settings: Settings) -> bool:
    """Return whether the resolved SDK route can only receive JSON function tools."""
    model = model_name.strip().lower()
    if model.startswith(("litellm/", "any-llm/")):
        return True
    return bool(settings.llm.api_base)
