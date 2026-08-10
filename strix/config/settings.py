"""Strix application settings — pydantic-settings powered."""

from __future__ import annotations

from typing import Literal

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


ReasoningEffort = Literal["none", "minimal", "low", "medium", "high", "xhigh"]

_BASE_CONFIG = SettingsConfigDict(
    case_sensitive=False,
    populate_by_name=True,
    extra="ignore",
)


class LlmSettings(BaseSettings):
    model_config = _BASE_CONFIG

    model: str | None = Field(default=None, alias="STRIX_LLM")
    api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("LLM_API_KEY", "OPENAI_API_KEY"),
    )
    api_base: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "LLM_API_BASE",
            "OPENAI_API_BASE",
            "OPENAI_BASE_URL",
            "LITELLM_BASE_URL",
            "OLLAMA_API_BASE",
        ),
    )
    reasoning_effort: ReasoningEffort = Field(default="high", alias="STRIX_REASONING_EFFORT")
    timeout: int = Field(default=300, alias="LLM_TIMEOUT")
    allow_public_endpoints: bool = Field(default=False, alias="STRIX_ALLOW_PUBLIC_LLM")


class RuntimeSettings(BaseSettings):
    model_config = _BASE_CONFIG

    image: str = Field(
        default="ghcr.io/usestrix/strix-sandbox:1.0.0",
        alias="STRIX_IMAGE",
    )
    backend: str = Field(default="docker", alias="STRIX_RUNTIME_BACKEND")


class TelemetrySettings(BaseSettings):
    model_config = _BASE_CONFIG

    enabled: bool = Field(default=False, alias="STRIX_TELEMETRY")


class MobSFSettings(BaseSettings):
    model_config = _BASE_CONFIG

    url: str = Field(default="http://localhost:8000", alias="MOBSF_URL")
    api_key: str = Field(default="", alias="MOBSF_API_KEY")
    timeout: int = Field(default=120, alias="MOBSF_TIMEOUT")


class IntegrationSettings(BaseSettings):
    model_config = _BASE_CONFIG

    perplexity_api_key: str | None = Field(default=None, alias="PERPLEXITY_API_KEY")
    enable_external_web_search: bool = Field(
        default=False,
        alias="STRIX_ENABLE_EXTERNAL_WEB_SEARCH",
    )


class SecuritySettings(BaseSettings):
    model_config = _BASE_CONFIG

    private_mode: bool = Field(default=True, alias="STRIX_PRIVATE_MODE")


class BudgetSettings(BaseSettings):
    """Cost-reduction and local-execution controls."""

    model_config = _BASE_CONFIG

    max_workers: int = Field(default=1, alias="STRIX_MAX_WORKERS")
    enable_local_mode: bool = Field(default=False, alias="STRIX_ENABLE_LOCAL_MODE")
    smart_truncate: bool = Field(default=True, alias="STRIX_SMART_TRUNCATE")
    escalation_endpoint: str | None = Field(default=None, alias="STRIX_ESCALATION_ENDPOINT")


class Settings(BaseSettings):
    model_config = _BASE_CONFIG

    llm: LlmSettings = Field(default_factory=LlmSettings)
    runtime: RuntimeSettings = Field(default_factory=RuntimeSettings)
    telemetry: TelemetrySettings = Field(default_factory=TelemetrySettings)
    integrations: IntegrationSettings = Field(default_factory=IntegrationSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    mobsf: MobSFSettings = Field(default_factory=MobSFSettings)
    budget: BudgetSettings = Field(default_factory=BudgetSettings)
