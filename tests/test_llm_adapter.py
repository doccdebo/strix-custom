"""Unit tests for LLM endpoint configuration and local-mode detection."""

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from strix.config.models import configure_sdk_model_defaults
from strix.config.settings import BudgetSettings, LlmSettings, SecuritySettings, Settings
from strix.llm.local_adapter import is_local_endpoint


def make_settings(
    *,
    model: str | None = None,
    api_key: str | None = None,
    api_base: str | None = None,
    enable_local_mode: bool = False,
    private_mode: bool = False,
) -> Settings:
    return Settings(
        llm=LlmSettings(model=model, api_key=api_key, api_base=api_base),
        budget=BudgetSettings(enable_local_mode=enable_local_mode),
        security=SecuritySettings(private_mode=private_mode),
    )


class TestLocalEndpointDetection(unittest.TestCase):
    def test_custom_cloud_api_base_is_not_treated_as_local(self) -> None:
        settings = make_settings(
            model="openai/gpt-4",
            api_base="https://gateway.internal.corp/openai",
        )
        self.assertFalse(is_local_endpoint(settings))

    def test_azure_api_base_is_not_treated_as_local(self) -> None:
        settings = make_settings(
            model="azure/gpt-4",
            api_base="https://example.openai.azure.com",
        )
        self.assertFalse(is_local_endpoint(settings))

    def test_local_model_prefix_is_treated_as_local(self) -> None:
        settings = make_settings(
            model="ollama/llama3",
            api_base="https://gateway.internal.corp/openai",
        )
        self.assertTrue(is_local_endpoint(settings))

    def test_explicit_local_mode_flag_overrides_model_route(self) -> None:
        settings = make_settings(
            model="openai/gpt-4",
            api_base="https://api.openai.com/v1",
            enable_local_mode=True,
        )
        self.assertTrue(is_local_endpoint(settings))


class TestSdkModelDefaults(unittest.TestCase):
    def test_settings_read_llm_api_base_from_environment(self) -> None:
        with patch.dict(
            os.environ,
            {"LLM_API_BASE": "https://gateway.internal.corp/openai"},
            clear=True,
        ):
            settings = Settings()
        self.assertEqual(settings.llm.api_base, "https://gateway.internal.corp/openai")

    @patch("strix.config.models._configure_litellm_compatibility")
    @patch("strix.config.models._configure_litellm_default")
    @patch("strix.config.models.set_default_openai_api")
    @patch("strix.config.models.set_default_openai_key")
    def test_custom_api_base_is_forwarded_to_sdk(
        self,
        mock_set_default_openai_key,
        mock_set_default_openai_api,
        mock_configure_litellm_default,
        mock_configure_litellm_compatibility,
    ) -> None:
        del mock_configure_litellm_compatibility
        settings = make_settings(
            model="openai/gpt-4",
            api_key="sk-test",
            api_base=" https://gateway.internal.corp/openai ",
        )

        with patch.dict(os.environ, {}, clear=True):
            configure_sdk_model_defaults(settings)
            self.assertEqual(
                os.environ["OPENAI_BASE_URL"],
                "https://gateway.internal.corp/openai",
            )

        mock_set_default_openai_key.assert_called_once_with("sk-test", use_for_tracing=False)
        mock_configure_litellm_default.assert_any_call("api_key", "sk-test")
        mock_configure_litellm_default.assert_any_call(
            "api_base",
            "https://gateway.internal.corp/openai",
        )
        mock_set_default_openai_api.assert_called_once_with("chat_completions")


if __name__ == "__main__":
    unittest.main()
