from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from strix.core.hooks import ReportUsageHooks


class TestReportUsageHooks(unittest.IsolatedAsyncioTestCase):
    async def test_missing_usage_is_reported_without_crashing(self) -> None:
        hooks = ReportUsageHooks(model="openai/gpt-4")
        fake_report_state = SimpleNamespace(record_sdk_usage=lambda **_: None)
        context = SimpleNamespace(context={"agent_id": "agent-1"})
        agent = SimpleNamespace(name="agent-name")
        response = SimpleNamespace(usage=None)

        with patch("strix.core.hooks.get_global_report_state", return_value=fake_report_state):
            with patch("strix.core.hooks.logger.warning") as warning_mock:
                await hooks.on_llm_end(context, agent, response)

        warning_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
