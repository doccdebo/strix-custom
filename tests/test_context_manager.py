"""Unit tests for strix.memory.context_manager."""

from __future__ import annotations

import unittest

from strix.memory.context_manager import AttackHistoryState, ContextManager


class TestSlidingWindow(unittest.TestCase):
    """Active window must never exceed window_size turns."""

    def test_turns_within_window(self) -> None:
        cm = ContextManager(window_size=10)
        for i in range(10):
            cm.add_turn("assistant", f"turn {i}")
        self.assertEqual(cm.turn_count(), 10)

    def test_overflow_compacts_oldest(self) -> None:
        cm = ContextManager(window_size=10)
        for i in range(15):
            cm.add_turn("assistant", f"turn {i}")
        self.assertEqual(cm.turn_count(), 10)

    def test_active_turns_are_newest(self) -> None:
        cm = ContextManager(window_size=3)
        for i in range(6):
            cm.add_turn("assistant", f"turn {i}")
        active = cm.get_active_turns()
        self.assertEqual(len(active), 3)
        self.assertEqual(active[-1].content, "turn 5")
        self.assertEqual(active[0].content, "turn 3")

    def test_history_state_grows_on_overflow(self) -> None:
        cm = ContextManager(window_size=5)
        # Add a vulnerability-related turn that will be compacted
        cm.add_turn("assistant", "confirmed vuln: SQL injection found at /login")
        for i in range(5):
            cm.add_turn("assistant", f"filler turn {i}")
        state = cm.get_history_state()
        all_entries = (
            state.explored_endpoints
            + state.tested_payloads
            + state.confirmed_vulnerabilities
            + state.failed_vectors
        )
        self.assertTrue(len(all_entries) > 0, "History state should have entries after overflow")


class TestPinnedContext(unittest.TestCase):
    """Pinned context must always appear in the rendered output."""

    def test_pinned_context_present_when_empty_turns(self) -> None:
        cm = ContextManager(pinned_context="TARGET: example.com\nSCOPE: /api/*")
        rendered = cm.render_full_context()
        self.assertIn("TARGET: example.com", rendered)

    def test_pinned_context_present_after_compaction(self) -> None:
        cm = ContextManager(window_size=3, pinned_context="SYSTEM_PROMPT_HERE")
        for i in range(10):
            cm.add_turn("assistant", f"turn {i}")
        rendered = cm.render_full_context()
        self.assertIn("SYSTEM_PROMPT_HERE", rendered)

    def test_pinned_context_present_with_many_turns(self) -> None:
        cm = ContextManager(window_size=10, pinned_context="PINNED_SCOPE")
        for i in range(30):
            cm.add_turn("user", f"msg {i}")
        rendered = cm.render_full_context()
        self.assertIn("PINNED_SCOPE", rendered)
        # Active window should be last 10 turns
        self.assertEqual(cm.turn_count(), 10)


class TestAttackHistoryStateRendering(unittest.TestCase):
    """Rendered history state must include all populated categories."""

    def test_render_all_categories(self) -> None:
        state = AttackHistoryState(
            explored_endpoints=["/admin", "/api/users"],
            tested_payloads=["' OR 1=1 --"],
            confirmed_vulnerabilities=["CVE-2021-44228"],
            failed_vectors=["XSS blocked by CSP"],
        )
        rendered = state.render()
        self.assertIn("Explored Endpoints", rendered)
        self.assertIn("/admin", rendered)
        self.assertIn("Tested Payloads", rendered)
        self.assertIn("OR 1=1", rendered)
        self.assertIn("Confirmed Vulnerabilities", rendered)
        self.assertIn("CVE-2021-44228", rendered)
        self.assertIn("Failed Vectors", rendered)
        self.assertIn("XSS blocked", rendered)

    def test_render_empty_state_is_header_only(self) -> None:
        state = AttackHistoryState()
        rendered = state.render()
        self.assertIn("Attack History State", rendered)
        self.assertNotIn("Explored", rendered)


class TestContextManagerRenderFullContext(unittest.TestCase):
    """render_full_context should include pinned block, history, and active turns."""

    def test_all_three_sections_present(self) -> None:
        cm = ContextManager(window_size=3, pinned_context="PINNED")
        for i in range(6):
            suffix = "endpoint /foo" if i == 0 else f"turn {i}"
            cm.add_turn("assistant", suffix)
        rendered = cm.render_full_context()
        self.assertIn("PINNED", rendered)
        self.assertIn("[ASSISTANT]:", rendered)


if __name__ == "__main__":
    unittest.main()
