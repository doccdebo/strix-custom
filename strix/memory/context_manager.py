"""Sliding-window context manager for Strix agent turn history.

Keeps token consumption flat by compacting turns older than the active
window into a high-density "Attack History State" summary block.

Architecture
------------
The context window is divided into two logical regions:

1. **Pinned block** — always present at position 0:
   - System prompt & safety directives (never compacted).
   - Initial target goal, scope boundaries, and discovered attack surface.

2. **Sliding active window** — the most recent ``window_size`` turns kept
   verbatim (default: 10).

When the turn count exceeds ``window_size``, older turns are replaced by a
compact bulleted summary produced by :meth:`ContextManager.compact`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Turn:
    """A single agent interaction turn."""

    role: str
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackHistoryState:
    """Compact summary replacing turns 0 … (N - window_size)."""

    explored_endpoints: list[str] = field(default_factory=list)
    tested_payloads: list[str] = field(default_factory=list)
    confirmed_vulnerabilities: list[str] = field(default_factory=list)
    failed_vectors: list[str] = field(default_factory=list)

    def render(self) -> str:
        """Render as a markdown bullet list for injection into the context."""
        lines = ["**[Attack History State — Compacted]**"]
        if self.explored_endpoints:
            lines.append("- Explored Endpoints:")
            lines.extend(f"  - {ep}" for ep in self.explored_endpoints)
        if self.tested_payloads:
            lines.append("- Tested Payloads:")
            lines.extend(f"  - {p}" for p in self.tested_payloads)
        if self.confirmed_vulnerabilities:
            lines.append("- Confirmed Vulnerabilities:")
            lines.extend(f"  - {v}" for v in self.confirmed_vulnerabilities)
        if self.failed_vectors:
            lines.append("- Failed Vectors:")
            lines.extend(f"  - {fv}" for fv in self.failed_vectors)
        return "\n".join(lines)


class ContextManager:
    """Maintain a sliding-window view of the agent's turn history.

    Args:
        window_size: Number of recent turns to keep verbatim.  When the
            history length exceeds this value, older turns are compacted
            into an :class:`AttackHistoryState` summary block.
        pinned_context: Static text pinned to the top of every rendered
            context (system prompt, scope, target goal).  Never compacted.
    """

    def __init__(
        self,
        window_size: int = 10,
        pinned_context: str = "",
    ) -> None:
        self.window_size = window_size
        self.pinned_context = pinned_context
        self._turns: list[Turn] = []
        self._history_state: AttackHistoryState = AttackHistoryState()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_turn(self, role: str, content: str, **metadata: Any) -> None:
        """Append a new turn and trigger compaction if needed."""
        self._turns.append(Turn(role=role, content=content, metadata=metadata))
        if len(self._turns) > self.window_size:
            self._compact_oldest()

    def get_active_turns(self) -> list[Turn]:
        """Return the current sliding-window turns (most recent ``window_size``)."""
        return list(self._turns)

    def get_history_state(self) -> AttackHistoryState:
        """Return the compacted attack history accumulated so far."""
        return self._history_state

    def render_full_context(self) -> str:
        """Render the complete context as a single string.

        Structure::

            <pinned_context>

            <attack_history_state>   (omitted when empty)

            <active turns — newest last>
        """
        parts: list[str] = []
        if self.pinned_context:
            parts.append(self.pinned_context)

        rendered_history = self._history_state.render()
        if rendered_history.strip() != "**[Attack History State — Compacted]**":
            parts.append(rendered_history)

        parts.extend(f"[{turn.role.upper()}]: {turn.content}" for turn in self._turns)

        return "\n\n".join(parts)

    def turn_count(self) -> int:
        """Return total number of active (non-compacted) turns."""
        return len(self._turns)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compact_oldest(self) -> None:
        """Move the oldest turn into the compacted history state."""
        overflow = self._turns.pop(0)
        self._absorb_into_history(overflow)

    def _absorb_into_history(self, turn: Turn) -> None:
        """Parse *turn* content and categorise into the history state."""
        content = turn.content
        lower = content.lower()

        if any(k in lower for k in ("endpoint", "path", "url", "/", "found", "discovered")):
            snippet = content[:120].replace("\n", " ")
            self._history_state.explored_endpoints.append(snippet)
        elif any(k in lower for k in ("payload", "inject", "fuzz", "xss", "sqli", "exploit")):
            snippet = content[:120].replace("\n", " ")
            self._history_state.tested_payloads.append(snippet)
        elif any(k in lower for k in ("vuln", "confirmed", "vulnerable", "cve", "cvss")):
            snippet = content[:120].replace("\n", " ")
            self._history_state.confirmed_vulnerabilities.append(snippet)
        elif any(k in lower for k in ("failed", "no result", "error", "denied", "blocked")):
            snippet = content[:120].replace("\n", " ")
            self._history_state.failed_vectors.append(snippet)
        else:
            # Generic — append to explored endpoints as a catch-all
            snippet = content[:120].replace("\n", " ")
            self._history_state.explored_endpoints.append(snippet)
