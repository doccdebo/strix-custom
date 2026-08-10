#!/usr/bin/env bash
# run_strix_budget.sh — Launch Strix in local budget mode with Ollama.
#
# Prerequisites:
#   - Ollama running on localhost:11434 with qwen2.5-coder:14b pulled.
#   - strix installed in the current Python environment (`pip install -e .`).
#
# Usage:
#   chmod +x scripts/run_strix_budget.sh
#   ./scripts/run_strix_budget.sh --target http://localhost:8080 [strix-args...]

set -euo pipefail

# ---------------------------------------------------------------------------
# Local Ollama bindings
# ---------------------------------------------------------------------------
export STRIX_LLM="ollama/qwen2.5-coder:14b"
export OLLAMA_API_BASE="${OLLAMA_API_BASE:-http://localhost:11434}"
export LLM_API_BASE="$OLLAMA_API_BASE"

# ---------------------------------------------------------------------------
# Memory & cost optimisation flags
# ---------------------------------------------------------------------------
export STRIX_MAX_WORKERS=1            # Sequential sub-agents — no RAM duplication
export STRIX_ENABLE_LOCAL_MODE=true   # Schema enforcement + sampling overrides
export STRIX_SMART_TRUNCATE=true      # Strip tool output noise before context injection

# ---------------------------------------------------------------------------
# Optional: cloud escalation endpoint (Copilot Bridge / Sonnet)
# Set to your bridge URL to enable automatic fallback for complex tasks.
# ---------------------------------------------------------------------------
# export STRIX_ESCALATION_ENDPOINT="http://localhost:9090/v1/chat/completions"

# ---------------------------------------------------------------------------
# Private mode — never send data to external providers
# ---------------------------------------------------------------------------
export STRIX_PRIVATE_MODE=true

# ---------------------------------------------------------------------------
# Telemetry off by default in budget mode
# ---------------------------------------------------------------------------
export STRIX_TELEMETRY=false

echo "[strix-budget] Starting Strix with local Ollama (${STRIX_LLM})"
echo "[strix-budget] Max workers: ${STRIX_MAX_WORKERS} | Smart truncate: ${STRIX_SMART_TRUNCATE}"
echo "[strix-budget] Escalation endpoint: ${STRIX_ESCALATION_ENDPOINT:-<disabled>}"
echo ""

exec strix "$@"
