"""E2E test configuration and shared fixtures.

Session-scoped cost tracking ensures the entire E2E suite stays within budget.
MCP server configuration points tests at the local bluespy-mcp installation.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# MCP server configuration
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

MCP_CONFIG = {
    "bluespy": {
        "command": "uv",
        "args": ["run", "--directory", str(PROJECT_ROOT), "bluespy-mcp"],
        "env": {"BLUESPY_LIBRARY_PATH": os.environ.get("BLUESPY_LIBRARY_PATH", "")},
    }
}


# ---------------------------------------------------------------------------
# Cost tracking
# ---------------------------------------------------------------------------

class CostTracker:
    """Thread-safe cumulative API spend tracker.

    Aborts the test suite when total spend exceeds the configured budget
    (default $5, override with E2E_MAX_BUDGET env var).
    """

    def __init__(self, max_budget: float) -> None:
        self.max_budget = max_budget
        self._total: float = 0.0
        self._lock = threading.Lock()

    @property
    def total(self) -> float:
        with self._lock:
            return self._total

    def add(self, amount: float) -> None:
        with self._lock:
            self._total += amount
            if self._total > self.max_budget:
                pytest.exit(
                    f"E2E budget exceeded: ${self._total:.2f} > ${self.max_budget:.2f}. "
                    "Aborting test suite.",
                    returncode=1,
                )


@pytest.fixture(scope="session")
def cost_tracker() -> CostTracker:
    """Session-wide cost tracker that enforces E2E_MAX_BUDGET."""
    max_budget = float(os.environ.get("E2E_MAX_BUDGET", "5.0"))
    return CostTracker(max_budget=max_budget)


@pytest.fixture(scope="session")
def mcp_server_config() -> dict:
    """Return MCP server configuration for the bluespy-mcp server."""
    return MCP_CONFIG
