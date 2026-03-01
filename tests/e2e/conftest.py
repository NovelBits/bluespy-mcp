"""E2E test configuration and shared fixtures.

Session-scoped cost tracking ensures the entire E2E suite stays within budget.
MCP server configuration points tests at the local bluespy-mcp installation.
Prints per-test and total cost summary at the end of the run.
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

_env: dict[str, str] = {}
if _lib_path := os.environ.get("BLUESPY_LIBRARY_PATH"):
    _env["BLUESPY_LIBRARY_PATH"] = _lib_path

MCP_CONFIG = {
    "bluespy": {
        "command": "uv",
        "args": ["run", "--directory", str(PROJECT_ROOT), "bluespy-mcp"],
        "env": _env,
    }
}


# ---------------------------------------------------------------------------
# Cost tracking
# ---------------------------------------------------------------------------

# Module-level singleton so pytest hooks and fixtures share the same instance.
_cost_tracker: CostTracker | None = None


class CostTracker:
    """Thread-safe cumulative API spend tracker.

    Aborts the test suite when total spend exceeds the configured budget
    (default $5, override with E2E_MAX_BUDGET env var).

    Also records per-test costs for the summary report.
    """

    def __init__(self, max_budget: float) -> None:
        self.max_budget = max_budget
        self._total: float = 0.0
        self._lock = threading.Lock()
        # Per-test cost log: list of (test_name, cost_usd)
        self.per_test: list[tuple[str, float]] = []
        # Snapshot before each test to compute delta
        self._snapshot: float = 0.0

    @property
    def total(self) -> float:
        with self._lock:
            return self._total

    def snapshot(self) -> None:
        """Save the current total so we can compute the delta after a test."""
        with self._lock:
            self._snapshot = self._total

    def record_test(self, name: str) -> None:
        """Record the cost delta since the last snapshot."""
        with self._lock:
            delta = self._total - self._snapshot
            self.per_test.append((name, delta))

    def add(self, amount: float) -> None:
        with self._lock:
            self._total += amount
            if self._total > self.max_budget:
                pytest.exit(
                    f"E2E budget exceeded: ${self._total:.2f} > ${self.max_budget:.2f}. "
                    "Aborting test suite.",
                    returncode=1,
                )


def _get_tracker() -> CostTracker:
    """Return the module-level cost tracker, creating it on first access."""
    global _cost_tracker
    if _cost_tracker is None:
        max_budget = float(os.environ.get("E2E_MAX_BUDGET", "5.0"))
        _cost_tracker = CostTracker(max_budget=max_budget)
    return _cost_tracker


@pytest.fixture(scope="session")
def cost_tracker() -> CostTracker:
    """Session-wide cost tracker that enforces E2E_MAX_BUDGET."""
    return _get_tracker()


@pytest.fixture(scope="session")
def mcp_server_config() -> dict:
    """Return MCP server configuration for the bluespy-mcp server."""
    return MCP_CONFIG


# ---------------------------------------------------------------------------
# Pytest hooks for per-test cost tracking and summary
# ---------------------------------------------------------------------------


def pytest_runtest_setup(item: pytest.Item) -> None:
    """Snapshot cost before each e2e test."""
    _get_tracker().snapshot()


def pytest_runtest_teardown(item: pytest.Item, nextitem: pytest.Item | None) -> None:
    """Record cost delta after each e2e test."""
    _get_tracker().record_test(item.nodeid)


def pytest_terminal_summary(
    terminalreporter: pytest.TerminalReporter,
    exitstatus: int,
    config: pytest.Config,
) -> None:
    """Print per-test and total cost summary at the end of the run."""
    tracker = _get_tracker()
    if not tracker.per_test:
        return

    terminalreporter.write_sep("=", "E2E Cost Summary")
    for name, cost in tracker.per_test:
        terminalreporter.write_line(f"  ${cost:.4f}  {name}")
    terminalreporter.write_sep("-", "")
    terminalreporter.write_line(
        f"  ${tracker.total:.4f}  TOTAL  (budget: ${tracker.max_budget:.2f})"
    )
