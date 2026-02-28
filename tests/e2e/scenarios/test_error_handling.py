"""E2E scenarios for error handling and edge cases.

Validates that the MCP server and Claude handle failure conditions gracefully
(e.g., missing files, invalid paths) without calling downstream tools.
"""

from __future__ import annotations

import pytest

from tests.e2e.scenario import Scenario


# ---------------------------------------------------------------------------
# Scenario 5: Wrong file path
# ---------------------------------------------------------------------------


@pytest.mark.e2e
@pytest.mark.file_only
@pytest.mark.asyncio
async def test_wrong_file_path(cost_tracker, mcp_server_config):
    """Attempt to load a nonexistent capture file and verify graceful failure."""
    scenario = Scenario(
        prompt="Load the capture file at /nonexistent/path/fake.pcapng and summarize it.",
        expect_tools_subset=["mcp__bluespy__load_capture"],
        forbidden_tools=["mcp__bluespy__capture_summary"],  # shouldn't try to summarize a failed load
        max_budget=0.10,
        model="haiku",
        mcp_config=mcp_server_config,
    )
    result = await scenario.run(cost_tracker)
    text = result.final_text.lower()
    assert "not found" in text or "error" in text or "doesn't exist" in text or "does not exist" in text
