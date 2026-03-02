"""E2E scenarios for file-based capture analysis workflows.

Each test sends a natural language prompt to Claude with the blueSPY MCP server
configured, then validates that the correct tools are called in the expected order.
"""

from __future__ import annotations

import pytest

from tests.e2e.fixtures.prompts import CAPTURE_5SEC, CAPTURE_10MIN
from tests.e2e.scenario import Scenario


# ---------------------------------------------------------------------------
# Scenario 1: Load and summarize
# ---------------------------------------------------------------------------


@pytest.mark.e2e
@pytest.mark.file_only
@pytest.mark.asyncio
async def test_load_and_summarize(cost_tracker, mcp_server_config):
    """Load a small capture file and get a summary of its contents."""
    scenario = Scenario(
        prompt=f"Load the capture file at {CAPTURE_5SEC} and give me a summary of what's in it.",
        expect_tools=["mcp__bluespy__load_capture", "mcp__bluespy__capture_summary"],
        max_budget=0.15,
        model="haiku",
        mcp_config=mcp_server_config,
    )
    result = await scenario.run(cost_tracker)
    # expect_tools validation happens inside run()
    assert "packet" in result.final_text.lower()


# ---------------------------------------------------------------------------
# Scenario 2: Search and inspect
# ---------------------------------------------------------------------------


@pytest.mark.e2e
@pytest.mark.file_only
@pytest.mark.asyncio
async def test_search_and_inspect(cost_tracker, mcp_server_config):
    """Load a capture, search for connection events, then inspect one."""
    scenario = Scenario(
        prompt=f"Load {CAPTURE_10MIN}, find all connection events, then inspect the first connection in detail.",
        expect_tools_subset=[
            "mcp__bluespy__load_capture",
            "mcp__bluespy__inspect_connection",
        ],
        max_budget=0.35,
        model="haiku",
        mcp_config=mcp_server_config,
    )
    result = await scenario.run(cost_tracker)
    assert result.tool_was_called("mcp__bluespy__inspect_connection")


# ---------------------------------------------------------------------------
# Scenario 3: Error investigation
# ---------------------------------------------------------------------------


@pytest.mark.e2e
@pytest.mark.file_only
@pytest.mark.asyncio
async def test_error_investigation(cost_tracker, mcp_server_config):
    """Load a capture and check for errors, disconnections, or failures."""
    scenario = Scenario(
        prompt=f"Load {CAPTURE_10MIN} and check for any errors, disconnections, or failures in the capture.",
        expect_tools_subset=[
            "mcp__bluespy__load_capture",
            "mcp__bluespy__find_capture_errors",
        ],
        max_budget=0.15,
        model="haiku",
        mcp_config=mcp_server_config,
    )
    result = await scenario.run(cost_tracker)


# ---------------------------------------------------------------------------
# Scenario 4: Full analysis workflow
# ---------------------------------------------------------------------------


@pytest.mark.e2e
@pytest.mark.file_only
@pytest.mark.asyncio
async def test_full_analysis(cost_tracker, mcp_server_config):
    """Run a complete multi-tool analysis of a capture file."""
    scenario = Scenario(
        prompt=f"Do a complete analysis of {CAPTURE_10MIN}. Tell me about the devices, connections, packet types, and any issues you find.",
        expect_tools_subset=[
            "mcp__bluespy__load_capture",
            "mcp__bluespy__capture_summary",
            "mcp__bluespy__list_devices",
            "mcp__bluespy__list_connections",
        ],
        max_budget=0.50,
        max_turns=20,
        model="haiku",
        mcp_config=mcp_server_config,
    )
    result = await scenario.run(cost_tracker)
    text = result.final_text.lower()
    assert "device" in text or "connection" in text or "packet" in text
