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


# ---------------------------------------------------------------------------
# Scenario 10: No hardware connected — graceful failure
# ---------------------------------------------------------------------------


@pytest.mark.e2e
@pytest.mark.hardware
@pytest.mark.asyncio
async def test_no_hardware_graceful_failure(cost_tracker, mcp_server_config):
    """Attempt to connect when no sniffer is plugged in.

    NOTE: Only run this test when the sniffer is NOT connected.
    Mark with ``hardware`` so it's only included in hardware test runs
    where the tester controls the physical setup.
    """
    scenario = Scenario(
        prompt="Connect to the BlueSPY sniffer.",
        expect_tools_subset=["mcp__bluespy__connect_hardware"],
        forbidden_tools=["mcp__bluespy__start_capture"],  # shouldn't attempt capture after failed connect
        max_budget=0.15,
        model="haiku",
        mcp_config=mcp_server_config,
    )
    result = await scenario.run(cost_tracker)
    text = result.final_text.lower()
    assert "error" in text or "failed" in text or "not connected" in text or "unable" in text


# ---------------------------------------------------------------------------
# Scenario 11: Status check and cleanup
# ---------------------------------------------------------------------------


@pytest.mark.e2e
@pytest.mark.hardware
@pytest.mark.asyncio
async def test_status_check_and_cleanup(cost_tracker, mcp_server_config):
    """Check hardware status and disconnect if connected."""
    scenario = Scenario(
        prompt="Check the hardware status. If anything is connected, disconnect it cleanly.",
        expect_tools_subset=["mcp__bluespy__hardware_status"],
        max_budget=0.10,
        model="haiku",
        mcp_config=mcp_server_config,
    )
    result = await scenario.run(cost_tracker)
    assert result.tool_was_called("mcp__bluespy__hardware_status")
