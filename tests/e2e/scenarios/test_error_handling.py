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
        prompt=(
            "Use the load_capture tool to load the capture file at "
            "/nonexistent/path/fake.pcapng and then summarize it."
        ),
        expect_tools_subset=["mcp__bluespy__load_capture"],
        max_budget=0.20,
        model="haiku",
        mcp_config=mcp_server_config,
    )
    result = await scenario.run(cost_tracker)
    # After a failed load, the model should NOT call capture_summary
    assert not result.tool_was_called("mcp__bluespy__capture_summary"), (
        "capture_summary should not be called after a failed load"
    )
    text = result.final_text.lower()
    assert "not found" in text or "error" in text or "doesn't exist" in text or "does not exist" in text


# ---------------------------------------------------------------------------
# Scenario 10: No hardware connected — graceful failure
# ---------------------------------------------------------------------------


@pytest.mark.e2e
@pytest.mark.no_hardware
@pytest.mark.asyncio
async def test_no_hardware_graceful_failure(cost_tracker, mcp_server_config):
    """Attempt to connect when no sniffer is plugged in.

    NOTE: Only run this test when the sniffer is NOT connected.
    Marked ``no_hardware`` so it's excluded from normal hardware runs.
    Run explicitly: pytest -m "e2e and no_hardware"
    """
    scenario = Scenario(
        prompt="Connect to the BlueSPY sniffer.",
        expect_tools_subset=["mcp__bluespy__connect_hardware"],
        max_budget=0.35,
        model="haiku",
        mcp_config=mcp_server_config,
    )
    result = await scenario.run(cost_tracker)
    # After a failed connect, the model should NOT attempt to start capture
    assert not result.tool_was_called("mcp__bluespy__start_capture"), (
        "start_capture should not be called after a failed connect"
    )
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
        max_budget=0.20,
        model="haiku",
        mcp_config=mcp_server_config,
    )
    result = await scenario.run(cost_tracker)
    assert result.tool_was_called("mcp__bluespy__hardware_status")
