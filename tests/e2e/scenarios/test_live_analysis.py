"""E2E scenarios for live capture-to-analysis transition workflows.

These tests require a physical blueSPY sniffer connected to the host machine.
They validate the workflow of capturing live data and then transitioning to
post-capture analysis of the recorded data.
"""

from __future__ import annotations

import pytest

from tests.e2e.scenario import Scenario


# ---------------------------------------------------------------------------
# Scenario 9: Capture to file analysis transition
# ---------------------------------------------------------------------------


@pytest.mark.e2e
@pytest.mark.hardware
@pytest.mark.asyncio
async def test_capture_then_inspect(cost_tracker, mcp_server_config):
    """Capture, stop, then inspect connections from the saved file."""
    scenario = Scenario(
        prompt=(
            "Connect to the sniffer, capture for 5 seconds, "
            "then list any connections you found and inspect the first one if "
            "there are any. Then disconnect."
        ),
        # stop_capture is optional — timed captures auto-stop
        expect_tools_subset=[
            "mcp__bluespy__connect_hardware",
            "mcp__bluespy__start_capture",
            "mcp__bluespy__list_connections",
            "mcp__bluespy__disconnect_hardware",
        ],
        max_budget=0.45,
        max_turns=20,
        model="haiku",
        mcp_config=mcp_server_config,
    )
    result = await scenario.run(cost_tracker)
    assert result.tool_called_before(
        "mcp__bluespy__start_capture", "mcp__bluespy__list_connections"
    )


# ---------------------------------------------------------------------------
# Scenario 10: Live inspect_connection during active capture
# ---------------------------------------------------------------------------


@pytest.mark.e2e
@pytest.mark.hardware
@pytest.mark.asyncio
async def test_live_inspect_connection(cost_tracker, mcp_server_config):
    """Connect, start continuous capture, inspect connections while live, stop, disconnect."""
    scenario = Scenario(
        prompt=(
            "Connect to the sniffer, start a continuous capture (do NOT set a duration), "
            "wait a few seconds, then list connections and inspect the first one while "
            "the capture is still running. After that, stop the capture and disconnect."
        ),
        expect_tools_subset=[
            "mcp__bluespy__connect_hardware",
            "mcp__bluespy__start_capture",
            "mcp__bluespy__list_connections",
            "mcp__bluespy__inspect_connection",
            "mcp__bluespy__disconnect_hardware",
        ],
        max_budget=0.50,
        max_turns=20,
        model="haiku",
        mcp_config=mcp_server_config,
    )
    result = await scenario.run(cost_tracker)
    assert result.tool_called_before(
        "mcp__bluespy__start_capture", "mcp__bluespy__inspect_connection"
    )


# ---------------------------------------------------------------------------
# Scenario 11: Live inspect_advertising during active capture
# ---------------------------------------------------------------------------


@pytest.mark.e2e
@pytest.mark.hardware
@pytest.mark.asyncio
async def test_live_inspect_advertising(cost_tracker, mcp_server_config):
    """Connect, start continuous capture, inspect advertising while live, stop, disconnect."""
    scenario = Scenario(
        prompt=(
            "Connect to the sniffer, start a continuous capture (do NOT set a duration), "
            "wait a few seconds, then list devices and inspect the advertising data "
            "for the first device while the capture is still running. "
            "After that, stop the capture and disconnect."
        ),
        expect_tools_subset=[
            "mcp__bluespy__connect_hardware",
            "mcp__bluespy__start_capture",
            "mcp__bluespy__list_devices",
            "mcp__bluespy__inspect_advertising",
            "mcp__bluespy__disconnect_hardware",
        ],
        max_budget=0.50,
        max_turns=20,
        model="haiku",
        mcp_config=mcp_server_config,
    )
    result = await scenario.run(cost_tracker)
    assert result.tool_called_before(
        "mcp__bluespy__start_capture", "mcp__bluespy__inspect_advertising"
    )
