"""E2E scenarios for hardware-based capture workflows.

These tests require a physical blueSPY sniffer connected to the host machine.
Each test sends a natural language prompt to Claude with the blueSPY MCP server
configured, then validates that the correct tools are called in the expected order.
"""

from __future__ import annotations

import pytest

from tests.e2e.scenario import Scenario


# ---------------------------------------------------------------------------
# Scenario 6: Quick capture
# ---------------------------------------------------------------------------


@pytest.mark.e2e
@pytest.mark.hardware
@pytest.mark.asyncio
async def test_quick_capture(cost_tracker, mcp_server_config):
    """Connect, timed capture, summary, disconnect."""
    scenario = Scenario(
        prompt=(
            "Connect to the sniffer, capture for 5 seconds, summarize what you found, "
            "and then disconnect from the sniffer."
        ),
        expect_tools_subset=[
            "mcp__bluespy__connect_hardware",
            "mcp__bluespy__start_capture",
            "mcp__bluespy__capture_summary",
            "mcp__bluespy__disconnect_hardware",
        ],
        max_budget=0.35,
        max_turns=20,
        model="haiku",
        mcp_config=mcp_server_config,
    )
    result = await scenario.run(cost_tracker)
    assert result.tool_called_before(
        "mcp__bluespy__connect_hardware", "mcp__bluespy__start_capture"
    )


# ---------------------------------------------------------------------------
# Scenario 7: Live capture with device discovery
# ---------------------------------------------------------------------------


@pytest.mark.e2e
@pytest.mark.hardware
@pytest.mark.asyncio
async def test_live_capture_device_discovery(cost_tracker, mcp_server_config):
    """Connect, continuous capture, query devices while capturing, stop, disconnect."""
    scenario = Scenario(
        prompt=(
            "Connect to the sniffer, start a continuous capture (do NOT set a duration), "
            "then list nearby devices while the capture is still running. "
            "After that, stop the capture and disconnect."
        ),
        expect_tools_subset=[
            "mcp__bluespy__connect_hardware",
            "mcp__bluespy__start_capture",
            "mcp__bluespy__list_devices",
            "mcp__bluespy__disconnect_hardware",
        ],
        max_budget=0.40,
        max_turns=20,
        model="haiku",
        mcp_config=mcp_server_config,
    )
    result = await scenario.run(cost_tracker)
    # list_devices should be called after start_capture (live analysis)
    assert result.tool_called_before(
        "mcp__bluespy__start_capture", "mcp__bluespy__list_devices"
    )


# ---------------------------------------------------------------------------
# Scenario 8: Channel activity
# ---------------------------------------------------------------------------


@pytest.mark.e2e
@pytest.mark.hardware
@pytest.mark.asyncio
async def test_channel_activity(cost_tracker, mcp_server_config):
    """Capture and analyze RF channel activity."""
    scenario = Scenario(
        prompt=(
            "Connect to the sniffer, start capturing, and tell me which RF channels "
            "have the most activity. Then stop and disconnect."
        ),
        # stop_capture is optional — Haiku often uses timed captures that auto-stop
        expect_tools_subset=[
            "mcp__bluespy__connect_hardware",
            "mcp__bluespy__start_capture",
            "mcp__bluespy__search_packets",
            "mcp__bluespy__disconnect_hardware",
        ],
        max_budget=0.55,
        max_turns=20,
        model="haiku",
        mcp_config=mcp_server_config,
    )
    result = await scenario.run(cost_tracker)
    text = result.final_text.lower()
    assert "channel" in text
