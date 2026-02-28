"""Unit tests for the E2E scenario framework (no real SDK calls)."""

from __future__ import annotations

import asyncio
import time
from unittest.mock import MagicMock

import pytest

from tests.e2e.scenario import (
    MODEL_MAP,
    ScenarioResult,
    Scenario,
    ToolCall,
    ToolTracker,
)
from claude_code_sdk import ToolUseBlock, ToolResultBlock


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_tool_call(
    name: str,
    input_: dict | None = None,
    output: dict | str | None = None,
    duration_ms: float = 10.0,
    timestamp: float | None = None,
) -> ToolCall:
    return ToolCall(
        name=name,
        input=input_ or {},
        output=output,
        duration_ms=duration_ms,
        timestamp=timestamp or time.time(),
    )


def _make_result(*names: str) -> ScenarioResult:
    """Build a ScenarioResult with the given tool names called in order."""
    calls = [_make_tool_call(n, input_={"arg": n}) for n in names]
    return ScenarioResult(
        tool_calls=calls,
        final_text="Done.",
        cost_usd=0.01,
        duration_s=1.5,
        model="claude-haiku-4-5-20251001",
    )


# ---------------------------------------------------------------------------
# ToolCall dataclass
# ---------------------------------------------------------------------------


class TestToolCall:
    def test_defaults(self):
        tc = ToolCall(name="mcp__bluespy__load_capture", input={"path": "/tmp/x.pcapng"})
        assert tc.name == "mcp__bluespy__load_capture"
        assert tc.output is None
        assert tc.duration_ms == 0.0

    def test_with_output(self):
        tc = ToolCall(
            name="mcp__bluespy__capture_summary",
            input={},
            output={"packets": 100},
            duration_ms=42.5,
            timestamp=1000.0,
        )
        assert tc.output == {"packets": 100}
        assert tc.duration_ms == 42.5


# ---------------------------------------------------------------------------
# ScenarioResult assertion helpers
# ---------------------------------------------------------------------------


class TestScenarioResult:
    def test_tool_was_called_true(self):
        r = _make_result("mcp__bluespy__load_capture", "mcp__bluespy__capture_summary")
        assert r.tool_was_called("mcp__bluespy__load_capture") is True

    def test_tool_was_called_false(self):
        r = _make_result("mcp__bluespy__load_capture")
        assert r.tool_was_called("mcp__bluespy__start_capture") is False

    def test_all_tools_called_in_order(self):
        r = _make_result(
            "mcp__bluespy__load_capture",
            "mcp__bluespy__capture_summary",
            "mcp__bluespy__list_devices",
        )
        assert r.all_tools_called(["mcp__bluespy__load_capture", "mcp__bluespy__list_devices"]) is True

    def test_all_tools_called_wrong_order(self):
        r = _make_result(
            "mcp__bluespy__load_capture",
            "mcp__bluespy__capture_summary",
        )
        assert r.all_tools_called(["mcp__bluespy__capture_summary", "mcp__bluespy__load_capture"]) is False

    def test_all_tools_called_missing(self):
        r = _make_result("mcp__bluespy__load_capture")
        assert r.all_tools_called(["mcp__bluespy__load_capture", "mcp__bluespy__list_devices"]) is False

    def test_tools_in_order_exact(self):
        r = _make_result("a", "b", "c")
        assert r.tools_in_order(["a", "b", "c"]) is True

    def test_tools_in_order_with_extras(self):
        r = _make_result("a", "x", "b", "y", "c")
        assert r.tools_in_order(["a", "b", "c"]) is True

    def test_tools_in_order_wrong(self):
        r = _make_result("a", "c", "b")
        assert r.tools_in_order(["a", "b", "c"]) is False

    def test_tools_in_order_empty(self):
        r = _make_result("a", "b")
        assert r.tools_in_order([]) is True

    def test_tool_result_found(self):
        calls = [_make_tool_call("load", output={"ok": True})]
        r = ScenarioResult(tool_calls=calls, final_text="", cost_usd=0, duration_s=0, model="m")
        assert r.tool_result("load") == {"ok": True}

    def test_tool_result_not_found(self):
        r = _make_result("a")
        assert r.tool_result("nonexistent") is None

    def test_tool_result_first_only(self):
        calls = [
            _make_tool_call("t", output={"first": True}),
            _make_tool_call("t", output={"second": True}),
        ]
        r = ScenarioResult(tool_calls=calls, final_text="", cost_usd=0, duration_s=0, model="m")
        assert r.tool_result("t") == {"first": True}

    def test_tool_arg(self):
        calls = [_make_tool_call("load", input_={"path": "/tmp/x.pcapng", "verbose": True})]
        r = ScenarioResult(tool_calls=calls, final_text="", cost_usd=0, duration_s=0, model="m")
        assert r.tool_arg("load", "path") == "/tmp/x.pcapng"
        assert r.tool_arg("load", "verbose") is True

    def test_tool_arg_missing_key(self):
        calls = [_make_tool_call("load", input_={"path": "/tmp/x.pcapng"})]
        r = ScenarioResult(tool_calls=calls, final_text="", cost_usd=0, duration_s=0, model="m")
        assert r.tool_arg("load", "nonexistent") is None

    def test_tool_arg_missing_tool(self):
        r = _make_result("a")
        assert r.tool_arg("nonexistent", "key") is None

    def test_tool_called_before_true(self):
        r = _make_result("a", "b", "c")
        assert r.tool_called_before("a", "c") is True

    def test_tool_called_before_false(self):
        r = _make_result("a", "b", "c")
        assert r.tool_called_before("c", "a") is False

    def test_tool_called_before_same(self):
        r = _make_result("a", "b")
        assert r.tool_called_before("a", "a") is False  # same index

    def test_tool_called_before_missing(self):
        r = _make_result("a", "b")
        assert r.tool_called_before("a", "z") is False
        assert r.tool_called_before("z", "a") is False

    def test_final_text(self):
        r = _make_result("a")
        assert r.final_text == "Done."

    def test_cost_and_duration(self):
        r = _make_result("a")
        assert r.cost_usd == 0.01
        assert r.duration_s == 1.5


# ---------------------------------------------------------------------------
# ToolTracker
# ---------------------------------------------------------------------------


class TestToolTracker:
    def test_record_tool_use_and_result(self):
        tracker = ToolTracker()
        use_block = ToolUseBlock(id="tu_1", name="mcp__bluespy__load_capture", input={"path": "/x"})
        result_block = ToolResultBlock(tool_use_id="tu_1", content="ok", is_error=False)

        tracker.record_tool_use(use_block)
        assert len(tracker.calls) == 0  # not yet appended
        assert len(tracker._pending) == 1

        tracker.record_tool_result(result_block)
        assert len(tracker.calls) == 1
        assert len(tracker._pending) == 0

        tc = tracker.calls[0]
        assert tc.name == "mcp__bluespy__load_capture"
        assert tc.input == {"path": "/x"}
        assert tc.output == "ok"
        assert tc.duration_ms > 0

    def test_record_multiple_calls(self):
        tracker = ToolTracker()
        for i in range(3):
            use = ToolUseBlock(id=f"tu_{i}", name=f"tool_{i}", input={})
            tracker.record_tool_use(use)
            result = ToolResultBlock(tool_use_id=f"tu_{i}", content=f"out_{i}", is_error=False)
            tracker.record_tool_result(result)

        assert len(tracker.calls) == 3
        assert [tc.name for tc in tracker.calls] == ["tool_0", "tool_1", "tool_2"]

    def test_orphan_result_ignored(self):
        tracker = ToolTracker()
        result = ToolResultBlock(tool_use_id="unknown", content="x", is_error=False)
        tracker.record_tool_result(result)
        assert len(tracker.calls) == 0

    def test_flush_pending(self):
        tracker = ToolTracker()
        use = ToolUseBlock(id="tu_1", name="dangling", input={"a": 1})
        tracker.record_tool_use(use)

        assert len(tracker.calls) == 0
        tracker.flush_pending()
        assert len(tracker.calls) == 1
        assert tracker.calls[0].name == "dangling"
        assert tracker.calls[0].output is None

    def test_can_use_tool_allows(self):
        tracker = ToolTracker(forbidden_tools=["mcp__bluespy__start_capture"])
        result = asyncio.run(tracker.can_use_tool("mcp__bluespy__load_capture", {}, None))
        assert result.behavior == "allow"

    def test_can_use_tool_denies_forbidden(self):
        tracker = ToolTracker(forbidden_tools=["mcp__bluespy__start_capture"])
        result = asyncio.run(tracker.can_use_tool("mcp__bluespy__start_capture", {}, None))
        assert result.behavior == "deny"
        assert "forbidden" in result.message.lower()


# ---------------------------------------------------------------------------
# Scenario construction
# ---------------------------------------------------------------------------


class TestScenarioInit:
    def test_model_mapping_haiku(self):
        s = Scenario(prompt="test", model="haiku")
        assert s.model == "claude-haiku-4-5-20251001"

    def test_model_mapping_sonnet(self):
        s = Scenario(prompt="test", model="sonnet")
        assert s.model == "claude-sonnet-4-5-20250929"

    def test_model_mapping_opus(self):
        s = Scenario(prompt="test", model="opus")
        assert s.model == "claude-opus-4-6"

    def test_model_passthrough(self):
        s = Scenario(prompt="test", model="claude-haiku-4-5-20251001")
        assert s.model == "claude-haiku-4-5-20251001"

    def test_defaults(self):
        s = Scenario(prompt="hello")
        assert s.max_turns == 15
        assert s.max_budget == 0.25
        assert s.forbidden_tools == []
        assert s.expect_tools is None
        assert s.expect_tools_subset is None

    def test_forbidden_tools(self):
        s = Scenario(prompt="x", forbidden_tools=["mcp__bluespy__start_capture"])
        assert s.forbidden_tools == ["mcp__bluespy__start_capture"]


# ---------------------------------------------------------------------------
# MODEL_MAP
# ---------------------------------------------------------------------------


class TestModelMap:
    def test_all_keys_present(self):
        assert "haiku" in MODEL_MAP
        assert "sonnet" in MODEL_MAP
        assert "opus" in MODEL_MAP
