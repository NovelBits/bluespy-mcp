"""E2E test framework: Scenario runner, ToolTracker, and ScenarioResult.

Uses the Claude Code SDK to send prompts with MCP servers configured,
then validates tool call sequences via message stream inspection and hooks.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from claude_code_sdk import (
    AssistantMessage,
    ClaudeCodeOptions,
    PermissionResultAllow,
    PermissionResultDeny,
    ResultMessage,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    query,
)

# ---------------------------------------------------------------------------
# Model ID mapping
# ---------------------------------------------------------------------------

MODEL_MAP: dict[str, str] = {
    "haiku": "claude-haiku-4-5-20251001",
    "sonnet": "claude-sonnet-4-5-20250929",
    "opus": "claude-opus-4-6",
}

RESULTS_DIR = Path(__file__).parent / "results"


# ---------------------------------------------------------------------------
# ToolCall dataclass
# ---------------------------------------------------------------------------


@dataclass
class ToolCall:
    """A single recorded tool invocation."""

    name: str
    input: dict[str, Any]
    output: dict[str, Any] | str | None = None
    duration_ms: float = 0.0
    timestamp: float = 0.0


# ---------------------------------------------------------------------------
# ToolTracker
# ---------------------------------------------------------------------------


class ToolTracker:
    """Records tool calls from the message stream and enforces forbidden tools.

    Works in two modes:
    1. As a ``can_use_tool`` callback to deny forbidden tools before execution.
    2. Via ``record_tool_use()`` and ``record_tool_result()`` called from the
       message stream handler to extract ToolUse/ToolResult pairs.
    """

    def __init__(self, forbidden_tools: list[str] | None = None) -> None:
        self.calls: list[ToolCall] = []
        self.forbidden_tools: list[str] = forbidden_tools or []
        # Pending tool_use blocks awaiting their result
        self._pending: dict[str, ToolCall] = {}

    # -- SDK can_use_tool callback -------------------------------------------

    async def can_use_tool(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        ctx: Any,
    ) -> PermissionResultAllow | PermissionResultDeny:
        """Called by the SDK before each tool invocation.

        Denies forbidden tools; allows everything else.
        """
        if tool_name in self.forbidden_tools:
            return PermissionResultDeny(
                behavior="deny",
                message=f"Tool '{tool_name}' is forbidden by this scenario.",
                interrupt=False,
            )
        return PermissionResultAllow(
            behavior="allow",
            updated_input=None,
            updated_permissions=None,
        )

    # -- Message-stream recording -------------------------------------------

    def record_tool_use(self, block: ToolUseBlock) -> None:
        """Record a tool_use block (start of a call)."""
        tc = ToolCall(
            name=block.name,
            input=dict(block.input),
            timestamp=time.time(),
        )
        self._pending[block.id] = tc

    def record_tool_result(self, block: ToolResultBlock) -> None:
        """Record a tool_result block (end of a call)."""
        tc = self._pending.pop(block.tool_use_id, None)
        if tc is None:
            return
        tc.output = block.content
        tc.duration_ms = (time.time() - tc.timestamp) * 1000
        self.calls.append(tc)

    def flush_pending(self) -> None:
        """Flush any tool_use blocks that never got a result."""
        for tc in self._pending.values():
            tc.duration_ms = (time.time() - tc.timestamp) * 1000
            self.calls.append(tc)
        self._pending.clear()


# ---------------------------------------------------------------------------
# ScenarioResult
# ---------------------------------------------------------------------------


@dataclass
class ScenarioResult:
    """Result of running a Scenario — provides assertion helpers for tests."""

    tool_calls: list[ToolCall]
    final_text: str
    cost_usd: float
    duration_s: float
    model: str

    # -- Assertion helpers ---------------------------------------------------

    def all_tools_called(self, expected: list[str]) -> bool:
        """Check all expected tools were called (order-preserving subsequence)."""
        called = [tc.name for tc in self.tool_calls]
        it = iter(called)
        return all(name in it for name in expected)

    def tools_in_order(self, expected: list[str]) -> bool:
        """Check tools were called in exact order (extras allowed between)."""
        called = [tc.name for tc in self.tool_calls]
        idx = 0
        for name in called:
            if idx < len(expected) and name == expected[idx]:
                idx += 1
        return idx == len(expected)

    def tool_was_called(self, name: str) -> bool:
        """Check if a specific tool was called at least once."""
        return any(tc.name == name for tc in self.tool_calls)

    def tool_result(self, name: str) -> dict[str, Any] | str | None:
        """Get the output of the first call to the named tool."""
        for tc in self.tool_calls:
            if tc.name == name:
                return tc.output
        return None

    def tool_arg(self, name: str, key: str) -> Any:
        """Get a specific argument from the first call to the named tool."""
        for tc in self.tool_calls:
            if tc.name == name:
                return tc.input.get(key)
        return None

    def tool_called_before(self, first: str, second: str) -> bool:
        """Check that *first* tool was called before *second* tool."""
        first_idx: int | None = None
        second_idx: int | None = None
        for i, tc in enumerate(self.tool_calls):
            if first_idx is None and tc.name == first:
                first_idx = i
            if second_idx is None and tc.name == second:
                second_idx = i
        if first_idx is None or second_idx is None:
            return False
        return first_idx < second_idx


# ---------------------------------------------------------------------------
# Scenario
# ---------------------------------------------------------------------------


class Scenario:
    """Configures and runs an E2E scenario against the blueSPY MCP server.

    Parameters
    ----------
    prompt : str
        The user prompt to send to Claude.
    expect_tools : list[str] | None
        If set, the strict ordered tool sequence to expect.
    expect_tools_subset : list[str] | None
        If set, an unordered set of tools that must all appear.
    forbidden_tools : list[str] | None
        Tools that must NOT be called (denied via ``can_use_tool``).
    max_budget : float
        Per-scenario budget cap in USD (advisory; the SDK itself manages this
        via ``max_turns``).
    max_turns : int
        Maximum agentic turns.
    model : str
        Short name ("haiku", "sonnet", "opus") or full model ID.
    mcp_config : dict | None
        MCP server configuration dict.  Falls back to conftest.MCP_CONFIG.
    """

    def __init__(
        self,
        prompt: str,
        expect_tools: list[str] | None = None,
        expect_tools_subset: list[str] | None = None,
        forbidden_tools: list[str] | None = None,
        max_budget: float = 0.25,
        max_turns: int = 15,
        model: str = "haiku",
        mcp_config: dict[str, Any] | None = None,
    ) -> None:
        self.prompt = prompt
        self.expect_tools = expect_tools
        self.expect_tools_subset = expect_tools_subset
        self.forbidden_tools = forbidden_tools or []
        self.max_budget = max_budget
        self.max_turns = max_turns
        self.model = MODEL_MAP.get(model, model)
        self.mcp_config = mcp_config

    async def run(self, cost_tracker: Any = None) -> ScenarioResult:
        """Execute the scenario and return a :class:`ScenarioResult`.

        Parameters
        ----------
        cost_tracker : CostTracker | None
            Session-level cost tracker from conftest. If provided, the
            scenario's cost is added to the cumulative session total.
        """
        tracker = ToolTracker(forbidden_tools=self.forbidden_tools)

        # Resolve MCP config
        mcp_servers: dict[str, Any] = self.mcp_config or {}

        options = ClaudeCodeOptions(
            allowed_tools=["mcp__bluespy__*"],
            mcp_servers=mcp_servers,
            max_turns=self.max_turns,
            model=self.model,
            permission_mode="bypassPermissions",
            can_use_tool=tracker.can_use_tool if self.forbidden_tools else None,
        )

        start = time.time()
        final_text = ""
        cost_usd = 0.0
        duration_ms = 0
        model_used = self.model
        error: str | None = None

        # The SDK requires an AsyncIterable prompt when can_use_tool is set.
        # The iterable must yield dicts with type/message structure.
        prompt: str | AsyncIterator[dict[str, Any]]
        if self.forbidden_tools:
            _prompt_text = self.prompt

            async def _stream_prompt() -> AsyncIterator[dict[str, Any]]:
                yield {
                    "type": "user",
                    "message": {
                        "role": "user",
                        "content": _prompt_text,
                    },
                }

            prompt = _stream_prompt()
        else:
            prompt = self.prompt

        # Short label for log lines
        _label = self.prompt[:60].replace("\n", " ")
        _tool_idx = 0
        print(f"\n  {'─' * 60}")
        print(f"  SCENARIO: {_label}...")
        print(f"  Model: {self.model} | Budget: ${self.max_budget:.2f} | Max turns: {self.max_turns}")
        print(f"  {'─' * 60}")

        try:
            async for message in query(prompt=prompt, options=options):
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, ToolUseBlock):
                            tracker.record_tool_use(block)
                            _tool_idx += 1
                            # Compact tool input summary
                            _args = {
                                k: (v if len(str(v)) < 60 else str(v)[:57] + "...")
                                for k, v in block.input.items()
                            } if block.input else {}
                            _args_str = f" {_args}" if _args else ""
                            _elapsed = time.time() - start
                            print(f"  [{_elapsed:6.1f}s] #{_tool_idx} → {block.name}{_args_str}")
                        elif isinstance(block, ToolResultBlock):
                            tracker.record_tool_result(block)
                        elif isinstance(block, TextBlock):
                            final_text = block.text
                    model_used = message.model or self.model

                elif isinstance(message, ResultMessage):
                    cost_usd = message.total_cost_usd or 0.0
                    duration_ms = message.duration_ms or 0
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"

        # Flush any unmatched pending tool calls
        tracker.flush_pending()

        elapsed = time.time() - start
        duration_s = duration_ms / 1000.0 if duration_ms else elapsed

        result = ScenarioResult(
            tool_calls=tracker.calls,
            final_text=final_text,
            cost_usd=cost_usd,
            duration_s=duration_s,
            model=model_used,
        )

        # Print summary
        _status = "ERROR" if error else "OK"
        _called = [tc.name.replace("mcp__bluespy__", "") for tc in result.tool_calls]
        print(f"  {'─' * 60}")
        print(f"  RESULT: {_status} | ${cost_usd:.4f} | {duration_s:.1f}s | {len(result.tool_calls)} tools")
        print(f"  Tools: {' → '.join(_called)}")
        if error:
            print(f"  Error: {error}")
        print(f"  {'─' * 60}\n")

        # Persist result log (always, even on error)
        self._save_result(result, error=error)

        # Session-level cost tracking
        if cost_tracker is not None:
            cost_tracker.add(cost_usd)

        # Per-scenario budget enforcement
        if cost_usd > self.max_budget:
            raise RuntimeError(
                f"Scenario exceeded budget: ${cost_usd:.4f} > ${self.max_budget:.2f}"
            )

        # Re-raise SDK errors after logging
        if error:
            raise RuntimeError(f"Scenario failed: {error}")

        # Validate expected tool sequences
        if self.expect_tools is not None:
            if not result.tools_in_order(self.expect_tools):
                called = [tc.name for tc in result.tool_calls]
                raise AssertionError(
                    f"Tool sequence mismatch.\n"
                    f"  Expected: {self.expect_tools}\n"
                    f"  Actual:   {called}"
                )

        if self.expect_tools_subset is not None:
            missing = [
                t for t in self.expect_tools_subset
                if not result.tool_was_called(t)
            ]
            if missing:
                called = [tc.name for tc in result.tool_calls]
                raise AssertionError(
                    f"Expected tools not called: {missing}\n"
                    f"  Actual calls: {called}"
                )

        return result

    # -- Result logging ------------------------------------------------------

    def _save_result(self, result: ScenarioResult, *, error: str | None = None) -> None:
        """Write a JSON log file under ``tests/e2e/results/``."""
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        # Sanitise prompt for filename
        slug = "".join(c if c.isalnum() else "_" for c in self.prompt[:40]).strip("_")
        filename = f"{ts}_{slug}.json"

        payload: dict[str, Any] = {
            "timestamp": ts,
            "model": result.model,
            "prompt": self.prompt,
            "cost_usd": result.cost_usd,
            "duration_s": result.duration_s,
            "final_text": result.final_text,
            "error": error,
            "tool_calls": [
                {
                    "name": tc.name,
                    "input": tc.input,
                    "output": tc.output,
                    "duration_ms": tc.duration_ms,
                    "timestamp": tc.timestamp,
                }
                for tc in result.tool_calls
            ],
        }

        (RESULTS_DIR / filename).write_text(
            json.dumps(payload, indent=2, default=str),
            encoding="utf-8",
        )
