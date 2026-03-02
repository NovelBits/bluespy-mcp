# CLAUDE.md

## What This Is

Open-source MCP server for the blueSPY Bluetooth LE protocol analyzer. Lets AI assistants load and analyze .pcapng capture files.

## Architecture

Flat Python package:

- `server.py` — FastMCP server, 16 tools + 2 resources + 3 prompts
- `capture.py` — CaptureManager wrapping blueSPY's global file state
- `analyzer.py` — Packet classification, filtering, summarization
- `hardware.py` — HardwareManager: subprocess isolation, file lock, state machine
- `worker.py` — Worker subprocess: executes bluespy hardware commands
- `loader.py` — Auto-discovers bluespy.py (installed > bundled fallback)
- `_vendor/bluespy.py` — Bundled fallback blueSPY API

## Development

```bash
# Setup
python -m venv .venv
source .venv/bin/activate
pip install -e .

# Run tests (no hardware needed)
python -m pytest tests/ -v

# Run integration tests (needs blueSPY hardware + dylib)
python -m pytest tests/ -v -m hardware

# Run server locally
bluespy-mcp
# or
python -m bluespy_mcp
```

## Key Patterns

- **Lazy loading**: blueSPY module loaded on first use, not at import time
- **One file at a time**: blueSPY uses global state. CaptureManager wraps this.
- **Defensive queries**: Every packet attribute access wrapped in try/except
- **JSON responses**: All tools return JSON. Errors are `{"error": "message"}`.
- **50K packet cap**: Summary operations cap iteration to prevent hanging on huge captures.
- **Subprocess isolation**: All hardware calls run in a child process. If ctypes hangs, the subprocess is killed — MCP server stays responsive.
- **File lock**: `~/.bluespy-mcp.lock` ensures single-client hardware access.
- **Reboot on connect**: Every connect_hardware() reboots the device first to avoid stale state.

## Public Repo Rules

This repo is **public**. Every committed file is visible to the world.

- **Never commit internal docs** (marketing plans, demo strategies, session notes, design docs with internal context). These belong in `novelbits-ops/campaigns/bluespy-mcp-launch/`.
- **Never reference AI assistants, Claude, or LLMs in source code or comments.** README mentions of Claude Desktop/Claude Code are fine (product integration docs), but source code and commit messages must be AI-neutral.
- **Never commit local paths** (`/Users/mafaneh/...`) in tracked files.
- **Never commit credentials, tokens, or API keys.**
- **E2E test results** (`tests/e2e/results/*.json`) are gitignored — they contain local paths and session data.
- **CLAUDE.md, .claude/, .mcp.json** are gitignored — local dev config only.

## Adding New Tools

1. Add analysis function to `analyzer.py`
2. Add `@mcp.tool` function to `server.py` (follows the pattern of existing tools)
3. Add tests to the corresponding test file
4. Update README.md tool table
