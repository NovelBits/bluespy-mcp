#!/usr/bin/env bash
#
# Run bluespy-mcp tests with verbose output and short summary.
#
# Usage:
#   ./scripts/test.sh              # Unit tests (no hardware, no e2e)
#   ./scripts/test.sh e2e-file     # E2E tests that only need capture files
#   ./scripts/test.sh e2e-hw       # E2E tests requiring blueSPY hardware
#   ./scripts/test.sh e2e          # All E2E tests (file + hardware)
#   ./scripts/test.sh all          # Everything (unit + all e2e)
#
# Flags are forwarded, so you can do:
#   ./scripts/test.sh -- -k "test_build_cache"
#   ./scripts/test.sh e2e-file -- --tb=long

set -euo pipefail
cd "$(dirname "$0")/.."

MODE="${1:-unit}"

# Consume mode arg; remaining args forwarded to pytest
if [[ "$MODE" != "--" && "$MODE" != -* ]]; then
    shift || true
fi

# Strip leading -- separator if present
if [[ "${1:-}" == "--" ]]; then
    shift
fi

case "$MODE" in
    unit)
        echo "==> Running unit tests (no hardware, no e2e)"
        uv run pytest tests/ --ignore=tests/e2e -m "not hardware" -v -s "$@"
        ;;
    e2e-file)
        echo "==> Running E2E file-only tests"
        uv run pytest tests/e2e/ -m "e2e and file_only" -v -s "$@"
        ;;
    e2e-hw)
        echo "==> Running E2E hardware tests"
        uv run pytest tests/e2e/ -m "e2e and hardware" -v -s "$@"
        ;;
    e2e)
        echo "==> Running all E2E tests (file + hardware)"
        uv run pytest tests/e2e/ -m "e2e" -v -s "$@"
        ;;
    all)
        echo "==> Running ALL tests (unit + e2e)"
        uv run pytest tests/ -m "" -v -s --override-ini="addopts=" "$@"
        ;;
    *)
        echo "Unknown mode: $MODE"
        echo "Usage: $0 [unit|e2e-file|e2e-hw|e2e|all] [-- extra pytest args]"
        exit 1
        ;;
esac
