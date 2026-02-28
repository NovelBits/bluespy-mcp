"""Reusable fixture paths for E2E test scenarios."""

from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "fixtures"
CAPTURE_5SEC = FIXTURES_DIR / "5_sec_capture.pcapng"
CAPTURE_10MIN = FIXTURES_DIR / "smart_home_capture_10min.pcapng"
