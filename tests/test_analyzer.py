"""Tests for capture analysis functions."""

from unittest.mock import patch

import pytest

from bluespy_mcp.analyzer import (
    classify_packet,
    find_packets,
    find_errors,
    summarize_capture,
)
from bluespy_mcp.capture import CaptureManager


class TestClassifyPacket:
    """Test packet type classification from summary strings."""

    @pytest.mark.parametrize("summary,expected", [
        ("ADV_IND from AA:BB:CC:DD:EE:FF", "ADV_IND"),
        ("ADV_NONCONN_IND from 11:22:33:44:55:66", "ADV_NONCONN_IND"),
        ("AUX_ADV_IND Extended", "AUX_ADV_IND"),
        ("SCAN_REQ to AA:BB:CC:DD:EE:FF", "SCAN_REQ"),
        ("SCAN_RSP from AA:BB:CC:DD:EE:FF", "SCAN_RSP"),
        ("CONNECT_IND to AA:BB:CC:DD:EE:FF", "CONNECT_IND"),
        ("LE-U L2CAP Data", "LE_DATA"),
        ("ATT Read Request", "ATT"),
        ("SMP Pairing Request", "SMP"),
        ("LL_TERMINATE_IND", "LL_CONTROL"),
        ("LL_CONNECTION_UPDATE_IND", "LL_CONNECTION_UPDATE"),
        ("Something unknown here", "OTHER"),
    ])
    def test_classification(self, summary, expected):
        assert classify_packet(summary) == expected

    def test_aux_adv_before_adv(self):
        """AUX_ADV_IND should not be misclassified as ADV_IND."""
        assert classify_packet("AUX_ADV_IND") == "AUX_ADV_IND"
        assert classify_packet("ADV_IND") == "ADV_IND"


class TestFindPackets:
    def test_filter_by_summary(self, tmp_path, mock_bluespy):
        pcapng = tmp_path / "test.pcapng"
        pcapng.write_bytes(b"\x00" * 100)
        mgr = CaptureManager()
        with patch("bluespy_mcp.capture.get_bluespy", return_value=mock_bluespy):
            mgr.load(str(pcapng))
            results = find_packets(mgr, summary_contains="ADV_IND")
        assert len(results) == 2
        assert all("ADV_IND" in r["summary"] for r in results)

    def test_filter_by_packet_type(self, tmp_path, mock_bluespy):
        pcapng = tmp_path / "test.pcapng"
        pcapng.write_bytes(b"\x00" * 100)
        mgr = CaptureManager()
        with patch("bluespy_mcp.capture.get_bluespy", return_value=mock_bluespy):
            mgr.load(str(pcapng))
            results = find_packets(mgr, packet_type="ATT")
        assert len(results) == 2  # ATT Read Request + ATT Read Response

    def test_max_results(self, tmp_path, mock_bluespy):
        pcapng = tmp_path / "test.pcapng"
        pcapng.write_bytes(b"\x00" * 100)
        mgr = CaptureManager()
        with patch("bluespy_mcp.capture.get_bluespy", return_value=mock_bluespy):
            mgr.load(str(pcapng))
            results = find_packets(mgr, max_results=3)
        assert len(results) == 3

    def test_no_results(self, tmp_path, mock_bluespy):
        pcapng = tmp_path / "test.pcapng"
        pcapng.write_bytes(b"\x00" * 100)
        mgr = CaptureManager()
        with patch("bluespy_mcp.capture.get_bluespy", return_value=mock_bluespy):
            mgr.load(str(pcapng))
            results = find_packets(mgr, summary_contains="NONEXISTENT")
        assert len(results) == 0


class TestFindErrors:
    def test_finds_terminate(self, tmp_path, mock_bluespy):
        pcapng = tmp_path / "test.pcapng"
        pcapng.write_bytes(b"\x00" * 100)
        mgr = CaptureManager()
        with patch("bluespy_mcp.capture.get_bluespy", return_value=mock_bluespy):
            mgr.load(str(pcapng))
            errors = find_errors(mgr)
        assert len(errors) >= 1
        assert any("TERMINATE" in e["summary"] for e in errors)


class TestSummarizeCapture:
    def test_summary_structure(self, tmp_path, mock_bluespy):
        pcapng = tmp_path / "test.pcapng"
        pcapng.write_bytes(b"\x00" * 100)
        mgr = CaptureManager()
        with patch("bluespy_mcp.capture.get_bluespy", return_value=mock_bluespy):
            mgr.load(str(pcapng))
            summary = summarize_capture(mgr)

        assert "packet_count" in summary
        assert "packet_type_counts" in summary
        assert "device_count" in summary
        assert summary["packet_count"] == 10
