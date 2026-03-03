"""Tests for capture analysis functions.

Note: find_packets, find_errors, summarize_capture, analyze_connection,
and analyze_advertising formerly operated on CaptureManager's direct
bluespy access (iter_packets, packet_count, etc.). Those APIs were
removed when CaptureManager moved to a worker subprocess architecture.
The equivalent functionality is now tested through test_capture.py
(TestAnalysisMethods) via CaptureManager.get_summary(), .search_packets(),
.get_errors(), .inspect_connection(), and .inspect_advertising().

Only classify_packet (a pure function) remains testable here.
"""

import pytest

from bluespy_mcp.analysis_core import classify_packet


class TestClassifyPacket:
    """Test packet type classification from summary strings."""

    @pytest.mark.parametrize("summary,expected", [
        ("ADV_IND from AA:BB:CC:DD:EE:FF", "ADV_IND"),
        ("ADV_NONCONN_IND from 11:22:33:44:55:66", "ADV_NONCONN_IND"),
        ("AUX_ADV_IND Extended", "AUX_ADV_IND"),
        ("SCAN_REQ to AA:BB:CC:DD:EE:FF", "SCAN_REQ"),
        ("SCAN_RSP from AA:BB:CC:DD:EE:FF", "SCAN_RSP"),
        ("CONNECT_IND to AA:BB:CC:DD:EE:FF", "CONNECT_IND"),
        ("LE-U L2CAP Data", "L2CAP"),
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
