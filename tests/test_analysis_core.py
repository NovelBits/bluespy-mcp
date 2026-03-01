"""Tests for shared analysis core — pure functions with no CaptureManager dependency."""

import pytest

from bluespy_mcp.analysis_core import (
    _extract_adv_address,
    classify_packet,
    summarize_packets,
    filter_packets,
    find_error_packets,
    extract_device_info,
    extract_connection_info,
    analyze_connection_live,
    analyze_advertising_live,
    ERROR_KEYWORDS,
    SUMMARY_PACKET_LIMIT,
)
from tests.conftest import MockPacket, MockPackets, MockDevice, MockConnection


class TestClassifyPacket:
    """Verify classify_packet works when imported from analysis_core."""

    @pytest.mark.parametrize("summary,expected", [
        ("ADV_IND from AA:BB:CC:DD:EE:FF", "ADV_IND"),
        ("AUX_ADV_IND Extended", "AUX_ADV_IND"),
        ("LE-U L2CAP Data", "LE_DATA"),
        ("ATT Read Request", "ATT"),
        ("Something unknown", "OTHER"),
    ])
    def test_classification(self, summary, expected):
        assert classify_packet(summary) == expected


class TestSummarizePackets:
    """Test summarize_packets with raw packet-like objects."""

    def test_counts_packet_types(self):
        packets = MockPackets([
            MockPacket(summary="ADV_IND from AA:BB", time=1000, rssi=-55, channel=37),
            MockPacket(summary="ADV_IND from AA:BB", time=1100, rssi=-58, channel=38),
            MockPacket(summary="SCAN_REQ to AA:BB", time=1200, rssi=-60, channel=37),
            MockPacket(summary="LE-U L2CAP Data", time=2000, rssi=-50, channel=5),
        ])
        result = summarize_packets(packets)
        assert result["packet_count"] == 4
        assert result["packet_type_counts"]["ADV_IND"] == 2
        assert result["packet_type_counts"]["SCAN_REQ"] == 1
        assert result["packet_type_counts"]["LE_DATA"] == 1

    def test_includes_duration(self):
        packets = MockPackets([
            MockPacket(summary="ADV_IND", time=1_000_000_000, rssi=-55, channel=37),
            MockPacket(summary="ADV_IND", time=6_000_000_000, rssi=-55, channel=38),
        ])
        result = summarize_packets(packets)
        assert result["duration_seconds"] == 5.0

    def test_empty_packets(self):
        result = summarize_packets(MockPackets([]))
        assert result["packet_count"] == 0
        assert result["packet_type_counts"] == {}

    def test_respects_limit(self):
        packets = MockPackets([
            MockPacket(summary=f"ADV_IND #{i}", time=i * 1000, rssi=-55, channel=37)
            for i in range(100)
        ])
        result = summarize_packets(packets, limit=10)
        assert result["packet_count"] == 100  # total count
        assert sum(result["packet_type_counts"].values()) == 10  # only classified 10


class TestFilterPackets:
    """Test filter_packets with raw packet-like objects."""

    def test_filter_by_channel(self):
        packets = MockPackets([
            MockPacket(summary="ADV_IND", time=1000, rssi=-55, channel=37),
            MockPacket(summary="ADV_IND", time=1100, rssi=-55, channel=38),
            MockPacket(summary="ADV_IND", time=1200, rssi=-55, channel=37),
        ])
        results = filter_packets(packets, channel=37)
        assert len(results) == 2

    def test_filter_by_packet_type(self):
        packets = MockPackets([
            MockPacket(summary="ADV_IND from AA:BB", time=1000, rssi=-55, channel=37),
            MockPacket(summary="SCAN_REQ to AA:BB", time=1100, rssi=-60, channel=37),
            MockPacket(summary="ATT Read Request", time=2000, rssi=-50, channel=5),
        ])
        results = filter_packets(packets, packet_type="ADV_IND")
        assert len(results) == 1
        assert results[0]["summary"] == "ADV_IND from AA:BB"

    def test_filter_by_summary_contains(self):
        packets = MockPackets([
            MockPacket(summary="ADV_IND from AA:BB", time=1000, rssi=-55, channel=37),
            MockPacket(summary="SCAN_REQ to CC:DD", time=1100, rssi=-60, channel=37),
        ])
        results = filter_packets(packets, summary_contains="AA:BB")
        assert len(results) == 1

    def test_max_results(self):
        packets = MockPackets([
            MockPacket(summary=f"ADV_IND #{i}", time=i * 1000, rssi=-55, channel=37)
            for i in range(50)
        ])
        results = filter_packets(packets, max_results=5)
        assert len(results) == 5

    def test_start_index(self):
        packets = MockPackets([
            MockPacket(summary=f"ADV_IND #{i}", time=i * 1000, rssi=-55, channel=37)
            for i in range(10)
        ])
        results = filter_packets(packets, start=7)
        assert len(results) == 3
        assert results[0]["index"] == 7

    def test_combined_filters(self):
        packets = MockPackets([
            MockPacket(summary="ADV_IND", time=1000, rssi=-55, channel=37),
            MockPacket(summary="ADV_IND", time=1100, rssi=-55, channel=38),
            MockPacket(summary="SCAN_REQ", time=1200, rssi=-60, channel=37),
        ])
        results = filter_packets(packets, packet_type="ADV_IND", channel=37)
        assert len(results) == 1

    def test_includes_payload_hex(self):
        payload = b"\x00\x06\xaa\xbb\xcc\xdd\xee\xff\x02\x01\x06"
        packets = MockPackets([
            MockPacket(summary="ADV_IND from AA:BB", time=1000, rssi=-55, channel=37, payload=payload),
        ])
        results = filter_packets(packets)
        assert len(results) == 1
        assert results[0]["payload_hex"] == payload.hex()

    def test_missing_payload_omitted(self):
        packets = MockPackets([
            MockPacket(summary="ADV_IND", time=1000, rssi=-55, channel=37),
        ])
        results = filter_packets(packets)
        assert "payload_hex" not in results[0]


class TestFindErrorPackets:
    def test_finds_errors(self):
        packets = MockPackets([
            MockPacket(summary="ADV_IND", time=1000, rssi=-55, channel=37),
            MockPacket(summary="LL_TERMINATE_IND Reason: Remote User Terminated", time=2000, rssi=-55, channel=5),
            MockPacket(summary="CRC ERROR", time=3000, rssi=-55, channel=37),
        ])
        errors = find_error_packets(packets)
        assert len(errors) == 2

    def test_max_results(self):
        packets = MockPackets([
            MockPacket(summary=f"ERROR #{i}", time=i * 1000, rssi=-55, channel=37)
            for i in range(20)
        ])
        errors = find_error_packets(packets, max_results=5)
        assert len(errors) == 5

    def test_start_index(self):
        packets = MockPackets([
            MockPacket(summary="ADV_IND", time=1000, rssi=-55, channel=37),
            MockPacket(summary="ERROR at start", time=2000, rssi=-55, channel=37),
            MockPacket(summary="TIMEOUT event", time=3000, rssi=-55, channel=37),
        ])
        errors = find_error_packets(packets, start=2)
        assert len(errors) == 1
        assert errors[0]["index"] == 2


class TestExtractDeviceInfo:
    def test_extracts_devices(self):
        devices = [MockDevice()]
        result = extract_device_info(devices)
        assert len(result) == 1
        assert result[0]["address"] == "AA:BB:CC:DD:EE:FF"

    def test_empty_devices(self):
        result = extract_device_info([])
        assert result == []

    def test_multiple_devices(self):
        devices = [
            MockDevice(_address="AA:BB:CC:DD:EE:FF"),
            MockDevice(_address="11:22:33:44:55:66"),
        ]
        result = extract_device_info(devices)
        assert len(result) == 2
        assert result[0]["address"] == "AA:BB:CC:DD:EE:FF"
        assert result[1]["address"] == "11:22:33:44:55:66"


class TestExtractConnectionInfo:
    def test_extracts_connections(self):
        connections = [MockConnection()]
        result = extract_connection_info(connections)
        assert len(result) == 1
        assert "0xABCD" in result[0]["summary"]

    def test_empty_connections(self):
        result = extract_connection_info([])
        assert result == []


class TestExtractAdvAddress:
    def test_extracts_address_from_payload(self):
        """Extract advertiser address from bytes 2-7 in little-endian."""
        pkt = MockPacket(summary="ADV_IND")
        # Payload: 2 header bytes + 6 address bytes (LE order: FF:EE:DD:CC:BB:AA)
        pkt.query = lambda name: (
            b"\x00\x00\xFF\xEE\xDD\xCC\xBB\xAA\x00\x00"
            if name == "payload" else MockPacket.query(pkt, name)
        )
        assert _extract_adv_address(pkt) == "AA:BB:CC:DD:EE:FF"

    def test_returns_empty_for_short_payload(self):
        pkt = MockPacket(summary="ADV_IND")
        pkt.query = lambda name: b"\x00\x01" if name == "payload" else MockPacket.query(pkt, name)
        assert _extract_adv_address(pkt) == ""

    def test_returns_empty_on_error(self):
        pkt = MockPacket(summary="ADV_IND")
        pkt.query = lambda name: (_ for _ in ()).throw(AttributeError())
        assert _extract_adv_address(pkt) == ""


class TestAnalyzeConnectionLive:
    def _make_data(self):
        connections = [MockConnection()]
        packets = MockPackets([
            MockPacket(summary="ADV_IND from AA:BB", time=1000, rssi=-55, channel=37),
            MockPacket(summary="CONNECT_IND to AA:BB", time=2000, rssi=-52, channel=39),
            MockPacket(summary="ATT Read Request", time=3000, rssi=-50, channel=5),
            MockPacket(summary="LE-U L2CAP Data", time=4000, rssi=-48, channel=5),
        ])
        return connections, packets

    def test_returns_connection_info(self):
        conns, pkts = self._make_data()
        result = analyze_connection_live(conns, pkts, connection_index=0)
        assert "summary" in result
        assert "0xABCD" in result["summary"]

    def test_counts_non_adv_packets(self):
        conns, pkts = self._make_data()
        result = analyze_connection_live(conns, pkts, connection_index=0)
        counts = result["packet_type_counts"]
        assert "ADV_IND" not in counts  # advertising excluded
        assert counts.get("CONNECT_IND", 0) == 1
        assert counts.get("ATT", 0) == 1
        assert counts.get("LE_DATA", 0) == 1

    def test_no_connections_error(self):
        result = analyze_connection_live([], MockPackets([]))
        assert "error" in result

    def test_index_out_of_range(self):
        conns, pkts = self._make_data()
        result = analyze_connection_live(conns, pkts, connection_index=5)
        assert "error" in result
        assert "out of range" in result["error"]


class TestAnalyzeAdvertisingLive:
    def _make_data(self):
        devices = [
            MockDevice(_address="AA:BB:CC:DD:EE:FF"),
            MockDevice(_address="11:22:33:44:55:66"),
        ]
        packets = MockPackets([
            MockPacket(summary="ADV_IND from AA:BB:CC:DD:EE:FF", time=1000, rssi=-55, channel=37),
            MockPacket(summary="ADV_IND from AA:BB:CC:DD:EE:FF", time=1100, rssi=-60, channel=38),
            MockPacket(summary="ADV_IND from 11:22:33:44:55:66", time=1200, rssi=-70, channel=39),
            MockPacket(summary="CONNECT_IND to AA:BB:CC:DD:EE:FF", time=2000, rssi=-52, channel=39),
        ])
        return devices, packets

    def test_returns_device_info(self):
        devs, pkts = self._make_data()
        result = analyze_advertising_live(devs, pkts, device_index=0)
        assert result["address"] == "AA:BB:CC:DD:EE:FF"

    def test_counts_advertisements_for_device(self):
        devs, pkts = self._make_data()
        result = analyze_advertising_live(devs, pkts, device_index=0)
        assert result["advertisement_count"] == 2  # only AA:BB's ADV packets

    def test_second_device(self):
        devs, pkts = self._make_data()
        result = analyze_advertising_live(devs, pkts, device_index=1)
        assert result["address"] == "11:22:33:44:55:66"
        assert result["advertisement_count"] == 1

    def test_rssi_stats(self):
        devs, pkts = self._make_data()
        result = analyze_advertising_live(devs, pkts, device_index=0)
        assert result["rssi_min"] == -60
        assert result["rssi_max"] == -55
        assert result["rssi_avg"] == -57.5

    def test_channels_used(self):
        devs, pkts = self._make_data()
        result = analyze_advertising_live(devs, pkts, device_index=0)
        assert 37 in result["channels_used"]
        assert 38 in result["channels_used"]

    def test_no_devices_error(self):
        result = analyze_advertising_live([], MockPackets([]))
        assert "error" in result

    def test_index_out_of_range(self):
        devs, pkts = self._make_data()
        result = analyze_advertising_live(devs, pkts, device_index=10)
        assert "error" in result
        assert "out of range" in result["error"]

    def test_limits_sample_to_50(self):
        devices = [MockDevice()]
        packets = MockPackets([
            MockPacket(summary=f"ADV_IND from AA:BB:CC:DD:EE:FF #{i}", time=i * 1000, rssi=-55, channel=37)
            for i in range(100)
        ])
        result = analyze_advertising_live(devices, packets, device_index=0)
        assert result["advertisement_count"] == 100
        assert len(result["advertisements_sample"]) == 50

    def test_case_insensitive_address_matching(self):
        """Address matching should work regardless of case from query_str."""
        # Simulate a device whose query_str returns lowercase address
        class LowercaseDevice:
            def query(self, name):
                raise AttributeError()
            def query_str(self, name):
                if name == "address":
                    return "aa:bb:cc:dd:ee:ff"
                if name == "name":
                    return "Lowercase Device"
                if name == "summary":
                    return "aa:bb:cc:dd:ee:ff, Static"
                raise AttributeError()
            def get_connections(self):
                return []

        devices = [LowercaseDevice()]
        packets = MockPackets([
            MockPacket(summary="ADV_IND from AA:BB:CC:DD:EE:FF", time=1000, rssi=-55, channel=37),
            MockPacket(summary="ADV_IND from aa:bb:cc:dd:ee:ff", time=1100, rssi=-60, channel=38),
        ])
        result = analyze_advertising_live(devices, packets, device_index=0)
        assert result["advertisement_count"] == 2
        assert result["address"] == "AA:BB:CC:DD:EE:FF"  # normalized to uppercase


class TestConstants:
    def test_summary_packet_limit(self):
        assert SUMMARY_PACKET_LIMIT == 50_000

    def test_error_keywords(self):
        assert "ERROR" in ERROR_KEYWORDS
        assert "TERMINATE" in ERROR_KEYWORDS
        assert len(ERROR_KEYWORDS) > 0
