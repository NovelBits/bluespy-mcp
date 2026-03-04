"""Tests for shared analysis core — pure functions with no CaptureManager dependency."""

import pytest

import struct

from bluespy_mcp.analysis_core import (
    _extract_adv_address,
    _extract_address_type,
    _parse_connection_addresses,
    classify_packet,
    parse_ad_structures,
    summarize_packets,
    filter_packets,
    find_error_packets,
    extract_device_info,
    enrich_device_names,
    enrich_device_rssi,
    extract_connection_info,
    analyze_connection_live,
    analyze_all_connections,
    analyze_advertising_live,
    analyze_all_advertising,
    ERROR_KEYWORDS,
    SUMMARY_PACKET_LIMIT,
)
from tests.conftest import MockPacket, MockPackets, MockDevice, MockConnection


class TestClassifyPacket:
    """Verify classify_packet works when imported from analysis_core."""

    @pytest.mark.parametrize("summary,expected", [
        ("ADV_IND from AA:BB:CC:DD:EE:FF", "ADV_IND"),
        ("AUX_ADV_IND Extended", "AUX_ADV_IND"),
        ("LE-U L2CAP Data", "L2CAP"),
        ("ATT Read Request", "ATT"),
        ("Something unknown", "OTHER"),
        # LE-U wrapped higher-layer protocols — most specific wins
        ("LE-U L2CAP Data ATT Read Request", "ATT"),
        ("LE-U L2CAP Data ATT Write Command", "ATT"),
        ("LE-U L2CAP Data ATT Handle Value Notification", "ATT"),
        ("LE-U L2CAP Data GATT Service Discovery", "ATT"),
        ("LE-U L2CAP Data SMP Pairing Request", "SMP"),
        ("LE-U L2CAP Data SMP Security Request", "SMP"),
        ("LE-U L2CAP Data L2CAP Connection Parameter Update Request", "L2CAP"),
        # Pure LE-U without L2CAP/upper-layer protocol → LE_DATA
        ("LE-U", "LE_DATA"),
        ("LE-U Data", "LE_DATA"),
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
        assert result["packet_type_counts"]["L2CAP"] == 1

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
        result = filter_packets(packets, channel=37)
        assert result["returned"] == 2

    def test_filter_by_packet_type(self):
        packets = MockPackets([
            MockPacket(summary="ADV_IND from AA:BB", time=1000, rssi=-55, channel=37),
            MockPacket(summary="SCAN_REQ to AA:BB", time=1100, rssi=-60, channel=37),
            MockPacket(summary="ATT Read Request", time=2000, rssi=-50, channel=5),
        ])
        result = filter_packets(packets, packet_type="ADV_IND")
        assert result["returned"] == 1
        assert result["packets"][0]["summary"] == "ADV_IND from AA:BB"

    def test_filter_by_summary_contains(self):
        packets = MockPackets([
            MockPacket(summary="ADV_IND from AA:BB", time=1000, rssi=-55, channel=37),
            MockPacket(summary="SCAN_REQ to CC:DD", time=1100, rssi=-60, channel=37),
        ])
        result = filter_packets(packets, summary_contains="AA:BB")
        assert result["returned"] == 1

    def test_max_results(self):
        packets = MockPackets([
            MockPacket(summary=f"ADV_IND #{i}", time=i * 1000, rssi=-55, channel=37)
            for i in range(50)
        ])
        result = filter_packets(packets, max_results=5)
        assert result["returned"] == 5
        assert result["has_more"] is True

    def test_start_index(self):
        packets = MockPackets([
            MockPacket(summary=f"ADV_IND #{i}", time=i * 1000, rssi=-55, channel=37)
            for i in range(10)
        ])
        result = filter_packets(packets, start=7)
        assert result["returned"] == 3
        assert result["packets"][0]["index"] == 7
        assert result["has_more"] is False

    def test_combined_filters(self):
        packets = MockPackets([
            MockPacket(summary="ADV_IND", time=1000, rssi=-55, channel=37),
            MockPacket(summary="ADV_IND", time=1100, rssi=-55, channel=38),
            MockPacket(summary="SCAN_REQ", time=1200, rssi=-60, channel=37),
        ])
        result = filter_packets(packets, packet_type="ADV_IND", channel=37)
        assert result["returned"] == 1

    def test_includes_payload_hex(self):
        payload = b"\x00\x06\xaa\xbb\xcc\xdd\xee\xff\x02\x01\x06"
        packets = MockPackets([
            MockPacket(summary="ADV_IND from AA:BB", time=1000, rssi=-55, channel=37, payload=payload),
        ])
        result = filter_packets(packets)
        assert result["returned"] == 1
        assert result["packets"][0]["payload_hex"] == payload.hex()

    def test_missing_payload_omitted(self):
        packets = MockPackets([
            MockPacket(summary="ADV_IND", time=1000, rssi=-55, channel=37),
        ])
        result = filter_packets(packets)
        assert "payload_hex" not in result["packets"][0]

    def test_has_more_false_when_exact_match(self):
        packets = MockPackets([
            MockPacket(summary=f"ADV_IND #{i}", time=i * 1000, rssi=-55, channel=37)
            for i in range(5)
        ])
        result = filter_packets(packets, max_results=5)
        assert result["returned"] == 5
        assert result["has_more"] is False

    def test_has_more_true_with_more_results(self):
        packets = MockPackets([
            MockPacket(summary=f"ADV_IND #{i}", time=i * 1000, rssi=-55, channel=37)
            for i in range(10)
        ])
        result = filter_packets(packets, max_results=5)
        assert result["returned"] == 5
        assert result["has_more"] is True


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
            MockPacket(summary="ADV_IND from AA:BB:CC:DD:EE:FF", time=1000, rssi=-55, channel=37),
            MockPacket(summary="CONNECT_IND to AA:BB:CC:DD:EE:FF", time=2000, rssi=-52, channel=39),
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
        assert counts.get("L2CAP", 0) == 1

    def test_no_connections_error(self):
        result = analyze_connection_live([], MockPackets([]))
        assert "error" in result

    def test_index_out_of_range(self):
        conns, pkts = self._make_data()
        result = analyze_connection_live(conns, pkts, connection_index=5)
        assert "error" in result
        assert "out of range" in result["error"]


class TestParseConnectionAddresses:
    def test_extracts_macs_from_summary(self):
        summary = "0xABCD1234 Central AA:BB:CC:DD:EE:FF Peripheral 11:22:33:44:55:66"
        addrs = _parse_connection_addresses(summary)
        assert "AA:BB:CC:DD:EE:FF" in addrs
        assert "11:22:33:44:55:66" in addrs

    def test_extracts_lowercase_macs(self):
        summary = "Central aa:bb:cc:dd:ee:ff"
        addrs = _parse_connection_addresses(summary)
        assert "AA:BB:CC:DD:EE:FF" in addrs

    def test_empty_for_no_macs(self):
        assert _parse_connection_addresses("0xABCD1234 no addresses here") == []


class TestConnectionAccuracy:
    def test_multi_connection_accuracy(self):
        """Two connections with different time ranges should only count their own packets."""
        conn1 = MockConnection(
            _summary="0xABCD Central AA:BB:CC:DD:EE:FF Peripheral 11:22:33:44:55:66"
        )
        conn2 = MockConnection(
            _summary="0xDEF0 Central CC:DD:EE:FF:00:11 Peripheral 22:33:44:55:66:77"
        )
        packets = MockPackets([
            # Advertising
            MockPacket(summary="ADV_IND from AA:BB:CC:DD:EE:FF", time=1000, rssi=-55, channel=37),
            # Connection 1 boundary + data
            MockPacket(summary="CONNECT_IND to AA:BB:CC:DD:EE:FF", time=2000, rssi=-52, channel=39),
            MockPacket(summary="ATT Read Request", time=3000, rssi=-50, channel=5),
            MockPacket(summary="LE-U L2CAP Data", time=4000, rssi=-48, channel=5),
            MockPacket(summary="LL_TERMINATE_IND Reason: Remote", time=5000, rssi=-55, channel=5),
            # Connection 2 boundary + data
            MockPacket(summary="CONNECT_IND to CC:DD:EE:FF:00:11", time=6000, rssi=-52, channel=39),
            MockPacket(summary="SMP Pairing Request", time=7000, rssi=-53, channel=5),
            MockPacket(summary="ATT Write Request", time=8000, rssi=-50, channel=5),
        ])
        result1 = analyze_connection_live([conn1, conn2], packets, connection_index=0)
        result2 = analyze_connection_live([conn1, conn2], packets, connection_index=1)

        # Connection 1: CONNECT_IND + ATT + L2CAP + LL_CONTROL (LL_TERMINATE)
        counts1 = result1["packet_type_counts"]
        assert counts1.get("CONNECT_IND", 0) == 1
        assert counts1.get("ATT", 0) == 1
        assert counts1.get("L2CAP", 0) == 1
        assert "SMP" not in counts1  # belongs to conn2

        # Connection 2: CONNECT_IND + SMP + ATT
        counts2 = result2["packet_type_counts"]
        assert counts2.get("CONNECT_IND", 0) == 1
        assert counts2.get("SMP", 0) == 1
        assert counts2.get("ATT", 0) == 1
        assert "L2CAP" not in counts2  # belongs to conn1

    def test_single_connection_backward_compatible(self):
        """Single connection still works as before."""
        connections = [MockConnection()]
        packets = MockPackets([
            MockPacket(summary="ADV_IND from AA:BB:CC:DD:EE:FF", time=1000, rssi=-55, channel=37),
            MockPacket(summary="CONNECT_IND to AA:BB:CC:DD:EE:FF", time=2000, rssi=-52, channel=39),
            MockPacket(summary="ATT Read Request", time=3000, rssi=-50, channel=5),
        ])
        result = analyze_connection_live(connections, packets, connection_index=0)
        counts = result["packet_type_counts"]
        assert "ADV_IND" not in counts
        assert counts.get("CONNECT_IND", 0) == 1
        assert counts.get("ATT", 0) == 1

    def test_no_boundaries_fallback(self):
        """When no CONNECT_IND found, falls back to address matching."""
        conn = MockConnection(
            _summary="0xABCD Central AA:BB:CC:DD:EE:FF Peripheral 11:22:33:44:55:66"
        )
        packets = MockPackets([
            MockPacket(summary="ADV_IND from AA:BB:CC:DD:EE:FF", time=1000, rssi=-55, channel=37),
            MockPacket(summary="ATT Read Request to AA:BB:CC:DD:EE:FF", time=3000, rssi=-50, channel=5),
            MockPacket(summary="SMP Request to CC:DD:EE:FF:00:11", time=4000, rssi=-53, channel=5),
        ])
        result = analyze_connection_live([conn], packets, connection_index=0)
        counts = result["packet_type_counts"]
        assert counts.get("ATT", 0) == 1  # has matching address
        assert "SMP" not in counts  # different address

    def test_mid_connection_single_conn_fallback(self):
        """When capture starts mid-connection (no CONNECT_IND), single connection
        should still get all non-ADV packets attributed to it."""
        conn = MockConnection(
            _summary="0xABCD Central AA:BB:CC:DD:EE:FF Peripheral 11:22:33:44:55:66"
        )
        # No CONNECT_IND in capture — simulates joining mid-connection.
        # Data packets don't contain addresses in summary, so address matching fails.
        packets = MockPackets([
            MockPacket(summary="ADV_IND from CC:DD:EE:FF:00:11", time=1000, rssi=-55, channel=37),
            MockPacket(summary="LE-U L2CAP Data ATT Read Request", time=2000, rssi=-50, channel=5),
            MockPacket(summary="LE-U L2CAP Data ATT Read Response", time=3000, rssi=-50, channel=5),
            MockPacket(summary="LE-U L2CAP Data", time=4000, rssi=-50, channel=5),
        ])
        result = analyze_connection_live([conn], packets, connection_index=0)
        counts = result["packet_type_counts"]
        # All non-ADV packets should be attributed via fallback
        assert counts.get("ATT", 0) == 2
        assert counts.get("L2CAP", 0) == 1
        assert "ADV_IND" not in counts

    def test_mid_connection_multi_conn_no_fallback(self):
        """With multiple connections and no boundaries, fallback should NOT fire
        (ambiguous which connection owns the packets)."""
        conn1 = MockConnection(
            _summary="0xABCD Central AA:BB:CC:DD:EE:FF Peripheral 11:22:33:44:55:66"
        )
        conn2 = MockConnection(
            _summary="0xDEF0 Central CC:DD:EE:FF:00:11 Peripheral 22:33:44:55:66:77"
        )
        packets = MockPackets([
            MockPacket(summary="LE-U L2CAP Data ATT Read Request", time=2000, rssi=-50, channel=5),
        ])
        result = analyze_connection_live([conn1, conn2], packets, connection_index=0)
        counts = result["packet_type_counts"]
        # Should be empty — no fallback for multi-connection
        assert len(counts) == 0

    def test_uses_cached_classified(self):
        """Should use pkt.classified when available (CachedPackets)."""
        from bluespy_mcp.packet_cache import CachedPackets, build_cache

        connections = [MockConnection()]
        raw = MockPackets([
            MockPacket(summary="ADV_IND from AA:BB:CC:DD:EE:FF", time=1000, rssi=-55, channel=37),
            MockPacket(summary="CONNECT_IND to AA:BB:CC:DD:EE:FF", time=2000, rssi=-52, channel=39),
            MockPacket(summary="ATT Read Request", time=3000, rssi=-50, channel=5),
        ])
        cached = CachedPackets(build_cache(raw))
        result = analyze_connection_live(connections, cached, connection_index=0)
        counts = result["packet_type_counts"]
        assert "ADV_IND" not in counts
        assert counts.get("CONNECT_IND", 0) == 1
        assert counts.get("ATT", 0) == 1


class TestAnalyzeAllConnections:
    def _make_multi_conn_data(self):
        conn1 = MockConnection(
            _summary="0xABCD Central AA:BB:CC:DD:EE:FF Peripheral 11:22:33:44:55:66"
        )
        conn2 = MockConnection(
            _summary="0xDEF0 Central CC:DD:EE:FF:00:11 Peripheral 22:33:44:55:66:77"
        )
        packets = MockPackets([
            MockPacket(summary="ADV_IND from AA:BB:CC:DD:EE:FF", time=1000, rssi=-55, channel=37),
            MockPacket(summary="CONNECT_IND to AA:BB:CC:DD:EE:FF", time=2000, rssi=-52, channel=39),
            MockPacket(summary="ATT Read Request", time=3000, rssi=-50, channel=5),
            MockPacket(summary="LL_TERMINATE_IND Reason: Remote", time=5000, rssi=-55, channel=5),
            MockPacket(summary="CONNECT_IND to CC:DD:EE:FF:00:11", time=6000, rssi=-52, channel=39),
            MockPacket(summary="SMP Pairing Request", time=7000, rssi=-53, channel=5),
        ])
        return [conn1, conn2], packets

    def test_basic_returns_all_connections(self):
        conns, pkts = self._make_multi_conn_data()
        result = analyze_all_connections(conns, pkts)
        assert result["total_connections"] == 2
        assert len(result["connections"]) == 2

    def test_empty_connections(self):
        result = analyze_all_connections([], MockPackets([]))
        assert result["total_connections"] == 0
        assert result["connections"] == []

    def test_matches_individual_counts(self):
        """Batch counts should match calling analyze_connection_live per connection."""
        conns, pkts = self._make_multi_conn_data()
        batch = analyze_all_connections(conns, pkts)
        for i, conn_result in enumerate(batch["connections"]):
            individual = analyze_connection_live(conns, pkts, connection_index=i)
            batch_counts = conn_result["packet_type_counts"]
            indiv_counts = individual["packet_type_counts"]
            assert batch_counts == indiv_counts, (
                f"Connection {i}: batch={batch_counts}, individual={indiv_counts}"
            )

    def test_mid_connection_single_conn_fallback(self):
        """Single connection with no CONNECT_IND should get all non-ADV packets."""
        conn = MockConnection(
            _summary="0xABCD Central AA:BB:CC:DD:EE:FF Peripheral 11:22:33:44:55:66"
        )
        packets = MockPackets([
            MockPacket(summary="ADV_IND from CC:DD:EE:FF:00:11", time=1000, rssi=-55, channel=37),
            MockPacket(summary="LE-U L2CAP Data ATT Read Request", time=2000, rssi=-50, channel=5),
            MockPacket(summary="LE-U L2CAP Data", time=3000, rssi=-50, channel=5),
        ])
        result = analyze_all_connections([conn], packets)
        counts = result["connections"][0]["packet_type_counts"]
        assert counts.get("ATT", 0) == 1
        assert counts.get("L2CAP", 0) == 1
        assert "ADV_IND" not in counts

    def test_mid_connection_multi_conn_no_fallback(self):
        """Multiple connections with no boundaries should NOT use fallback."""
        conn1 = MockConnection(
            _summary="0xABCD Central AA:BB:CC:DD:EE:FF Peripheral 11:22:33:44:55:66"
        )
        conn2 = MockConnection(
            _summary="0xDEF0 Central CC:DD:EE:FF:00:11 Peripheral 22:33:44:55:66:77"
        )
        packets = MockPackets([
            MockPacket(summary="LE-U L2CAP Data ATT Read Request", time=2000, rssi=-50, channel=5),
        ])
        result = analyze_all_connections([conn1, conn2], packets)
        # With 2 connections and no boundaries, no fallback — counts stay empty
        assert result["connections"][0]["packet_type_counts"] == {}
        assert result["connections"][1]["packet_type_counts"] == {}


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


class TestAnalyzeAllAdvertising:
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

    def test_basic_returns_all_devices(self):
        devs, pkts = self._make_data()
        result = analyze_all_advertising(devs, pkts)
        assert result["total_devices"] == 2
        assert len(result["devices"]) == 2
        # First device has 2 ADV packets
        dev0 = result["devices"][0]
        assert dev0["address"] == "AA:BB:CC:DD:EE:FF"
        assert dev0["advertisement_count"] == 2
        # Second device has 1 ADV packet
        dev1 = result["devices"][1]
        assert dev1["address"] == "11:22:33:44:55:66"
        assert dev1["advertisement_count"] == 1

    def test_empty_packets(self):
        devices = [MockDevice(), MockDevice(_address="11:22:33:44:55:66")]
        result = analyze_all_advertising(devices, MockPackets([]))
        assert result["total_devices"] == 2
        for dev in result["devices"]:
            assert dev["advertisement_count"] == 0

    def test_no_devices(self):
        result = analyze_all_advertising([], MockPackets([]))
        assert result["total_devices"] == 0
        assert result["devices"] == []

    def test_rssi_stats(self):
        devs, pkts = self._make_data()
        result = analyze_all_advertising(devs, pkts)
        dev0 = result["devices"][0]
        assert dev0["rssi_min"] == -60
        assert dev0["rssi_max"] == -55
        assert dev0["rssi_avg"] == -57.5
        dev1 = result["devices"][1]
        assert dev1["rssi_min"] == -70
        assert dev1["rssi_max"] == -70
        assert dev1["rssi_avg"] == -70.0

    def test_sample_limit(self):
        devices = [MockDevice()]
        packets = MockPackets([
            MockPacket(summary=f"ADV_IND from AA:BB:CC:DD:EE:FF #{i}", time=i * 1000, rssi=-55, channel=37)
            for i in range(30)
        ])
        result = analyze_all_advertising(devices, packets)
        dev = result["devices"][0]
        assert dev["advertisement_count"] == 30
        assert len(dev["advertisements_sample"]) == 10  # capped at 10

    def test_matches_individual_counts(self):
        """Batch counts should match calling analyze_advertising_live per device."""
        devs, pkts = self._make_data()
        batch = analyze_all_advertising(devs, pkts)
        for i, dev in enumerate(batch["devices"]):
            individual = analyze_advertising_live(devs, pkts, device_index=i)
            assert dev["advertisement_count"] == individual["advertisement_count"], (
                f"Device {i} ({dev['address']}): batch={dev['advertisement_count']}, "
                f"individual={individual['advertisement_count']}"
            )

    def test_channels_used(self):
        devs, pkts = self._make_data()
        result = analyze_all_advertising(devs, pkts)
        dev0 = result["devices"][0]
        assert 37 in dev0["channels_used"]
        assert 38 in dev0["channels_used"]
        dev1 = result["devices"][1]
        assert 39 in dev1["channels_used"]


class TestEnrichDeviceNames:
    """Tests for enrich_device_names — extracting names from packet summaries."""

    def test_extracts_name_from_scan_rsp(self):
        devices = [{"address": "AA:BB:CC:DD:EE:FF", "name": ""}]
        packets = MockPackets([
            MockPacket("SCAN_RSP (nRF54L15 HRM) AA:BB:CC:DD:EE:FF", 37),
        ])
        result = enrich_device_names(devices, packets)
        assert result[0]["name"] == "nRF54L15 HRM"

    def test_extracts_name_from_adv_ind(self):
        devices = [{"address": "11:22:33:44:55:66", "name": ""}]
        packets = MockPackets([
            MockPacket("ADV_IND (MyDevice) 11:22:33:44:55:66", 37),
        ])
        result = enrich_device_names(devices, packets)
        assert result[0]["name"] == "MyDevice"

    def test_skips_devices_that_already_have_names(self):
        devices = [{"address": "AA:BB:CC:DD:EE:FF", "name": "Existing"}]
        packets = MockPackets([
            MockPacket("SCAN_RSP (NewName) AA:BB:CC:DD:EE:FF", 37),
        ])
        result = enrich_device_names(devices, packets)
        assert result[0]["name"] == "Existing"

    def test_skips_non_advertising_packets(self):
        devices = [{"address": "AA:BB:CC:DD:EE:FF", "name": ""}]
        packets = MockPackets([
            MockPacket("LE-U L2CAP Data (SomeName) AA:BB:CC:DD:EE:FF", 0),
        ])
        result = enrich_device_names(devices, packets)
        assert result[0]["name"] == ""

    def test_no_match_when_address_differs(self):
        devices = [{"address": "AA:BB:CC:DD:EE:FF", "name": ""}]
        packets = MockPackets([
            MockPacket("SCAN_RSP (OtherDevice) 11:22:33:44:55:66", 37),
        ])
        result = enrich_device_names(devices, packets)
        assert result[0]["name"] == ""

    def test_enriches_multiple_devices(self):
        devices = [
            {"address": "AA:BB:CC:DD:EE:FF", "name": ""},
            {"address": "11:22:33:44:55:66", "name": ""},
        ]
        packets = MockPackets([
            MockPacket("SCAN_RSP (Device1) AA:BB:CC:DD:EE:FF", 37),
            MockPacket("ADV_IND (Device2) 11:22:33:44:55:66", 38),
        ])
        result = enrich_device_names(devices, packets)
        assert result[0]["name"] == "Device1"
        assert result[1]["name"] == "Device2"

    def test_stops_early_when_all_names_found(self):
        devices = [{"address": "AA:BB:CC:DD:EE:FF", "name": ""}]
        packets = MockPackets([
            MockPacket("SCAN_RSP (Found) AA:BB:CC:DD:EE:FF", 37),
            MockPacket("SCAN_RSP (Later) AA:BB:CC:DD:EE:FF", 37),
        ])
        result = enrich_device_names(devices, packets)
        assert result[0]["name"] == "Found"

    def test_returns_unchanged_when_all_have_names(self):
        devices = [{"address": "AA:BB:CC:DD:EE:FF", "name": "Already"}]
        packets = MockPackets([])
        result = enrich_device_names(devices, packets)
        assert result[0]["name"] == "Already"

    def test_case_insensitive_address_matching(self):
        devices = [{"address": "aa:bb:cc:dd:ee:ff", "name": ""}]
        packets = MockPackets([
            MockPacket("SCAN_RSP (CaseTest) AA:BB:CC:DD:EE:FF", 37),
        ])
        result = enrich_device_names(devices, packets)
        assert result[0]["name"] == "CaseTest"

    def test_handles_empty_devices_list(self):
        result = enrich_device_names([], MockPackets([]))
        assert result == []

    def test_handles_empty_packets(self):
        devices = [{"address": "AA:BB:CC:DD:EE:FF", "name": ""}]
        result = enrich_device_names(devices, MockPackets([]))
        assert result[0]["name"] == ""

    def test_adds_name_hint_when_no_name_found(self):
        devices = [{"address": "AA:BB:CC:DD:EE:FF", "name": ""}]
        packets = MockPackets([
            MockPacket("ADV_IND AA:BB:CC:DD:EE:FF", 37),
        ])
        result = enrich_device_names(devices, packets)
        assert result[0]["name"] == ""
        assert "name_hint" in result[0]
        assert "Scan Response" in result[0]["name_hint"]

    def test_no_name_hint_when_name_found(self):
        devices = [{"address": "AA:BB:CC:DD:EE:FF", "name": ""}]
        packets = MockPackets([
            MockPacket("SCAN_RSP (MyDevice) AA:BB:CC:DD:EE:FF", 37),
        ])
        result = enrich_device_names(devices, packets)
        assert result[0]["name"] == "MyDevice"
        assert "name_hint" not in result[0]

    def test_no_name_hint_when_already_named(self):
        devices = [{"address": "AA:BB:CC:DD:EE:FF", "name": "Known"}]
        result = enrich_device_names(devices, MockPackets([]))
        assert "name_hint" not in result[0]


class TestEnrichDeviceRssi:
    """Tests for enrich_device_rssi — per-device RSSI stats from packets."""

    def test_computes_rssi_stats(self):
        devices = [{"address": "AA:BB:CC:DD:EE:FF"}]
        packets = MockPackets([
            MockPacket("ADV_IND AA:BB:CC:DD:EE:FF", 37, rssi=-50),
            MockPacket("ADV_IND AA:BB:CC:DD:EE:FF", 38, rssi=-60),
            MockPacket("ADV_IND AA:BB:CC:DD:EE:FF", 39, rssi=-70),
        ])
        result = enrich_device_rssi(devices, packets)
        assert result[0]["rssi_min"] == -70
        assert result[0]["rssi_max"] == -50
        assert result[0]["rssi_avg"] == -60.0

    def test_skips_non_advertising_packets(self):
        devices = [{"address": "AA:BB:CC:DD:EE:FF"}]
        packets = MockPackets([
            MockPacket("ADV_IND AA:BB:CC:DD:EE:FF", 37, rssi=-50),
            MockPacket("LE-U L2CAP Data AA:BB:CC:DD:EE:FF", 5, rssi=-30),
        ])
        result = enrich_device_rssi(devices, packets)
        assert result[0]["rssi_min"] == -50
        assert result[0]["rssi_max"] == -50

    def test_separates_devices(self):
        devices = [
            {"address": "AA:BB:CC:DD:EE:FF"},
            {"address": "11:22:33:44:55:66"},
        ]
        packets = MockPackets([
            MockPacket("ADV_IND AA:BB:CC:DD:EE:FF", 37, rssi=-40),
            MockPacket("ADV_IND 11:22:33:44:55:66", 37, rssi=-80),
        ])
        result = enrich_device_rssi(devices, packets)
        assert result[0]["rssi_avg"] == -40.0
        assert result[1]["rssi_avg"] == -80.0

    def test_no_rssi_when_no_matching_packets(self):
        devices = [{"address": "AA:BB:CC:DD:EE:FF"}]
        packets = MockPackets([
            MockPacket("ADV_IND 11:22:33:44:55:66", 37, rssi=-50),
        ])
        result = enrich_device_rssi(devices, packets)
        assert "rssi_min" not in result[0]

    def test_empty_packets(self):
        devices = [{"address": "AA:BB:CC:DD:EE:FF"}]
        result = enrich_device_rssi(devices, MockPackets([]))
        assert "rssi_min" not in result[0]

    def test_empty_devices(self):
        result = enrich_device_rssi([], MockPackets([]))
        assert result == []


class TestParseAdStructures:
    """Tests for parse_ad_structures — Bluetooth LE AD type-length-value parsing."""

    def test_parse_16bit_service_uuids(self):
        # AD: length=5, type=0x03 (complete 16-bit UUIDs), data=0x0D18 0x4518
        payload = bytes([5, 0x03, 0x0D, 0x18, 0x45, 0x18])
        result = parse_ad_structures(payload)
        assert result["service_uuids"] == ["0x180D", "0x1845"]

    def test_parse_complete_local_name(self):
        name = "nRF54L15 HRM"
        name_bytes = name.encode("utf-8")
        payload = bytes([1 + len(name_bytes), 0x09]) + name_bytes
        result = parse_ad_structures(payload)
        assert result["local_name"] == "nRF54L15 HRM"
        assert "local_name_shortened" not in result

    def test_parse_shortened_local_name(self):
        name = "nRF54"
        name_bytes = name.encode("utf-8")
        payload = bytes([1 + len(name_bytes), 0x08]) + name_bytes
        result = parse_ad_structures(payload)
        assert result["local_name"] == "nRF54"
        assert result["local_name_shortened"] is True

    def test_parse_tx_power_level(self):
        # AD: length=2, type=0x0A, data=-10 dBm (0xF6 signed)
        payload = bytes([2, 0x0A, 0xF6])
        result = parse_ad_structures(payload)
        assert result["tx_power_dbm"] == -10

    def test_parse_manufacturer_data_apple(self):
        # AD: length=5, type=0xFF, company_id=0x004C (Apple), data=0x0102
        payload = bytes([5, 0xFF, 0x4C, 0x00, 0x01, 0x02])
        result = parse_ad_structures(payload)
        assert result["manufacturer_data"]["company_id"] == "0x004C"
        assert result["manufacturer_data"]["company_name"] == "Apple"
        assert result["manufacturer_data"]["data_hex"] == "0102"

    def test_parse_manufacturer_data_unknown_company(self):
        # Unknown company ID
        payload = bytes([4, 0xFF, 0xAB, 0xCD, 0x01])
        result = parse_ad_structures(payload)
        assert result["manufacturer_data"]["company_id"] == "0xCDAB"
        assert "company_name" not in result["manufacturer_data"]

    def test_parse_flags(self):
        # AD: length=2, type=0x01 (flags), data=0x06 (LE General + BR/EDR Not Supported)
        payload = bytes([2, 0x01, 0x06])
        result = parse_ad_structures(payload)
        assert result["flags"] == 0x06

    def test_parse_multiple_ad_structures(self):
        # Flags + 16-bit UUID + Complete Local Name
        flags = bytes([2, 0x01, 0x06])
        uuids = bytes([3, 0x03, 0x0D, 0x18])
        name = b"HRM"
        name_ad = bytes([1 + len(name), 0x09]) + name
        payload = flags + uuids + name_ad
        result = parse_ad_structures(payload)
        assert result["flags"] == 0x06
        assert result["service_uuids"] == ["0x180D"]
        assert result["local_name"] == "HRM"

    def test_parse_empty_payload(self):
        result = parse_ad_structures(b"")
        assert result == {}

    def test_parse_zero_length_stops(self):
        # Zero length byte stops parsing
        payload = bytes([2, 0x01, 0x06, 0, 0xFF, 0xFF])
        result = parse_ad_structures(payload)
        assert result["flags"] == 0x06
        assert "manufacturer_data" not in result

    def test_parse_128bit_uuid(self):
        # 128-bit UUID in little-endian (as broadcast over the air)
        # Big-endian (standard): 00000d0d-0000-1000-8000-00805f9b34fb
        # = 00000d0d 0000 1000 8000 00805f9b34fb as bytes
        uuid_be = bytes.fromhex("00000d0d00001000800000805f9b34fb")
        uuid_le = uuid_be[::-1]  # Reverse for little-endian
        payload = bytes([17, 0x07]) + uuid_le
        result = parse_ad_structures(payload)
        assert len(result["service_uuids"]) == 1
        assert result["service_uuids"][0] == "00000d0d-0000-1000-8000-00805f9b34fb"


class TestExtractAddressType:
    """Tests for _extract_address_type — parsing device summary address types."""

    def test_static_address(self):
        info = {"address_type": ""}
        _extract_address_type(info, "AA:BB:CC:DD:EE:FF, Static")
        assert info["address_type"] == "Random Static"

    def test_public_address(self):
        info = {"address_type": ""}
        _extract_address_type(info, "AA:BB:CC:DD:EE:FF, Public")
        assert info["address_type"] == "Public"

    def test_random_address(self):
        info = {"address_type": ""}
        _extract_address_type(info, "AA:BB:CC:DD:EE:FF, Random")
        assert info["address_type"] == "Random"

    def test_resolvable_address(self):
        info = {"address_type": ""}
        _extract_address_type(info, "AA:BB:CC:DD:EE:FF, Resolvable")
        assert info["address_type"] == "Random Resolvable"

    def test_no_comma(self):
        info = {"address_type": ""}
        _extract_address_type(info, "AA:BB:CC:DD:EE:FF")
        assert info["address_type"] == ""

    def test_unknown_type(self):
        info = {"address_type": ""}
        _extract_address_type(info, "AA:BB:CC:DD:EE:FF, SomethingNew")
        assert info["address_type"] == ""


class TestConstants:
    def test_summary_packet_limit(self):
        assert SUMMARY_PACKET_LIMIT == 50_000

    def test_error_keywords(self):
        assert "ERROR" in ERROR_KEYWORDS
        assert "TERMINATE" in ERROR_KEYWORDS
        assert len(ERROR_KEYWORDS) > 0
