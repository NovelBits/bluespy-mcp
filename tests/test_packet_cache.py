"""Tests for the packet index cache."""

import pytest

from bluespy_mcp.analysis_core import (
    classify_packet,
    summarize_packets,
    filter_packets,
    find_error_packets,
    analyze_connection_live,
    analyze_advertising_live,
)
from bluespy_mcp.packet_cache import (
    PacketCache,
    CachedPacket,
    CachedPackets,
    build_cache,
    extend_cache,
)
from tests.conftest import MockPacket, MockPackets, MockDevice, MockConnection


def _sample_packets():
    """Create sample MockPackets for testing."""
    return MockPackets([
        MockPacket(summary="ADV_IND from AA:BB:CC:DD:EE:FF", time=1000000, rssi=-55, channel=37),
        MockPacket(summary="ADV_IND from AA:BB:CC:DD:EE:FF", time=1100000, rssi=-58, channel=38),
        MockPacket(summary="SCAN_REQ to AA:BB:CC:DD:EE:FF", time=1200000, rssi=-60, channel=37),
        MockPacket(summary="CONNECT_IND to AA:BB:CC:DD:EE:FF", time=2000000, rssi=-52, channel=39),
        MockPacket(summary="ATT Read Request", time=3000000, rssi=-50, channel=5),
        MockPacket(
            summary="LL_TERMINATE_IND Reason: Remote User Terminated",
            time=5000000, rssi=-55, channel=5,
        ),
    ])


class TestBuildCache:
    def test_build_cache_from_mock_packets(self):
        packets = _sample_packets()
        cache = build_cache(packets)
        assert len(cache.summaries) == 6
        assert len(cache.times) == 6
        assert len(cache.rssis) == 6
        assert len(cache.channels) == 6
        assert len(cache.payloads) == 6
        assert len(cache.classified) == 6

    def test_build_cache_values(self):
        packets = _sample_packets()
        cache = build_cache(packets)
        assert cache.summaries[0] == "ADV_IND from AA:BB:CC:DD:EE:FF"
        assert cache.times[0] == 1000000
        assert cache.rssis[0] == -55
        assert cache.channels[0] == 37
        assert cache.classified[0] == "ADV_IND"

    def test_build_cache_empty(self):
        cache = build_cache(MockPackets([]))
        assert len(cache.summaries) == 0
        assert len(cache.times) == 0

    def test_build_cache_with_payload(self):
        payload = b"\x00\x06\xaa\xbb\xcc\xdd\xee\xff"
        packets = MockPackets([
            MockPacket(summary="ADV_IND", time=1000, rssi=-55, channel=37, payload=payload),
        ])
        cache = build_cache(packets)
        assert cache.payloads[0] == payload

    def test_build_cache_no_payload(self):
        packets = MockPackets([
            MockPacket(summary="ADV_IND", time=1000, rssi=-55, channel=37),
        ])
        cache = build_cache(packets)
        assert cache.payloads[0] is None

    def test_classified_precomputed(self):
        packets = MockPackets([
            MockPacket(summary="ADV_IND test", time=0, rssi=0, channel=37),
            MockPacket(summary="ATT Read Request", time=0, rssi=0, channel=5),
            MockPacket(summary="Something unknown", time=0, rssi=0, channel=0),
        ])
        cache = build_cache(packets)
        assert cache.classified[0] == "ADV_IND"
        assert cache.classified[1] == "ATT"
        assert cache.classified[2] == "OTHER"


class TestCachedPacket:
    def test_properties(self):
        cache = build_cache(_sample_packets())
        pkt = CachedPacket(cache, 0)
        assert pkt.summary == "ADV_IND from AA:BB:CC:DD:EE:FF"
        assert pkt.time == 1000000
        assert pkt.rssi == -55
        assert pkt.channel == 37

    def test_query_payload(self):
        payload = b"\xde\xad\xbe\xef"
        packets = MockPackets([
            MockPacket(summary="ADV_IND", time=0, rssi=0, channel=37, payload=payload),
        ])
        cache = build_cache(packets)
        pkt = CachedPacket(cache, 0)
        assert pkt.query("payload") == payload

    def test_query_named_fields(self):
        cache = build_cache(_sample_packets())
        pkt = CachedPacket(cache, 0)
        assert pkt.query("summary") == pkt.summary
        assert pkt.query("time") == pkt.time
        assert pkt.query("rssi") == pkt.rssi
        assert pkt.query("channel") == pkt.channel

    def test_query_unknown_field_raises(self):
        cache = build_cache(_sample_packets())
        pkt = CachedPacket(cache, 0)
        with pytest.raises(AttributeError, match="No cached field"):
            pkt.query("nonexistent")

    def test_query_str(self):
        cache = build_cache(_sample_packets())
        pkt = CachedPacket(cache, 0)
        assert pkt.query_str("time") == str(1000000)


class TestCachedPackets:
    def test_len(self):
        cache = build_cache(_sample_packets())
        cached = CachedPackets(cache)
        assert len(cached) == 6

    def test_getitem(self):
        cache = build_cache(_sample_packets())
        cached = CachedPackets(cache)
        assert cached[0].summary == "ADV_IND from AA:BB:CC:DD:EE:FF"
        assert cached[4].summary == "ATT Read Request"

    def test_getitem_negative(self):
        cache = build_cache(_sample_packets())
        cached = CachedPackets(cache)
        assert cached[-1].summary == "LL_TERMINATE_IND Reason: Remote User Terminated"

    def test_getitem_slice(self):
        cache = build_cache(_sample_packets())
        cached = CachedPackets(cache)
        sliced = cached[1:3]
        assert len(sliced) == 2
        assert sliced[0].summary == "ADV_IND from AA:BB:CC:DD:EE:FF"
        assert sliced[1].summary == "SCAN_REQ to AA:BB:CC:DD:EE:FF"

    def test_iter(self):
        cache = build_cache(_sample_packets())
        cached = CachedPackets(cache)
        summaries = [p.summary for p in cached]
        assert len(summaries) == 6
        assert summaries[0] == "ADV_IND from AA:BB:CC:DD:EE:FF"

    def test_empty(self):
        cache = build_cache(MockPackets([]))
        cached = CachedPackets(cache)
        assert len(cached) == 0
        assert list(cached) == []


class TestExtendCache:
    def test_extend_adds_new_packets(self):
        packets = _sample_packets()
        # Build cache from first 3 packets
        cache = build_cache(MockPackets(list(packets._packets[:3])))
        assert len(cache.summaries) == 3

        # Extend with the full set (packets 3-5 are new)
        extend_cache(cache, packets, 3)
        assert len(cache.summaries) == 6
        assert cache.summaries[3] == "CONNECT_IND to AA:BB:CC:DD:EE:FF"
        assert cache.times[3] == 2000000

    def test_extend_noop_when_up_to_date(self):
        packets = _sample_packets()
        cache = build_cache(packets)
        original_len = len(cache.summaries)
        extend_cache(cache, packets, original_len)
        assert len(cache.summaries) == original_len


class TestAnalysisCoreWithCachedPackets:
    """Verify analysis_core functions produce identical results with CachedPackets."""

    def test_summarize_packets(self):
        raw = _sample_packets()
        cached = CachedPackets(build_cache(raw))

        raw_result = summarize_packets(raw)
        cached_result = summarize_packets(cached)

        assert raw_result == cached_result

    def test_summarize_packets_with_limit(self):
        raw = _sample_packets()
        cached = CachedPackets(build_cache(raw))

        raw_result = summarize_packets(raw, limit=3)
        cached_result = summarize_packets(cached, limit=3)

        assert raw_result == cached_result

    def test_filter_packets_no_filter(self):
        raw = _sample_packets()
        cached = CachedPackets(build_cache(raw))

        raw_result = filter_packets(raw)
        cached_result = filter_packets(cached)

        assert raw_result == cached_result

    def test_filter_packets_by_channel(self):
        raw = _sample_packets()
        cached = CachedPackets(build_cache(raw))

        raw_result = filter_packets(raw, channel=37)
        cached_result = filter_packets(cached, channel=37)

        assert raw_result == cached_result

    def test_filter_packets_by_type(self):
        raw = _sample_packets()
        cached = CachedPackets(build_cache(raw))

        raw_result = filter_packets(raw, packet_type="ADV_IND")
        cached_result = filter_packets(cached, packet_type="ADV_IND")

        assert raw_result == cached_result

    def test_filter_packets_by_summary(self):
        raw = _sample_packets()
        cached = CachedPackets(build_cache(raw))

        raw_result = filter_packets(raw, summary_contains="ATT")
        cached_result = filter_packets(cached, summary_contains="ATT")

        assert raw_result == cached_result

    def test_find_error_packets(self):
        raw = _sample_packets()
        cached = CachedPackets(build_cache(raw))

        raw_result = find_error_packets(raw)
        cached_result = find_error_packets(cached)

        assert raw_result == cached_result

    def test_analyze_connection_live(self):
        connections = [MockConnection()]
        raw = _sample_packets()
        cached = CachedPackets(build_cache(raw))

        raw_result = analyze_connection_live(connections, raw)
        cached_result = analyze_connection_live(connections, cached)

        assert raw_result == cached_result

    def test_analyze_advertising_live(self):
        devices = [MockDevice()]
        raw = _sample_packets()
        cached = CachedPackets(build_cache(raw))

        raw_result = analyze_advertising_live(devices, raw)
        cached_result = analyze_advertising_live(devices, cached)

        assert raw_result == cached_result


class TestCachedClassifiedProperty:
    """Verify the classified property on CachedPacket works."""

    def test_classified_property(self):
        cache = build_cache(_sample_packets())
        pkt = CachedPacket(cache, 0)
        assert pkt.classified == "ADV_IND"

    def test_classified_query(self):
        cache = build_cache(_sample_packets())
        pkt = CachedPacket(cache, 0)
        assert pkt.query("classified") == "ADV_IND"

    def test_classified_matches_classify_packet(self):
        raw = _sample_packets()
        cache = build_cache(raw)
        for i in range(len(raw)):
            expected = classify_packet(raw[i].summary)
            assert CachedPacket(cache, i).classified == expected


class TestErrorIndicesPrecomputed:
    """Verify error_indices are populated during cache build."""

    def test_error_indices_populated(self):
        cache = build_cache(_sample_packets())
        # _sample_packets has LL_TERMINATE_IND at index 5
        assert 5 in cache.error_indices

    def test_error_indices_empty_for_no_errors(self):
        packets = MockPackets([
            MockPacket(summary="ADV_IND", time=1000, rssi=-55, channel=37),
            MockPacket(summary="ATT Read Request", time=2000, rssi=-50, channel=5),
        ])
        cache = build_cache(packets)
        assert cache.error_indices == []

    def test_error_indices_multiple_errors(self):
        packets = MockPackets([
            MockPacket(summary="ADV_IND", time=1000, rssi=-55, channel=37),
            MockPacket(summary="CRC ERROR", time=2000, rssi=-55, channel=37),
            MockPacket(summary="ATT Read Request", time=3000, rssi=-50, channel=5),
            MockPacket(summary="LL_TERMINATE_IND Reason: TIMEOUT", time=4000, rssi=-55, channel=5),
        ])
        cache = build_cache(packets)
        assert cache.error_indices == [1, 3]

    def test_find_error_packets_uses_precomputed(self):
        """Cached path should produce same results as raw path."""
        raw = _sample_packets()
        cached = CachedPackets(build_cache(raw))
        raw_result = find_error_packets(raw)
        cached_result = find_error_packets(cached)
        assert raw_result == cached_result

    def test_find_error_packets_cached_with_start(self):
        packets = MockPackets([
            MockPacket(summary="ERROR at 0", time=1000, rssi=-55, channel=37),
            MockPacket(summary="ADV_IND", time=2000, rssi=-55, channel=37),
            MockPacket(summary="TIMEOUT at 2", time=3000, rssi=-55, channel=5),
        ])
        cached = CachedPackets(build_cache(packets))
        errors = find_error_packets(cached, start=1)
        assert len(errors) == 1
        assert errors[0]["index"] == 2

    def test_find_error_packets_cached_max_results(self):
        packets = MockPackets([
            MockPacket(summary=f"ERROR #{i}", time=i * 1000, rssi=-55, channel=37)
            for i in range(10)
        ])
        cached = CachedPackets(build_cache(packets))
        errors = find_error_packets(cached, max_results=3)
        assert len(errors) == 3

    def test_extend_cache_adds_error_indices(self):
        packets = MockPackets([
            MockPacket(summary="ADV_IND", time=1000, rssi=-55, channel=37),
        ])
        cache = build_cache(packets)
        assert cache.error_indices == []

        more = MockPackets([
            MockPacket(summary="ADV_IND", time=1000, rssi=-55, channel=37),
            MockPacket(summary="DISCONNECT event", time=2000, rssi=-55, channel=5),
        ])
        extend_cache(cache, more, 1)
        assert 1 in cache.error_indices


class TestTypeIndex:
    """Verify type_index is built and maintained correctly."""

    def test_type_index_populated(self):
        cache = build_cache(_sample_packets())
        assert "ADV_IND" in cache.type_index
        assert len(cache.type_index["ADV_IND"]) == 2
        assert "SCAN_REQ" in cache.type_index
        assert len(cache.type_index["SCAN_REQ"]) == 1
        assert "ATT" in cache.type_index
        assert len(cache.type_index["ATT"]) == 1

    def test_type_index_empty(self):
        cache = build_cache(MockPackets([]))
        assert cache.type_index == {}

    def test_type_index_after_extend(self):
        packets = MockPackets([
            MockPacket(summary="ADV_IND from AA:BB", time=1000, rssi=-55, channel=37),
        ])
        cache = build_cache(packets)
        assert len(cache.type_index["ADV_IND"]) == 1

        more = MockPackets([
            MockPacket(summary="ADV_IND from AA:BB", time=1000, rssi=-55, channel=37),
            MockPacket(summary="ATT Read Request", time=2000, rssi=-50, channel=5),
        ])
        extend_cache(cache, more, 1)
        assert len(cache.type_index["ADV_IND"]) == 1  # not re-indexed
        assert len(cache.type_index["ATT"]) == 1
        assert cache.type_index["ATT"] == [1]

    def test_filter_uses_type_index(self):
        """Type index fast path should return same results as full scan."""
        raw = _sample_packets()
        cached = CachedPackets(build_cache(raw))

        raw_result = filter_packets(raw, packet_type="ADV_IND")
        cached_result = filter_packets(cached, packet_type="ADV_IND")

        assert raw_result == cached_result

    def test_filter_type_and_channel_uses_index(self):
        """Type index fast path with additional channel filter."""
        raw = _sample_packets()
        cached = CachedPackets(build_cache(raw))

        raw_result = filter_packets(raw, packet_type="ADV_IND", channel=37)
        cached_result = filter_packets(cached, packet_type="ADV_IND", channel=37)

        assert raw_result == cached_result
