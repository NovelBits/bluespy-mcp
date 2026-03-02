"""Packet index cache — eliminates redundant ctypes FFI calls.

Extracts packet metadata once into parallel Python lists, then wraps
them in CachedPacket/CachedPackets classes that satisfy the same
duck-type interface as real BlueSPY packets. Analysis functions in
analysis_core.py work unchanged.

One-time cost on load/capture, near-instant analysis tool calls after.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from bluespy_mcp.analysis_core import ERROR_KEYWORDS, classify_packet


@dataclass
class PacketCache:
    """Parallel arrays of extracted packet metadata."""

    summaries: list[str] = field(default_factory=list)
    times: list[int] = field(default_factory=list)
    rssis: list[int] = field(default_factory=list)
    channels: list[int] = field(default_factory=list)
    payloads: list[bytes | None] = field(default_factory=list)
    classified: list[str] = field(default_factory=list)
    error_indices: list[int] = field(default_factory=list)
    type_index: dict[str, list[int]] = field(default_factory=dict)


class CachedPacket:
    """Single-packet view into the cache by index.

    Provides the same duck-type interface as BlueSPY event_id objects:
    .summary, .time, .rssi, .channel properties and .query()/.query_str().
    """

    __slots__ = ("_cache", "_index")

    def __init__(self, cache: PacketCache, index: int):
        self._cache = cache
        self._index = index

    @property
    def summary(self) -> str:
        return self._cache.summaries[self._index]

    @property
    def time(self) -> int:
        return self._cache.times[self._index]

    @property
    def rssi(self) -> int:
        return self._cache.rssis[self._index]

    @property
    def channel(self) -> int:
        return self._cache.channels[self._index]

    @property
    def classified(self) -> str:
        return self._cache.classified[self._index]

    def query(self, name: str):
        if name == "payload":
            return self._cache.payloads[self._index]
        if name == "summary":
            return self.summary
        if name == "time":
            return self.time
        if name == "rssi":
            return self.rssi
        if name == "channel":
            return self.channel
        if name == "classified":
            return self.classified
        raise AttributeError(f"No cached field: {name}")

    def query_str(self, name: str) -> str:
        return str(self.query(name))


class CachedPackets:
    """List-like wrapper over PacketCache.

    Supports len(), __getitem__, __iter__ — same interface as
    bluespy.packets and MockPackets.
    """

    __slots__ = ("_cache",)

    def __init__(self, cache: PacketCache):
        self._cache = cache

    def __len__(self) -> int:
        return len(self._cache.summaries)

    def __getitem__(self, index):
        if isinstance(index, slice):
            indices = range(*index.indices(len(self)))
            return [CachedPacket(self._cache, i) for i in indices]
        if index < 0:
            index += len(self)
        return CachedPacket(self._cache, index)

    def __iter__(self):
        for i in range(len(self)):
            yield CachedPacket(self._cache, i)


def build_cache(packets) -> PacketCache:
    """Build a PacketCache by iterating all raw packets once.

    Each packet's .summary, .time, .rssi, .channel, and .query("payload")
    are extracted via ctypes FFI exactly once. Failed extractions get
    safe defaults.
    """
    n = len(packets)
    summaries = []
    times = []
    rssis = []
    channels = []
    payloads = []
    classified = []
    error_indices = []

    for i in range(n):
        pkt = packets[i]

        try:
            s = pkt.summary
        except Exception:
            s = ""
        summaries.append(s)

        try:
            times.append(int(pkt.time))
        except Exception:
            times.append(0)

        try:
            rssis.append(int(pkt.rssi))
        except Exception:
            rssis.append(0)

        try:
            channels.append(int(pkt.channel))
        except Exception:
            channels.append(0)

        try:
            p = pkt.query("payload")
            payloads.append(p if isinstance(p, bytes) else None)
        except Exception:
            payloads.append(None)

        classified.append(classify_packet(s))

        s_upper = s.upper()
        if any(kw in s_upper for kw in ERROR_KEYWORDS):
            error_indices.append(i)

    type_index: dict[str, list[int]] = {}
    for i, pkt_type in enumerate(classified):
        type_index.setdefault(pkt_type, []).append(i)

    return PacketCache(summaries, times, rssis, channels, payloads, classified, error_indices, type_index)


def extend_cache(cache: PacketCache, packets, from_index: int) -> None:
    """Extend an existing cache with new packets (for live capture).

    Appends packets from from_index to len(packets) into the cache's
    parallel arrays.
    """
    n = len(packets)
    for i in range(from_index, n):
        pkt = packets[i]

        try:
            s = pkt.summary
        except Exception:
            s = ""
        cache.summaries.append(s)

        try:
            cache.times.append(int(pkt.time))
        except Exception:
            cache.times.append(0)

        try:
            cache.rssis.append(int(pkt.rssi))
        except Exception:
            cache.rssis.append(0)

        try:
            cache.channels.append(int(pkt.channel))
        except Exception:
            cache.channels.append(0)

        try:
            p = pkt.query("payload")
            cache.payloads.append(p if isinstance(p, bytes) else None)
        except Exception:
            cache.payloads.append(None)

        pkt_type = classify_packet(s)
        cache.classified.append(pkt_type)
        cache.type_index.setdefault(pkt_type, []).append(i)

        s_upper = s.upper()
        if any(kw in s_upper for kw in ERROR_KEYWORDS):
            cache.error_indices.append(i)
