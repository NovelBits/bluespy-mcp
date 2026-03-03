"""Shared packet analysis functions — no CaptureManager dependency.

These functions operate on raw blueSPY objects (event_id, device_id,
connection_id) that support attribute access (.summary, .channel, .rssi,
.time) and .query()/.query_str() methods.

Used by:
- analyzer.py (file-based analysis via CaptureManager)
- worker.py (live capture analysis in subprocess)
"""

from __future__ import annotations

import re
from typing import Any

# Maximum packets to iterate for summary (prevents hanging on huge captures)
SUMMARY_PACKET_LIMIT = 50_000

ERROR_KEYWORDS = [
    "ERROR", "FAIL", "REJECT", "TIMEOUT", "DISCONNECT",
    "UNKNOWN", "INVALID", "REFUSED", "TERMINATE",
]


def classify_packet(summary: str) -> str:
    """Classify a packet based on its summary string.

    Checks longer/more-specific names first to avoid substring collisions
    (e.g., AUX_ADV_IND contains ADV_IND).
    """
    s = summary.upper()

    # Extended advertising (check before base types)
    if "AUX_ADV_IND" in s:
        return "AUX_ADV_IND"
    if "AUX_CONNECT_RSP" in s:
        return "AUX_CONNECT_RSP"
    if "AUX_SCAN_RSP" in s:
        return "AUX_SCAN_RSP"
    if "AUX_SCAN_REQ" in s:
        return "AUX_SCAN_REQ"
    if "ADV_EXT_IND" in s:
        return "ADV_EXT_IND"

    # Legacy advertising
    if "ADV_DIRECT_IND" in s:
        return "ADV_DIRECT_IND"
    if "ADV_NONCONN_IND" in s:
        return "ADV_NONCONN_IND"
    if "ADV_SCAN_IND" in s:
        return "ADV_SCAN_IND"
    if "ADV_IND" in s:
        return "ADV_IND"
    if "SCAN_RSP" in s:
        return "SCAN_RSP"
    if "SCAN_REQ" in s:
        return "SCAN_REQ"

    # Connection events
    if "CONNECT_IND" in s or "AUX_CONNECT_REQ" in s:
        return "CONNECT_IND"

    # Higher-layer protocols (check before LE-U — summaries like
    # "LE-U L2CAP Data ATT Read Request" should classify as ATT, not LE_DATA)
    if "ATT" in s or "GATT" in s:
        return "ATT"
    if "SMP" in s:
        return "SMP"
    if "L2CAP" in s:
        return "L2CAP"

    # Link Layer control (specific before generic)
    if "LL_CONNECTION_UPDATE" in s:
        return "LL_CONNECTION_UPDATE"
    if "LL_TERMINATE" in s:
        return "LL_CONTROL"
    if "LL_" in s:
        return "LL_CONTROL"

    # LE data — generic Link Layer data without upper-layer protocol info
    if "LE-U" in s:
        return "LE_DATA"

    # Error/status
    if "CRC" in s:
        return "CRC_ERROR"
    if "ENCRYPTED" in s or "POSSIBLY ENCRYPTED" in s:
        return "ENCRYPTED"
    if "NOT DECODED" in s or "NOT CONNECTED" in s:
        return "UNDECODED"

    if "DATA" in s:
        return "DATA"

    return "OTHER"


def summarize_packets(packets, limit: int | None = None) -> dict:
    """Summarize a list/iterable of packet-like objects.

    Args:
        packets: Iterable with .summary, .time attributes. Supports len().
        limit: Max packets to classify (None = all). Total count still uses len().

    Returns:
        Dict with packet_count, packet_type_counts, duration_seconds, timestamps.
    """
    total = len(packets)
    cap = total if limit is None else min(limit, total)

    type_counts: dict[str, int] = {}
    first_time: int | None = None
    last_time: int | None = None

    for i in range(cap):
        pkt = packets[i]
        try:
            pkt_type = getattr(pkt, "classified", None) or classify_packet(pkt.summary)
            type_counts[pkt_type] = type_counts.get(pkt_type, 0) + 1
        except (AttributeError, Exception):
            type_counts["unknown"] = type_counts.get("unknown", 0) + 1

        try:
            t = int(pkt.time)
            if first_time is None:
                first_time = t
            last_time = t
        except (AttributeError, TypeError, ValueError):
            pass

    result: dict[str, Any] = {
        "packet_count": total,
        "packet_type_counts": type_counts,
    }

    if first_time is not None and last_time is not None:
        result["first_timestamp_ns"] = first_time
        result["last_timestamp_ns"] = last_time
        result["duration_ns"] = last_time - first_time
        result["duration_seconds"] = round((last_time - first_time) / 1e9, 3)

    if cap < total:
        result["note"] = (
            f"Packet type counts based on first {cap:,} of "
            f"{total:,} total packets."
        )

    return result


def filter_packets(
    packets,
    *,
    summary_contains: str | None = None,
    packet_type: str | None = None,
    channel: int | None = None,
    max_results: int = 100,
    start: int = 0,
) -> dict:
    """Filter packets by criteria.

    Args:
        packets: Indexable packet list with .summary, .channel, .rssi, .time.
        summary_contains: Case-insensitive substring match on summary.
        packet_type: Match classified packet type.
        channel: Match channel number.
        max_results: Maximum results to return.
        start: Start index (skip earlier packets).

    Returns:
        Dict with packets list, has_more boolean, and returned count.
    """
    results: list[dict] = []
    search_term = summary_contains.upper() if summary_contains else None
    total = len(packets)
    has_more = False

    def _build_pkt_dict(pkt, i: int) -> dict[str, Any]:
        pkt_dict: dict[str, Any] = {"index": i, "summary": pkt.summary}
        for attr in ["time", "rssi", "channel"]:
            try:
                pkt_dict[attr] = getattr(pkt, attr)
            except (AttributeError, Exception):
                pass
        try:
            payload = pkt.query("payload")
            if isinstance(payload, bytes) and payload:
                pkt_dict["payload_hex"] = payload.hex()
        except (AttributeError, Exception):
            pass
        return pkt_dict

    # Fast path: use precomputed type index from cache
    cache = getattr(packets, "_cache", None)
    if cache is not None and hasattr(cache, "type_index") and packet_type and not summary_contains:
        target_type = packet_type.upper()
        indices = cache.type_index.get(target_type, [])
        for i in indices:
            if i < start:
                continue
            if len(results) >= max_results:
                has_more = True
                break
            pkt = packets[i]
            if channel is not None:
                try:
                    if pkt.channel != channel:
                        continue
                except (AttributeError, Exception):
                    continue
            results.append(_build_pkt_dict(pkt, i))
        return {"packets": results, "has_more": has_more, "returned": len(results)}

    for i in range(start, total):
        if len(results) >= max_results:
            # Check if there's at least one more matching packet
            for j in range(i, total):
                pkt = packets[j]
                try:
                    summary = pkt.summary
                except (AttributeError, Exception):
                    continue
                if search_term and search_term not in summary.upper():
                    continue
                if packet_type:
                    pkt_class = getattr(pkt, "classified", None) or classify_packet(summary)
                    if pkt_class.upper() != packet_type.upper():
                        continue
                if channel is not None:
                    try:
                        if pkt.channel != channel:
                            continue
                    except (AttributeError, Exception):
                        continue
                has_more = True
                break
            break
        pkt = packets[i]
        try:
            summary = pkt.summary
        except (AttributeError, Exception):
            continue

        if search_term and search_term not in summary.upper():
            continue
        if packet_type:
            pkt_class = getattr(pkt, "classified", None) or classify_packet(summary)
            if pkt_class.upper() != packet_type.upper():
                continue
        if channel is not None:
            try:
                if pkt.channel != channel:
                    continue
            except (AttributeError, Exception):
                continue

        results.append(_build_pkt_dict(pkt, i))

    return {"packets": results, "has_more": has_more, "returned": len(results)}


def find_error_packets(packets, *, max_results: int = 100, start: int = 0) -> list[dict]:
    """Find error, failure, and disconnect packets.

    Uses precomputed error_indices from PacketCache when available (O(e)
    where e = error count), otherwise falls back to full scan (O(n)).

    Args:
        packets: Indexable packet list (CachedPackets or raw).
        max_results: Maximum errors to return.
        start: Start index.
    """
    # Fast path: use precomputed error indices from cache
    cache = getattr(packets, "_cache", None)
    if cache is not None and hasattr(cache, "error_indices"):
        errors: list[dict] = []
        for i in cache.error_indices:
            if i < start:
                continue
            if len(errors) >= max_results:
                break
            pkt = packets[i]
            error_info: dict[str, Any] = {"index": i, "summary": pkt.summary}
            try:
                error_info["time"] = pkt.time
            except (AttributeError, Exception):
                pass
            errors.append(error_info)
        return errors

    # Slow path: full scan for raw packets
    errors = []
    total = len(packets)

    for i in range(start, total):
        if len(errors) >= max_results:
            break
        pkt = packets[i]
        try:
            summary = pkt.summary
            summary_upper = summary.upper()
            if any(kw in summary_upper for kw in ERROR_KEYWORDS):
                error_info = {"index": i, "summary": summary}
                try:
                    error_info["time"] = pkt.time
                except (AttributeError, Exception):
                    pass
                errors.append(error_info)
        except (AttributeError, Exception):
            continue

    return errors


def extract_device_info(devices) -> list[dict]:
    """Extract device information from blueSPY device objects.

    Args:
        devices: Iterable of blueSPY device_id objects.

    Returns:
        List of dicts with index, address, name, connection_count.
    """
    result = []
    for idx, dev in enumerate(devices):
        info: dict[str, Any] = {"index": idx, "address": "", "name": "", "connection_count": 0}

        # Extract address
        for method in ["query_str", "query"]:
            try:
                addr = getattr(dev, method)("address")
                if isinstance(addr, bytes) and len(addr) >= 6:
                    info["address"] = ":".join(f"{b:02X}" for b in addr[:6])
                    break
                if isinstance(addr, str) and addr:
                    info["address"] = addr.upper()
                    break
            except (AttributeError, Exception):
                continue

        if not info["address"]:
            try:
                summary = dev.query_str("summary")
                match = re.search(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", summary)
                if match:
                    info["address"] = match.group(1)
            except (AttributeError, Exception):
                pass

        # Extract name
        for method in ["query_str", "query"]:
            try:
                name = getattr(dev, method)("name")
                if isinstance(name, bytes):
                    info["name"] = name.decode("utf-8", errors="replace")
                    break
                if isinstance(name, str) and name:
                    info["name"] = name
                    break
            except (AttributeError, Exception):
                continue

        # Connection count
        try:
            info["connection_count"] = len(list(dev.get_connections()))
        except (AttributeError, Exception):
            pass

        result.append(info)

    return result


def _extract_adv_address(pkt) -> str:
    """Extract advertiser address from an advertising PDU's payload.

    In legacy advertising PDUs (ADV_IND, ADV_NONCONN_IND, etc.), the
    advertiser address (AdvA) occupies bytes 2-7 of the payload in
    little-endian order.
    """
    try:
        payload = pkt.query("payload")
        if isinstance(payload, bytes) and len(payload) >= 8:
            return ":".join(f"{b:02X}" for b in reversed(payload[2:8]))
    except (AttributeError, Exception):
        pass
    return ""


# Advertising packet types to exclude when counting connection traffic
_ADV_TYPES = frozenset({
    "ADV_IND", "ADV_NONCONN_IND", "ADV_SCAN_IND",
    "ADV_DIRECT_IND", "ADV_EXT_IND", "AUX_ADV_IND",
    "SCAN_REQ", "SCAN_RSP",
})


_MAC_RE = re.compile(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}")


def _parse_connection_addresses(summary: str) -> list[str]:
    """Extract MAC addresses from a connection summary string.

    Returns uppercase addresses for case-insensitive matching.
    """
    return [m.upper() for m in _MAC_RE.findall(summary)]


def analyze_connection_live(connections, packets, connection_index: int = 0) -> dict:
    """Analyze a connection during live capture.

    Uses address matching and temporal boundaries (CONNECT_IND / LL_TERMINATE)
    to attribute packets to the correct connection instead of counting all
    non-advertising packets globally.

    Args:
        connections: blueSPY connection objects (from bluespy.connections).
        packets: blueSPY packet objects (from bluespy.packets).
        connection_index: 0-based index into connections list.

    Returns:
        Dict with connection info and packet type counts.
    """
    conn_list = extract_connection_info(connections)
    if not conn_list:
        return {"error": "No connections found in this capture."}
    if connection_index >= len(conn_list):
        return {
            "error": f"Connection index {connection_index} out of range. "
            f"Found {len(conn_list)} connection(s)."
        }

    result = conn_list[connection_index]
    conn_summary = result.get("summary", "")
    conn_addrs = _parse_connection_addresses(conn_summary)

    # Find time boundaries from CONNECT_IND / LL_TERMINATE
    start_time: int | None = None
    end_time: int | None = None
    total = len(packets)
    for i in range(total):
        try:
            s = packets[i].summary.upper()
            t = packets[i].time
            if "CONNECT_IND" in s and conn_addrs and any(a in s for a in conn_addrs):
                start_time = t
            if start_time is not None and "LL_TERMINATE" in s and t > start_time:
                end_time = t
                break
        except (AttributeError, Exception):
            continue

    # Count connection-specific packets
    conn_type_counts: dict[str, int] = {}
    for i in range(total):
        try:
            pkt = packets[i]
            summary = pkt.summary
            pkt_type = getattr(pkt, "classified", None) or classify_packet(summary)
            if pkt_type in _ADV_TYPES:
                continue

            # When we have time boundaries, use temporal scoping
            if start_time is not None:
                pkt_time = pkt.time
                if pkt_time < start_time:
                    continue
                if end_time is not None and pkt_time > end_time:
                    continue
            elif conn_addrs:
                # Fallback: address matching when no CONNECT_IND found
                s_upper = summary.upper()
                if not any(a in s_upper for a in conn_addrs):
                    continue

            conn_type_counts[pkt_type] = conn_type_counts.get(pkt_type, 0) + 1
        except (AttributeError, Exception):
            continue

    result["packet_type_counts"] = conn_type_counts
    return result


def analyze_all_connections(connections, packets) -> dict:
    """Analyze ALL connections in a single packet pass.

    Instead of calling analyze_connection_live() N times (each iterating
    all packets), this iterates packets once and buckets by connection
    using address matching and temporal boundaries.
    """
    conn_list = extract_connection_info(connections)
    if not conn_list:
        return {"connections": [], "total_connections": 0}

    # For each connection, find addresses and prepare boundary tracking
    conn_bounds: list[dict] = []
    for conn_info in conn_list:
        addrs = _parse_connection_addresses(conn_info.get("summary", ""))
        conn_bounds.append({"addrs": addrs, "start": None, "end": None})

    # First pass: find CONNECT_IND / LL_TERMINATE boundaries for each
    total = len(packets)
    for i in range(total):
        try:
            s = packets[i].summary.upper()
            t = packets[i].time
            if "CONNECT_IND" in s:
                for cb in conn_bounds:
                    if cb["start"] is None and cb["addrs"] and any(a in s for a in cb["addrs"]):
                        cb["start"] = t
                        break
            if "LL_TERMINATE" in s:
                for cb in conn_bounds:
                    if cb["start"] is not None and cb["end"] is None and t > cb["start"]:
                        cb["end"] = t
                        break
        except (AttributeError, Exception):
            continue

    # Second pass: bucket non-ADV packets by connection
    per_conn_counts: list[dict[str, int]] = [dict() for _ in conn_list]
    for i in range(total):
        try:
            pkt = packets[i]
            pkt_type = getattr(pkt, "classified", None) or classify_packet(pkt.summary)
            if pkt_type in _ADV_TYPES:
                continue
            pkt_time = pkt.time
            for idx, cb in enumerate(conn_bounds):
                if cb["start"] is not None:
                    if pkt_time >= cb["start"] and (cb["end"] is None or pkt_time <= cb["end"]):
                        per_conn_counts[idx][pkt_type] = per_conn_counts[idx].get(pkt_type, 0) + 1
                        break
        except (AttributeError, Exception):
            continue

    results = []
    for idx, conn_info in enumerate(conn_list):
        conn_info["packet_type_counts"] = per_conn_counts[idx]
        results.append(conn_info)

    return {"connections": results, "total_connections": len(results)}


def analyze_advertising_live(devices, packets, device_index: int = 0) -> dict:
    """Analyze advertising data for a device during live capture.

    Args:
        devices: blueSPY device objects (from bluespy.devices).
        packets: blueSPY packet objects (from bluespy.packets).
        device_index: 0-based index into devices list.

    Returns:
        Dict with device info, advertising sample, RSSI/channel stats.
    """
    dev_list = extract_device_info(devices)
    if not dev_list:
        return {"error": "No devices found in this capture."}
    if device_index >= len(dev_list):
        return {
            "error": f"Device index {device_index} out of range. "
            f"Found {len(dev_list)} device(s)."
        }

    dev_info = dev_list[device_index]
    device_address = dev_info.get("address", "")

    adv_packets: list[dict] = []
    channels_seen: set[int] = set()
    rssi_values: list[int] = []

    total = len(packets)
    for i in range(total):
        pkt = packets[i]
        try:
            summary = pkt.summary
            if "ADV" not in summary.upper():
                continue
            # Filter to this device by matching address (case-insensitive)
            if device_address:
                addr_upper = device_address.upper()
                if addr_upper in summary.upper():
                    pass  # match via summary text
                else:
                    pkt_addr = _extract_adv_address(pkt)
                    if pkt_addr.upper() != addr_upper:
                        continue

            adv_info: dict[str, Any] = {"index": i, "summary": summary}
            try:
                adv_info["rssi"] = pkt.rssi
                rssi_values.append(pkt.rssi)
            except (AttributeError, Exception):
                pass
            try:
                adv_info["channel"] = pkt.channel
                channels_seen.add(pkt.channel)
            except (AttributeError, Exception):
                pass
            try:
                payload = pkt.query("payload")
                if isinstance(payload, bytes) and payload:
                    adv_info["payload_hex"] = payload.hex()
            except (AttributeError, Exception):
                pass
            adv_packets.append(adv_info)
        except (AttributeError, Exception):
            continue

    result: dict[str, Any] = {
        "address": device_address,
        "name": dev_info.get("name", ""),
        "advertisement_count": len(adv_packets),
        "advertisements_sample": adv_packets[:50],
        "channels_used": sorted(channels_seen),
    }
    if rssi_values:
        result["rssi_min"] = min(rssi_values)
        result["rssi_max"] = max(rssi_values)
        result["rssi_avg"] = round(sum(rssi_values) / len(rssi_values), 1)

    return result


def analyze_all_advertising(devices, packets) -> dict:
    """Analyze advertising data for ALL devices in a single packet pass.

    Instead of calling analyze_advertising_live() N times (each iterating
    all packets), this iterates packets once and buckets by device address.
    """
    dev_list = extract_device_info(devices)
    if not dev_list:
        return {"devices": [], "total_devices": 0}

    # Build address lookup — uppercase for case-insensitive matching
    known_addrs = {d["address"].upper() for d in dev_list if d.get("address")}

    # Per-device accumulators (keyed by uppercase address)
    adv_packets: dict[str, list[dict]] = {a: [] for a in known_addrs}
    channels_seen: dict[str, set[int]] = {a: set() for a in known_addrs}
    rssi_values: dict[str, list[int]] = {a: [] for a in known_addrs}

    total = len(packets)
    for i in range(total):
        pkt = packets[i]
        try:
            summary = pkt.summary
            if "ADV" not in summary.upper():
                continue

            # Determine which device this packet belongs to
            matched_addr = None

            # Fast path: check summary text for known addresses
            summary_upper = summary.upper()
            for addr in known_addrs:
                if addr in summary_upper:
                    matched_addr = addr
                    break

            # Slow path: extract from payload
            if matched_addr is None:
                pkt_addr = _extract_adv_address(pkt).upper()
                if pkt_addr in known_addrs:
                    matched_addr = pkt_addr

            if matched_addr is None:
                continue

            # Collect packet info
            adv_info: dict[str, Any] = {"index": i, "summary": summary}
            try:
                adv_info["rssi"] = pkt.rssi
                rssi_values[matched_addr].append(pkt.rssi)
            except (AttributeError, Exception):
                pass
            try:
                adv_info["channel"] = pkt.channel
                channels_seen[matched_addr].add(pkt.channel)
            except (AttributeError, Exception):
                pass
            try:
                payload = pkt.query("payload")
                if isinstance(payload, bytes) and payload:
                    adv_info["payload_hex"] = payload.hex()
            except (AttributeError, Exception):
                pass
            adv_packets[matched_addr].append(adv_info)

        except (AttributeError, Exception):
            continue

    # Build per-device results
    results = []
    for dev_info in dev_list:
        addr = dev_info.get("address", "").upper()
        pkts = adv_packets.get(addr, [])
        rssis = rssi_values.get(addr, [])

        device_result: dict[str, Any] = {
            "address": dev_info.get("address", ""),
            "name": dev_info.get("name", ""),
            "advertisement_count": len(pkts),
            "advertisements_sample": pkts[:10],  # Fewer per device in batch mode
            "channels_used": sorted(channels_seen.get(addr, set())),
        }
        if rssis:
            device_result["rssi_min"] = min(rssis)
            device_result["rssi_max"] = max(rssis)
            device_result["rssi_avg"] = round(sum(rssis) / len(rssis), 1)
        results.append(device_result)

    return {"devices": results, "total_devices": len(results)}


def extract_connection_info(connections) -> list[dict]:
    """Extract connection information from blueSPY connection objects.

    Args:
        connections: Iterable of blueSPY connection_id objects.

    Returns:
        List of dicts with index, summary, interval, latency, timeout.
    """
    result = []
    for idx, conn in enumerate(connections):
        info: dict[str, Any] = {"index": idx, "summary": ""}

        try:
            info["summary"] = conn.query_str("summary")
        except (AttributeError, Exception):
            try:
                info["summary"] = str(conn.summary)
            except (AttributeError, Exception):
                pass

        for field_name in ["interval", "latency", "timeout"]:
            try:
                info[field_name] = conn.query(field_name)
            except (AttributeError, Exception):
                pass

        result.append(info)

    return result
