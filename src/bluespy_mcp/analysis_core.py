"""Shared packet analysis functions — no CaptureManager dependency.

These functions operate on raw BlueSPY objects (event_id, device_id,
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
    if "LL_CONNECTION_UPDATE" in s:
        return "LL_CONNECTION_UPDATE"
    if "LL_TERMINATE" in s:
        return "LL_CONTROL"

    # LE data (check before L2CAP — "LE-U L2CAP Data" should be LE_DATA)
    if "LE-U" in s:
        return "LE_DATA"

    # Higher-layer protocols
    if "L2CAP" in s:
        return "L2CAP"
    if "ATT" in s or "GATT" in s:
        return "ATT"
    if "SMP" in s:
        return "SMP"

    # Link Layer control
    if "LL_" in s:
        return "LL_CONTROL"

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
            pkt_type = classify_packet(pkt.summary)
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
) -> list[dict]:
    """Filter packets by criteria.

    Args:
        packets: Indexable packet list with .summary, .channel, .rssi, .time.
        summary_contains: Case-insensitive substring match on summary.
        packet_type: Match classified packet type.
        channel: Match channel number.
        max_results: Maximum results to return.
        start: Start index (skip earlier packets).

    Returns:
        List of dicts with index, summary, time, rssi, channel.
    """
    results: list[dict] = []
    search_term = summary_contains.upper() if summary_contains else None
    total = len(packets)

    for i in range(start, total):
        if len(results) >= max_results:
            break
        pkt = packets[i]
        try:
            summary = pkt.summary
        except (AttributeError, Exception):
            continue

        if search_term and search_term not in summary.upper():
            continue
        if packet_type and classify_packet(summary).upper() != packet_type.upper():
            continue
        if channel is not None:
            try:
                if pkt.channel != channel:
                    continue
            except (AttributeError, Exception):
                continue

        pkt_dict: dict[str, Any] = {"index": i, "summary": summary}
        for attr in ["time", "rssi", "channel"]:
            try:
                pkt_dict[attr] = getattr(pkt, attr)
            except (AttributeError, Exception):
                pass
        results.append(pkt_dict)

    return results


def find_error_packets(packets, *, max_results: int = 100, start: int = 0) -> list[dict]:
    """Find error, failure, and disconnect packets.

    Args:
        packets: Indexable packet list.
        max_results: Maximum errors to return.
        start: Start index.
    """
    errors: list[dict] = []
    total = len(packets)

    for i in range(start, total):
        if len(errors) >= max_results:
            break
        pkt = packets[i]
        try:
            summary = pkt.summary
            summary_upper = summary.upper()
            if any(kw in summary_upper for kw in ERROR_KEYWORDS):
                error_info: dict[str, Any] = {"index": i, "summary": summary}
                try:
                    error_info["time"] = pkt.time
                except (AttributeError, Exception):
                    pass
                errors.append(error_info)
        except (AttributeError, Exception):
            continue

    return errors


def extract_device_info(devices) -> list[dict]:
    """Extract device information from BlueSPY device objects.

    Args:
        devices: Iterable of BlueSPY device_id objects.

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


def analyze_connection_live(connections, packets, connection_index: int = 0) -> dict:
    """Analyze a connection during live capture.

    Args:
        connections: BlueSPY connection objects (from bluespy.connections).
        packets: BlueSPY packet objects (from bluespy.packets).
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

    # Count non-advertising packets by type (heuristic for connection traffic)
    conn_type_counts: dict[str, int] = {}
    total = len(packets)
    for i in range(total):
        try:
            summary = packets[i].summary
            pkt_type = classify_packet(summary)
            if pkt_type not in _ADV_TYPES:
                conn_type_counts[pkt_type] = conn_type_counts.get(pkt_type, 0) + 1
        except (AttributeError, Exception):
            continue

    result["packet_type_counts"] = conn_type_counts
    return result


def analyze_advertising_live(devices, packets, device_index: int = 0) -> dict:
    """Analyze advertising data for a device during live capture.

    Args:
        devices: BlueSPY device objects (from bluespy.devices).
        packets: BlueSPY packet objects (from bluespy.packets).
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


def extract_connection_info(connections) -> list[dict]:
    """Extract connection information from BlueSPY connection objects.

    Args:
        connections: Iterable of BlueSPY connection_id objects.

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
