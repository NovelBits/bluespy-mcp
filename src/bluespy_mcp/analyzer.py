"""Capture analysis functions using the BlueSPY query API.

All functions operate on a CaptureManager that has a file loaded.
Results are plain dicts/lists for easy JSON serialization.
"""

from __future__ import annotations

from typing import Any

from bluespy_mcp.capture import CaptureManager

# Maximum packets to iterate for summary (prevents hanging on huge captures)
_SUMMARY_PACKET_LIMIT = 50_000

_ERROR_KEYWORDS = [
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


def summarize_capture(capture: CaptureManager) -> dict:
    """High-level overview of a loaded capture."""
    capture._require_loaded()
    metadata = capture.get_metadata()

    type_counts: dict[str, int] = {}
    sample_limit = min(capture.packet_count, _SUMMARY_PACKET_LIMIT)

    for i, pkt in capture.iter_packets(limit=sample_limit):
        try:
            pkt_type = classify_packet(pkt.summary)
            type_counts[pkt_type] = type_counts.get(pkt_type, 0) + 1
        except (AttributeError, Exception):
            type_counts["unknown"] = type_counts.get("unknown", 0) + 1

    metadata["packet_type_counts"] = type_counts
    if sample_limit < capture.packet_count:
        metadata["note"] = (
            f"Packet type counts based on first {sample_limit:,} of "
            f"{capture.packet_count:,} total packets."
        )
    return metadata


def find_packets(
    capture: CaptureManager,
    *,
    summary_contains: str | None = None,
    packet_type: str | None = None,
    channel: int | None = None,
    max_results: int = 100,
) -> list[dict]:
    """Filter packets by criteria."""
    capture._require_loaded()
    results: list[dict] = []
    search_term = summary_contains.upper() if summary_contains else None

    for i, pkt in capture.iter_packets():
        if len(results) >= max_results:
            break
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
        for attr in ["timestamp", "rssi", "channel"]:
            try:
                pkt_dict[attr] = getattr(pkt, attr)
            except (AttributeError, Exception):
                pass
        results.append(pkt_dict)

    return results


def find_errors(capture: CaptureManager, max_results: int = 100) -> list[dict]:
    """Find all error, failure, and disconnect packets."""
    capture._require_loaded()
    errors: list[dict] = []

    for i, pkt in capture.iter_packets():
        if len(errors) >= max_results:
            break
        try:
            summary = pkt.summary
            summary_upper = summary.upper()
            if any(kw in summary_upper for kw in _ERROR_KEYWORDS):
                error_info: dict[str, Any] = {"index": i, "summary": summary}
                try:
                    error_info["timestamp"] = pkt.timestamp
                except (AttributeError, Exception):
                    pass
                errors.append(error_info)
        except (AttributeError, Exception):
            continue

    return errors


def analyze_connection(capture: CaptureManager, connection_index: int = 0) -> dict:
    """Deep-dive analysis of a specific connection."""
    capture._require_loaded()
    connections = capture.get_connections()

    if not connections:
        return {"error": "No connections found in this capture."}
    if connection_index >= len(connections):
        return {
            "error": f"Connection index {connection_index} out of range. "
            f"Found {len(connections)} connection(s)."
        }

    conn = connections[connection_index]
    result: dict[str, Any] = conn.to_dict()

    # Count packets by type for this connection (heuristic: all non-ADV packets)
    conn_type_counts: dict[str, int] = {}
    for i, pkt in capture.iter_packets():
        try:
            summary = pkt.summary
            pkt_type = classify_packet(summary)
            if pkt_type not in ("ADV_IND", "ADV_NONCONN_IND", "ADV_SCAN_IND",
                                "ADV_DIRECT_IND", "ADV_EXT_IND", "AUX_ADV_IND",
                                "SCAN_REQ", "SCAN_RSP"):
                conn_type_counts[pkt_type] = conn_type_counts.get(pkt_type, 0) + 1
        except (AttributeError, Exception):
            continue

    result["packet_type_counts"] = conn_type_counts
    return result


def analyze_advertising(capture: CaptureManager, device_index: int = 0) -> dict:
    """Analyze advertising data for a specific device."""
    capture._require_loaded()
    devices = capture.get_devices()

    if not devices:
        return {"error": "No devices found in this capture."}
    if device_index >= len(devices):
        return {
            "error": f"Device index {device_index} out of range. "
            f"Found {len(devices)} device(s)."
        }

    device = devices[device_index]
    result: dict[str, Any] = {
        "address": device.address,
        "name": device.name,
    }

    adv_packets: list[dict] = []
    channels_seen: set[int] = set()
    rssi_values: list[int] = []

    for i, pkt in capture.iter_packets():
        try:
            summary = pkt.summary
            if "ADV" not in summary.upper():
                continue
            # If we can check address, filter to this device
            if device.address:
                try:
                    if device.address not in pkt.query_str("address") and \
                       device.address not in summary:
                        continue
                except (AttributeError, Exception):
                    pass

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

    result["advertisement_count"] = len(adv_packets)
    result["advertisements_sample"] = adv_packets[:50]
    result["channels_used"] = sorted(channels_seen)
    if rssi_values:
        result["rssi_min"] = min(rssi_values)
        result["rssi_max"] = max(rssi_values)
        result["rssi_avg"] = round(sum(rssi_values) / len(rssi_values), 1)

    return result
