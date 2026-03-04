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
import struct
from typing import Any

# Maximum packets to iterate for summary (prevents hanging on huge captures)
SUMMARY_PACKET_LIMIT = 50_000

# Common Bluetooth LE AD types (Bluetooth Core Spec, Supplement to the Core Spec)
_AD_TYPE_FLAGS = 0x01
_AD_TYPE_INCOMPLETE_16BIT_UUIDS = 0x02
_AD_TYPE_COMPLETE_16BIT_UUIDS = 0x03
_AD_TYPE_INCOMPLETE_128BIT_UUIDS = 0x06
_AD_TYPE_COMPLETE_128BIT_UUIDS = 0x07
_AD_TYPE_SHORTENED_LOCAL_NAME = 0x08
_AD_TYPE_COMPLETE_LOCAL_NAME = 0x09
_AD_TYPE_TX_POWER_LEVEL = 0x0A
_AD_TYPE_MANUFACTURER_SPECIFIC = 0xFF

# Well-known Company IDs (Bluetooth SIG assigned numbers)
_COMPANY_IDS = {
    0x004C: "Apple",
    0x0006: "Microsoft",
    0x000F: "Broadcom",
    0x000D: "Texas Instruments",
    0x0059: "Nordic Semiconductor",
    0x00E0: "Google",
    0x0075: "Samsung",
    0x0310: "Qualcomm",
}

ERROR_KEYWORDS = [
    "ERROR", "FAIL", "REJECT", "TIMEOUT", "DISCONNECT",
    "UNKNOWN", "INVALID", "REFUSED", "TERMINATE",
]


def parse_ad_structures(payload: bytes) -> dict[str, Any]:
    """Parse Bluetooth LE AD structures from an advertising payload.

    AD structures use a type-length-value encoding:
    [length] [ad_type] [data...] repeated until end of payload.

    Returns a dict with parsed fields: service_uuids, local_name,
    tx_power, manufacturer_data, flags.
    """
    result: dict[str, Any] = {}
    uuids: list[str] = []
    i = 0
    n = len(payload)

    while i < n:
        length = payload[i]
        if length == 0 or i + length >= n:
            break
        ad_type = payload[i + 1]
        data = payload[i + 2:i + 1 + length]

        if ad_type == _AD_TYPE_FLAGS and data:
            result["flags"] = data[0]

        elif ad_type in (_AD_TYPE_COMPLETE_16BIT_UUIDS, _AD_TYPE_INCOMPLETE_16BIT_UUIDS):
            for j in range(0, len(data) - 1, 2):
                uuid_val = struct.unpack_from("<H", data, j)[0]
                uuids.append(f"0x{uuid_val:04X}")

        elif ad_type in (_AD_TYPE_COMPLETE_128BIT_UUIDS, _AD_TYPE_INCOMPLETE_128BIT_UUIDS):
            for j in range(0, len(data) - 15, 16):
                uuid_bytes = data[j:j + 16][::-1]  # Little-endian to big-endian
                uuid_hex = uuid_bytes.hex()
                uuid_str = (
                    f"{uuid_hex[0:8]}-{uuid_hex[8:12]}-{uuid_hex[12:16]}-"
                    f"{uuid_hex[16:20]}-{uuid_hex[20:32]}"
                )
                uuids.append(uuid_str)

        elif ad_type in (_AD_TYPE_COMPLETE_LOCAL_NAME, _AD_TYPE_SHORTENED_LOCAL_NAME):
            try:
                name = data.decode("utf-8", errors="replace")
                result["local_name"] = name
                if ad_type == _AD_TYPE_SHORTENED_LOCAL_NAME:
                    result["local_name_shortened"] = True
            except Exception:
                pass

        elif ad_type == _AD_TYPE_TX_POWER_LEVEL and len(data) >= 1:
            result["tx_power_dbm"] = struct.unpack("b", data[:1])[0]

        elif ad_type == _AD_TYPE_MANUFACTURER_SPECIFIC and len(data) >= 2:
            company_id = struct.unpack_from("<H", data, 0)[0]
            company_name = _COMPANY_IDS.get(company_id)
            mfr: dict[str, Any] = {
                "company_id": f"0x{company_id:04X}",
            }
            if company_name:
                mfr["company_name"] = company_name
            if len(data) > 2:
                mfr["data_hex"] = data[2:].hex()
            result["manufacturer_data"] = mfr

        i += 1 + length

    if uuids:
        result["service_uuids"] = uuids

    return result


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


_ADDRESS_TYPE_MAP = {
    "static": "Random Static",
    "public": "Public",
    "random": "Random",
    "resolvable": "Random Resolvable",
    "non-resolvable": "Random Non-Resolvable",
}


def _extract_address_type(info: dict, dev_summary: str) -> None:
    """Extract address type from device summary string.

    BlueSPY device summaries follow the format "AA:BB:CC:DD:EE:FF, Static"
    where the part after the comma indicates the address type.
    """
    parts = dev_summary.split(",", 1)
    if len(parts) > 1:
        type_str = parts[1].strip().lower()
        for key, label in _ADDRESS_TYPE_MAP.items():
            if key in type_str:
                info["address_type"] = label
                return


def extract_device_info(devices) -> list[dict]:
    """Extract device information from blueSPY device objects.

    Args:
        devices: Iterable of blueSPY device_id objects.

    Returns:
        List of dicts with index, address, name, connection_count.
    """
    result = []
    for idx, dev in enumerate(devices):
        info: dict[str, Any] = {
            "index": idx, "address": "", "address_type": "",
            "name": "", "connection_count": 0,
        }

        # Extract address (and address type from summary)
        dev_summary = ""
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
                dev_summary = dev.query_str("summary")
                match = re.search(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", dev_summary)
                if match:
                    info["address"] = match.group(1)
            except (AttributeError, Exception):
                pass

        # Extract address type from device summary (format: "AA:BB:CC:DD:EE:FF, Static")
        if not dev_summary:
            try:
                dev_summary = dev.query_str("summary")
            except (AttributeError, Exception):
                pass
        if dev_summary:
            _extract_address_type(info, dev_summary)

        # Extract name — try query first, fall back to device summary
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

        # Fallback: parse name from device summary parentheses
        # e.g. "D1:11:FE:93:26:44, Static (nRF54L15 HRM)"
        if not info["name"] and dev_summary:
            m = _NAME_IN_PARENS_RE.search(dev_summary)
            if m:
                info["name"] = m.group(1).strip()

        # Connection count
        try:
            info["connection_count"] = len(list(dev.get_connections()))
        except (AttributeError, Exception):
            pass

        result.append(info)

    return result


_NAME_IN_PARENS_RE = re.compile(r"\((.+?)\)")


def enrich_device_names(devices_info: list[dict], packets) -> list[dict]:
    """Fill in missing device names by scanning advertising packet summaries.

    The blueSPY device object's query("name") often raises AttributeError,
    but the packet summary includes the name in parentheses, e.g.:
      "SCAN_RSP (nRF54L15 HRM)"
      "ADV_IND (MyDevice)"

    For each device without a name, this scans advertising/scan response
    packets matching the device's address and extracts the parenthesized name.
    """
    # Collect devices that need names
    nameless = {
        d["address"].upper(): d
        for d in devices_info
        if d.get("address") and not d.get("name")
    }
    if not nameless:
        return devices_info

    total = len(packets)
    for i in range(total):
        if not nameless:
            break
        try:
            summary = packets[i].summary
            s_upper = summary.upper()
            if "ADV" not in s_upper and "SCAN_RSP" not in s_upper:
                continue
            m = _NAME_IN_PARENS_RE.search(summary)
            if not m:
                continue
            name = m.group(1).strip()
            if not name:
                continue
            # Check if this packet belongs to a nameless device
            for addr, dev_info in list(nameless.items()):
                if addr in s_upper:
                    dev_info["name"] = name
                    del nameless[addr]
                    break
        except (AttributeError, Exception):
            continue

    # Add hint for devices that still have no name
    for dev_info in nameless.values():
        dev_info["name_hint"] = (
            "Device name not found. Names are typically broadcast in Scan "
            "Response (SCAN_RSP) packets, which only appear when another "
            "device actively scans this device. Try capturing longer or "
            "while a phone/tablet is scanning nearby."
        )

    return devices_info


def enrich_device_rssi(devices_info: list[dict], packets) -> list[dict]:
    """Add per-device RSSI statistics by scanning advertising packets.

    For each device, collects RSSI values from advertising packets that
    match the device's address, then computes min, max, and average.
    """
    addr_map = {
        d["address"].upper(): d
        for d in devices_info
        if d.get("address")
    }
    if not addr_map:
        return devices_info

    rssi_values: dict[str, list[int]] = {a: [] for a in addr_map}

    total = len(packets)
    for i in range(total):
        try:
            pkt = packets[i]
            summary = pkt.summary
            s_upper = summary.upper()
            if "ADV" not in s_upper and "SCAN_RSP" not in s_upper:
                continue
            rssi = pkt.rssi
            for addr in addr_map:
                if addr in s_upper:
                    rssi_values[addr].append(rssi)
                    break
        except (AttributeError, Exception):
            continue

    for addr, dev_info in addr_map.items():
        vals = rssi_values.get(addr, [])
        if vals:
            dev_info["rssi_min"] = min(vals)
            dev_info["rssi_max"] = max(vals)
            dev_info["rssi_avg"] = round(sum(vals) / len(vals), 1)

    return devices_info


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
    num_connections = len(conn_list)
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
            # else: no boundaries and no addresses — count all non-ADV
            # (only accurate for single-connection captures)

            conn_type_counts[pkt_type] = conn_type_counts.get(pkt_type, 0) + 1
        except (AttributeError, Exception):
            continue

    # If filtering yielded nothing but packets exist, and this is the only
    # connection, fall back to counting all non-ADV packets. This handles
    # live captures that started mid-connection (no CONNECT_IND in capture).
    if not conn_type_counts and num_connections == 1 and start_time is None:
        for i in range(total):
            try:
                pkt = packets[i]
                pkt_type = getattr(pkt, "classified", None) or classify_packet(pkt.summary)
                if pkt_type not in _ADV_TYPES:
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
    has_any_boundaries = any(cb["start"] is not None for cb in conn_bounds)
    per_conn_counts: list[dict[str, int]] = [dict() for _ in conn_list]
    for i in range(total):
        try:
            pkt = packets[i]
            pkt_type = getattr(pkt, "classified", None) or classify_packet(pkt.summary)
            if pkt_type in _ADV_TYPES:
                continue
            pkt_time = pkt.time
            matched = False
            for idx, cb in enumerate(conn_bounds):
                if cb["start"] is not None:
                    if pkt_time >= cb["start"] and (cb["end"] is None or pkt_time <= cb["end"]):
                        per_conn_counts[idx][pkt_type] = per_conn_counts[idx].get(pkt_type, 0) + 1
                        matched = True
                        break
            # Single connection with no boundaries (mid-connection live capture):
            # attribute all non-ADV packets to the only connection
            if not matched and len(conn_list) == 1 and not has_any_boundaries:
                per_conn_counts[0][pkt_type] = per_conn_counts[0].get(pkt_type, 0) + 1
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
    enrich_device_names(dev_list, packets)
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
        "address_type": dev_info.get("address_type", ""),
        "name": dev_info.get("name", ""),
        "advertisement_count": len(adv_packets),
        "advertisements_sample": adv_packets[:50],
        "channels_used": sorted(channels_seen),
    }
    if rssi_values:
        result["rssi_min"] = min(rssi_values)
        result["rssi_max"] = max(rssi_values)
        result["rssi_avg"] = round(sum(rssi_values) / len(rssi_values), 1)

    # Parse AD structures from first advertising packet with a payload
    for adv in adv_packets:
        hex_str = adv.get("payload_hex")
        if hex_str:
            try:
                parsed = parse_ad_structures(bytes.fromhex(hex_str))
                if parsed:
                    result["advertising_data"] = parsed
                    # Use AD local name as fallback for device name
                    if not result["name"] and parsed.get("local_name"):
                        result["name"] = parsed["local_name"]
                    break
            except (ValueError, Exception):
                continue

    if not result["name"]:
        result["name_hint"] = (
            "Device name not found in advertising payload. Names are "
            "typically in Scan Response (SCAN_RSP) packets, which only "
            "appear when another device actively scans this device. "
            "Try capturing longer or while a phone/tablet is scanning nearby."
        )

    return result


def analyze_all_advertising(devices, packets) -> dict:
    """Analyze advertising data for ALL devices in a single packet pass.

    Instead of calling analyze_advertising_live() N times (each iterating
    all packets), this iterates packets once and buckets by device address.
    """
    dev_list = extract_device_info(devices)
    enrich_device_names(dev_list, packets)
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
            "address_type": dev_info.get("address_type", ""),
            "name": dev_info.get("name", ""),
            "advertisement_count": len(pkts),
            "advertisements_sample": pkts[:10],  # Fewer per device in batch mode
            "channels_used": sorted(channels_seen.get(addr, set())),
        }
        if rssis:
            device_result["rssi_min"] = min(rssis)
            device_result["rssi_max"] = max(rssis)
            device_result["rssi_avg"] = round(sum(rssis) / len(rssis), 1)

        # Parse AD structures from first advertising packet with a payload
        for adv in pkts:
            hex_str = adv.get("payload_hex")
            if hex_str:
                try:
                    parsed = parse_ad_structures(bytes.fromhex(hex_str))
                    if parsed:
                        device_result["advertising_data"] = parsed
                        if not device_result["name"] and parsed.get("local_name"):
                            device_result["name"] = parsed["local_name"]
                        break
                except (ValueError, Exception):
                    continue

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
