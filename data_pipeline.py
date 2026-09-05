"""Network telemetry ingestion and feature-window construction.

This module is deliberately dependency-free.  It accepts classic libpcap
captures (Ethernet + IPv4) and JSON Lines packet/flow logs, then emits the
19-feature, [0, 1]-normalised vectors consumed by the prediction engine.

Examples:
    python data_pipeline.py pcap traffic.pcap --output features.jsonl
    python data_pipeline.py jsonl zeek-or-firewall.jsonl --output features.jsonl
    python data_pipeline.py jsonl events.jsonl --sequence-size 10 --output windows.jsonl

PCAPNG, IPv6, and live capture are intentionally outside this small offline
ingester.  Convert PCAPNG to PCAP first, or add a dedicated capture adapter.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import statistics
import struct
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Optional


FEATURE_NAMES = [
    "syn_count", "ack_count", "fin_count", "rst_count", "psh_count",
    "urg_count", "bytes_per_flow", "packets_per_flow", "flow_duration",
    "iat_mean", "iat_variance", "iat_max", "unique_dst_ports",
    "port_scan_rate", "internal_ip_ratio", "ttl_variance", "window_size",
    "retransmission_count", "beacon_periodicity_score",
]

# Upper bounds for a conservative min-max transform.  Tune these from a
# benign training corpus before fitting the production world model.
NORMALIZATION_SCALES = {
    "syn_count": 100.0, "ack_count": 100.0, "fin_count": 100.0,
    "rst_count": 100.0, "psh_count": 100.0, "urg_count": 100.0,
    "bytes_per_flow": 1_000_000.0, "packets_per_flow": 1_000.0,
    "flow_duration": 60.0, "iat_mean": 10.0, "iat_variance": 100.0,
    "iat_max": 60.0, "unique_dst_ports": 100.0, "port_scan_rate": 1.0,
    "internal_ip_ratio": 1.0, "ttl_variance": 1_000.0,
    "window_size": 65_535.0, "retransmission_count": 100.0,
    "beacon_periodicity_score": 1.0,
}


@dataclass(frozen=True)
class PacketRecord:
    """Canonical event produced by every input adapter.

    ``packet_count`` lets a flow log represent many packets without expanding
    the log into synthetic packet records.
    """

    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str = "other"
    src_port: int = 0
    dst_port: int = 0
    byte_count: int = 0
    tcp_flags: frozenset[str] = frozenset()
    ttl: Optional[int] = None
    tcp_window: Optional[int] = None
    tcp_sequence: Optional[int] = None
    packet_count: int = 1

    @property
    def flow_key(self) -> tuple[str, str, str, int, int]:
        return (self.src_ip, self.dst_ip, self.protocol, self.src_port, self.dst_port)


def _is_internal(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def _as_float(record: dict, *names: str, default: float = 0.0) -> float:
    for name in names:
        value = record.get(name)
        if value not in (None, "", "-"):
            return float(value)
    return default


def _as_int(record: dict, *names: str, default: int = 0) -> int:
    return int(_as_float(record, *names, default=default))


def _parse_flags(value: object) -> frozenset[str]:
    if value is None:
        return frozenset()
    if isinstance(value, int):
        flags = value
        return frozenset(name for bit, name in ((0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"),
                                                 (0x04, "RST"), (0x08, "PSH"), (0x20, "URG"))
                         if flags & bit)
    text = str(value).upper()
    aliases = {"S": "SYN", "A": "ACK", "F": "FIN", "R": "RST", "P": "PSH", "U": "URG"}
    return frozenset(aliases.get(char, char) for char in text if char in aliases)


def packet_from_log(record: dict) -> PacketRecord:
    """Map common JSONL firewall/Suricata/Zeek field names to PacketRecord."""
    src = record.get("src_ip", record.get("src", record.get("id.orig_h", record.get("orig_h"))))
    dst = record.get("dest_ip", record.get("dst_ip", record.get("dst", record.get("id.resp_h", record.get("resp_h")))))
    if not src or not dst:
        raise ValueError("log record needs source and destination IP fields")
    protocol = str(record.get("proto", record.get("protocol", "other"))).lower()
    if protocol == "6":
        protocol = "tcp"
    elif protocol == "17":
        protocol = "udp"
    return PacketRecord(
        timestamp=_as_float(record, "timestamp", "ts", "time"),
        src_ip=str(src), dst_ip=str(dst), protocol=protocol,
        src_port=_as_int(record, "src_port", "sport", "id.orig_p", "orig_p"),
        dst_port=_as_int(record, "dest_port", "dst_port", "dport", "id.resp_p", "resp_p"),
        byte_count=_as_int(record, "bytes", "byte_count", "len", "length", "orig_bytes"),
        tcp_flags=_parse_flags(record.get("tcp_flags", record.get("flags"))),
        ttl=_as_int(record, "ttl", default=0) or None,
        tcp_window=_as_int(record, "tcp_window", "window", default=0) or None,
        tcp_sequence=_as_int(record, "tcp_seq", "sequence", default=0) or None,
        packet_count=max(1, _as_int(record, "packet_count", "pkts", "orig_pkts", default=1)),
    )


def read_jsonl(path: str | Path) -> Iterator[PacketRecord]:
    with Path(path).open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                yield packet_from_log(json.loads(line))
            except (json.JSONDecodeError, TypeError, ValueError) as error:
                raise ValueError(f"invalid JSONL record at line {line_number}: {error}") from error


def _parse_ipv4_ethernet(frame: bytes) -> Optional[tuple[str, str, str, int, int, int, frozenset[str], Optional[int], Optional[int], Optional[int]]]:
    if len(frame) < 14:
        return None
    ether_type = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    if ether_type == 0x8100 and len(frame) >= 18:  # one 802.1Q VLAN tag
        ether_type = struct.unpack("!H", frame[16:18])[0]
        offset = 18
    if ether_type != 0x0800 or len(frame) < offset + 20:
        return None
    version_ihl = frame[offset]
    if version_ihl >> 4 != 4:
        return None
    ip_header_len = (version_ihl & 0x0F) * 4
    if ip_header_len < 20 or len(frame) < offset + ip_header_len:
        return None
    total_length = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
    protocol_number = frame[offset + 9]
    protocol = {6: "tcp", 17: "udp"}.get(protocol_number, str(protocol_number))
    ttl = frame[offset + 8]
    src = str(ipaddress.ip_address(frame[offset + 12:offset + 16]))
    dst = str(ipaddress.ip_address(frame[offset + 16:offset + 20]))
    transport = offset + ip_header_len
    src_port = dst_port = 0
    flags: frozenset[str] = frozenset()
    tcp_window = tcp_sequence = None
    if protocol in {"tcp", "udp"} and len(frame) >= transport + 4:
        src_port, dst_port = struct.unpack("!HH", frame[transport:transport + 4])
    if protocol == "tcp" and len(frame) >= transport + 16:
        tcp_sequence = struct.unpack("!I", frame[transport + 4:transport + 8])[0]
        flags = _parse_flags(frame[transport + 13])
        tcp_window = struct.unpack("!H", frame[transport + 14:transport + 16])[0]
    return src, dst, protocol, src_port, dst_port, total_length, flags, ttl, tcp_window, tcp_sequence


def read_classic_pcap(path: str | Path) -> Iterator[PacketRecord]:
    """Read classic .pcap files with Ethernet link-layer frames (DLT_EN10MB)."""
    with Path(path).open("rb") as handle:
        magic = handle.read(4)
        formats = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
                   b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}
        if magic not in formats:
            raise ValueError("only classic PCAP is supported; convert PCAPNG first")
        endian, fractional_scale = formats[magic]
        header = handle.read(20)
        if len(header) != 20:
            raise ValueError("truncated PCAP global header")
        _, _, _, _, _, link_type = struct.unpack(endian + "HHiIII", header)
        if link_type != 1:
            raise ValueError(f"unsupported PCAP link type {link_type}; only Ethernet (1) is supported")
        while packet_header := handle.read(16):
            if len(packet_header) != 16:
                raise ValueError("truncated PCAP packet header")
            seconds, fraction, included_length, _ = struct.unpack(endian + "IIII", packet_header)
            frame = handle.read(included_length)
            if len(frame) != included_length:
                raise ValueError("truncated PCAP packet data")
            parsed = _parse_ipv4_ethernet(frame)
            if parsed is None:
                continue
            src, dst, protocol, sport, dport, byte_count, flags, ttl, tcp_window, tcp_sequence = parsed
            yield PacketRecord(seconds + fraction * fractional_scale, src, dst, protocol, sport, dport,
                               byte_count, flags, ttl, tcp_window, tcp_sequence)


def _normalise(features: dict[str, float]) -> list[float]:
    return [round(min(1.0, max(0.0, features[name] / NORMALIZATION_SCALES[name])), 6)
            for name in FEATURE_NAMES]


def _make_feature_row(source: str, window_start: float, events: list[PacketRecord]) -> dict:
    events.sort(key=lambda item: item.timestamp)
    packet_total = sum(item.packet_count for item in events)
    flow_count = max(1, len({item.flow_key for item in events}))
    iats = [later.timestamp - earlier.timestamp for earlier, later in zip(events, events[1:])]
    ttls = [item.ttl for item in events if item.ttl is not None]
    tcp_windows = [item.tcp_window for item in events if item.tcp_window is not None]
    seen_sequences: set[tuple[tuple[str, str, str, int, int], int]] = set()
    retransmissions = 0
    for item in events:
        if item.tcp_sequence is not None:
            key = (item.flow_key, item.tcp_sequence)
            if key in seen_sequences:
                retransmissions += 1
            seen_sequences.add(key)
    flag_count = lambda name: sum(item.packet_count for item in events if name in item.tcp_flags)
    mean_iat = statistics.fmean(iats) if iats else 0.0
    iat_variance = statistics.pvariance(iats) if len(iats) > 1 else 0.0
    beacon_score = 0.0 if len(iats) < 3 or mean_iat <= 0 else max(0.0, 1.0 - min(1.0, math.sqrt(iat_variance) / mean_iat))
    raw = {
        "syn_count": flag_count("SYN"), "ack_count": flag_count("ACK"),
        "fin_count": flag_count("FIN"), "rst_count": flag_count("RST"),
        "psh_count": flag_count("PSH"), "urg_count": flag_count("URG"),
        "bytes_per_flow": sum(item.byte_count for item in events) / flow_count,
        "packets_per_flow": packet_total / flow_count,
        "flow_duration": max(0.0, events[-1].timestamp - events[0].timestamp),
        "iat_mean": mean_iat, "iat_variance": iat_variance, "iat_max": max(iats, default=0.0),
        "unique_dst_ports": float(len({item.dst_port for item in events if item.dst_port})),
        "port_scan_rate": len({item.dst_port for item in events if item.dst_port}) / max(1, packet_total),
        "internal_ip_ratio": sum(item.packet_count for item in events if _is_internal(item.dst_ip)) / max(1, packet_total),
        "ttl_variance": statistics.pvariance(ttls) if len(ttls) > 1 else 0.0,
        "window_size": statistics.fmean(tcp_windows) if tcp_windows else 0.0,
        "retransmission_count": float(retransmissions), "beacon_periodicity_score": beacon_score,
    }
    return {"source_ip": source, "window_start": window_start, "window_end": window_start,
            "packet_count": packet_total, "raw_features": raw,
            "feature_names": FEATURE_NAMES, "features": _normalise(raw)}


def build_feature_rows(events: Iterable[PacketRecord], window_seconds: int = 60) -> list[dict]:
    """Create one source-IP feature vector per fixed observation window."""
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    buckets: dict[tuple[str, int], list[PacketRecord]] = defaultdict(list)
    for event in events:
        buckets[(event.src_ip, math.floor(event.timestamp / window_seconds))].append(event)
    rows = []
    for (source, bucket), grouped_events in sorted(buckets.items(), key=lambda item: (item[0][0], item[0][1])):
        row = _make_feature_row(source, bucket * window_seconds, grouped_events)
        row["window_end"] = row["window_start"] + window_seconds
        rows.append(row)
    return rows


def build_model_windows(rows: Iterable[dict], sequence_size: int) -> list[dict]:
    """Turn chronological feature rows into LSTM-ready arrays of shape (T, 19)."""
    if sequence_size < 1:
        raise ValueError("sequence_size must be at least 1")
    by_source: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_source[row["source_ip"]].append(row)
    output = []
    for source, source_rows in by_source.items():
        source_rows.sort(key=lambda row: row["window_start"])
        for end in range(sequence_size, len(source_rows) + 1):
            sequence = source_rows[end - sequence_size:end]
            output.append({"source_ip": source, "window_start": sequence[0]["window_start"],
                           "window_end": sequence[-1]["window_end"], "feature_names": FEATURE_NAMES,
                           "model_window": [row["features"] for row in sequence]})
    return output


def write_jsonl(rows: Iterable[dict], output: str | Path) -> None:
    with Path(output).open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, separators=(",", ":")) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build normalised network feature windows from PCAP or JSONL logs.")
    parser.add_argument("input_type", choices=("pcap", "jsonl"))
    parser.add_argument("input", help="classic .pcap file or JSON Lines network log")
    parser.add_argument("--output", required=True, help="destination JSON Lines file")
    parser.add_argument("--window-seconds", type=int, default=60, help="tumbling feature-window duration (default: 60)")
    parser.add_argument("--sequence-size", type=int, help="emit LSTM windows of this many feature rows instead of single rows")
    args = parser.parse_args()
    events = read_classic_pcap(args.input) if args.input_type == "pcap" else read_jsonl(args.input)
    rows = build_feature_rows(events, args.window_seconds)
    output = build_model_windows(rows, args.sequence_size) if args.sequence_size else rows
    write_jsonl(output, args.output)
    print(f"wrote {len(output)} {'model windows' if args.sequence_size else 'feature rows'} to {args.output}")


if __name__ == "__main__":
    main()
