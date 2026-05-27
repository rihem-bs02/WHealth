from __future__ import annotations

import math
import time
from collections import defaultdict
from typing import Any

try:
    from scapy.all import sniff, IP, TCP, UDP
except Exception:
    sniff = None
    IP = None
    TCP = None
    UDP = None


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        value = float(value)
        if math.isfinite(value):
            return value
    except Exception:
        pass
    return default


def _mean(values: list[float]) -> float:
    if not values:
        return 0.0
    return float(sum(values) / len(values))


def _std(values: list[float]) -> float:
    if len(values) <= 1:
        return 0.0
    m = _mean(values)
    return float(math.sqrt(sum((x - m) ** 2 for x in values) / len(values)))


def _min(values: list[float]) -> float:
    return float(min(values)) if values else 0.0


def _max(values: list[float]) -> float:
    return float(max(values)) if values else 0.0


def _sum(values: list[float]) -> float:
    return float(sum(values)) if values else 0.0


def _iat_stats(times: list[float]) -> dict[str, float]:
    if len(times) <= 1:
        return {
            "total": 0.0,
            "mean": 0.0,
            "std": 0.0,
            "max": 0.0,
            "min": 0.0,
        }

    times = sorted(times)
    iats = [
        max(0.0, (times[i] - times[i - 1]) * 1_000_000.0)
        for i in range(1, len(times))
    ]

    return {
        "total": _sum(iats),
        "mean": _mean(iats),
        "std": _std(iats),
        "max": _max(iats),
        "min": _min(iats),
    }


class FlowAccumulator:
    def __init__(
        self,
        proto: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        first_time: float,
    ):
        self.proto = proto

        self.fwd_src_ip = src_ip
        self.fwd_src_port = src_port
        self.fwd_dst_ip = dst_ip
        self.fwd_dst_port = dst_port

        self.start_time = first_time
        self.end_time = first_time

        self.fwd_lengths: list[float] = []
        self.bwd_lengths: list[float] = []
        self.all_lengths: list[float] = []

        self.fwd_times: list[float] = []
        self.bwd_times: list[float] = []
        self.all_times: list[float] = []

        self.fin_count = 0
        self.syn_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.ack_count = 0
        self.urg_count = 0
        self.cwe_count = 0
        self.ece_count = 0

        self.fwd_psh_flags = 0
        self.bwd_psh_flags = 0
        self.fwd_urg_flags = 0
        self.bwd_urg_flags = 0

        self.fwd_header_lengths: list[float] = []
        self.bwd_header_lengths: list[float] = []

        self.fwd_init_window_bytes = 0
        self.bwd_init_window_bytes = 0

        self.fwd_seen = False
        self.bwd_seen = False

    def is_forward(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> bool:
        return (
            src_ip == self.fwd_src_ip
            and src_port == self.fwd_src_port
            and dst_ip == self.fwd_dst_ip
            and dst_port == self.fwd_dst_port
        )

    def add_packet(self, pkt, src_ip: str, src_port: int, dst_ip: str, dst_port: int, ts: float):
        pkt_len = float(len(pkt))
        self.end_time = max(self.end_time, ts)

        is_fwd = self.is_forward(src_ip, src_port, dst_ip, dst_port)

        self.all_lengths.append(pkt_len)
        self.all_times.append(ts)

        header_len = 0.0

        try:
            header_len += int(pkt[IP].ihl) * 4
        except Exception:
            pass

        flags = 0
        window = 0

        if TCP is not None and pkt.haslayer(TCP):
            tcp = pkt[TCP]

            try:
                header_len += int(tcp.dataofs) * 4
            except Exception:
                pass

            try:
                flags = int(tcp.flags)
            except Exception:
                flags = 0

            try:
                window = int(tcp.window)
            except Exception:
                window = 0

            # TCP flag bits
            fin = bool(flags & 0x01)
            syn = bool(flags & 0x02)
            rst = bool(flags & 0x04)
            psh = bool(flags & 0x08)
            ack = bool(flags & 0x10)
            urg = bool(flags & 0x20)
            ece = bool(flags & 0x40)
            cwe = bool(flags & 0x80)

            self.fin_count += int(fin)
            self.syn_count += int(syn)
            self.rst_count += int(rst)
            self.psh_count += int(psh)
            self.ack_count += int(ack)
            self.urg_count += int(urg)
            self.ece_count += int(ece)
            self.cwe_count += int(cwe)

            if is_fwd:
                self.fwd_psh_flags += int(psh)
                self.fwd_urg_flags += int(urg)
            else:
                self.bwd_psh_flags += int(psh)
                self.bwd_urg_flags += int(urg)

        if is_fwd:
            self.fwd_lengths.append(pkt_len)
            self.fwd_times.append(ts)
            self.fwd_header_lengths.append(header_len)

            if not self.fwd_seen:
                self.fwd_init_window_bytes = window
                self.fwd_seen = True
        else:
            self.bwd_lengths.append(pkt_len)
            self.bwd_times.append(ts)
            self.bwd_header_lengths.append(header_len)

            if not self.bwd_seen:
                self.bwd_init_window_bytes = window
                self.bwd_seen = True

    def to_cicids_features(self) -> dict[str, float]:
        duration_seconds = max(1e-6, self.end_time - self.start_time)
        duration_micro = duration_seconds * 1_000_000.0

        total_fwd = len(self.fwd_lengths)
        total_bwd = len(self.bwd_lengths)
        total_packets = total_fwd + total_bwd

        total_fwd_bytes = _sum(self.fwd_lengths)
        total_bwd_bytes = _sum(self.bwd_lengths)
        total_bytes = total_fwd_bytes + total_bwd_bytes

        flow_iat = _iat_stats(self.all_times)
        fwd_iat = _iat_stats(self.fwd_times)
        bwd_iat = _iat_stats(self.bwd_times)

        down_up_ratio = total_bwd / total_fwd if total_fwd > 0 else 0.0

        active_stats = {
            "mean": 0.0,
            "std": 0.0,
            "max": 0.0,
            "min": 0.0,
        }

        idle_stats = {
            "mean": 0.0,
            "std": 0.0,
            "max": 0.0,
            "min": 0.0,
        }

        row = {
            "Destination Port": self.fwd_dst_port,
            "Flow Duration": duration_micro,

            "Total Fwd Packets": total_fwd,
            "Total Backward Packets": total_bwd,
            "Total Length of Fwd Packets": total_fwd_bytes,
            "Total Length of Bwd Packets": total_bwd_bytes,

            "Fwd Packet Length Max": _max(self.fwd_lengths),
            "Fwd Packet Length Min": _min(self.fwd_lengths),
            "Fwd Packet Length Mean": _mean(self.fwd_lengths),
            "Fwd Packet Length Std": _std(self.fwd_lengths),

            "Bwd Packet Length Max": _max(self.bwd_lengths),
            "Bwd Packet Length Min": _min(self.bwd_lengths),
            "Bwd Packet Length Mean": _mean(self.bwd_lengths),
            "Bwd Packet Length Std": _std(self.bwd_lengths),

            "Flow Bytes/s": total_bytes / duration_seconds,
            "Flow Packets/s": total_packets / duration_seconds,

            "Flow IAT Mean": flow_iat["mean"],
            "Flow IAT Std": flow_iat["std"],
            "Flow IAT Max": flow_iat["max"],
            "Flow IAT Min": flow_iat["min"],

            "Fwd IAT Total": fwd_iat["total"],
            "Fwd IAT Mean": fwd_iat["mean"],
            "Fwd IAT Std": fwd_iat["std"],
            "Fwd IAT Max": fwd_iat["max"],
            "Fwd IAT Min": fwd_iat["min"],

            "Bwd IAT Total": bwd_iat["total"],
            "Bwd IAT Mean": bwd_iat["mean"],
            "Bwd IAT Std": bwd_iat["std"],
            "Bwd IAT Max": bwd_iat["max"],
            "Bwd IAT Min": bwd_iat["min"],

            "Fwd PSH Flags": self.fwd_psh_flags,
            "Bwd PSH Flags": self.bwd_psh_flags,
            "Fwd URG Flags": self.fwd_urg_flags,
            "Bwd URG Flags": self.bwd_urg_flags,

            "Fwd Header Length": _sum(self.fwd_header_lengths),
            "Bwd Header Length": _sum(self.bwd_header_lengths),

            "Fwd Packets/s": total_fwd / duration_seconds,
            "Bwd Packets/s": total_bwd / duration_seconds,

            "Min Packet Length": _min(self.all_lengths),
            "Max Packet Length": _max(self.all_lengths),
            "Packet Length Mean": _mean(self.all_lengths),
            "Packet Length Std": _std(self.all_lengths),
            "Packet Length Variance": _std(self.all_lengths) ** 2,

            "FIN Flag Count": self.fin_count,
            "SYN Flag Count": self.syn_count,
            "RST Flag Count": self.rst_count,
            "PSH Flag Count": self.psh_count,
            "ACK Flag Count": self.ack_count,
            "URG Flag Count": self.urg_count,
            "CWE Flag Count": self.cwe_count,
            "ECE Flag Count": self.ece_count,

            "Down/Up Ratio": down_up_ratio,
            "Average Packet Size": total_bytes / total_packets if total_packets else 0.0,
            "Avg Fwd Segment Size": _mean(self.fwd_lengths),
            "Avg Bwd Segment Size": _mean(self.bwd_lengths),

            "Fwd Header Length.1": _sum(self.fwd_header_lengths),

            "Subflow Fwd Packets": total_fwd,
            "Subflow Fwd Bytes": total_fwd_bytes,
            "Subflow Bwd Packets": total_bwd,
            "Subflow Bwd Bytes": total_bwd_bytes,

            "Init_Win_bytes_forward": self.fwd_init_window_bytes,
            "Init_Win_bytes_backward": self.bwd_init_window_bytes,

            "act_data_pkt_fwd": total_fwd,
            "min_seg_size_forward": _min(self.fwd_header_lengths),

            "Active Mean": active_stats["mean"],
            "Active Std": active_stats["std"],
            "Active Max": active_stats["max"],
            "Active Min": active_stats["min"],

            "Idle Mean": idle_stats["mean"],
            "Idle Std": idle_stats["std"],
            "Idle Max": idle_stats["max"],
            "Idle Min": idle_stats["min"],
        }

        # Extra metadata, ignored by CICIDS model if not requested.
        row["_proto"] = self.proto
        row["_src_ip"] = self.fwd_src_ip
        row["_src_port"] = self.fwd_src_port
        row["_dst_ip"] = self.fwd_dst_ip
        row["_dst_port"] = self.fwd_dst_port
        row["_packets"] = total_packets

        # Add underscore aliases because some exported models use normalized names.
        aliases = {}
        for key, value in row.items():
            clean = (
                key.replace(" ", "_")
                .replace("/", "_")
                .replace(".", "_")
                .replace("-", "_")
            )
            aliases[clean] = value

        row.update(aliases)

        return row


def _flow_key(proto: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int):
    a = (src_ip, int(src_port))
    b = (dst_ip, int(dst_port))

    if a <= b:
        return proto, a[0], a[1], b[0], b[1]
    return proto, b[0], b[1], a[0], a[1]


def capture_cicids_flows(
    duration: int = 15,
    max_packets: int = 3000,
    iface: str | None = None,
) -> dict[str, Any]:
    """
    Capture live packets and aggregate them into CICIDS-style flow features.

    Windows note:
    This usually requires Npcap and often requires running the app as Administrator.
    """
    if sniff is None or IP is None:
        return {
            "ok": False,
            "error": "Scapy is not installed or packet capture backend is unavailable. Run: python -m pip install scapy",
            "flows": [],
            "packet_count": 0,
            "flow_count": 0,
        }

    flows: dict[tuple, FlowAccumulator] = {}
    packet_count = 0

    def handle_packet(pkt):
        nonlocal packet_count

        try:
            if not pkt.haslayer(IP):
                return

            proto = ""
            src_port = 0
            dst_port = 0

            if TCP is not None and pkt.haslayer(TCP):
                proto = "TCP"
                src_port = int(pkt[TCP].sport)
                dst_port = int(pkt[TCP].dport)

            elif UDP is not None and pkt.haslayer(UDP):
                proto = "UDP"
                src_port = int(pkt[UDP].sport)
                dst_port = int(pkt[UDP].dport)

            else:
                return

            src_ip = str(pkt[IP].src)
            dst_ip = str(pkt[IP].dst)
            ts = float(getattr(pkt, "time", time.time()))

            key = _flow_key(proto, src_ip, src_port, dst_ip, dst_port)

            if key not in flows:
                flows[key] = FlowAccumulator(
                    proto=proto,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    first_time=ts,
                )

            flows[key].add_packet(pkt, src_ip, src_port, dst_ip, dst_port, ts)
            packet_count += 1

        except Exception:
            return

    try:
        sniff(
            prn=handle_packet,
            timeout=duration,
            count=max_packets,
            store=False,
            iface=iface,
        )

    except Exception as exc:
        return {
            "ok": False,
            "error": (
                "Packet capture failed. On Windows, install Npcap and run the app as Administrator. "
                f"Original error: {exc}"
            ),
            "flows": [],
            "packet_count": packet_count,
            "flow_count": 0,
        }

    rows = [
        flow.to_cicids_features()
        for flow in flows.values()
        if (len(flow.fwd_lengths) + len(flow.bwd_lengths)) > 0
    ]

    return {
        "ok": True,
        "error": "",
        "flows": rows,
        "packet_count": packet_count,
        "flow_count": len(rows),
        "duration": duration,
    }