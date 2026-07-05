"""CICIDS2017-style feature mapping for external pretrained IDS models."""

from __future__ import annotations

from typing import Any


# The preferred external model expects CICIDS2017/CICFlowMeter-like numeric
# features. PondSec derives the subset it can explain from normalized metadata
# and fills unavailable packet-level fields with zero rather than inventing data.
CICIDS2017_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]


def cicids_vector_from_feature(feature: dict[str, Any]) -> list[float]:
    override = feature.get("cicids_vector")
    if isinstance(override, list) and len(override) == len(CICIDS2017_FEATURES):
        return [float(value) for value in override]

    duration = float(feature.get("flow_duration") or 0)
    packets = float(feature.get("packet_count") or 0)
    packets_out = float(feature.get("packets_out") or 0)
    packets_in = float(feature.get("packets_in") or 0)
    bytes_out = float(feature.get("bytes_out") or 0)
    bytes_in = float(feature.get("bytes_in") or 0)
    byte_count = float(feature.get("byte_count") or 0)
    fwd_packets = max(1.0, packets_out or packets * 0.5)
    bwd_packets = max(1.0, packets_in or packets - fwd_packets)
    flow_seconds = max(duration, 1.0)
    avg_packet = byte_count / max(packets, 1.0)

    values = {name: 0.0 for name in CICIDS2017_FEATURES}
    values.update({
        "Destination Port": float(feature.get("dominant_destination_port") or 0),
        "Flow Duration": duration,
        "Total Fwd Packets": fwd_packets,
        "Total Backward Packets": bwd_packets,
        "Total Length of Fwd Packets": bytes_out,
        "Total Length of Bwd Packets": bytes_in,
        "Fwd Packet Length Mean": bytes_out / fwd_packets,
        "Bwd Packet Length Mean": bytes_in / bwd_packets,
        "Flow Bytes/s": byte_count / flow_seconds,
        "Flow Packets/s": packets / flow_seconds,
        "Fwd Packets/s": fwd_packets / flow_seconds,
        "Bwd Packets/s": bwd_packets / flow_seconds,
        "Min Packet Length": avg_packet,
        "Max Packet Length": avg_packet,
        "Packet Length Mean": avg_packet,
        "Down/Up Ratio": bytes_in / max(bytes_out, 1.0),
        "Average Packet Size": avg_packet,
        "Avg Fwd Segment Size": bytes_out / fwd_packets,
        "Avg Bwd Segment Size": bytes_in / bwd_packets,
        "Subflow Fwd Packets": fwd_packets,
        "Subflow Fwd Bytes": bytes_out,
        "Subflow Bwd Packets": bwd_packets,
        "Subflow Bwd Bytes": bytes_in,
    })
    return [float(values[name]) for name in CICIDS2017_FEATURES]
