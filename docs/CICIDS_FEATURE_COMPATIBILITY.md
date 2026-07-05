# CICIDS2017 Feature Compatibility

PondSec NDR uses the pretrained `saidimn/ids-cnn-cicids2017` CNN-1D model through a pickle-free NumPy runtime artifact exported from the verified upstream PyTorch weights. The model expects 78 CICIDS2017/CICFlowMeter-style numeric features.

Important scope: Suricata EVE JSON does not expose every packet-level field that CICFlowMeter computes from raw packet captures. PondSec therefore maps only explainable values from EVE metadata and uses conservative defaults for unavailable fields. The synthetic AI validation vector is a runtime self-test vector, not a claim of real-world detection quality.

## Compatibility Table

Summary:

- Direct from Suricata EVE: 6 features.
- Exactly calculated from Suricata counters: 15 features.
- Approximated from aggregate EVE metadata: 2 features.
- Set to explicit default value `0`: 27 features.
- Currently unavailable from normal Suricata EVE flow records: 28 features.

| # | CICIDS2017 feature | PondSec source | Status |
|---:|---|---|---|
| 1 | Destination Port | `dest_port` from Suricata EVE | Direct |
| 2 | Flow Duration | `flow.age` from Suricata EVE | Direct |
| 3 | Total Fwd Packets | `flow.pkts_toserver` | Direct |
| 4 | Total Backward Packets | `flow.pkts_toclient` | Direct |
| 5 | Total Length of Fwd Packets | `flow.bytes_toserver` | Direct |
| 6 | Total Length of Bwd Packets | `flow.bytes_toclient` | Direct |
| 7 | Fwd Packet Length Max | Not exposed in EVE flow summary | Default 0 |
| 8 | Fwd Packet Length Min | Not exposed in EVE flow summary | Default 0 |
| 9 | Fwd Packet Length Mean | `bytes_toserver / pkts_toserver` | Calculated |
| 10 | Fwd Packet Length Std | Not exposed in EVE flow summary | Default 0 |
| 11 | Bwd Packet Length Max | Not exposed in EVE flow summary | Default 0 |
| 12 | Bwd Packet Length Min | Not exposed in EVE flow summary | Default 0 |
| 13 | Bwd Packet Length Mean | `bytes_toclient / pkts_toclient` | Calculated |
| 14 | Bwd Packet Length Std | Not exposed in EVE flow summary | Default 0 |
| 15 | Flow Bytes/s | `(bytes_toserver + bytes_toclient) / flow_duration` | Calculated |
| 16 | Flow Packets/s | `(pkts_toserver + pkts_toclient) / flow_duration` | Calculated |
| 17 | Flow IAT Mean | Requires per-packet timing | Unavailable |
| 18 | Flow IAT Std | Requires per-packet timing | Unavailable |
| 19 | Flow IAT Max | Requires per-packet timing | Unavailable |
| 20 | Flow IAT Min | Requires per-packet timing | Unavailable |
| 21 | Fwd IAT Total | Requires per-packet timing | Unavailable |
| 22 | Fwd IAT Mean | Requires per-packet timing | Unavailable |
| 23 | Fwd IAT Std | Requires per-packet timing | Unavailable |
| 24 | Fwd IAT Max | Requires per-packet timing | Unavailable |
| 25 | Fwd IAT Min | Requires per-packet timing | Unavailable |
| 26 | Bwd IAT Total | Requires per-packet timing | Unavailable |
| 27 | Bwd IAT Mean | Requires per-packet timing | Unavailable |
| 28 | Bwd IAT Std | Requires per-packet timing | Unavailable |
| 29 | Bwd IAT Max | Requires per-packet timing | Unavailable |
| 30 | Bwd IAT Min | Requires per-packet timing | Unavailable |
| 31 | Fwd PSH Flags | Not exposed in EVE flow summary | Default 0 |
| 32 | Bwd PSH Flags | Not exposed in EVE flow summary | Default 0 |
| 33 | Fwd URG Flags | Not exposed in EVE flow summary | Default 0 |
| 34 | Bwd URG Flags | Not exposed in EVE flow summary | Default 0 |
| 35 | Fwd Header Length | Not exposed in EVE flow summary | Default 0 |
| 36 | Bwd Header Length | Not exposed in EVE flow summary | Default 0 |
| 37 | Fwd Packets/s | `pkts_toserver / flow_duration` | Calculated |
| 38 | Bwd Packets/s | `pkts_toclient / flow_duration` | Calculated |
| 39 | Min Packet Length | Total bytes divided by total packets | Approximated |
| 40 | Max Packet Length | Total bytes divided by total packets | Approximated |
| 41 | Packet Length Mean | Total bytes divided by total packets | Calculated |
| 42 | Packet Length Std | Requires per-packet lengths | Unavailable |
| 43 | Packet Length Variance | Requires per-packet lengths | Unavailable |
| 44 | FIN Flag Count | Not exposed in EVE flow summary | Default 0 |
| 45 | SYN Flag Count | Not exposed in EVE flow summary | Default 0 |
| 46 | RST Flag Count | Not exposed in EVE flow summary | Default 0 |
| 47 | PSH Flag Count | Not exposed in EVE flow summary | Default 0 |
| 48 | ACK Flag Count | Not exposed in EVE flow summary | Default 0 |
| 49 | URG Flag Count | Not exposed in EVE flow summary | Default 0 |
| 50 | CWE Flag Count | Not exposed in EVE flow summary | Default 0 |
| 51 | ECE Flag Count | Not exposed in EVE flow summary | Default 0 |
| 52 | Down/Up Ratio | `bytes_toclient / bytes_toserver` | Calculated |
| 53 | Average Packet Size | Total bytes divided by total packets | Calculated |
| 54 | Avg Fwd Segment Size | `bytes_toserver / pkts_toserver` | Calculated |
| 55 | Avg Bwd Segment Size | `bytes_toclient / pkts_toclient` | Calculated |
| 56 | Fwd Header Length.1 | Duplicate CICIDS header-length field | Default 0 |
| 57 | Fwd Avg Bytes/Bulk | Bulk transfer accounting is not exposed | Default 0 |
| 58 | Fwd Avg Packets/Bulk | Bulk transfer accounting is not exposed | Default 0 |
| 59 | Fwd Avg Bulk Rate | Bulk transfer accounting is not exposed | Default 0 |
| 60 | Bwd Avg Bytes/Bulk | Bulk transfer accounting is not exposed | Default 0 |
| 61 | Bwd Avg Packets/Bulk | Bulk transfer accounting is not exposed | Default 0 |
| 62 | Bwd Avg Bulk Rate | Bulk transfer accounting is not exposed | Default 0 |
| 63 | Subflow Fwd Packets | Same as forward packet count in EVE window | Calculated |
| 64 | Subflow Fwd Bytes | Same as forward bytes in EVE window | Calculated |
| 65 | Subflow Bwd Packets | Same as backward packet count in EVE window | Calculated |
| 66 | Subflow Bwd Bytes | Same as backward bytes in EVE window | Calculated |
| 67 | Init_Win_bytes_forward | TCP initial window is not exposed | Unavailable |
| 68 | Init_Win_bytes_backward | TCP initial window is not exposed | Unavailable |
| 69 | act_data_pkt_fwd | Requires packet-level TCP accounting | Unavailable |
| 70 | min_seg_size_forward | Requires packet-level TCP accounting | Unavailable |
| 71 | Active Mean | Requires active/idle flow segmentation | Unavailable |
| 72 | Active Std | Requires active/idle flow segmentation | Unavailable |
| 73 | Active Max | Requires active/idle flow segmentation | Unavailable |
| 74 | Active Min | Requires active/idle flow segmentation | Unavailable |
| 75 | Idle Mean | Requires active/idle flow segmentation | Unavailable |
| 76 | Idle Std | Requires active/idle flow segmentation | Unavailable |
| 77 | Idle Max | Requires active/idle flow segmentation | Unavailable |
| 78 | Idle Min | Requires active/idle flow segmentation | Unavailable |

## Production Meaning

- `Direct` values are copied from Suricata EVE flow fields.
- `Calculated` values are deterministic calculations from direct Suricata counters.
- `Approximated` values are explainable estimates because EVE lacks per-packet distributions.
- `Default 0` values are present in the model vector but intentionally set to zero.
- `Unavailable` values require packet timing, TCP option/window, active/idle, or per-packet length information that normal EVE flow records do not provide.

For higher model fidelity, a future packet-level feature collector can replace the defaulted and unavailable fields with native CICFlowMeter-compatible values.
