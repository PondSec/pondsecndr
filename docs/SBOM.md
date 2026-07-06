# PondSec NDR SBOM

This is the human-readable SBOM snapshot for the `0.1.0-beta` package stream.
It is not a replacement for a generated SPDX or CycloneDX file, but it records
the components that must be checked before a public release.

## Package

| Field | Value |
| --- | --- |
| Package | `os-pondsec-ndr` |
| Version | `0.1.0` |
| Revision | `1` |
| License | BSD-2-Clause |
| Runtime user | `pondsecndr` |
| Data directory | `/var/db/pondsec-ndr` |
| Config directory | `/usr/local/etc/pondsec-ndr` |
| Service | `pondsec_ndr` |

## Runtime Components

| Component | Purpose | Source | Required |
| --- | --- | --- | --- |
| OPNsense MVC/API files | GUI, API, menu, ACL | This repository | Yes |
| configd actions | Controlled backend command execution | This repository | Yes |
| rc.d script | Service lifecycle | This repository | Yes |
| Python backend | Collect, normalize, detect, correlate, respond | This repository | Yes |
| SQLite database | Local metadata and incident store | FreeBSD/Python sqlite3 package | Yes |
| NumPy | Pretrained model inference runtime | FreeBSD `py*-numpy` package | Yes |
| PF/pfctl | Temporary block enforcement | FreeBSD/OPNsense base | Required for prevent mode |
| Suricata EVE JSON | Network security telemetry | OPNsense Suricata package | Recommended |
| Zenarmor or Squid TLS inspection | Optional decrypted metadata source when already configured | Local firewall service | Optional |

## Model Artifact

| Field | Value |
| --- | --- |
| Model ID | `saidimn-ids-cnn-cicids2017` |
| Runtime version | `pondsec-numpy-cnn1d-v1` |
| Artifact path | `/usr/local/share/pondsec-ndr/pondsec_ndr/models/artifacts/saidimn_ids_cnn_cicids2017.npz` |
| SHA-256 | `51bec93ec2c8ac9a480fcef8694852792a8869a817b07d1cef11a2f1fd62c45b` |
| Feature schema | `1` |
| Training dataset | CICIDS2017-derived feature vectors |
| Runtime format | Pickle-free NumPy archive |
| Activation rule | May be shown as `active` only after target-box load and self-test |

The optimized 99.58 percent vector is a synthetic AI validation vector. It is a
runtime self-test and not a claim of real-world detection quality.

## Generated Release Artifacts

Public releases must add generated artifacts next to this document:

- SPDX or CycloneDX SBOM,
- package SHA-256 checksums,
- signed repository metadata,
- model manifest checksum,
- dependency license scan output.

## Data Handling Boundaries

PondSec NDR stores network metadata. It must not include private keys,
passwords, decrypted payload bodies, cookies, authorization headers, or full
payload captures in diagnostic archives or default exports.
