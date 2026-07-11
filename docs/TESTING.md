# Testing

## Current Tests

The test suite covers:

- Suricata EVE parsing.
- Corrupt JSON line handling.
- Collector offsets and rotation.
- Event normalization.
- IP and port validation.
- Feature aggregation.
- Port scan detection.
- Beaconing detection.
- DNS tunneling heuristics.
- Incident correlation and risk scoring.
- SQLite migration and dashboard queries.
- External pretrained model catalog and CICIDS2017 feature vector mapping.
- Verified external model download with SHA-256 checks in a temporary directory.
- Safe response proposal, allowlist denial, protected target denial, PF table activation/removal, and controlled protection validation.
- CLI health and configuration validation.
- Package shell syntax, conservative deinstall defaults, full cleanup controls,
  PF block cleanup fallback, install/remove message content, and signed
  repository documentation requirements.

See [VALIDATION.md](VALIDATION.md) for firewall-level validation results.

## Command

```sh
python3 -m unittest discover -s tests
```

## Validation Lab

`tools/ndr_validation_lab.py` generates harmless Suricata EVE JSONL telemetry
for broad NDR validation. It covers reconnaissance, brute-force-like credential
pressure, exploit-attempt markers, DNS tunneling, TLS fingerprint churn,
beaconing, malware callback markers, supply-chain callback patterns, lateral
movement, exfiltration, and multi-stage correlation.

```sh
python3 tools/ndr_validation_lab.py --json generate --scenario all --output reports/validation-lab/all-scenarios.eve.jsonl
python3 tools/ndr_validation_lab.py --json analyze --input reports/validation-lab/all-scenarios.eve.jsonl --manifest reports/validation-lab/all-scenarios.eve.jsonl.manifest.json
python3 tools/ndr_validation_lab.py --json report --analysis reports/validation-lab/all-scenarios.analysis.json --output reports/validation-lab/all-scenarios.report.md
```

The lab data is synthetic and must not include real credentials, working
exploits, malware, or destructive payloads. Use it as a regression harness
before controlled live network-path testing.

## Test Data Policy

All test data must be synthetic. Do not commit real firewall logs or personally identifiable network traffic.

## OPNsense Tests

Target firewall validation must include:

- Package install.
- Menu visibility.
- ACL visibility.
- Settings save.
- Service start, stop, restart.
- Healthcheck.
- EVE ingestion.
- Dashboard data.
- Diagnostics self-test.
- Controlled detect-and-block validation with `pondsec-ndrctl protection validate --json`.
- Uninstall and residual path checks.
- Signed repository install from `PondSec.conf`.
