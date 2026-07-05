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
- CLI health and configuration validation.

## Command

```sh
python3 -m unittest discover -s tests
```

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
- Uninstall and residual path checks.
