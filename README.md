# PondSec NDR

Behavioral Network Detection and Response for OPNsense

PondSec NDR is an open-source OPNsense plugin foundation for network detection and response. It collects firewall-visible telemetry, normalizes events, stores metadata locally, runs deterministic network detectors, correlates detections into incidents, and prepares controlled response actions through OPNsense and PF.

The project is intentionally scoped as an NDR. It is not an endpoint detection and response system and cannot reliably observe local process manipulation, registry changes, memory injection, local file changes, or traffic that does not traverse the firewall.

## Current Status

This repository currently contains the first production-oriented foundation:

- OPNsense plugin package skeleton for `os-pondsec-ndr`
- OPNsense MVC model, API controllers, menu entries, ACL entries, forms, and views
- Configd service actions for `pondsec-ndr`
- Python 3 backend service using only standard-library dependencies
- Structured JSON logging, service health output, and CLI commands
- Suricata EVE JSON collector and normalizer
- SQLite event store with migrations, WAL mode, retention hooks, and dashboard queries
- Initial port scan, horizontal scan, vertical scan, DNS tunneling, beaconing, lateral movement, exfiltration, TLS fingerprint, and Suricata alert detectors
- External pretrained IDS model catalog with verified checksums for MIT-licensed CICIDS2017 models
- Unit tests using synthetic events only

Automatic blocking is disabled by default. The default operating mode is `monitor`.

## Supported Data Sources

The first collector supports Suricata EVE JSON event types:

- `flow`
- `alert`
- `dns`
- `tls`
- `http`
- `fileinfo`
- `anomaly`
- `stats`

Additional OPNsense firewall logs, PF state data, DNS, TLS, HTTP metadata, DHCP leases, ARP/NDP data, and interface statistics are planned behind the same normalized event schema.

## Architecture

PondSec NDR separates the OPNsense GUI and API from the backend service. GUI controllers call configd actions, configd calls the local CLI, and the CLI reads backend health and metadata from controlled paths.

Main components:

- OPNsense GUI and API
- Configuration Manager
- Service Manager
- Telemetry Collector
- Event Normalizer
- Feature Aggregator
- Detection Engine
- Machine Learning Engine
- Correlation Engine
- Risk Engine
- Response Engine
- Local Event Store
- Model Manager
- Diagnostics Service
- Replay and Benchmark Tool

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for details.

## Security Model

PondSec NDR follows fail-open behavior. A service error must not interrupt firewall packet forwarding. ML output alone must never create a permanent block. Prevent-mode response actions require policy approval, high confidence, protected-target checks, allowlist checks, and time-limited enforcement.

Sensitive payloads such as HTTP bodies, credentials, cookies, authorization headers, full query strings, and file contents are not stored by default.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), [docs/PRIVACY.md](docs/PRIVACY.md), and [docs/EXTERNAL_MODELS.md](docs/EXTERNAL_MODELS.md).

## Development

Run the Python tests from the repository root:

```sh
python3 -m unittest discover -s tests
```

Run a local one-shot replay with synthetic EVE data:

```sh
PYTHONPATH=src/usr/local/share/pondsec-ndr \
python3 -m pondsec_ndr.cli replay tests/fixtures/suricata_eve_sample.jsonl --json
```

List external pretrained IDS models:

```sh
PYTHONPATH=src/usr/local/share/pondsec-ndr \
python3 -m pondsec_ndr.cli model list --json
```

## OPNsense Installation Status

The plugin is laid out like an OPNsense plugin and is intended to build as `os-pondsec-ndr` inside the OPNsense plugins tree. The repository is not yet upstreamed into `opnsense/plugins`, so installation on a firewall currently uses a development checkout or package build.

See [docs/OPNSENSE_INSTALLATION.md](docs/OPNSENSE_INSTALLATION.md) and [docs/PACKAGING.md](docs/PACKAGING.md).

Firewall-level validation notes are tracked in [docs/VALIDATION.md](docs/VALIDATION.md).

## Roadmap

- Phase 1: plugin skeleton, menu, ACL, settings, service control, dashboard, healthcheck
- Phase 2: EVE collector, normalization, SQLite, detections, hosts, diagnostics
- Phase 3: feature aggregation, deterministic detectors, risk scoring
- Phase 4: model lifecycle, host learning phase, safe anomaly model support
- Phase 5: incident correlation, timelines, policies, response suggestions
- Phase 6: PF integration, temporary blocks, allowlist, audit log
- Phase 7: replay, benchmarks, packaging, OPNsense upgrade and rollback tests

## License

PondSec NDR is prepared for BSD-2-Clause licensing to match the OPNsense plugin ecosystem. See [LICENSE](LICENSE).

## Contributing

Contributions should keep the system fail-open, avoid payload storage, use synthetic test data, and maintain the separation between GUI/API, configd, backend processing, and response helpers.
