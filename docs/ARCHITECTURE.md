# PondSec NDR Architecture

## Repository Analysis

The repository started as an empty git repository on branch `main` with a configured `origin` remote at `https://github.com/pondsec/pondsecndr.git`. No application files, package structure, tests, OPNsense components, build system, CI configuration, documentation, data models, or backend services existed before this initial implementation.

Observed initial state:

- Files: only `.DS_Store` plus git metadata.
- Languages: none present before implementation.
- Package structure: none present before implementation.
- Tests: none present before implementation.
- OPNsense components: none present before implementation.
- Build system: none present before implementation.
- CI: none present before implementation.
- Documentation: none present before implementation.
- Security issues found in existing code: none, because no code existed.

This implementation adds a production-oriented plugin foundation rather than a mockup.

## Design Constraints

- PondSec NDR is an NDR, not an EDR.
- The first version does not implement an inline packet engine in the netmap path.
- The default mode is `monitor`.
- Failures must be fail-open.
- ML detections alone must not create permanent blocks.
- GUI and API must use OPNsense MVC and configd, not a separate web server.
- Backend code must avoid direct `config.xml` reads.
- Raw payloads and secrets must not be stored by default.

## Runtime Paths

- Configuration: `/usr/local/etc/pondsec-ndr/`
- Data: `/var/db/pondsec-ndr/`
- Logs: `/var/log/pondsec-ndr/`
- Runtime state: `/var/run/pondsec-ndr/`

## Components

### OPNsense GUI

The GUI is implemented as standard OPNsense MVC pages under `OPNsense/PondSecNDR`. The left navigation exposes `PondSec NDR` with the required subpages. Pages load real backend data through API endpoints. Missing data renders empty states instead of synthetic values.

### OPNsense API

API controllers expose service status, settings, dashboard, detections, incidents, hosts, lists, models, diagnostics, and logs. Controllers delegate backend reads to configd actions.

### Configuration Manager

Configuration is stored in the OPNsense model `//OPNsense/pondsecndr` and rendered to `/usr/local/etc/pondsec-ndr/pondsec-ndr.json` through configd templates.

### Service Manager

The service manager uses configd actions and an rc.d script. The main process is `pondsec-ndr`. The CLI is `pondsec-ndrctl`.

### Telemetry Collector

The first collector tails Suricata EVE JSON, tracks inode and offset, detects rotation, tolerates corrupt lines, counts parser errors, and persists progress.

### Event Normalizer

Normalizers convert external source events into a versioned internal schema. The first normalizer supports Suricata EVE event types and removes sensitive content.

### Feature Aggregator

The feature aggregator calculates deterministic metadata features over configured time windows. It is separated from detectors so future data sources can reuse the same feature schema.

### Detection Engine

Detectors implement a common interface and return versioned detection results. Initial deterministic detectors cover scan behavior, beaconing, DNS tunneling, lateral movement, data exfiltration, unusual TLS fingerprints, unusual destinations, and Suricata alerts.

### Machine Learning Engine

The ML engine is prepared around external pretrained IDS models. It keeps training and inference separate, tracks model metadata and checksums, and rejects unsafe or incompatible model artifacts. Pickle/joblib artifacts from model repositories are downloaded only with checksum verification and are not deserialized by the root service.

### Correlation Engine

The first correlation layer groups detections by source, category, and time into incidents. Later phases will add attack-path timelines across host pairs, domains, TLS fingerprints, and Suricata signatures.

### Risk Engine

Risk scores are deterministic and explainable. Factors include severity, confidence, anomaly score, detector count, event count, baseline deviation, Suricata alerts, affected hosts, policy weight, and allowlist results.

### Response Engine

The response implementation prepares alert and block proposal records first. A confirmed block activation writes the source to the configured PF table after risk, confidence, protected-target, and allowlist checks. Automatic blocking remains disabled by default. Current controlled enforcement uses OPNsense's active `virusprot` block table on the validated firewall:

- `PONDSEC_NDR_BLOCK`
- `PONDSEC_NDR_QUARANTINE`
- `PONDSEC_NDR_ALLOWLIST`

### Local Event Store

SQLite is used for the first version with WAL mode, schema migrations, indexes, batch writes, retention hooks, and metadata tables.

### Model Manager

The model manager stores model metadata, checksums, compatibility state, metrics, activation state, and rollback information.

### Diagnostics Service

Diagnostics read service health, queue counters, collector offsets, database status, active model metadata, and recent component errors.

### Replay and Benchmark Tool

`pondsec-ndrctl replay` reads EVE files using the same normalizer and detectors. Replay is simulation-only and must not modify PF.

## Data Flow

1. Suricata writes EVE JSON.
2. The collector reads new lines and persists offsets.
3. The normalizer validates IPs, ports, timestamps, event type, and sensitive metadata.
4. Normalized events are batched into SQLite.
5. Feature aggregation updates host and flow windows.
6. Detectors run on batches or windows.
7. Detections are stored and correlated into incidents.
8. The risk engine calculates explainable scores.
9. The dashboard and API read summaries through the CLI/configd boundary.
10. Response actions remain suggestions unless policies and mode allow controlled enforcement.

## Process Boundaries

- PHP controllers: presentation and OPNsense API glue only.
- Configd: controlled command boundary.
- Python backend: collection, normalization, detection, storage, health.
- Privileged response path: PF table mutations only, with constrained inputs.

## Privileges

The main backend should run as a dedicated unprivileged user. Root-only operations are isolated to install scripts, rc.d setup, configd service actions, and response helpers. The main service does not require raw packet access.

## Dependencies

The first implementation uses:

- OPNsense MVC, configd, rc.d
- Python 3 standard library
- SQLite through Python `sqlite3`

No large ML/runtime dependency is added in the first foundation.

## Performance Risks

- Large EVE files can exceed configured processing limits.
- SQLite write pressure can rise during bursts.
- Dashboard queries can become expensive without retention and indexes.
- Detector windows must remain bounded.
- Queue overflow must be visible and counted.

## Security Risks

- Incorrect interface validation could monitor or exclude the wrong source.
- PF integration could block protected infrastructure if guardrails fail.
- Model artifact import could become unsafe if checksums and formats are bypassed.
- Alert floods could exhaust storage if retention limits are misconfigured.

## Open Decisions

- Final FreeBSD package dependency name for Python 3 on target OPNsense releases.
- Whether verified external model inference should use an optional PyTorch worker, ONNX conversion, or a compact native runtime on OPNsense.
- Automatic prevent-mode policy and helper design.
- Final dashboard charting pattern after testing inside the OPNsense UI.
- Upstream placement in the OPNsense plugins tree category.
