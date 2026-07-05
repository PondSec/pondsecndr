# Implementation Plan

## Phase 1: Plugin Foundation

Status: in progress.

Deliverables:

- Repository analysis and documentation.
- `os-pondsec-ndr` OPNsense plugin skeleton.
- OPNsense menu entries and ACL keys.
- Settings model and form.
- Service controller with configd actions.
- Backend healthcheck and CLI.
- Dashboard page backed by real service data.

Acceptance checks:

- PHP files pass syntax checks where PHP is available.
- Python CLI can run locally with a test data directory.
- Unit tests pass with synthetic inputs.

## Phase 2: Telemetry and Storage

Status: initial implementation in this repository.

Deliverables:

- Suricata EVE collector.
- Offset persistence and rotation handling.
- Event normalization.
- SQLite schema migrations and WAL mode.
- Detections and hosts list APIs.
- Diagnostics API and self-test.

## Phase 3: Deterministic Detection and Risk

Status: initial implementation in this repository.

Deliverables:

- Feature aggregation windows: 10s, 60s, 5m, 1h, 24h.
- Port scan, horizontal scan, vertical scan.
- Beaconing and DNS tunneling.
- Suricata alert adapter.
- Explainable risk scoring.
- External pretrained IDS model catalog and feature mapping.

## Phase 4: Models and Learning Phase

Status: planned.

Deliverables:

- Host learning progress.
- Baseline reset.
- Model metadata, checksum verification, compatibility checks.
- Safe model activation and rollback.
- Optional anomaly model when FreeBSD packaging is verified.
- Optional PyTorch worker for verified external pretrained CICIDS2017 models.

## Phase 5: Correlation and Incidents

Status: planned.

Deliverables:

- Incident timelines.
- Multi-detector correlation.
- False-positive feedback storage.
- Policy evaluation.
- Response suggestions.

## Phase 6: Controlled Response

Status: planned.

Deliverables:

- PF table helper with strict validation.
- Temporary block lifecycle.
- Quarantine suggestions.
- Allowlist and protected address checks.
- Audit log for every action.

## Phase 7: Packaging, Replay, Benchmarking

Status: planned.

Deliverables:

- Full OPNsense package build validation.
- Install, uninstall, upgrade, and rollback tests.
- Replay controls.
- Benchmarks at 1k, 5k, and 10k events/sec.
- Transparent event drop reporting.

## Current Scope Boundaries

The current foundation does not claim complete prevent-mode enforcement, production ML inference, or full OPNsense package certification. It provides the structure and first working backend needed to test on a firewall and iterate safely.
