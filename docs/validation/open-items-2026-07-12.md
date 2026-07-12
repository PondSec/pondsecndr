# Open validation and hardening items - 2026-07-12

This list tracks the current PondSec NDR hardening work before final cleanup,
validation reporting, and production readiness.

## Active security fixes

- Completed: active PF blocks are rehydrated from `block_entries` after service,
  firewall, or deployment reloads.
- Completed: traffic that is already blocked by OPNsense filterlog is treated as
  prevention evidence and no longer opens fresh reconnaissance incidents by
  itself.
- Verified on the target box: `51.159.110.167`, `107.180.212.85`, and
  `176.65.148.230` were present in the `virusprot` PF table after redeploy.

## Data source coverage

- Completed: diagnostics backend response time was reduced on the target box
  from roughly 16 seconds to roughly 5 seconds by avoiding a full SQLite
  integrity check on normal status/diagnostics views. The full check remains
  available in self-test and database check workflows.
- Completed: diagnostics browser view now renders a concrete backend error when
  the API fails or exceeds the UI timeout instead of leaving every panel on
  `Loading`.
- Zeek is not installed as a running service on the target box yet; install,
  configure, and connect its logs to PondSec NDR.
- Suricata EVE currently does not emit `fileinfo`; enable and validate file
  metadata without enabling destructive payload storage.
- File sandbox coverage is deployed but currently has zero live file verdict
  events; validate result ingestion and pending request handling.
- Zenarmor coverage is active for flow, DNS, TLS, HTTP, app and security
  metadata; continue validating provider field mapping and TLS-inspection
  metadata quality.

## Detection quality

- Re-check open false-positive incidents after the current implementation work.
- Confirm false-positive feedback is reflected in deterministic suppression or
  local IOC overrides without teaching malicious validation traffic as normal.
- Validate that independent attacks stay separate and multi-stage attacks are
  correlated into one case.
- Validate that prevention actions remain reversible and do not block normal
  clients or infrastructure.

## Validation and reporting

- Repeat no-VPN internal safe adversary emulation after the block and data-source
  fixes.
- Repeat external safe validation against the approved public targets.
- Re-run worm-like internal and external simulations after prevention gating.
- Update validation reports with expected detection class, actual result,
  latency, false positive/negative status, root cause, fix, and retest result.
- Update the feature catalog and repository documentation after implementation
  is stable.

## Final cleanup

- Preserve validation evidence first.
- Remove only generated test artifacts, temporary test services, test blocks and
  sinkholes.
- Reset incidents, detections, learning/baseline test state, and validation data
  at the very end so test traffic is not retained as normal baseline.
