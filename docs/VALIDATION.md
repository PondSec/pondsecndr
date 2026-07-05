# Validation Log

## 2026-07-05: OPNsense Firewall Development Install

Target:

- Host: `HWFirewall01.internal`
- Address: `192.168.99.2`
- User used for deployment: `pondadmin`
- OS: FreeBSD 14.3 / OPNsense stable/26.1 base

Validated deployment path:

- Copied plugin MVC files into `/usr/local/opnsense/mvc/app/...`
- Copied configd actions into `/usr/local/opnsense/service/conf/actions.d/actions_pondsecndr.conf`
- Copied configd templates into `/usr/local/opnsense/service/templates/OPNsense/PondSecNDR/`
- Copied backend into `/usr/local/share/pondsec-ndr/`
- Copied CLI and service wrappers into `/usr/local/sbin/`
- Copied rc.d service into `/usr/local/etc/rc.d/pondsec_ndr`
- Created/updated dedicated service user `pondsecndr`
- Created runtime paths under `/usr/local/etc/pondsec-ndr/`, `/var/db/pondsec-ndr/`, `/var/log/pondsec-ndr/`, and `/var/run/pondsec-ndr/`

Validation results:

- Python backend syntax: passed on firewall.
- PHP controller syntax: passed on firewall.
- OPNsense model/form/menu/ACL XML parsing: passed on firewall.
- `pondsec-ndrctl config validate`: passed.
- SQLite migration and integrity check: passed.
- External pretrained IDS model fetch: passed with SHA-256 verification for `saidimn-ids-cnn-cicids2017`.
- rc.d service start: passed.
- rc.d service stop: passed.
- Service runs as dedicated user: passed.
- Service health: `healthy` while running, `stopped` with null PID after stop.
- Suricata EVE synthetic ingestion: passed.
- Detections generated: port scan, vertical scan, beaconing.
- Incidents generated: reconnaissance and command-and-control.
- Dashboard summary returns real database data.
- Diagnostics returns DB, model, queue, parser, and PF table status.
- Diagnostics reports `eve_access`, including service-user readability of the configured EVE source.
- configd actions for dashboard, detections, incidents, models, allowlist, blocklist, and block expiry: passed.
- Allowlist safety gate: passed.
- Default response threshold gate: passed.
- Temporary lowered-threshold block proposal: passed.
- Proposed block activation/removal: initially passed in database-only mode.
- Incident close/reopen through configd: passed.

Post-validation production state:

- Test EVE path was removed from active configuration.
- Active configuration points to `/var/log/suricata/eve.json`.
- Synthetic validation database was backed up on the firewall and active DB was reset.
- Service remains running as `pondsecndr`.
- Because the target firewall currently has no readable Suricata EVE file, service health correctly reports `degraded`.
- The expected production remediation is to enable Suricata EVE JSON output and grant the unprivileged `pondsecndr` user read/traverse access to `/var/log/suricata/eve.json` without running PondSec NDR as root.
- Dashboard reports empty real data rather than synthetic records.
- Fail-open behavior was preserved during initial monitor-mode validation.

Important safety state:

- Default operating mode remains `monitor`.
- Automatic blocking remains disabled.
- PF mutation is limited to confirmed, time-limited blocklist activations through configd/CLI; automatic blocking remains disabled.
- External `.pth` and `.pkl` model artifacts are verified but not deserialized in the privileged service path.

Known validation gap:

- GitHub push now succeeds against `https://github.com/PondSec/pondsecndr.git`.
- Full package build inside the upstream OPNsense plugins tree is not yet completed.
- Browser-level GUI click testing must verify each authenticated PondSec NDR page after route fixes.

## 2026-07-05: Production EVE Ingest Enabled

The target firewall already had Suricata running and an active EVE file at
`/var/log/suricata/eve.json`, but the log directory and file were only readable
by `root:wheel`. Production telemetry was enabled without running PondSec NDR as
root:

- Added a FreeBSD ACL that lets `pondsecndr` traverse `/var/log/suricata`.
- Changed the active `eve.json` group to `pondsecndr` and mode to `640`.
- Added a file ACL that lets `pondsecndr` read the active EVE file.
- Updated `/etc/newsyslog.conf.d/suricata` so future `eve.json` rotations use `root:pondsecndr` with mode `640`.
- Backups were written under `/root/pondsec-ndr-suricata-acl-before-20260705184058.txt` and `/root/pondsec-ndr-newsyslog-suricata-before-20260705184058`.

Validation results after the change:

- `pondsec-ndrctl diagnostics self-test --json`: `status=ok`.
- `eve_access`: `status=ok`, `checked_by=service-user-probe`, `readable=true`.
- Service status: `healthy`, running as `pondsecndr`.
- Database integrity: `ok`, schema version `1`.
- Dashboard: real Suricata data, not synthetic fixtures.
- Observed real data: 16 events in the last 24 hours, 12 signature detections, 11 open incidents, 1 critical incident.
- Replay against the real EVE file parsed Suricata `drop` records and produced `pondsec.suricata_drop` detections without touching the production database.
- configd actions validated: `health`, `diagnostics`, `dashboard_summary`, `selftest`, `detections`, and `incidents`.
- Operating mode remained `monitor`; automatic blocking remained disabled.
- PF mutation remained disabled during passive EVE ingestion; controlled block validation is tracked separately.

## 2026-07-05: GUI Route and Protection Validation Fix

Follow-up validation target:

- Every menu URL under `/ui/pondsecndr/...` must resolve to a concrete UI controller.
- The diagnostics page exposes self-test and protection validation actions.
- `pondsec-ndrctl protection validate --json` must produce a port-scan detection, incident, response proposal, PF table activation, and PF verification.
- The configd action `configctl pondsecndr protection_validate` must return the same proof path.
- The PF block table is OPNsense `virusprot`, which is already referenced by an active `block drop ... from <virusprot> to any` rule on the target firewall.
