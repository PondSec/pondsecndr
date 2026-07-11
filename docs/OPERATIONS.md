# Operations

## Modes

Runtime mode and response mode are separate.

Runtime mode:

- `monitor`: collect telemetry and maintain baselines.
- `alert`: collect, detect, and create incidents.
- `interactive`: allow operator-driven response proposals.
- `prevent`: allow the response engine to evaluate enforcement candidates.

Response mode:

- `observe`: default after install and update. PondSec records decisions but never changes PF tables.
- `recommend`: PondSec can create response proposals without activating PF enforcement.
- `enforce`: PondSec can activate eligible response actions only after every safety precondition passes.

When `auto_arm_after_learning` is enabled, the stored configuration may remain
in `monitor` / `observe` during the initial learning phase. After the recorded
learning start is at least the configured number of days old and remaining days
reach zero, the service uses an effective runtime posture of `prevent` /
`enforce` with automatic blocking, AI full decision mode, internal isolation,
external blocking, and no manual confirmation delay. The stored configuration
is not rewritten; diagnostics and dashboard metrics show both configured and
effective modes.

Auto-arm still respects the response kill switch, maintenance mode, protected
assets, allowlists, confidence/risk thresholds, multi-source evidence gates,
cooldowns, rate limits, and mass-isolation safety fallback. Baselines continue
to update after the initial learning phase, but anomalous sources are skipped
from baseline updates for that run.

Internal auto-isolation requires all of the following:

- the 14-day learning phase is complete and recorded,
- the host baseline is stable,
- Enforce mode and automatic blocking are explicitly enabled,
- AI full decision mode is enabled,
- the target is not allowlisted, protected, management, or break-glass,
- multiple independent engines and categories agree,
- at least one strong attack category is present,
- risk, severity, and confidence thresholds pass,
- internal isolation cooldown and hourly rate limits are not exceeded.

Machine-learning evidence contributes to risk and confidence, but it does not
isolate a host by itself. False-positive feedback is host-local and
time-limited; it can help future baseline updates for the same host, but it
does not weaken global rules.

## Protection Validation

Run a controlled detect-and-block proof from the CLI or configd only in a
planned maintenance window:

```sh
pondsec-ndrctl protection validate --json
configctl pondsecndr protection_validate
```

The validation emits synthetic port-scan metadata, runs the normal detection
and correlation pipeline, creates a response proposal, activates it, and
verifies that PF has the source in the configured block table. The default
table is OPNsense's `virusprot`, which is referenced by the firewall rule set.

Use `--remove-after` during development when the validation block should be
removed immediately after proof. Without it, the block remains time-limited by
the generated block entry.

Do not use this command as proof of live attack detection. It is a synthetic
validation path for response plumbing and PF rollback.

## Health States

- `healthy`
- `degraded`
- `collector_error`
- `database_error`
- `model_error`
- `response_error`
- `stopped`

`degraded` is a valid fail-open state when the service process is alive but
telemetry is incomplete. A common production cause is an unreadable or missing
Suricata EVE file. Run:

```sh
pondsec-ndrctl diagnostics self-test --json
```

The `eve_access` block reports whether the `pondsecndr` service user can
traverse the configured log path and read `eve.json`.

## Suricata EVE Access

PondSec NDR must stay unprivileged. On OPNsense systems where Suricata logs are
owned by `root:wheel`, grant the service account only the access needed to read
EVE telemetry:

```sh
setfacl -m u:pondsecndr:xaRcs::allow /var/log/suricata
chgrp pondsecndr /var/log/suricata/eve.json
chmod 640 /var/log/suricata/eve.json
setfacl -m u:pondsecndr:raRcs::allow /var/log/suricata/eve.json
```

For log rotation, keep the EVE newsyslog entry at `root:pondsecndr` with mode
`640`. The development deploy helper applies this when `/var/log/suricata`
exists.

## Zeek And Zenarmor Connectors

Zeek can be used as a local log reader only when the active OPNsense package
repositories provide a stable Zeek package. Do not add unrelated FreeBSD
repositories to a firewall just to satisfy this dependency. If no package is
available, run Zeek on an external sensor and point PondSec to the exported
`conn.log`, `dns.log`, `ssl.log`, `x509.log`, `http.log`, `files.log`,
`notice.log`, and `weird.log` files. The collector tracks offsets per log,
detects rotation by inode and size, and reports per-log health in provider
inventory.

Zenarmor integration reads administrator-configured documented exports and
metadata. The preferred local path is Zenarmor stream reporting to PondSec's
UDP listener on `127.0.0.1:5514` with sender allowlist `127.0.0.1`. File-based
Syslog/reporting exports, official log files, and documented API metadata
references remain supported. Import switches control applications, categories,
TLS metadata, session context, policy actions, device context, and security
events. Do not paste API keys, certificates, SASE secrets, or passwords into
the PondSec form; use an external credential reference.

## Logs

Logs are structured JSON under `/var/log/pondsec-ndr/`. Log entries include timestamp, level, component, event, message, run id, and optional incident, detection, host, and error fields.

## Database

SQLite uses WAL mode. Operators should monitor database size, retention, and cleanup activity.

## Backup

Back up:

- `/usr/local/etc/pondsec-ndr/`
- `/var/db/pondsec-ndr/pondsec-ndr.db`

Do not back up transient files under `/var/run/pondsec-ndr/`.

## Recovery

If the database is corrupt, stop the service, preserve the database for forensic review, restore from backup, and restart. The collector offset can be reset to replay from the current EVE file when needed.
