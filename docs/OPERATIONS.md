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
