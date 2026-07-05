# Operations

## Modes

- `monitor`: collect, baseline, detect, no forced alerts or blocks.
- `alert`: collect, detect, create incidents, no automatic blocks.
- `interactive`: propose blocks, administrator confirms.
- `prevent`: automatic response only when policy, confidence, risk, allowlist, and protected-target checks pass.

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
