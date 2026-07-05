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
