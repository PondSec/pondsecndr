# Threat Model

## Assets

- Firewall availability.
- OPNsense configuration integrity.
- Network telemetry metadata.
- Incident and detection records.
- Model metadata and future model artifacts.
- PF response state.
- Administrator credentials and sessions.

## Trust Boundaries

- OPNsense GUI/API to configd.
- Configd to backend CLI.
- Backend service to SQLite store.
- Backend service to Suricata EVE file.
- Future response helper to PF.
- Administrator browser to OPNsense API.

## Threats

### Firewall Disruption

Risk: a collector, detector, or response failure could interrupt traffic.

Controls:

- Fail-open architecture.
- No inline packet engine in the first version.
- Monitor mode by default.
- Response actions separated from detection.
- PF helper must create time-limited entries only after policy checks.

### Unsafe Blocking

Risk: false positives block management systems, DNS, DHCP, gateways, HA peers, or firewall-owned addresses.

Controls:

- Automatic blocking disabled by default.
- Protected address checks.
- Allowlist enforcement.
- Policy gates for prevent mode.
- High confidence and risk thresholds.
- Temporary block expiry.
- Audit log for all actions.

### Payload or Secret Exposure

Risk: logs or database records contain credentials, cookies, authorization headers, HTTP bodies, POST data, or file contents.

Controls:

- Metadata mode by default.
- Normalizer redacts sensitive HTTP fields.
- Raw source events are not stored by default.
- Structured logs avoid payload fields.
- Export paths must omit personal payloads.

### Path Traversal and File Abuse

Risk: user-controlled paths cause the backend to read or write arbitrary files.

Controls:

- Configured paths are validated and normalized.
- Runtime paths are fixed.
- CLI commands avoid arbitrary write targets.
- Future model import must use safe temporary files and checksum verification.

### Command Injection

Risk: API input is passed to shell commands.

Controls:

- GUI controllers call fixed configd actions.
- No shell commands are built from user input.
- Python subprocess use is limited to fixed diagnostics commands.

### Event Flooding

Risk: high event volume exhausts memory, disk, or CPU.

Controls:

- Queue and batch limits.
- Maximum event rate setting.
- SQLite retention and database size settings.
- Backpressure and event drop counters.
- Detector windows are bounded.

### Corrupt or Malicious EVE Input

Risk: malformed JSON or unexpected fields crash processing.

Controls:

- Corrupt lines are skipped and counted.
- Unknown fields are tolerated.
- Event schema validates IPs, ports, timestamps, and event types.
- Sensitive content is removed before storage.

### Unsafe Model Artifact

Risk: external model files execute code or produce incompatible inference.

Controls:

- No unsafe pickle loading from external sources.
- Model metadata requires schema version, checksum, dimensions, and status.
- Incompatible or corrupt models are rejected.
- Activation is audited and rollback is retained.

### Privilege Escalation

Risk: the main backend runs as root and exposes broad filesystem or PF access.

Controls:

- Main service is designed for a dedicated unprivileged user.
- Root-only tasks are limited to install, service management, configd actions, and response helper execution.
- PF mutation is not inside the unprivileged main detection loop.

## Residual Risks

- OPNsense packaging and rc.d behavior require testing on the target firewall.
- Dynamic interface validation depends on target OPNsense utilities.
- SQLite performance under sustained high EVE rates must be benchmarked on firewall hardware.
- Full automatic prevent-mode response must receive a separate security review before enabling by default.
