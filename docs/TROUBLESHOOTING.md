# Troubleshooting

## Service Does Not Start

Check:

```sh
configctl pondsecndr status
pondsec-ndrctl config validate
pondsec-ndrctl database check
tail -f /var/log/pondsec-ndr/pondsec-ndr.log
```

Verify the runtime directories exist and are writable by the service user.

## No Events

Check the configured Suricata EVE path and permissions. If Suricata log rotation occurred, inspect collector offsets:

```sh
pondsec-ndrctl diagnostics
```

## Dashboard Empty

An empty dashboard is expected before events are ingested. The UI must not show fake metrics. Use `pondsec-ndrctl replay` with synthetic data for controlled testing.

## High Event Drops

Increase queue or batch settings only after checking CPU, memory, and database write pressure. If the firewall is under load, keeping the firewall available is more important than retaining every telemetry event.

## Unexpected Block Proposal

Review the incident evidence, allowlist entries, protected networks, policy thresholds, and risk factors. Monitor mode and alert mode must not create automatic PF blocks.
