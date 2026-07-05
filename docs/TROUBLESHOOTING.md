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

Check the configured Suricata EVE path and permissions. The service runs as the
dedicated `pondsecndr` user, so a root-readable EVE file is not enough. The
service user must be able to traverse the Suricata log directory and read the
configured EVE file.

```sh
pondsec-ndrctl diagnostics --json
pondsec-ndrctl diagnostics self-test --json
sudo -u pondsecndr test -r /var/log/suricata/eve.json
```

On FreeBSD/OPNsense systems without `sudo -u`, use `su` for the same check:

```sh
su -m pondsecndr -c 'test -r /var/log/suricata/eve.json'
```

If `/var/log/suricata` is only accessible to `root:wheel`, grant the least
privilege needed through the log-reading group or an ACL. Do not run PondSec NDR
as root just to read EVE telemetry.

For a persistent OPNsense setup, the active EVE file should be readable by the
`pondsecndr` group and the Suricata newsyslog entry should rotate it as
`root:pondsecndr` with mode `640`.

If Suricata log rotation occurred, inspect collector offsets with diagnostics.

If the OPNsense filterlog collector reports permission errors after midnight
rotation, restart PondSec NDR so its prestart hook reapplies ACLs to
`/var/log/filter/latest.log` and the filterlog directory inheritance. The
service runs unprivileged and should not be changed to root for log access.

## Dashboard Empty

An empty dashboard is expected before events are ingested. The UI must not show fake metrics. Use `pondsec-ndrctl replay` with synthetic data for controlled testing.

## High Event Drops

Increase queue or batch settings only after checking CPU, memory, and database write pressure. If the firewall is under load, keeping the firewall available is more important than retaining every telemetry event.

## Unexpected Block Proposal

Review the incident evidence, allowlist entries, protected networks, policy thresholds, and risk factors. Monitor mode and alert mode must not create automatic PF blocks.
