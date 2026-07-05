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
- configd actions for dashboard, detections, incidents, models, allowlist, blocklist, and block expiry: passed.
- Allowlist safety gate: passed.
- Default response threshold gate: passed.
- Temporary lowered-threshold block proposal: passed.
- Proposed block activation/removal: passed with `pf_side_effects: none`.
- Incident close/reopen through configd: passed.

Important safety state:

- Default operating mode remains `monitor`.
- Automatic blocking remains disabled.
- PF mutation is not enabled by this foundation build.
- External `.pth` and `.pkl` model artifacts are verified but not deserialized in the privileged service path.

Known validation gap:

- GitHub push is currently blocked by network redirection from `github.com` to `rtap.zenarmor.net`.
- Full package build inside the upstream OPNsense plugins tree is not yet completed.
- Browser-level GUI click testing requires an authenticated OPNsense web session.
