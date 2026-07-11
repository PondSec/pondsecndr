# Validation Log

## 2026-07-11: Zeek Package Check And Connector Expansion

Target firewall:

- Address: `192.168.99.2`
- OPNsense: `26.1.11_6`
- FreeBSD: `14.3-RELEASE-p16`
- Active repositories checked: OPNsense, SunnyValley

Validation results:

- `pkg search -x "^(zeek|bro)$|^zeek-|^bro-"`: no matching package in active repositories.
- `pkg install -y zeek`: failed cleanly with no package available.
- `pkg info -x "^(zeek|bro)$|^os-sensei"`: Zenarmor packages present, no Zeek/Bro package installed.

Decision:

- Do not add unrelated FreeBSD package repositories to the firewall.
- Keep the Zeek connector as a complete external-sensor integration for
  `conn.log`, `dns.log`, `ssl.log`, `x509.log`, `http.log`, `files.log`,
  `notice.log`, and `weird.log`.
- Expose Zeek rotation, offset recovery, and provider monitoring through
  diagnostics/provider inventory.
- Expand Zenarmor settings for documented Syslog/reporting export, official log
  and API metadata references without storing secrets in the PondSec form.

## 2026-07-11: Local Zenarmor Stream Receiver

Implementation validation:

- Added PondSec Zenarmor Syslog UDP listener support for local stream reporting.
- Default listener: `127.0.0.1:5514`.
- Default sender allowlist: `127.0.0.1`.
- Unit test sends a real UDP datagram to the collector and verifies normalized
  Zenarmor metadata is inserted into the same event path as file exports.
- Full local regression suite: `90` tests passed.

Firewall integration validation:

- PondSec NDR configured for Zenarmor `syslog_udp` on `127.0.0.1:5514`.
- Zenarmor Stream Reporting configured through the documented Stream Reporting
  path after the Zenarmor license check returned allowed.
- Enabled Zenarmor stream indexes: `conn`, `http`, `dns`, `tls`, `alert`.
- `ipdrstreamer` observed sending UDP to `127.0.0.1:5514`.
- PondSec service observed listening on `127.0.0.1:5514` and NetFlow on
  `127.0.0.1:2055`.
- Controlled local Zenarmor-style UDP event was persisted in SQLite with
  `raw_source=zenarmor`, TLS metadata, application, SNI and policy context.
- Real Zenarmor stream payloads were parsed after adding support for
  `data={...}` Syslog exports, millisecond `start_time`, and Zenarmor field
  names such as `ip_src_saddr`, `ip_dst_saddr`, `transport_proto`, `device`,
  `conn_uuid`, and `index`.
- Live provider status after parser deployment: `healthy`, `read_datagrams=7`,
  `accepted_events=7`, `parser_errors=0`, `normalization_errors=0`.
- Observed real event types from Zenarmor: `flow`, `tls`, and `dns`, with
  application, domain, OS/device, VLAN/interface and index metadata available
  where Zenarmor exported it.

## 2026-07-11: Learning Auto-Arm Runtime Posture

Implementation validation:

- Added a response option that automatically arms the effective runtime posture
  after the configured learning days count down to zero.
- The stored operator configuration remains unchanged; service health,
  diagnostics, readiness, and dashboard metrics expose configured and effective
  modes separately.
- Effective auto-arm enables `prevent` / `enforce`, automatic blocking, AI full
  decision mode, internal isolation, external blocking, and disables manual
  confirmation delay.
- Kill switch and maintenance mode prevent auto-arm.
- Existing response safety gates remain in force.

Local validation:

- Targeted unit tests covered learning countdown, effective runtime posture,
  pre-learning suppression, diagnostics readiness output, and JSON config
  loading.

## 2026-07-11: Entity Resolution Storage Foundation

Implementation validation:

- Added schema version `3` with `entities`, `entity_observations`, and
  `hosts.entity_id`.
- Host inventory now returns the entity-oriented device view while retaining
  underlying host records for compatibility.
- DHCP lease changes with the same MAC resolve to one stable entity and retain
  both current/previous IP history.
- Zenarmor device context contributes MAC, device name, OS, interface, VLAN,
  source tag, role and service evidence to the entity inventory.
- Local regression suite: `91` tests passed.

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

## 2026-07-05: Authenticated GUI and Auto-Prevent Validation

Target firewall:

- Host: `HWFirewall01.internal`
- Address: `192.168.99.2`
- OPNsense mode after validation: `prevent`
- PondSec response mode after validation: `automatic_blocking=1`, `manual_confirmation=0`
- Response thresholds after validation: `minimum_risk_score=70`, `minimum_confidence=75`
- Monitored devices: `re0`, `igb0_vlan10`, `igb0_vlan20`, `pppoe0`
- Management devices excluded/protected: `igb0`, `wg1`

Authenticated WebGUI route validation:

- A temporary admin-only test user was created for browser validation and removed after testing.
- The temporary user removal was verified, and the dedicated `pondsecndr` service user was restored after OPNsense local group sync removed it.
- The package installer was hardened to keep `pondsecndr` on fixed system UID/GID `1988`, below the OPNsense-managed local user/group synchronization range.
- `pondsec_ndr` service status after cleanup: `healthy`, running as `pondsecndr`.
- Suricata EVE access after cleanup: `status=ok`, checked by service-user probe.
- All authenticated PondSec UI pages resolved to concrete PondSec content and did not show `Page not found`:
  - `/ui/pondsecndr/dashboard`
  - `/ui/pondsecndr/incidents`
  - `/ui/pondsecndr/detections`
  - `/ui/pondsecndr/hosts`
  - `/ui/pondsecndr/traffic_analytics`
  - `/ui/pondsecndr/interfaces`
  - `/ui/pondsecndr/policies`
  - `/ui/pondsecndr/models`
  - `/ui/pondsecndr/allowlist`
  - `/ui/pondsecndr/blocklist`
  - `/ui/pondsecndr/service`
  - `/ui/pondsecndr/logs`
  - `/ui/pondsecndr/diagnostics`
  - `/ui/pondsecndr/settings`
  - `/ui/pondsecndr/about`

## 2026-07-05: Pretrained AI Runtime End-to-End Proof on Firewall

Target firewall:

- Host: `HWFirewall01.internal`
- Address: `192.168.99.2`
- Evidence directory on firewall: `/tmp/pondsec-ai-e2e-20260705T212826Z`
- Monitor-mode API proof directory on firewall: `/tmp/pondsec-monitor-api-proof-20260705T212938Z`

Important scope:

- The optimized `attack_probability=0.995789` vector is a synthetic AI validation vector and only proves that the installed NumPy runtime, manifest, checksum, feature schema, detector, storage, and incident correlation path work end to end.
- It is not a claim of real-world detection quality.
- Live-traffic detection quality must only be claimed for real Suricata EVE flows that traverse the full pipeline.

Validated results:

| Check | Result |
|---|---:|
| On firewall installed | passed |
| NumPy available | passed (`numpy 2.4.6`) |
| Model artifact present | passed (`saidimn_ids_cnn_cicids2017.npz`) |
| Runtime artifact SHA-256 correct | passed (`51bec93ec2c8ac9a480fcef8694852792a8869a817b07d1cef11a2f1fd62c45b`) |
| Manifest present | passed (`feature_count=78`, `runtime=pondsec-numpy-cnn1d`) |
| Runtime loaded | passed |
| Model self-test passed before restart | passed |
| Service restart passed | passed |
| Model self-test passed after restart | passed |
| Synthetic AI validation detection created | passed (`detector_id=pondsec.pretrained_ids_model`) |
| Synthetic AI validation incident created | passed |
| Detection contains model name/version/checksum | passed (`saidimn-ids-cnn-cicids2017`, `pondsec-numpy-cnn1d-v1`) |
| Detection contains feature schema version | passed (`1`) |
| Detection contains attack probability and predicted class | passed (`0.995789`, `Bot`) |
| Detection contains feature values | passed (`78` CICIDS-style values) |
| Monitor mode did not block in PF | passed (`pf_source_blocked_after=false`) |
| Dashboard API | passed (`configctl pondsecndr dashboard_summary`) |
| Detections API | passed (`configctl pondsecndr detections`) |
| Incidents API | passed (`configctl pondsecndr incidents`) |
| Attack inference duration | passed (`53.17 ms`) |
| Attack validation max RSS | passed (`47628 KB`) |
| Self-test max RSS | passed (`46432 KB`) |
| Service RSS after validation | passed (`48356 KB`) |
| Benign validation score | passed (`attack_probability=0.020657`, no AI detection) |

Post-fix service-health validation:

- Deployed storage fix for structured TLS fingerprints that previously caused `TypeError: unhashable type: 'dict'`.
- Local regression tests: `21` passed.
- Firewall process after deploy: `pondsec_ndr` running as `pondsecndr`, PID `25354`.
- Dashboard after deploy: `service_status=healthy`, `operating_mode=prevent`, `last_collector_errors=[]`, `last_response_errors=[]`, `active_model_version=saidimn-ids-cnn-cicids2017`.
- Fresh service log scan after deploy: no new `loop_error`, `unhashable`, or database readonly errors.

Auto-prevent validation command:

```sh
pondsec-ndrctl protection validate-suite --duration-seconds 600 --remove-after --json
```

Validation result:

- Suite status: `ok`
- Mode: `prevent`
- Automatic blocking: `true`
- Every scenario produced the expected detection, incident, PF add, PF verify, and cleanup removal.

Scenario coverage:

| Scenario | Expected behavior | Detector proof | Source | Risk | PF verified | Cleanup |
|---|---|---|---|---:|---|---|
| `pretrained_ai_model_inference_vlan10` | Synthetic AI validation vector classified as attack | `pondsec.pretrained_ids_model` | `192.168.10.243` | 86 | yes | removed |
| `wan_attack_prevention` | WAN reconnaissance/port scan against DMZ | `pondsec.portscan`, `pondsec.vertical_scan` | `203.0.113.241` | 75 | yes | removed |
| `beaconing_vlan10` | Periodic C2-style beaconing from VLAN10 | `pondsec.beaconing` | `192.168.10.241` | 81 | yes | removed |
| `lateral_movement_vlan20` | Internal SMB/RDP fan-out from VLAN20 | `pondsec.lateral_movement` | `192.168.20.241` | 87 | yes | removed |
| `dns_tunneling_dmz` | High-entropy NXDOMAIN DNS tunneling from DMZ | `pondsec.dns_tunneling` | `192.168.30.241` | 82 | yes | removed |
| `data_exfiltration_vlan10` | Large asymmetric upload from VLAN10 | `pondsec.data_exfiltration` | `192.168.10.242` | 97 | yes | removed |
| `unknown_zero_day_baseline_anomaly` | Baseline anomaly without a signature | `pondsec.host_baseline_anomaly` | `192.168.20.242` | 81 | yes | removed |

Important scope:

- `pretrained_ai_model_inference_vlan10` still uses the synthetic AI validation vector. It proves runtime and pipeline wiring, not live zero-day detection quality.
- The suite does prove the automatic prevent path: configured `prevent` mode, detection, incident, response proposal, PF add, PF verification, and cleanup.
- A separate active external TEST-NET validation block remained present for `203.0.113.250` in PF table `virusprot` after the suite as a time-limited proof of a live block entry.

## 2026-07-05: Live VLAN10 Filterlog Detection and PF Fallback Hardening

Target firewall:

- Host: `HWFirewall01.internal`
- Address: `192.168.99.2`
- Mode: `prevent`
- Monitored devices: `re0`, `igb0_vlan10`, `igb0_vlan20`, `pppoe0`
- Admin protection: `192.168.10.20` and `10.66.66.2` were allowlisted/protected before live testing.

Why this change was required:

- Suricata on the target firewall runs in OPNsense `divert` mode, and the VLAN10 pass rule did not divert all VLAN10 traffic to Suricata.
- PF/filterlog did contain the blocked VLAN10-to-DMZ scan events.
- PondSec now ingests OPNsense filterlog `block` events as internal flow events via `raw_source=opnsense_filterlog`.
- Filterlog `pass` events are intentionally not ingested by this collector because outbound NAT pass logs can use the firewall WAN address as source. Suricata remains the source for allowed flow telemetry.

Validation artifacts:

- First live proof directory on Mac: `reports/evidence/20260705T214733Z-vlan10-filterlog-portscan-proof`
- Hardened block-only proof directory on Mac: `reports/evidence/20260705T215753Z-vlan10-blockonly-portscan-proof`
- Local regression suite after hardening: `30` tests passed with `ResourceWarning` treated as an error.

Validated results:

| Check | Result |
|---|---:|
| Filterlog readable by service user | passed |
| Filterlog collector appears in service health | passed (`collector_sources.opnsense_filterlog`) |
| Live VLAN10 scan routed outside VPN | passed (`en0` route during test) |
| Live PF block events ingested | passed (`raw_source=opnsense_filterlog`) |
| Port scan detection created | passed (`pondsec.portscan`) |
| Vertical scan detection created | passed (`pondsec.vertical_scan`) |
| Incident created for live VLAN10 scan | passed (`source_ip=192.168.10.20`, `destination_ip=192.168.30.3`) |
| Admin Mac not blocked by PF | passed |
| Admin VPN IP not blocked by PF | passed |
| CrowdSec admin allowlist intact | passed |
| PF add/test/delete works through configd fallback | passed as unprivileged `pondsecndr` |
| `configctl Execute error` on negative PF test handled as failure | passed |
| Baseline-only anomaly does not auto-block | passed |
| Self-WAN false-positive block removed | passed (`80.153.171.185` not in `virusprot`) |
| Nextcloud false-positive block removed | passed (`192.168.20.115` not in `virusprot`) |
| Service health after fixes | passed (`healthy`, no collector or response errors) |

Live detection examples from the block-only proof:

- `pondsec.portscan`: `source_ip=192.168.10.20`, `failed_connections=146`, `unique_ports=76`
- `pondsec.vertical_scan`: `source_ip=192.168.10.20`, `destination_ip=192.168.30.3`, `unique_ports=76`
- Fresh live incident: `Reconnaissance from 192.168.10.20`, `risk_score=85`, `confidence=0.98`

Auto-prevent proof after PF fallback hardening:

- Active PF table: `virusprot`
- Active external auto-blocks after validation:
  - `172.236.201.181`, incident `08bb4703-4031-5ed7-9386-e7d78fe3ba10`, category `reconnaissance`
  - `23.94.252.207`, incident `5b695cbd-b33a-5eb3-921a-89b1feff7c07`, category `signature`
- Admin/self critical IPs verified not blocked:
  - `192.168.10.20`
  - `10.66.66.2`
  - `80.153.171.185`
  - `192.168.20.115`

Safety changes made from the live findings:

- PF/filterlog collector accepts only `block` events and ignores short/non-L4/pass lines without parser errors.
- `pondsecndr` gets ACL read access to `/var/log/filter/latest.log` at service prestart.
- The filterlog directory also receives an inherited ACL so newly rotated OPNsense
  filter logs remain readable by the unprivileged daemon after midnight rotation.
- PF table mutation falls back to fixed OPNsense configd actions when the daemon lacks direct `/dev/pf` write permission.
- Response logic reuses an existing active source block instead of creating duplicate active PF entries.
- Baseline-only host anomalies require manual confirmation for blocking; they still create detections and incidents.
- Expected safety denials such as protected source, allowlist, and low threshold are no longer shown as service response errors.

System service registration proof after the production deploy:

- `configctl service list` includes `PondSec NDR`.
- Service name: `pondsec_ndr`.
- Status message: `pondsec_ndr is running as pid 67494.`
- This confirms the plugin service is visible to the OPNsense service inventory
  used by **System: Diagnostics: Services**.

## 2026-07-06: Filterlog Permission Regression Guard Deploy

Target firewall:

- Host: `HWFirewall01.internal`
- Address: `192.168.99.2`
- Deployment backup: `/root/pondsec-ndr-backup-20260706113106`
- Runtime commit deployed: `3fbed21`

Reason:

- Historical service logs contained repeated `PermissionError` entries for
  `/var/log/filter/latest.log` when the daemon tried to check the path before
  the filterlog collector could handle permission failures.
- The service loop now always delegates the filterlog read attempt to
  `FilterLogCollector`, which records unreadable or missing filter logs as
  collector status instead of throwing a service-loop exception.

Local regression result before deploy:

- `46` tests passed with `PYTHONPATH=src/usr/local/share/pondsec-ndr python3 -m unittest discover -s tests -v`.
- Python compile check passed for backend modules and tests.
- `git diff --check` passed.

Post-deploy firewall proof:

| Check | Result |
|---|---:|
| Development deploy completed | passed |
| New service PID | `50366` |
| `sudo service pondsec_ndr onestatus` | `pondsec_ndr is running as pid 50366.` |
| OPNsense service inventory | `configctl service list` includes `PondSec NDR`, `pondsec_ndr`, running as PID `50366` |
| `configctl pondsecndr status` | `healthy` |
| `last_collector_errors` | `[]` |
| Queue size | `0` |
| RAM usage | about `33 MB` |
| Model self-test | passed |
| Model checksum | `51bec93ec2c8ac9a480fcef8694852792a8869a817b07d1cef11a2f1fd62c45b` |
| Synthetic AI validation vector inference | `56.253 ms`, `Bot`, attack probability `0.995789` |
| Learning mode | active, `14` days remaining |
| Dashboard API | `healthy`, `operating_mode=monitor`, `events_last_24h=26147`, `queue_utilization=0` |

Important interpretation:

- The model self-test remains a synthetic AI validation vector, not a claim of
  live detection quality.
- The service is healthy and the AI/baseline detectors remain suppressed by
  Learning Mode until the baseline phase completes or an administrator accepts
  the early-activation false-positive risk.
