# NAT private-egress worm-lookalike validation

Date: 2026-07-11
System: <firewall-hostname> / PondSec NDR
Scope: local client network only, harmless TCP connect attempts to non-production private test addresses

## Test setup

- Source host: <test-client-ip>
- VPN state during valid traffic run: disconnected
- Route during valid traffic run: <private-test-target-range> via en0, gateway <client-gateway-ip>
- Test targets: <private-test-target-1>, <private-test-target-2>, <private-test-target-3>, <private-test-target-4>
- Ports: 445, 135, 139
- Tool: tools/pentest/ndr_worm_lookalike.py
- Safety: no credentials, no exploit payload, no malware, no file write, no self-propagation

## Initial finding

The first internal worm-lookalike run produced PF filterlog records only after NAT on WAN:

- source: <wan-origin-ip>
- destination: <private-test-target-range>
- action: pass
- direction: out

Before the fix, PondSec ignored non-block filterlog pass records. This created a false negative for worm-like fanout attempts that Suricata did not surface as EVE flow telemetry.

## Changes validated

- Ingest only suspicious filterlog pass records for private-destination administration/file-sharing fanout.
- Add `pondsec.worm_like_propagation` detector for repeated private-destination fanout over admin/service ports.
- Mark post-NAT evidence with `nat_mapping_required=true`.
- Mark response confidence as `low_without_pre_nat_session_context`.
- Keep NAT private-egress incidents separate from unrelated external reconnaissance against the WAN address.
- Do not expose a direct incident response target until pre-NAT or Zenarmor session context maps the real client.
- Make incident inserts idempotent so repeated correlation cannot break the service loop.

## Result

Fresh post-fix case:

- Incident: 7e051efb-6ff4-5bde-84fb-5cc238dd4ea1
- Category: lateral_movement
- Source field: <wan-origin-ip>
- Destination: private_egress
- Risk score: 82
- Detection count: 1
- Event count: 12
- Detector: pondsec.worm_like_propagation
- Evidence flags: `nat_mapping_required=true`, `response_target_confidence=low_without_pre_nat_session_context`
- Entity roles: `affected_host=unresolved_internal_host_behind_nat`, `destination=private_egress`, `threat_source=<wan-origin-ip>`
- Response target: absent

Expected behavior was met: the attack-like pattern is detected as lateral movement, is not merged with external reconnaissance cases, and does not propose blocking the WAN address without a real pre-NAT client mapping.

## Remaining limitation

The firewall sees this traffic after NAT in PF filterlog. PondSec can detect the private-egress pattern, but precise host isolation still requires pre-NAT context from Zenarmor session metadata, firewall state/NAT mapping, NetFlow/Zeek on the internal segment, or another authoritative client mapping source.
