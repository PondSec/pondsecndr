# External detection validation: direct origin target

## Scope

- Date: 2026-07-11
- Target: `<direct-origin-fqdn>`
- Resolved origin: `<wan-origin-ip>`
- Cloudflare target excluded: `<cloudflare-fronted-fqdn>` resolves to Cloudflare and was not scanned as an origin test.
- Test class: external reconnaissance and service enumeration
- Safety constraints: no destructive payloads, no brute force, no malware, no persistence, no denial-of-service test

## Test execution

| Field | Value |
| --- | --- |
| External tool | Nmap Online web API |
| Tool result channel | API request returned Cloudflare `504`, but scan traffic reached the origin |
| Source observed by NDR | `<external-scanner-ip>` |
| Target observed by NDR | `<wan-origin-ip>` |
| Test start | 2026-07-11T21:28Z |
| Expected detection | External reconnaissance / port scan / vertical scan |
| Expected correlation | One incident for the same source and target |
| Expected prevention | No automatic prevention in current `monitor` / `observe` mode |

## PondSec NDR result

| Field | Actual result |
| --- | --- |
| Incident ID | `96cf3e70-b3a0-5e91-8241-cf4a211ffa5c` |
| Incident title | `Reconnaissance from <external-scanner-ip> (3 detections)` |
| Status | `open` |
| Category | `reconnaissance` |
| MITRE phase | `reconnaissance` |
| Risk score | `91` |
| Confidence | `0.98` |
| Detection count | `14` |
| Event count | `219` |
| Detectors | `pondsec.portscan`, `pondsec.vertical_scan`, `pondsec.auth_service_pressure` |
| Promotion reason | `actionable_reconnaissance` |
| Promotion score | `100` |

## Assessment

The NDR correctly detected the external scan against the direct origin as reconnaissance, assigned the external source and WAN target correctly, correlated the related detections into one incident, and retained supporting evidence for the detector thresholds.

No automatic block was expected because runtime mode is currently `monitor` and response mode is `observe`. Manual response remains available through the incident manual block action and the blocklist editor.

## Cleanup

The validation incident was closed after evidence capture. Open and active incident counts returned to `0`.

## Follow-up

- Repeat from a second independent external runner to validate independent-source separation.
- Run a controlled service-enumeration stage from an external runner with a bounded port list.
- Keep Cloudflare-fronted tests separate from origin tests because Cloudflare terminates that path before the firewall.
