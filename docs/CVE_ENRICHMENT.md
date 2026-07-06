# PondSec NDR CVE Enrichment

PondSec NDR enriches host and case details with CVE context. It does not create CVEs and it does not claim that a host is vulnerable from an IP address alone.

## Data sources

Supported cache sources:

- NVD CVE API 2.0: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- CISA Known Exploited Vulnerabilities JSON: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- FIRST EPSS API: `https://api.first.org/data/v1/epss`
- MITRE ATT&CK: tactic and technique mapping only
- Local Suricata rule metadata: signature IDs, references, CVE references, CPE, product and version hints

External lookups are opt-in. The running service uses local cache files and remains functional offline.

## Matching policy

PondSec extracts CVE IDs from local detection evidence, especially Suricata rule references. Additional context can raise confidence when local telemetry contains:

- target port
- protocol
- product
- CPE
- version
- local Suricata signature metadata

PondSec never assigns a CVE based only on a source IP address. A vulnerability is not shown as confirmed unless product or version evidence exists locally.

## Evidence levels

- `referenced`
- `possible`
- `product_matched`
- `version_matched`
- `exploitation_attempt_observed`
- `exploitation_success_unconfirmed`

`exploitation_attempt_observed` means a local detector observed traffic or a signature reference consistent with an attempt. It does not mean the exploit succeeded.

## Risk integration

CISA KEV membership and high EPSS scores can add a case risk-priority modifier. External CVE data never replaces local evidence and is never sufficient by itself to trigger automatic blocking or isolation.

## Cache operation

Default behavior:

- CVE enrichment enabled
- external lookup disabled
- cache TTL 24 hours
- API timeout 5 seconds

Cache files live under `intel/` inside the PondSec data directory. Missing, stale, or unreadable cache files are treated as empty data so case analysis stays fail-open.
