# Third-Party Notices

This file records third-party software and data sources relevant to PondSec NDR
packaging and release review.

## Runtime Dependencies

| Component | Role | License / Notice |
| --- | --- | --- |
| OPNsense plugin framework | GUI, MVC, configd integration | OPNsense project license; verify against upstream release |
| FreeBSD base, pf, pkg | Operating system, packet filter, package tooling | FreeBSD project licenses |
| Python | Backend runtime | Python Software Foundation License |
| SQLite | Local metadata database | Public domain / SQLite blessing |
| NumPy | Model inference runtime | BSD-3-Clause |
| Suricata EVE JSON | Recommended telemetry source | Suricata project license; external OPNsense package |

## Model And Data

| Component | Role | License / Notice |
| --- | --- | --- |
| `saidimn/ids-cnn-cicids2017` | Preferred pretrained IDS model source | MIT license in upstream model repository |
| CICIDS2017 | Training dataset family for the preferred model | Canadian Institute for Cybersecurity dataset terms; cite dataset source in public release notes |

## Optional Integrations

| Integration | Role | Notice |
| --- | --- | --- |
| Zenarmor | Optional TLS-inspected metadata source when already deployed by the administrator | Not bundled, not required |
| Squid TLS inspection | Optional decrypted proxy metadata source when explicitly configured | Not bundled, not required |
| CrowdSec | Independent firewall protection signal | Not bundled, not required |

## Release Requirements

- Public releases must include checksums for package and model artifacts.
- Model artifacts must be signed or covered by signed package/repository
  metadata.
- No service-start code may fetch or execute unsigned remote content.
- Any added dependency must be recorded here before release.
- Generated SPDX or CycloneDX SBOM output should be attached to GitHub Releases
  once package builds are automated.
