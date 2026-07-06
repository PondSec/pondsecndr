# Security Policy

PondSec NDR is security software for OPNsense. Reports should be precise,
private when needed, and reproducible without exposing unrelated user traffic.

## Supported Versions

| Version | Status |
| --- | --- |
| `0.1.0-beta` | Development and external testing |

No production support promise is made before the first stable release.

## Reporting A Vulnerability

Preferred path:

1. Open a private GitHub Security Advisory for this repository when available.
2. If advisories are not enabled, contact the maintainer listed in `Makefile`.
3. Do not publish exploit details until a fix or mitigation has been released.

Include:

- PondSec NDR version and commit hash,
- OPNsense version,
- FreeBSD version,
- installation method,
- affected configuration,
- sanitized logs or diagnostics archive,
- reproduction steps,
- expected and actual behavior,
- whether PF blocking, model inference, or privacy export is involved.

Do not include private keys, passwords, full packet payloads, decrypted user
content, or unmasked personal traffic unless the maintainer explicitly asks for
that data through a safe channel.

## Release Integrity

Public releases must provide:

- signed Git tags,
- package SHA-256 checksums,
- signed pkg repository metadata,
- model artifact checksum and manifest,
- SBOM,
- third-party license notice,
- documented upgrade and rollback path.

The service must not download unsigned code or model artifacts during startup.

## Security Design Commitments

- Firewall forwarding must fail open if PondSec NDR fails.
- Monitor mode must not create PF blocks.
- Prevent mode must respect allowlists, protected networks, and response rate
  limits.
- Diagnostic archives must be sanitized by default.
- Payload storage is off by default.
- The model can be shown as `active` only after it loads on the target firewall
  and passes the end-to-end self-test.

## Out Of Scope For Public Testing

Do not perform destructive testing against third-party systems, denial of
service against services not owned by the tester, credential attacks outside an
explicit written scope, or attempts to bypass legal authorization boundaries.
