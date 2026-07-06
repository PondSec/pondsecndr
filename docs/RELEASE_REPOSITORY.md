# Signed Release Repository

This document describes the first public distribution path for PondSec NDR:
GitHub Releases plus a PondSec-owned signed FreeBSD/pkg repository. It is the
preferred path before an upstream pull request is accepted into the official
`opnsense/plugins` tree.

## Release Flow

1. Build `os-pondsec-ndr-*.txz` in an OPNsense/FreeBSD build environment.
2. Run the package lifecycle tests from `docs/PLUGIN_PUBLICATION.md`.
3. Sign the Git tag and upload the source archive, package, public repository
   key, checksums, SBOM, and release notes to GitHub Releases.
4. Create a signed pkg repository catalogue with `pkg repo`.
5. Publish the repository over HTTPS.
6. Install on test firewalls through a `PondSec.conf` pkg repository entry.
7. Keep the upstream OPNsense plugin pull request separate from the signed
   community repository release.

The service must not download unsigned code, model artifacts, or package data
at runtime. Model artifacts shipped in the package are verified by checksum and
manifest before the model can become `active`.

## Build Package

Inside an OPNsense plugins tree, place this plugin under a category such as:

```text
security/pondsec-ndr/
```

Build with the normal OPNsense tools workflow. The official OPNsense Hello
World example documents that plugins are built as standard `os-*.txz` packages
through the `/usr/tools` workflow.

Expected package name:

```text
os-pondsec-ndr-0.1.0.txz
```

## Create Repository Key

Generate the repository signing key on the release builder and keep the private
key offline after use:

```sh
openssl genrsa -out pondsec-repo.key 4096
openssl rsa -in pondsec-repo.key -pubout -out pondsec-repo.pub
chmod 0600 pondsec-repo.key
```

Do not commit either key to this repository. Only the public key is published.

## Sign Repository

Run on FreeBSD/OPNsense or another system with `pkg(8)`:

```sh
tools/build_signed_repo.sh \
  --packages /path/to/built/packages \
  --private-key /secure/release/pondsec-repo.key \
  --output /srv/pondsec/pkg \
  --channel latest
```

The script copies `os-pondsec-ndr-*.txz`, runs `pkg repo`, and writes
`SHA256SUMS` next to the repository metadata. FreeBSD `pkg-repo(8)` describes
`pkg repo` as the command that creates package repository catalogues and can add
a cryptographic signature. FreeBSD `pkg.conf(5)` documents `SIGNATURE_TYPE:
PUBKEY` for clients that verify repositories with a public key.

## Client Configuration

Install the public key and repository configuration on an OPNsense test system:

```sh
install -d -m 0755 /usr/local/etc/pkg/repos /usr/local/etc/ssl/pondsec
fetch -o /usr/local/etc/ssl/pondsec/pkg-repo.pub \
  https://repo.example.invalid/pondsec/pkg-repo.pub
cat >/usr/local/etc/pkg/repos/PondSec.conf <<'EOF'
PondSec: {
  url: "pkg+https://repo.example.invalid/pondsec/pkg/${ABI}/latest",
  mirror_type: "none",
  signature_type: "PUBKEY",
  pubkey: "/usr/local/etc/ssl/pondsec/pkg-repo.pub",
  enabled: yes,
  priority: 10
}
EOF
pkg update -r PondSec
pkg install os-pondsec-ndr
service configd restart
```

The placeholder host must be replaced by the real PondSec repository host.

## Deinstall Policy

The package deinstall script is intentionally conservative. By default it keeps
configuration, database telemetry, and model artifacts, and it does not remove
PF table entries unless the administrator asks for it.

Interactive removal asks:

- Keep PondSec NDR configuration?
- Keep PondSec NDR database and telemetry?
- Keep downloaded model artifacts?
- Remove PondSec-created PF block entries?

Unattended removal can set environment variables:

```sh
env \
  PONDSEC_KEEP_CONFIG=yes \
  PONDSEC_KEEP_DATABASE=yes \
  PONDSEC_KEEP_MODELS=yes \
  PONDSEC_REMOVE_PF_BLOCKS=no \
  pkg delete os-pondsec-ndr
```

For a full lab cleanup:

```sh
env \
  PONDSEC_KEEP_CONFIG=no \
  PONDSEC_KEEP_DATABASE=no \
  PONDSEC_KEEP_MODELS=no \
  PONDSEC_REMOVE_PF_BLOCKS=yes \
  pkg delete os-pondsec-ndr
```

## Upgrade And Rollback

- Every release that changes SQLite structure must ship a versioned migration.
- Migration runs before the service starts.
- The database must be backed up before migration.
- Migration must run in a transaction and roll back on failure.
- Downgrades across schema changes must be blocked or explicitly documented.
- Release notes must document rollback from the previous public beta.

Rollback procedure for package-level failures:

```sh
service pondsec_ndr onestop || true
pkg delete -y os-pondsec-ndr
pkg add /path/to/previous/os-pondsec-ndr-previous.txz
service configd restart
service pondsec_ndr onestart
configctl pondsecndr diagnostics
```

## Required Release Checks

Before a public package is published, test at minimum:

- fresh installation,
- update from the previous version,
- service restart,
- OPNsense restart,
- log rotation for Suricata EVE and filterlog access,
- database migration with backup and rollback,
- package deletion with retained configuration,
- package deletion with full cleanup,
- reinstall with existing configuration,
- disabled Suricata,
- missing model artifact,
- full or read-only partition,
- model self-test,
- synthetic AI validation flow,
- benign AI validation flow,
- monitor mode without PF blocking,
- prevent mode with protected-source allowlist gates,
- sanitized diagnostic archive creation.

## Public Release Artifacts

Each GitHub Release should contain:

- signed Git tag,
- `os-pondsec-ndr-*.txz`,
- `SHA256SUMS`,
- signed repository catalogue,
- repository public key,
- `docs/SBOM.md`,
- `docs/THIRD_PARTY_NOTICES.md`,
- `SECURITY.md`,
- release notes with known limitations,
- model artifact checksum and manifest details.

## Sources

- OPNsense Hello World plugin example:
  https://docs.opnsense.org/development/examples/helloworld.html
- FreeBSD `pkg-repo(8)`:
  https://man.freebsd.org/cgi/man.cgi?query=pkg-repo&sektion=8
- FreeBSD `pkg.conf(5)`:
  https://man.freebsd.org/cgi/man.cgi?query=pkg.conf&sektion=5
- FreeBSD Porter's Handbook, poudriere testing:
  https://docs.freebsd.org/en/books/porters-handbook/testing/
