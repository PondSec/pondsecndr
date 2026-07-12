# PondSec NDR Plugin Publication

This document tracks the path from a working development plugin to an
OPNsense-installable `os-pondsec-ndr` package.

## Current Status

- The repository has the expected OPNsense plugin layout: `Makefile`,
  `pkg-descr`, `pkg-install`, `pkg-deinstall`, `pkg-message`, and `src/...`.
- The package name is `os-pondsec-ndr`.
- NumPy is declared as a package dependency in `Makefile` and verified in
  `pkg-install`.
- The verified pretrained NumPy model runtime artifact is included in `src/`.
- The plugin has been development-deployed and validated on
  `<firewall-hostname>` / `<management-box-ip>`.
- Conservative deinstall prompts are implemented for configuration, database,
  model artifacts, and PF block cleanup.
- The signed community repository workflow is documented and a helper script is
  present at `tools/build_signed_repo.sh`.
- The repository is not yet upstreamed into `opnsense/plugins` and no signed
  PondSec package repository has been published yet.

Result: users cannot yet install PondSec NDR from the default OPNsense plugin
list. They can install it through a development deploy, a package built from an
OPNsense plugins tree, or a configured signed PondSec repository after that
repository is published.

## Official OPNsense Path

1. Fork or check out `https://github.com/opnsense/plugins`.
2. Copy this plugin directory to a category path such as:

   ```text
   security/pondsec-ndr/
   ```

3. Build the package in an OPNsense build environment.

   Official OPNsense documentation describes building plugins through the
   `/usr/tools` workflow, which produces an `os-<name>-<version>.txz` package.

4. Install and test the generated package on a clean OPNsense VM:

   ```sh
   pkg install work/pkg/os-pondsec-ndr-*.txz
   service configd restart
   rm -f /tmp/opnsense_menu_cache.xml /tmp/opnsense_acl_cache.json
   ```

5. Verify at minimum:

   - plugin appears in the menu,
   - ACL entries appear in user/group permissions,
   - `configctl pondsecndr status` works,
   - service appears under **System: Diagnostics: Services**,
   - dashboard, detections, incidents, models, interfaces, settings, logs, and
     diagnostics pages load,
   - NumPy imports on the target firewall,
   - model self-test passes,
   - monitor mode does not block,
   - prevent mode blocks only allowed non-protected test sources,
   - uninstall removes package files without deleting forensic runtime data
     unexpectedly.

6. Open an upstream pull request to `opnsense/plugins`.

After upstream acceptance and release integration, OPNsense can offer
`os-pondsec-ndr` in the normal firmware GUI plugin list.

## Private Repository Path

If official upstream review is not ready, PondSec can publish a private or
community package repository:

1. Build `os-pondsec-ndr-*.txz` in the OPNsense build environment.
2. Create a pkg repository with `pkg repo`.
3. Sign the repository metadata.
4. Publish it via HTTPS.
5. Add the repository configuration to test firewalls.
6. Install through OPNsense firmware/package tooling.

The concrete signed repository procedure is in `docs/RELEASE_REPOSITORY.md`.

## Package Lifecycle Acceptance Tests

Before a public beta repository is announced, run and record:

1. Fresh package installation.
2. Upgrade from the previous package version.
3. Service restart.
4. OPNsense restart.
5. Suricata EVE and filterlog log rotation.
6. Database migration with backup and rollback.
7. Deinstallation with retained configuration.
8. Deinstallation with full cleanup and PF block removal.
9. Reinstallation with existing configuration.
10. Disabled or missing Suricata.
11. Missing model artifact.
12. Full or read-only data partition.
13. Model self-test.
14. Synthetic AI validation flow.
15. Benign AI validation flow.
16. Monitor mode with no PF block.
17. Prevent mode with allowlist and protected-source gates.
18. Sanitized diagnostic archive creation.

Every failed item blocks publication until fixed or documented as an explicit
known limitation.

## Sources

- OPNsense plugin collection README:
  https://github.com/opnsense/plugins
- OPNsense Hello World plugin example:
  https://docs.opnsense.org/development/examples/helloworld.html
- OPNsense tools repository:
  https://github.com/opnsense/tools
- FreeBSD pkg repository signing:
  https://man.freebsd.org/cgi/man.cgi?query=pkg-repo&sektion=8
- FreeBSD pkg repository verification config:
  https://man.freebsd.org/cgi/man.cgi?query=pkg.conf&sektion=5
