# PondSec NDR Plugin Publication

This document tracks the path from a working development plugin to an
OPNsense-installable `os-pondsec-ndr` package.

## Current Status

- The repository has the expected OPNsense plugin layout: `Makefile`,
  `pkg-descr`, `pkg-install`, `pkg-deinstall`, and `src/...`.
- The package name is `os-pondsec-ndr`.
- NumPy is declared as a package dependency in `Makefile` and verified in
  `pkg-install`.
- The verified pretrained NumPy model runtime artifact is included in `src/`.
- The plugin has been development-deployed and validated on
  `HWFirewall01.internal` / `192.168.99.2`.
- The repository is not yet upstreamed into `opnsense/plugins` and no signed
  PondSec package repository has been published yet.

Result: users cannot yet install PondSec NDR from the default OPNsense plugin
list. They can install it only through a development deploy or a package built
from an OPNsense plugins tree.

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

This path still needs signing, update policy, rollback policy, and trust
documentation before it is safe for non-development users.

## Sources

- OPNsense plugin collection README:
  https://github.com/opnsense/plugins
- OPNsense Hello World plugin example:
  https://docs.opnsense.org/development/examples/helloworld.html
- OPNsense tools repository:
  https://github.com/opnsense/tools
