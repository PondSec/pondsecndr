# Packaging

## Package Name

The OPNsense package name is `os-pondsec-ndr`.

The plugin Makefile uses:

- `PLUGIN_NAME=pondsec-ndr`
- `PLUGIN_VERSION=0.1.0`

OPNsense plugin packaging prefixes plugin packages with `os-`.

## Build Location

The plugin is intended to be placed in an OPNsense plugins tree category, for example:

```text
security/pondsec-ndr/
```

Then build through the OPNsense tools workflow.

## Installed Paths

- MVC files: `/usr/local/opnsense/mvc/app/...`
- Configd actions: `/usr/local/opnsense/service/conf/actions.d/actions_pondsecndr.conf`
- Config template: `/usr/local/opnsense/service/templates/OPNsense/PondSecNDR/`
- Backend package: `/usr/local/share/pondsec-ndr/`
- Service executable: `/usr/local/sbin/pondsec-ndr`
- CLI executable: `/usr/local/sbin/pondsec-ndrctl`
- rc.d script: `/usr/local/etc/rc.d/pondsec_ndr`
- pkg install/remove message: `pkg-message`

## Install And Deinstall Scripts

`pkg-install` creates the dedicated `pondsecndr` user/group, verifies NumPy,
and creates runtime directories with restrictive ownership.

`pkg-deinstall` is conservative by default. It stops the service, removes the
runtime directory, and asks whether configuration, telemetry database, model
artifacts, and PondSec-created PF blocks should be retained or removed.

Unattended package tests can control the prompts through:

- `PONDSEC_KEEP_CONFIG`
- `PONDSEC_KEEP_DATABASE`
- `PONDSEC_KEEP_MODELS`
- `PONDSEC_REMOVE_PF_BLOCKS`

Defaults are chosen to avoid accidental forensic data loss and to avoid removing
PF entries without administrator intent.

## External Model Artifacts

The verified NumPy runtime artifact for the preferred pretrained model is
vendored with the plugin backend:

```text
/usr/local/share/pondsec-ndr/pondsec_ndr/models/artifacts/saidimn_ids_cnn_cicids2017.npz
```

The package declares NumPy as a dependency and `pkg-install` verifies that
`import numpy` works before completing installation.

Original external pretrained IDS artifacts can also be fetched into
`/var/db/pondsec-ndr/models/` for audit and future runtime work:

```sh
pondsec-ndrctl model fetch saidimn-ids-cnn-cicids2017
```

The preferred model artifacts are MIT-licensed. The production inference path
validated on `HWFirewall01.internal` is the package-shipped NumPy export with
SHA-256 and manifest verification, not an in-process PyTorch worker.

## Publication Paths

There are two supported publication paths:

- Official OPNsense community plugin: place this directory in the
  `opnsense/plugins` tree, for example `security/pondsec-ndr`, build it in the
  OPNsense tools workflow, open an upstream pull request, and complete review.
  After upstream acceptance and release, `os-pondsec-ndr` can appear in the
  normal firmware GUI plugin list.
- Private/community repository: build `os-pondsec-ndr-*.txz`, publish it in a
  signed pkg repository, and add that repository to target OPNsense systems.
  It can then be installed through firmware/package tooling for systems that
  trust that repository.

The repository alone is not enough to appear automatically in every OPNsense
plugin list. The package must be available from a configured OPNsense package
repository.

The signed community repository workflow is documented in
`docs/RELEASE_REPOSITORY.md`.

## Packaging Risks

- Final Python package dependency names must be checked against the target OPNsense release.
- User and group creation must be verified during package install.
- The rc.d script must be tested under FreeBSD/OPNsense, not only macOS/Linux.
- Optional PyTorch packages must not become hard dependencies until
  FreeBSD/OPNsense compatibility and resource use are verified.
- A generated SPDX or CycloneDX SBOM should be attached to public releases in
  addition to `docs/SBOM.md`.
