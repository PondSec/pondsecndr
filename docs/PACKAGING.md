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

## External Model Artifacts

External pretrained IDS artifacts are not vendored into the plugin package. Operators can fetch verified artifacts into `/var/db/pondsec-ndr/models/` with:

```sh
pondsec-ndrctl model fetch saidimn-ids-cnn-cicids2017
```

The preferred external model artifacts total roughly 2.9 MB and are MIT-licensed, but runtime inference requires a validated PyTorch worker or future ONNX conversion on the target OPNsense release.

## Packaging Risks

- Final Python package dependency names must be checked against the target OPNsense release.
- User and group creation must be verified during package install.
- The rc.d script must be tested under FreeBSD/OPNsense, not only macOS/Linux.
- Optional ML runtime packages must not become hard dependencies until FreeBSD/OPNsense compatibility is verified.
