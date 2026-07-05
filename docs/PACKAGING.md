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

## Packaging Risks

- Final Python package dependency names must be checked against the target OPNsense release.
- User and group creation must be verified during package install.
- The rc.d script must be tested under FreeBSD/OPNsense, not only macOS/Linux.
