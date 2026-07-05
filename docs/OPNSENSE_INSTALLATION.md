# OPNsense Installation

## Development Install

On a development OPNsense host, install the plugin package built from the OPNsense plugins tree:

```sh
pkg install work/pkg/os-pondsec-ndr-*.txz
```

Restart configd after installing or updating configd actions:

```sh
service configd restart
```

Clear UI caches when menu or ACL entries change:

```sh
rm -f /tmp/opnsense_menu_cache.xml /tmp/opnsense_acl_cache.json
```

## Service Control

```sh
configctl pondsecndr start
configctl pondsecndr status
configctl pondsecndr health
configctl pondsecndr stop
```

CLI:

```sh
pondsec-ndrctl status
pondsec-ndrctl health
pondsec-ndrctl diagnostics
```

## Default Mode

The plugin installs in `monitor` mode. It collects and stores metadata but does not automatically block traffic.

## Uninstall

Use the package manager:

```sh
pkg delete os-pondsec-ndr
```

Runtime data in `/var/db/pondsec-ndr/`, `/var/log/pondsec-ndr/`, and `/var/run/pondsec-ndr/` should be reviewed before deletion.
