# OPNsense Installation

## Development Install

On a development OPNsense host, install the plugin package built from the OPNsense plugins tree:

```sh
pkg install work/pkg/os-pondsec-ndr-*.txz
```

For local development without a package build, this repository also contains
`tools/deploy_opnsense_dev.sh`, which copies the plugin files to a target
firewall and restarts the required OPNsense services. That path is useful for
testing, but it is not the same as public plugin distribution.

## Public Plugin Availability

PondSec NDR will appear under **System: Firmware: Plugins** for normal users
only after `os-pondsec-ndr` is available from a configured OPNsense package
repository.

The official path is upstreaming into the `opnsense/plugins` tree and passing
review. A private/community path is also possible by publishing a signed pkg
repository and configuring target firewalls to trust it.

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
