#!/bin/sh

set -eu

TARGET="${1:-pondadmin@192.168.99.2}"
ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
ARCHIVE="/tmp/pondsec-ndr-deploy.tgz"

cd "$ROOT_DIR"

COPYFILE_DISABLE=1 tar --exclude='._*' --exclude='.DS_Store' -czf "$ARCHIVE" \
    src pkg-install tests/fixtures/suricata_eve_sample.jsonl

scp -q "$ARCHIVE" "$TARGET:/tmp/pondsec-ndr-deploy.tgz"

ssh "$TARGET" 'set -eu
STAGE=/tmp/pondsec-ndr-stage
BACKUP=/root/pondsec-ndr-backup-$(date +%Y%m%d%H%M%S)
rm -rf "$STAGE"
mkdir -p "$STAGE"
sudo mkdir -p "$BACKUP"
tar -xzf /tmp/pondsec-ndr-deploy.tgz -C "$STAGE"

sudo service pondsec_ndr onestop >/dev/null 2>&1 || true
sudo sh "$STAGE/pkg-install" dummy POST-INSTALL

for path in \
    /usr/local/opnsense/mvc/app/controllers/OPNsense/PondSecNDR \
    /usr/local/opnsense/mvc/app/models/OPNsense/PondSecNDR \
    /usr/local/opnsense/mvc/app/views/OPNsense/PondSecNDR \
    /usr/local/opnsense/service/conf/actions.d/actions_pondsecndr.conf \
    /usr/local/opnsense/service/templates/OPNsense/PondSecNDR \
    /usr/local/share/pondsec-ndr \
    /usr/local/sbin/pondsec-ndr \
    /usr/local/sbin/pondsec-ndrctl \
    /usr/local/etc/rc.d/pondsec_ndr \
    /usr/local/etc/inc/plugins.inc.d/pondsecndr.inc; do
    if [ -e "$path" ]; then
        sudo mkdir -p "$BACKUP$(dirname "$path")"
        sudo cp -Rp "$path" "$BACKUP$path"
    fi
done

sudo mkdir -p \
    /usr/local/opnsense/mvc/app/controllers/OPNsense \
    /usr/local/opnsense/mvc/app/models/OPNsense \
    /usr/local/opnsense/mvc/app/views/OPNsense \
    /usr/local/opnsense/service/conf/actions.d \
    /usr/local/opnsense/service/templates/OPNsense \
    /usr/local/share /usr/local/sbin /usr/local/etc/rc.d /usr/local/etc/inc/plugins.inc.d

sudo cp -Rp "$STAGE/src/opnsense/mvc/app/controllers/OPNsense/PondSecNDR" /usr/local/opnsense/mvc/app/controllers/OPNsense/
sudo cp -Rp "$STAGE/src/opnsense/mvc/app/models/OPNsense/PondSecNDR" /usr/local/opnsense/mvc/app/models/OPNsense/
sudo cp -Rp "$STAGE/src/opnsense/mvc/app/views/OPNsense/PondSecNDR" /usr/local/opnsense/mvc/app/views/OPNsense/
sudo cp -p "$STAGE/src/opnsense/service/conf/actions.d/actions_pondsecndr.conf" /usr/local/opnsense/service/conf/actions.d/actions_pondsecndr.conf
sudo cp -Rp "$STAGE/src/opnsense/service/templates/OPNsense/PondSecNDR" /usr/local/opnsense/service/templates/OPNsense/
sudo rm -rf /usr/local/share/pondsec-ndr
sudo cp -Rp "$STAGE/src/usr/local/share/pondsec-ndr" /usr/local/share/pondsec-ndr
sudo cp -p "$STAGE/src/usr/local/sbin/pondsec-ndr" "$STAGE/src/usr/local/sbin/pondsec-ndrctl" /usr/local/sbin/
sudo cp -p "$STAGE/src/usr/local/etc/rc.d/pondsec_ndr" /usr/local/etc/rc.d/pondsec_ndr
sudo cp -p "$STAGE/src/usr/local/etc/inc/plugins.inc.d/pondsecndr.inc" /usr/local/etc/inc/plugins.inc.d/pondsecndr.inc

if [ -d /var/log/suricata ]; then
    sudo sh -c "getfacl /var/log/suricata /var/log/suricata/eve.json > \"$BACKUP/suricata-acl-before.txt\" 2>/dev/null || true"
    sudo setfacl -m u:pondsecndr:xaRcs::allow /var/log/suricata || true
    if sudo test -f /var/log/suricata/eve.json; then
        sudo chgrp pondsecndr /var/log/suricata/eve.json
        sudo chmod 640 /var/log/suricata/eve.json
        sudo setfacl -m u:pondsecndr:raRcs::allow /var/log/suricata/eve.json || true
    fi
    if sudo test -f /etc/newsyslog.conf.d/suricata; then
        sudo mkdir -p "$BACKUP/etc/newsyslog.conf.d"
        sudo cp -p /etc/newsyslog.conf.d/suricata "$BACKUP/etc/newsyslog.conf.d/suricata"
        sudo sed -i "" -E "s#^(/var/log/suricata/eve\\.json[[:space:]]+)root:wheel([[:space:]]+640[[:space:]])#\\1root:pondsecndr\\2#" /etc/newsyslog.conf.d/suricata
    fi
fi

sudo find \
    /usr/local/opnsense/mvc/app/controllers/OPNsense/PondSecNDR \
    /usr/local/opnsense/mvc/app/models/OPNsense/PondSecNDR \
    /usr/local/opnsense/mvc/app/views/OPNsense/PondSecNDR \
    /usr/local/opnsense/service/templates/OPNsense/PondSecNDR \
    /usr/local/share/pondsec-ndr \
    \( -name "._*" -o -name ".DS_Store" -o -name "__pycache__" \) -prune -exec rm -rf {} +

sudo chown -R root:wheel \
    /usr/local/opnsense/mvc/app/controllers/OPNsense/PondSecNDR \
    /usr/local/opnsense/mvc/app/models/OPNsense/PondSecNDR \
    /usr/local/opnsense/mvc/app/views/OPNsense/PondSecNDR \
    /usr/local/opnsense/service/conf/actions.d/actions_pondsecndr.conf \
    /usr/local/opnsense/service/templates/OPNsense/PondSecNDR \
    /usr/local/share/pondsec-ndr \
    /usr/local/sbin/pondsec-ndr \
    /usr/local/sbin/pondsec-ndrctl \
    /usr/local/etc/rc.d/pondsec_ndr \
    /usr/local/etc/inc/plugins.inc.d/pondsecndr.inc
sudo chmod 755 /usr/local/sbin/pondsec-ndr /usr/local/sbin/pondsec-ndrctl /usr/local/etc/rc.d/pondsec_ndr
sudo find /usr/local/share/pondsec-ndr -type f -name "*.py" -exec chmod 644 {} +
sudo chown -R pondsecndr:pondsecndr /var/db/pondsec-ndr /var/log/pondsec-ndr /var/run/pondsec-ndr

sudo service configd restart
sudo service pondsec_ndr onestart >/dev/null
sudo service pondsec_ndr onestatus || true
echo "backup=$BACKUP"
'
