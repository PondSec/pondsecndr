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
    /usr/local/sbin/pondsec-ndr-api \
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
sudo cp -p "$STAGE/src/usr/local/sbin/pondsec-ndr" "$STAGE/src/usr/local/sbin/pondsec-ndr-api" "$STAGE/src/usr/local/sbin/pondsec-ndrctl" /usr/local/sbin/
sudo cp -p "$STAGE/src/usr/local/etc/rc.d/pondsec_ndr" /usr/local/etc/rc.d/pondsec_ndr
sudo cp -p "$STAGE/src/usr/local/etc/inc/plugins.inc.d/pondsecndr.inc" /usr/local/etc/inc/plugins.inc.d/pondsecndr.inc

if [ -f /conf/config.xml ]; then
    sudo perl -0pi -e "s{(<pondsecndr\\b.*?</pondsecndr>)}{my \$b=\$1; \$b =~ s#(<general>.*?<mode>)\\w+(</mode>.*?</general>)#\${1}monitor\$2#s; \$b =~ s#(<learning_mode>)\\d+(</learning_mode>)#\${1}1\$2#g; \$b =~ s#(<learning_days>)\\d+(</learning_days>)#\${1}14\$2#g; \$b =~ s#(<early_ai_activation_override>)\\d+(</early_ai_activation_override>)#\${1}0\$2#g; \$b =~ s#(<response>.*?<mode>)\\w+(</mode>.*?</response>)#\${1}observe\$2#s; \$b =~ s#(<ai_full_decision_mode>)\\d+(</ai_full_decision_mode>)#\${1}0\$2#g; \$b =~ s#(<automatic_blocking>)\\d+(</automatic_blocking>)#\${1}0\$2#g; \$b =~ s#(<minimum_confidence>)\\d+(</minimum_confidence>)#\${1}95\$2#g; \$b =~ s#(<minimum_risk_score>)\\d+(</minimum_risk_score>)#\${1}95\$2#g; \$b =~ s#(<internal_isolation_cooldown_seconds>)\\d+(</internal_isolation_cooldown_seconds>)#\${1}900\$2#g; \$b =~ s#(<block_external>)\\d+(</block_external>)#\${1}0\$2#g; \$b =~ s#(<isolate_internal>)\\d+(</isolate_internal>)#\${1}0\$2#g; \$b =~ s#(<manual_confirmation>)\\d+(</manual_confirmation>)#\${1}1\$2#g; \$b}seg" /conf/config.xml
fi

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

if [ -d /var/log/dnsmasq ] || [ -f /var/db/dnsmasq.leases ]; then
    sudo sh -c "getfacl /var/log/dnsmasq /var/log/dnsmasq/*.log /var/log/dnsmasq/latest.log /var/db/dnsmasq.leases > \"$BACKUP/dnsmasq-acl-before.txt\" 2>/dev/null || true"
    if [ -d /var/log/dnsmasq ]; then
        sudo setfacl -m u:pondsecndr:rxaRcs:fd:allow /var/log/dnsmasq || true
        for file in /var/log/dnsmasq/*.log /var/log/dnsmasq/latest.log; do
            if sudo test -e "$file"; then
                sudo setfacl -m u:pondsecndr:raRcs::allow "$file" || true
            fi
        done
    fi
    if sudo test -f /var/db/dnsmasq.leases; then
        sudo setfacl -m u:pondsecndr:raRcs::allow /var/db/dnsmasq.leases || true
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
    /usr/local/sbin/pondsec-ndr-api \
    /usr/local/sbin/pondsec-ndrctl \
    /usr/local/etc/rc.d/pondsec_ndr \
    /usr/local/etc/inc/plugins.inc.d/pondsecndr.inc
sudo chmod 755 /usr/local/sbin/pondsec-ndr /usr/local/sbin/pondsec-ndr-api /usr/local/sbin/pondsec-ndrctl /usr/local/etc/rc.d/pondsec_ndr
sudo find /usr/local/share/pondsec-ndr -type f -name "*.py" -exec chmod 644 {} +
sudo chown -R pondsecndr:pondsecndr /var/db/pondsec-ndr /var/log/pondsec-ndr /var/run/pondsec-ndr

sudo service configd restart
sudo configctl template reload OPNsense/PondSecNDR >/dev/null 2>&1 || true
sudo /sbin/pfctl -t virusprot -T flush >/dev/null 2>&1 || true
sudo service pondsec_ndr onestart >/dev/null
sudo service pondsec_ndr onestatus || true
echo "backup=$BACKUP"
'
