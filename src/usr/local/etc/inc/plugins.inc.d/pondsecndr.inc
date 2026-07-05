<?php

function pondsecndr_services()
{
    return [[
        'description' => gettext('PondSec NDR'),
        'configd' => [
            'restart' => ['pondsecndr restart'],
            'start' => ['pondsecndr start'],
            'stop' => ['pondsecndr stop'],
            'status' => ['pondsecndr status'],
        ],
        'pidfile' => '/var/run/pondsec-ndr/pondsec-ndr.pid',
        'name' => 'pondsec_ndr',
    ]];
}
