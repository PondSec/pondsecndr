<?php

namespace OPNsense\PondSecNDR\Api;

use OPNsense\Base\ApiControllerBase;

class DashboardController extends ApiControllerBase
{
    use BackendJsonTrait;

    public function summaryAction()
    {
        return $this->runBackendJson('dashboard_summary');
    }

    public function timelineAction()
    {
        return $this->runBackendJson('dashboard_timeline');
    }

    public function trafficAction()
    {
        return $this->runBackendJson('traffic');
    }
}
