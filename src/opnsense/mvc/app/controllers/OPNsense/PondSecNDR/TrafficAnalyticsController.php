<?php

namespace OPNsense\PondSecNDR;

class TrafficAnalyticsController extends IndexController
{
    public function indexAction()
    {
        return $this->trafficAnalyticsAction();
    }
}
