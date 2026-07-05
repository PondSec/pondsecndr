<?php

namespace OPNsense\PondSecNDR;

class DashboardController extends IndexController
{
    public function indexAction()
    {
        return $this->dashboardAction();
    }
}
