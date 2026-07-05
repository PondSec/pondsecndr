<?php

namespace OPNsense\PondSecNDR;

class HostsController extends IndexController
{
    public function indexAction()
    {
        return $this->hostsAction();
    }
}
