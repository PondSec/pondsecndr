<?php

namespace OPNsense\PondSecNDR;

class ServiceController extends IndexController
{
    public function indexAction()
    {
        return $this->serviceAction();
    }
}
