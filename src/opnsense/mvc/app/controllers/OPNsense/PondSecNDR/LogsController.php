<?php

namespace OPNsense\PondSecNDR;

class LogsController extends IndexController
{
    public function indexAction()
    {
        return $this->logsAction();
    }
}
