<?php

namespace OPNsense\PondSecNDR;

class IncidentsController extends IndexController
{
    public function indexAction()
    {
        return $this->incidentsAction();
    }
}
