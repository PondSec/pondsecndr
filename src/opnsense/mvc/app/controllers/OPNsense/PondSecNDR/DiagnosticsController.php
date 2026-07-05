<?php

namespace OPNsense\PondSecNDR;

class DiagnosticsController extends IndexController
{
    public function indexAction()
    {
        return $this->diagnosticsAction();
    }
}
