<?php

namespace OPNsense\PondSecNDR;

class InterfacesController extends IndexController
{
    public function indexAction()
    {
        return $this->interfacesAction();
    }
}
