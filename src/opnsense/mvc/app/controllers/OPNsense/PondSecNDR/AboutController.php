<?php

namespace OPNsense\PondSecNDR;

class AboutController extends IndexController
{
    public function indexAction()
    {
        return $this->aboutAction();
    }
}
