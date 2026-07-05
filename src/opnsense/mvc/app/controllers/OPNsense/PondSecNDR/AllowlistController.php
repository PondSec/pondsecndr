<?php

namespace OPNsense\PondSecNDR;

class AllowlistController extends IndexController
{
    public function indexAction()
    {
        return $this->allowlistAction();
    }
}
