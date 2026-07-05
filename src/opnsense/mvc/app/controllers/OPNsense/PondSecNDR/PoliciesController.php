<?php

namespace OPNsense\PondSecNDR;

class PoliciesController extends IndexController
{
    public function indexAction()
    {
        return $this->policiesAction();
    }
}
