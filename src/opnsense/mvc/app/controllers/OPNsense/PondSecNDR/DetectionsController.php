<?php

namespace OPNsense\PondSecNDR;

class DetectionsController extends IndexController
{
    public function indexAction()
    {
        return $this->detectionsAction();
    }
}
