<?php

namespace OPNsense\PondSecNDR;

class SettingsController extends IndexController
{
    public function indexAction()
    {
        return $this->settingsAction();
    }
}
