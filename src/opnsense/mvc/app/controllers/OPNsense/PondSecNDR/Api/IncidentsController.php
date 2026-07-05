<?php

namespace OPNsense\PondSecNDR\Api;

use OPNsense\Base\ApiControllerBase;

class IncidentsController extends ApiControllerBase
{
    use BackendJsonTrait;

    public function listAction()
    {
        return $this->runBackendJson('incidents');
    }

    public function getAction($id = null)
    {
        return $this->notAvailable('incident detail');
    }

    public function closeAction($id = null)
    {
        return $this->notAvailable('incident close');
    }

    public function reopenAction($id = null)
    {
        return $this->notAvailable('incident reopen');
    }
}
