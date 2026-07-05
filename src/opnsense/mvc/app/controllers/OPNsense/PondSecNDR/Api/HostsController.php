<?php

namespace OPNsense\PondSecNDR\Api;

use OPNsense\Base\ApiControllerBase;

class HostsController extends ApiControllerBase
{
    use BackendJsonTrait;

    public function listAction()
    {
        return $this->runBackendJson('hosts');
    }

    public function getAction($id = null)
    {
        return $this->notAvailable('host detail');
    }

    public function resetBaselineAction($id = null)
    {
        return $this->notAvailable('host baseline reset');
    }
}
