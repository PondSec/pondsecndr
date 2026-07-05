<?php

namespace OPNsense\PondSecNDR\Api;

use OPNsense\Base\ApiControllerBase;

class AllowlistController extends ApiControllerBase
{
    use BackendJsonTrait;

    public function listAction()
    {
        return $this->runBackendJson('allowlist');
    }

    public function addAction()
    {
        return $this->notAvailable('allowlist add');
    }

    public function deleteAction($id = null)
    {
        return $this->notAvailable('allowlist delete');
    }
}
