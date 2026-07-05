<?php

namespace OPNsense\PondSecNDR\Api;

use OPNsense\Base\ApiControllerBase;

class BlocklistController extends ApiControllerBase
{
    use BackendJsonTrait;

    public function listAction()
    {
        return $this->runBackendJson('blocklist');
    }

    public function addAction()
    {
        return $this->notAvailable('blocklist add');
    }

    public function deleteAction($id = null)
    {
        return $this->notAvailable('blocklist delete');
    }
}
