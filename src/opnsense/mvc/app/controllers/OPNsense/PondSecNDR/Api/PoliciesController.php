<?php

namespace OPNsense\PondSecNDR\Api;

use OPNsense\Base\ApiControllerBase;

class PoliciesController extends ApiControllerBase
{
    use BackendJsonTrait;

    public function listAction()
    {
        return $this->runBackendJson('policies');
    }

    public function addAction()
    {
        return $this->notAvailable('policy add');
    }

    public function setAction($id = null)
    {
        return $this->notAvailable('policy update');
    }

    public function deleteAction($id = null)
    {
        return $this->notAvailable('policy delete');
    }
}
