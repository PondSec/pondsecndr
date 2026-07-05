<?php

namespace OPNsense\PondSecNDR\Api;

use OPNsense\Base\ApiControllerBase;

class ModelsController extends ApiControllerBase
{
    use BackendJsonTrait;

    public function listAction()
    {
        return $this->runBackendJson('models');
    }

    public function getAction($id = null)
    {
        return $this->notAvailable('model detail');
    }

    public function activateAction($id = null)
    {
        return $this->notAvailable('model activation');
    }

    public function rollbackAction($id = null)
    {
        return $this->notAvailable('model rollback');
    }
}
