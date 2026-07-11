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
        if (!$this->isSafeHostId($id)) {
            $this->response->setStatusCode(400, 'Bad Request');
            return ['status' => 'error', 'message' => 'invalid host id'];
        }
        return $this->runBackendJson('host_get ' . escapeshellarg($id));
    }

    public function resetBaselineAction($id = null)
    {
        return $this->notAvailable('host baseline reset');
    }

    private function isSafeHostId($id)
    {
        return is_string($id) && preg_match('/^[A-Za-z0-9._:\\-]{1,160}$/', $id);
    }
}
