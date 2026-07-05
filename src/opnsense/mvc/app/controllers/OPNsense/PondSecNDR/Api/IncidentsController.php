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
        if (!$this->isSafeId($id)) {
            $this->response->setStatusCode(400, 'Bad Request');
            return ['status' => 'error', 'message' => 'invalid incident id'];
        }
        return $this->runBackendJson('incident_close ' . $id);
    }

    public function reopenAction($id = null)
    {
        if (!$this->isSafeId($id)) {
            $this->response->setStatusCode(400, 'Bad Request');
            return ['status' => 'error', 'message' => 'invalid incident id'];
        }
        return $this->runBackendJson('incident_reopen ' . $id);
    }

    private function isSafeId($id)
    {
        return is_string($id) && preg_match('/^[A-Za-z0-9._:-]{1,128}$/', $id);
    }
}
