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
        if (!$this->isSafeId($id)) {
            $this->response->setStatusCode(400, 'Bad Request');
            return ['status' => 'error', 'message' => 'invalid incident id'];
        }
        return $this->runBackendJson('incident_get ' . escapeshellarg($id));
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

    public function releaseAction($id = null)
    {
        if (!$this->isSafeId($id)) {
            $this->response->setStatusCode(400, 'Bad Request');
            return ['status' => 'error', 'message' => 'invalid incident id'];
        }
        return $this->runBackendJson('incident_release ' . $id);
    }

    public function mergeAction($primaryId = null, $secondaryId = null)
    {
        if (!$this->isSafeId($primaryId) || !$this->isSafeId($secondaryId)) {
            $this->response->setStatusCode(400, 'Bad Request');
            return ['status' => 'error', 'message' => 'invalid incident id'];
        }
        return $this->runBackendJson('incident_merge ' . $primaryId . ' ' . $secondaryId);
    }

    public function linkAction($primaryId = null, $relatedId = null)
    {
        if (!$this->isSafeId($primaryId) || !$this->isSafeId($relatedId)) {
            $this->response->setStatusCode(400, 'Bad Request');
            return ['status' => 'error', 'message' => 'invalid incident id'];
        }
        return $this->runBackendJson('incident_link ' . $primaryId . ' ' . $relatedId);
    }

    public function keepSeparateAction($primaryId = null, $relatedId = null)
    {
        if (!$this->isSafeId($primaryId) || !$this->isSafeId($relatedId)) {
            $this->response->setStatusCode(400, 'Bad Request');
            return ['status' => 'error', 'message' => 'invalid incident id'];
        }
        return $this->runBackendJson('incident_keep_separate ' . $primaryId . ' ' . $relatedId);
    }

    private function isSafeId($id)
    {
        return is_string($id) && preg_match('/^[A-Za-z0-9._:-]{1,128}$/', $id);
    }
}
