<?php

namespace OPNsense\PondSecNDR\Api;

use OPNsense\Base\ApiControllerBase;

class SinkholeController extends ApiControllerBase
{
    use BackendJsonTrait;

    public function listAction()
    {
        return $this->runBackendJson('sinkhole');
    }

    public function addAction()
    {
        $domain = trim((string)$this->request->getPost('domain', null, ''));
        $reason = trim((string)$this->request->getPost('reason', null, ''));
        $duration = (int)$this->request->getPost('duration_seconds', 'int', 3600);
        if ($domain === '') {
            return array('status' => 'error', 'message' => 'missing sinkhole domain');
        }
        if ($duration < 60) {
            $duration = 3600;
        }
        return $this->runBackendJson(
            'sinkhole_add ' . escapeshellarg($domain) . ' ' . escapeshellarg($reason) . ' ' . escapeshellarg((string)$duration)
        );
    }

    public function proposeAction($incidentId = null)
    {
        if ($incidentId === null) {
            return array('status' => 'error', 'message' => 'missing incident id');
        }
        return $this->runBackendJson('sinkhole_propose ' . escapeshellarg($incidentId));
    }

    public function editAction($id = null)
    {
        if ($id === null) {
            return array('status' => 'error', 'message' => 'missing sinkhole id');
        }
        $reason = trim((string)$this->request->getPost('reason', null, ''));
        $expiresAt = trim((string)$this->request->getPost('expires_at', null, ''));
        if ($reason === '') {
            $reason = 'Manual DNS sinkhole entry';
        }
        if ($expiresAt === '') {
            $expiresAt = 'never';
        }
        return $this->runBackendJson(
            'sinkhole_edit ' . escapeshellarg($id) . ' ' . escapeshellarg($reason) . ' ' . escapeshellarg($expiresAt)
        );
    }

    public function activateAction($id = null)
    {
        if ($id === null) {
            return array('status' => 'error', 'message' => 'missing sinkhole id');
        }
        return $this->runBackendJson('sinkhole_activate ' . escapeshellarg($id));
    }

    public function removeAction($id = null)
    {
        if ($id === null) {
            return array('status' => 'error', 'message' => 'missing sinkhole id');
        }
        return $this->runBackendJson('sinkhole_remove ' . escapeshellarg($id));
    }

    public function deleteAction($id = null)
    {
        return $this->removeAction($id);
    }
}
