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
        $value = trim((string)$this->request->getPost('value', null, ''));
        $reason = trim((string)$this->request->getPost('reason', null, ''));
        $duration = (int)$this->request->getPost('duration_seconds', 'int', 3600);
        if ($value === '') {
            return array('status' => 'error', 'message' => 'missing block value');
        }
        if ($duration < 60) {
            $duration = 3600;
        }
        return $this->runBackendJson(
            'blocklist_add ' . escapeshellarg($value) . ' ' . escapeshellarg($reason) . ' ' . escapeshellarg((string)$duration)
        );
    }

    public function proposeAction($incidentId = null)
    {
        if ($incidentId === null) {
            return array('status' => 'error', 'message' => 'missing incident id');
        }
        return $this->runBackendJson('blocklist_propose ' . escapeshellarg($incidentId));
    }

    public function manualIncidentAction($incidentId = null)
    {
        if ($incidentId === null) {
            return array('status' => 'error', 'message' => 'missing incident id');
        }
        return $this->runBackendJson('blocklist_manual_incident ' . escapeshellarg($incidentId));
    }

    public function activateAction($id = null)
    {
        if ($id === null) {
            return array('status' => 'error', 'message' => 'missing block id');
        }
        return $this->runBackendJson('blocklist_activate ' . escapeshellarg($id));
    }

    public function removeAction($id = null)
    {
        if ($id === null) {
            return array('status' => 'error', 'message' => 'missing block id');
        }
        return $this->runBackendJson('blocklist_remove ' . escapeshellarg($id));
    }

    public function deleteAction($id = null)
    {
        return $this->removeAction($id);
    }
}
