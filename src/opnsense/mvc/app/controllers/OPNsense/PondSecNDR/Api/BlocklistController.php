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

    public function proposeAction($incidentId = null)
    {
        if ($incidentId === null) {
            return array('status' => 'error', 'message' => 'missing incident id');
        }
        return $this->runBackendJson('blocklist_propose ' . escapeshellarg($incidentId));
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
