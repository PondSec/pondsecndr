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
        $value = trim((string)$this->request->getPost('value', null, ''));
        $reason = trim((string)$this->request->getPost('reason', null, ''));
        $expiresAt = trim((string)$this->request->getPost('expires_at', null, ''));
        if ($value === '') {
            return array('status' => 'error', 'message' => 'missing allowlist value');
        }
        return $this->runBackendJson(
            'allowlist_add ' . escapeshellarg($value) . ' ' . escapeshellarg($reason) . ' ' . escapeshellarg($expiresAt)
        );
    }

    public function deleteAction($id = null)
    {
        if ($id === null) {
            return array('status' => 'error', 'message' => 'missing allowlist id');
        }
        return $this->runBackendJson('allowlist_delete ' . escapeshellarg($id));
    }
}
