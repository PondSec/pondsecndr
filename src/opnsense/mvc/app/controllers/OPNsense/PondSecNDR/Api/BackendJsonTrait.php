<?php

namespace OPNsense\PondSecNDR\Api;

use OPNsense\Core\Backend;

trait BackendJsonTrait
{
    private function runBackendJson($action)
    {
        $result = trim((new Backend())->configdRun('pondsecndr ' . $action));
        $decoded = json_decode($result, true);
        if ($decoded !== null) {
            return $decoded;
        }
        return [
            'status' => 'error',
            'message' => 'backend returned invalid json',
            'action' => $action
        ];
    }

    private function notAvailable($feature)
    {
        $this->response->setStatusCode(501, 'Not Implemented');
        return [
            'status' => 'not_available',
            'feature' => $feature,
            'message' => 'This PondSec NDR workflow is prepared but not enabled in this foundation build.'
        ];
    }
}
