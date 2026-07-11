<?php

namespace OPNsense\PondSecNDR\Api;

use OPNsense\Core\Backend;

trait BackendJsonTrait
{
    private function runBackendJson($action)
    {
        $result = trim((string)(new Backend())->configdRun('pondsecndr ' . $action));
        $decoded = json_decode($result, true);
        if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
            return $decoded;
        }
        $excerpt = trim(preg_replace('/\s+/', ' ', strip_tags($result)));
        if (strlen($excerpt) > 500) {
            $excerpt = substr($excerpt, 0, 500) . '...';
        }
        $this->response->setStatusCode(502, 'Bad Gateway');
        return [
            'status' => 'error',
            'message' => 'backend returned invalid json',
            'action' => $action,
            'json_error' => json_last_error_msg(),
            'raw_excerpt' => $excerpt
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
