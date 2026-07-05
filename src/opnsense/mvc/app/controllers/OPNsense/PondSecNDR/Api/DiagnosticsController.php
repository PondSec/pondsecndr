<?php

namespace OPNsense\PondSecNDR\Api;

use OPNsense\Base\ApiControllerBase;

class DiagnosticsController extends ApiControllerBase
{
    use BackendJsonTrait;

    public function getAction()
    {
        return $this->runBackendJson('diagnostics');
    }

    public function selfTestAction()
    {
        return $this->runBackendJson('selftest');
    }

    public function protectionValidateAction()
    {
        return $this->runBackendJson('protection_validate');
    }

    public function protectionValidateSuiteAction()
    {
        return $this->runBackendJson('protection_validate_suite');
    }
}
