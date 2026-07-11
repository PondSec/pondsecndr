<?php

namespace OPNsense\PondSecNDR\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;

class ServiceController extends ApiMutableServiceControllerBase
{
    use BackendJsonTrait;

    protected static $internalServiceClass = '\OPNsense\PondSecNDR\PondSecNDR';
    protected static $internalServiceTemplate = 'OPNsense/PondSecNDR';
    protected static $internalServiceEnabled = 'general.enabled';
    protected static $internalServiceName = 'pondsecndr';

    protected function reconfigureForceRestart()
    {
        return 0;
    }

    public function healthAction()
    {
        return $this->runBackendJson('health');
    }

    public function diagnosticsAction()
    {
        return $this->runBackendJson('diagnostics');
    }

    public function resetRuntimeAction()
    {
        return $this->runBackendJson('reset_runtime');
    }
}
