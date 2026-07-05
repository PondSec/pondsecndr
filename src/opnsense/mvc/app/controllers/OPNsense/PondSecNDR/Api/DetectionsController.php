<?php

namespace OPNsense\PondSecNDR\Api;

use OPNsense\Base\ApiControllerBase;

class DetectionsController extends ApiControllerBase
{
    use BackendJsonTrait;

    public function listAction()
    {
        return $this->runBackendJson('detections');
    }

    public function getAction($id = null)
    {
        return $this->notAvailable('detection detail');
    }
}
