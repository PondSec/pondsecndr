<?php

namespace OPNsense\PondSecNDR;

class BlocklistController extends IndexController
{
    public function indexAction()
    {
        return $this->blocklistAction();
    }
}
