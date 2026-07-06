<?php

namespace OPNsense\PondSecNDR;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        return $this->dashboardAction();
    }

    public function dashboardAction()
    {
        $this->view->pick('OPNsense/PondSecNDR/dashboard');
    }

    public function incidentsAction()
    {
        $this->renderList('Incidents', '/api/pondsecndr/incidents/list');
    }

    public function detectionsAction()
    {
        $this->renderList('Detections', '/api/pondsecndr/detections/list');
    }

    public function hostsAction()
    {
        $this->renderList('Hosts', '/api/pondsecndr/hosts/list');
    }

    public function trafficAnalyticsAction()
    {
        $this->renderList('Traffic Analytics', '/api/pondsecndr/dashboard/traffic');
    }

    public function interfacesAction()
    {
        $this->renderList('Interfaces', '/api/pondsecndr/interfaces/list');
    }

    public function policiesAction()
    {
        $this->renderList('Policies', '/api/pondsecndr/policies/list');
    }

    public function modelsAction()
    {
        $this->renderList('Models', '/api/pondsecndr/models/list');
    }

    public function allowlistAction()
    {
        $this->view->pick('OPNsense/PondSecNDR/allowlist');
    }

    public function blocklistAction()
    {
        $this->view->pick('OPNsense/PondSecNDR/blocklist');
    }

    public function serviceAction()
    {
        $this->view->pick('OPNsense/PondSecNDR/service');
    }

    public function logsAction()
    {
        $this->renderList('Logs', '/api/pondsecndr/logs/list');
    }

    public function diagnosticsAction()
    {
        $this->view->pick('OPNsense/PondSecNDR/diagnostics');
    }

    public function settingsAction()
    {
        $this->view->generalForm = $this->getForm('general');
        $this->view->pick('OPNsense/PondSecNDR/settings');
    }

    public function aboutAction()
    {
        $this->view->pick('OPNsense/PondSecNDR/about');
    }

    private function renderList($title, $endpoint)
    {
        $this->view->title = $title;
        $this->view->endpoint = $endpoint;
        $this->view->pick('OPNsense/PondSecNDR/list');
    }
}
