<script>
$(function() {
    var pageTitle = '{{ title }}';
    var endpoint = '{{ endpoint }}';
    var allRows = [];
    var rows = [];
    var summary = {};
    var caseDetailLookup = {};
    var currentIncidentId = null;
    var uiLanguage = initialLanguage();
    var translationTimer = null;
    var translationObserver = null;
    var de = {
        'PondSec NDR: Incidents': 'PondSec NDR: Incidents',
        'PondSec NDR: Detections': 'PondSec NDR: Detections',
        'PondSec NDR: Hosts': 'PondSec NDR: Hosts',
        'PondSec NDR: Interfaces': 'PondSec NDR: Schnittstellen',
        'PondSec NDR: Logs': 'PondSec NDR: Logs',
        'PondSec NDR: Models': 'PondSec NDR: Modelle',
        'Search': 'Suche',
        'Status': 'Status',
        'All statuses': 'Alle Status',
        'Category': 'Kategorie',
        'All categories': 'Alle Kategorien',
        'Reset': 'Zuruecksetzen',
        'Loading': 'Laedt',
        'No records available.': 'Keine Eintraege verfuegbar.',
        'Records': 'Eintraege',
        'Shown': 'Angezeigt',
        'Open': 'Offen',
        'Active': 'Aktiv',
        'High risk': 'Hohes Risiko',
        'Interfaces': 'Schnittstellen',
        'Selected': 'Ausgewaehlt',
        'Status': 'Status',
        'Risk': 'Risiko',
        'Source': 'Quelle',
        'Destination': 'Ziel',
        'Incident': 'Incident',
        'Updated': 'Aktualisiert',
        'Action': 'Aktion',
        'Detector': 'Detektor',
        'Severity': 'Schweregrad',
        'Confidence': 'Vertrauen',
        'Time': 'Zeit',
        'Host': 'Host',
        'Peer group': 'Peer-Gruppe',
        'Protection': 'Schutz',
        'Open incidents': 'Offene Incidents',
        'Interface': 'Schnittstelle',
        'Last seen': 'Zuletzt gesehen',
        'Trusted value': 'Vertrauenswuerdiger Wert',
        'Reason': 'Grund',
        'Expires': 'Laeuft ab',
        'Created by': 'Erstellt von',
        'Created': 'Erstellt',
        'Model': 'Modell',
        'Provider': 'Provider',
        'Type': 'Typ',
        'Trained on': 'Trainiert mit',
        'License': 'Lizenz',
        'Configured': 'Konfiguriert',
        'Level': 'Level',
        'Component': 'Komponente',
        'Message': 'Meldung',
        'Close': 'Schliessen',
        'False positive': 'False Positive',
        'Archive': 'Archivieren',
        'Reopen': 'Wieder oeffnen',
        'Propose block': 'Block vorschlagen',
        'Manual block': 'Manuell blocken',
        'Propose DNS sinkhole': 'DNS-Sinkhole vorschlagen',
        'DNS sinkhole': 'DNS-Sinkhole',
        'Release block/isolation': 'Block/Isolation freigeben',
        'Delete': 'Loeschen',
        'Activate': 'Aktivieren',
        'Remove': 'Entfernen',
        'Merge': 'Zusammenfuehren',
        'Link': 'Verknuepfen',
        'Keep separate': 'Getrennt lassen',
        'Open case view': 'Case-Ansicht oeffnen',
        'Open entity resolution': 'Entity-Aufloesung oeffnen',
        'Back to incidents': 'Zurueck zu Incidents',
        'Back to hosts': 'Zurueck zu Hosts',
        'Overview': 'Ueberblick',
        'Attack graph': 'Angriffsgraph',
        'Timeline': 'Timeline',
        'Evidence': 'Evidenz',
        'CVE context': 'CVE-Kontext',
        'Related cases': 'Verwandte Cases',
        'Case narrative': 'Case-Narrativ',
        'Case summary': 'Case-Zusammenfassung',
        'Host story': 'Host-Verlauf',
        'Attack stages': 'Angriffsphasen',
        'What to check next': 'Als Naechstes pruefen',
        'Selected evidence': 'Ausgewaehlte Evidence',
        'Case overview': 'Case-Ueberblick',
        'Visual timeline': 'Visuelle Timeline',
        'Affected targets': 'Betroffene Ziele',
        'File sandbox and file verdicts': 'Datei-Sandbox und Datei-Verdicts',
        'Confidence boundaries': 'Confidence-Grenzen',
        'Notable features': 'Auffaellige Merkmale',
        'Risk factors': 'Risikofaktoren',
        'Response policy decisions': 'Response-Policy-Entscheidungen',
        'Promotion decision': 'Promotion-Entscheidung',
        'Promotion score': 'Promotion-Score',
        'Threshold': 'Schwellenwert',
        'Decision': 'Entscheidung',
        'Positive evidence': 'Positive Evidenz',
        'Negative evidence': 'Entlastende Evidenz',
        'No promotion decision recorded.': 'Keine Promotion-Entscheidung aufgezeichnet.',
        'Entity resolution': 'Entity-Aufloesung',
        'IP identity': 'IP-Identitaet',
        'Roles and context': 'Rollen und Kontext',
        'Linked host records': 'Verknuepfte Host-Eintraege',
        'Resolution history': 'Aufloesungsverlauf',
        'Close case detail': 'Case-Detail schliessen',
        'Close host detail': 'Host-Detail schliessen',
        'Case analysis tabs': 'Case-Analyse-Tabs',
        'Incident attack graph': 'Incident-Angriffsgraph',
        'Case': 'Case',
        'Relationship': 'Beziehung',
        'Node': 'Knoten',
        'Attack stage': 'Angriffsphase',
        'Timeline event': 'Timeline-Event',
        'Selected evidence': 'Ausgewaehlte Evidence',
        'Type': 'Typ',
        'Stage': 'Phase',
        'Kind': 'Art',
        'Protocol': 'Protokoll',
        'Ports': 'Ports',
        'Risk contribution': 'Risiko-Beitrag',
        'Detection IDs': 'Detection-IDs',
        'Summary': 'Zusammenfassung',
        'Affected host': 'Betroffener Host',
        'Possible entry source': 'Moegliche Eintrittsquelle',
        'Primary destination': 'Primaeres Ziel',
        'First seen': 'Zuerst gesehen',
        'Risk score': 'Risiko-Score',
        'Block status': 'Block-Status',
        'Isolation': 'Isolation',
        'Response action': 'Response-Aktion',
        'Target': 'Ziel',
        'Proposal': 'Vorschlag',
        'Activation': 'Aktivierung',
        'Compromise': 'Kompromittierung',
        'Confirmed': 'Bestaetigt',
        'Not confirmed': 'Nicht bestaetigt',
        'No narrative generated for this case yet.': 'Fuer diesen Case wurde noch kein Narrativ erzeugt.',
        'No response policy decision recorded for this case.': 'Fuer diesen Case ist keine Response-Policy-Entscheidung aufgezeichnet.',
        'No related cases found in the current window.': 'Im aktuellen Fenster wurden keine verwandten Cases gefunden.',
        'CVE enrichment is disabled.': 'CVE-Anreicherung ist deaktiviert.',
        'No CVE references found in local evidence for this case.': 'In der lokalen Evidence wurden keine CVE-Referenzen fuer diesen Case gefunden.',
        'No graph data recorded for this incident.': 'Fuer diesen Incident sind keine Graphdaten aufgezeichnet.',
        'No attack stage analysis recorded.': 'Keine Angriffsphasenanalyse aufgezeichnet.',
        'No detection timeline recorded.': 'Keine Detection-Timeline aufgezeichnet.',
        'Select a graph node, relationship, phase, or timeline item.': 'Graph-Knoten, Beziehung, Phase oder Timeline-Eintrag auswaehlen.',
        'No target list recorded.': 'Keine Zielliste aufgezeichnet.',
        'No file, AV or sandbox verdict evidence was recorded for this incident.': 'Fuer diesen Incident wurde keine Datei-, AV- oder Sandbox-Verdict-Evidenz aufgezeichnet.',
        'File verdict evidence': 'Datei-Verdict-Evidenz',
        'Provider': 'Provider',
        'Sandbox status': 'Sandbox-Status',
        'Sandbox confidence': 'Sandbox-Confidence',
        'Detection confidence': 'Detection-Confidence',
        'Threat name': 'Threat-Name',
        'MIME type': 'MIME-Typ',
        'File size': 'Dateigroesse',
        'Analysis ID': 'Analyse-ID',
        'Hashes': 'Hashes',
        'Findings': 'Findings',
        'No file hashes recorded.': 'Keine Datei-Hashes aufgezeichnet.',
        'Safe test marker recorded.': 'Sicherer Testmarker aufgezeichnet.',
        'No sandbox findings recorded.': 'Keine Sandbox-Findings aufgezeichnet.',
        'No guidance recorded.': 'Keine Hinweise aufgezeichnet.',
        'No notable feature list recorded.': 'Keine auffaelligen Merkmale aufgezeichnet.',
        'No risk factors recorded.': 'Keine Risikofaktoren aufgezeichnet.',
        'No IP-oriented host records are linked to this entity.': 'Mit dieser Entity sind keine IP-basierten Host-Eintraege verknuepft.',
        'No entity history recorded yet.': 'Noch kein Entity-Verlauf aufgezeichnet.',
        'No current IPs recorded.': 'Keine aktuellen IPs aufgezeichnet.',
        'No previous IPs recorded.': 'Keine frueheren IPs aufgezeichnet.',
        'No roles recorded.': 'Keine Rollen aufgezeichnet.',
        'No services recorded.': 'Keine Dienste aufgezeichnet.',
        'No tags recorded.': 'Keine Tags aufgezeichnet.',
        'None recorded.': 'Keine aufgezeichnet.',
        'Details available': 'Details verfuegbar',
        'Action completed': 'Aktion abgeschlossen',
        'Delete this incident? Active responses must be released first.': 'Diesen Incident loeschen? Aktive Responses muessen zuerst freigegeben werden.',
        'Manually block this incident response target now?': 'Response-Ziel dieses Incidents jetzt manuell blocken?',
        'Create a DNS sinkhole proposal from this incident evidence?': 'DNS-Sinkhole-Vorschlag aus der Evidenz dieses Incidents erstellen?',
        'IP, category, detector, message': 'IP, Kategorie, Detektor, Meldung',
        'IP': 'IP',
        'Baseline': 'Baseline',
        'Current IPs': 'Aktuelle IPs',
        'Previous IPs': 'Fruehere IPs',
        'Entity ID': 'Entity-ID',
        'Primary IP': 'Primaere IP',
        'Hostname': 'Hostname',
        'MAC': 'MAC',
        'OS': 'OS',
        'VLAN': 'VLAN',
        'Zone': 'Zone',
        'Roles': 'Rollen',
        'Known services': 'Bekannte Dienste',
        'Tags': 'Tags',
        'Peer group source': 'Peer-Gruppen-Quelle',
        'Peer': 'Peer',
        'Window': 'Fenster',
        'Detections': 'Detektionen',
        'Events': 'Events',
        'Suppressed duplicates': 'Unterdrueckte Duplikate',
        'Response decision': 'Response-Entscheidung',
        'response decision': 'Response-Entscheidung',
        'recorded': 'aufgezeichnet',
        'allowed': 'erlaubt',
        'denied': 'abgelehnt',
        'would_execute': 'wuerde ausgefuehrt',
        'not_found': 'nicht gefunden',
        'sinkhole': 'Sinkhole',
        'not allowed': 'nicht erlaubt',
        'unrecorded': 'nicht aufgezeichnet',
        'audited': 'auditiert',
        'observed': 'beobachtet',
        'inferred': 'abgeleitet',
        'confirmed': 'bestaetigt',
        'not_claimed': 'nicht beansprucht',
        'Not Claimed': 'Nicht beansprucht',
        'unknown': 'unbekannt',
        'none': 'keine',
        'normal': 'normal',
        'open': 'offen',
        'closed': 'geschlossen',
        'active': 'aktiv',
        'proposed': 'vorgeschlagen',
        'monitor': 'Monitor',
        'catalog': 'Katalog',
        'warning': 'Warnung',
        'healthy': 'gesund',
        'ok': 'ok',
        'running': 'laeuft',
        'installed': 'installiert',
        'failed': 'fehlgeschlagen',
        'error': 'Fehler',
        'blocked': 'blockiert',
        'isolated': 'isoliert',
        'critical': 'kritisch',
        'removed': 'entfernt',
        'stopped': 'gestoppt',
        'allowlisted': 'allowlisted',
        'selected': 'ausgewaehlt',
        'available': 'verfuegbar',
        'Initial Access': 'Initial Access',
        'Execution': 'Execution',
        'Persistence': 'Persistence',
        'Privilege Escalation': 'Privilege Escalation',
        'Defense Evasion': 'Defense Evasion',
        'Credential Access': 'Credential Access',
        'Discovery': 'Discovery',
        'Lateral Movement': 'Lateral Movement',
        'Collection': 'Collection',
        'Command And Control': 'Command and Control',
        'Exfiltration': 'Exfiltration',
        'Impact': 'Impact'
    };

    function normalizeText(value) {
        return $.trim(String(value || '').replace(/\s+/g, ' '));
    }

    function initialLanguage() {
        var value = (
            $('html').attr('lang') ||
            document.documentElement.getAttribute('lang') ||
            navigator.language ||
            navigator.userLanguage ||
            ''
        ).toLowerCase();
        return value.indexOf('de') === 0 ? 'de' : 'en';
    }

    function extractLanguage(data) {
        if (!data || typeof data !== 'object') {
            return '';
        }
        if (data.language) {
            return data.language;
        }
        if (data.general && data.general.language) {
            return data.general.language;
        }
        if (data.pondsecndr && data.pondsecndr.general && data.pondsecndr.general.language) {
            return data.pondsecndr.general.language;
        }
        var found = '';
        $.each(data, function(key, value) {
            if (!found && key === 'language') {
                found = value;
                return false;
            }
            if (!found && value && typeof value === 'object') {
                found = extractLanguage(value);
            }
        });
        return found;
    }

    function t(key) {
        return uiLanguage === 'de' && de[key] ? de[key] : key;
    }

    function translateTextNode(node) {
        if (node._pondsecOriginalText === undefined) {
            node._pondsecOriginalText = node.nodeValue || '';
        }
        var original = node._pondsecOriginalText;
        if (uiLanguage !== 'de') {
            if (node.nodeValue !== original) {
                node.nodeValue = original;
            }
            return;
        }
        var key = normalizeText(original);
        if (!key || !de[key]) {
            return;
        }
        var prefix = (original.match(/^\s*/) || [''])[0];
        var suffix = (original.match(/\s*$/) || [''])[0];
        node.nodeValue = prefix + de[key] + suffix;
    }

    function translateElement(root) {
        $(root).find('*').addBack().each(function() {
            var $item = $(this);
            if ($item.is('script, style, pre, code, textarea, input')) {
                return;
            }
            ['placeholder', 'aria-label', 'title'].forEach(function(attr) {
                var value = $item.attr(attr);
                if (value === undefined) {
                    return;
                }
                var dataKey = 'pondsecOriginal' + attr.replace(/[^a-z]/gi, '');
                if ($item.data(dataKey) === undefined) {
                    $item.data(dataKey, value);
                }
                var original = $item.data(dataKey);
                var key = normalizeText(original);
                if (uiLanguage === 'de' && key && de[key]) {
                    $item.attr(attr, de[key]);
                } else if (uiLanguage !== 'de') {
                    $item.attr(attr, original);
                }
            });
            $item.contents().filter(function() {
                return this.nodeType === 3;
            }).each(function() {
                translateTextNode(this);
            });
        });
    }

    function translateVisibleUi() {
        translateElement($('.pondsec-list-page, #incident_detail_panel, #host_detail_panel'));
    }

    function scheduleTranslation() {
        clearTimeout(translationTimer);
        translationTimer = setTimeout(translateVisibleUi, 0);
    }

    function setLanguage(language) {
        uiLanguage = language === 'de' ? 'de' : 'en';
        scheduleTranslation();
    }

    function observeTranslations() {
        if (!window.MutationObserver || translationObserver) {
            return;
        }
        translationObserver = new MutationObserver(scheduleTranslation);
        $('.pondsec-list-page, #incident_detail_panel, #host_detail_panel').each(function() {
            translationObserver.observe(this, {childList: true, subtree: true, characterData: true, attributes: true});
        });
    }

    function escapeHtml(value) {
        return $('<div/>').text(value === null || value === undefined ? '' : String(value)).html();
    }

    function pageKind() {
        return pageTitle.toLowerCase().replace(/\s+/g, '_');
    }

    function hasValue(value) {
        return value !== null && value !== undefined && value !== '';
    }

    function value(row, keys) {
        for (var i = 0; i < keys.length; i++) {
            if (hasValue(row[keys[i]])) {
                return row[keys[i]];
            }
        }
        return '';
    }

    function humanKey(key) {
        return String(key).replace(/_/g, ' ').replace(/\b\w/g, function(char) { return char.toUpperCase(); });
    }

    function formatNumber(value) {
        var parsed = Number(value);
        if (!Number.isFinite(parsed)) {
            return hasValue(value) ? escapeHtml(value) : '-';
        }
        return parsed.toLocaleString();
    }

    function formatPercent(value) {
        var parsed = Number(value);
        if (!Number.isFinite(parsed)) {
            return '-';
        }
        return Math.round(parsed * 100) + '%';
    }

    function formatDate(value) {
        if (!hasValue(value)) {
            return '-';
        }
        var parsed = new Date(value);
        if (Number.isNaN(parsed.getTime())) {
            return escapeHtml(value);
        }
        return parsed.toLocaleString();
    }

    function statusClass(value) {
        value = String(value || '').toLowerCase();
        if (['ok', 'healthy', 'active', 'running', 'installed', 'open'].indexOf(value) !== -1) {
            return 'good';
        }
        if (['proposed', 'monitor', 'catalog', 'warning'].indexOf(value) !== -1) {
            return 'info';
        }
        if (['failed', 'error', 'blocked', 'isolated', 'critical', 'removed', 'closed', 'stopped'].indexOf(value) !== -1) {
            return 'bad';
        }
        return 'neutral';
    }

    function badge(value) {
        if (!hasValue(value)) {
            return '<span class="pondsec-badge neutral">' + escapeHtml(t('unknown')) + '</span>';
        }
        return '<span class="pondsec-badge ' + statusClass(value) + '">' + escapeHtml(t(value)) + '</span>';
    }

    function riskCell(value) {
        var risk = Number(value);
        if (!Number.isFinite(risk)) {
            return '-';
        }
        return '<div class="pondsec-risk"><span style="width:' + Math.max(0, Math.min(100, risk)) + '%"></span></div><strong>' + risk + '</strong>';
    }

    function compactValue(data) {
        if (!hasValue(data)) {
            return '-';
        }
        if (Array.isArray(data)) {
            if (!data.length) {
                return '-';
            }
            return escapeHtml(data.map(function(item) {
                if (typeof item === 'object' && item !== null) {
                    return item.name || item.detector_id || item.value || item.category || 'detail';
                }
                return item;
            }).join(', '));
        }
        if (typeof data === 'object') {
            var parts = [];
            Object.keys(data).slice(0, 4).forEach(function(key) {
                var item = data[key];
                if (typeof item !== 'object') {
                    parts.push(humanKey(key) + ': ' + item);
                }
            });
            return parts.length ? escapeHtml(parts.join(' | ')) : 'Details available';
        }
        return escapeHtml(data);
    }

    function tokens(values, emptyLabel) {
        values = Array.isArray(values) ? values.filter(hasValue) : (hasValue(values) ? [values] : []);
        if (!values.length) {
            return '<span class="pondsec-empty-inline">' + escapeHtml(emptyLabel || 'None recorded.') + '</span>';
        }
        return values.map(function(value) {
            return '<span class="pondsec-token">' + escapeHtml(value) + '</span>';
        }).join('');
    }

    function escapeAttr(value) {
        return escapeHtml(value).replace(/"/g, '&quot;');
    }

    function className(value) {
        return String(value || 'unknown').toLowerCase().replace(/[^a-z0-9_-]+/g, '-');
    }

    function shortLabel(value, length) {
        value = String(value || '-');
        if (value.length <= length) {
            return value;
        }
        return value.substring(0, Math.max(1, length - 3)) + '...';
    }

    function stageLabel(value) {
        return humanKey(value || 'unknown');
    }

    function resetCaseDetails() {
        caseDetailLookup = {};
    }

    function decodeId(id) {
        try {
            return decodeURIComponent(String(id || ''));
        } catch (err) {
            return String(id || '');
        }
    }

    function registerCaseDetail(type, title, item) {
        var id = 'case-detail-' + Object.keys(caseDetailLookup).length;
        caseDetailLookup[id] = {type: type, title: title, item: item || {}};
        return id;
    }

    function renderCaseDetail(detail) {
        detail = detail || {type: 'Case', title: 'Case overview', item: {}};
        var item = detail.item || {};
        var rows = [
            ['Type', detail.type],
            ['Status', item.status || item.stage_status || item.certainty],
            ['Stage', item.stage],
            ['Kind', item.kind || item.edge_kind || item.type],
            ['Time', item.timestamp || item.first_seen || item.last_seen],
            ['Protocol', item.protocol],
            ['Ports', item.ports],
            ['Confidence', hasValue(item.confidence) ? formatPercent(item.confidence) : null],
            ['Risk contribution', item.risk_contribution || item.risk_delta || item.risk],
            ['Detection IDs', item.detection_ids],
            ['Summary', item.summary || item.reason || item.title]
        ].filter(function(row) { return hasValue(row[1]) && row[1] !== '-'; });
        $('#incident_focus_title').text(detail.title || 'Selected evidence');
        $('#incident_focus_body').html(rows.length ? rows.map(function(row) {
            return '<div class="pondsec-focus-row"><span>' + escapeHtml(row[0]) + '</span><strong>' + compactValue(row[1]) + '</strong></div>';
        }).join('') : '<div class="pondsec-empty">Select a graph node, relationship, phase, or timeline item.</div>');
        var evidence = item.evidence || item.details || {};
        $('#incident_focus_evidence').html(Object.keys(evidence).length ? '<pre>' + escapeHtml(JSON.stringify(evidence, null, 2)) + '</pre>' : '');
    }

    function renderCaseSummary(summaryData, incident) {
        summaryData = summaryData || {};
        var entry = summaryData.possible_entry_source || {};
        var response = summaryData.response || {};
        var rows = [
            ['Affected host', mono(summaryData.affected_host || incident.source_ip), 'observed'],
            ['Possible entry source', escapeHtml(entry.value || '-'), entry.certainty || 'inferred'],
            ['Primary destination', mono(summaryData.primary_destination || incident.destination_ip), hasValue(summaryData.primary_destination || incident.destination_ip) ? 'observed' : 'inferred'],
            ['First seen', formatDate(summaryData.first_seen || incident.created_at), 'observed'],
            ['Last seen', formatDate(summaryData.last_seen || incident.updated_at), 'observed'],
            ['Risk score', riskCell(summaryData.risk_score || incident.risk_score), 'observed'],
            ['Confidence', formatPercent(summaryData.confidence || incident.confidence), 'observed'],
            ['Block status', badge(response.status || 'none'), response.status === 'active' ? 'confirmed' : 'observed'],
            ['Isolation', badge(response.isolation || 'none'), response.isolation === 'active' ? 'confirmed' : 'observed']
        ];
        $('#incident_case_summary').html(rows.map(function(row) {
            return '<div class="pondsec-case-kv">' +
                '<span>' + escapeHtml(row[0]) + '</span>' +
                '<strong>' + row[1] + '</strong>' +
                '<em class="pondsec-certainty ' + className(row[2]) + '">' + escapeHtml(row[2]) + '</em>' +
            '</div>';
        }).join('') + (response.release_available ? '<div class="pondsec-case-kv pondsec-case-action"><span>Response action</span><strong><button class="btn btn-xs btn-danger pondsec-row-action" data-action="release-case" data-id="' + encodeURIComponent(incident.incident_id || '') + '">Release block/isolation</button></strong><em class="pondsec-certainty confirmed">audited</em></div>' : ''));
        $('#incident_entry_reason').text(entry.reason || '');
    }

    function renderResponseDecisions(decisions) {
        decisions = decisions || [];
        if (!decisions.length) {
            return '<div class="pondsec-empty">No response policy decision recorded for this case.</div>';
        }
        return decisions.map(function(item) {
            var detail = item.detail || {};
            var reasons = detail.reasons || detail.blocking_reasons || detail.activation_reasons || [];
            var layers = detail.decision_layers || {};
            return '<div class="pondsec-decision">' +
                '<div class="pondsec-decision-head">' +
                    badge(detail.status || item.action || 'recorded') +
                    '<strong>' + escapeHtml(item.action || 'response decision') + '</strong>' +
                    '<span>' + escapeHtml(formatDate(item.timestamp)) + '</span>' +
                    '<span>' + escapeHtml(item.actor || '-') + '</span>' +
                '</div>' +
                '<div class="pondsec-decision-grid">' +
                    '<div><span>Target</span><strong>' + mono(detail.target_ip || '-') + '</strong></div>' +
                    '<div><span>Proposal</span><strong>' + escapeHtml(detail.proposal_allowed ? 'allowed' : 'denied') + '</strong></div>' +
                    '<div><span>Activation</span><strong>' + escapeHtml(detail.activation_allowed ? 'allowed' : 'not allowed') + '</strong></div>' +
                    '<div><span>Compromise</span><strong>' + escapeHtml(((layers.compromise_assessment || {}).status) || 'unrecorded') + '</strong></div>' +
                '</div>' +
                (reasons.length ? '<ul>' + reasons.slice(0, 6).map(function(reason) { return '<li>' + escapeHtml(reason) + '</li>'; }).join('') + '</ul>' : '') +
            '</div>';
        }).join('');
    }

    function renderPromotionDecision(promotion) {
        promotion = promotion || {};
        if (!Object.keys(promotion).length) {
            return '<div class="pondsec-empty">No promotion decision recorded.</div>';
        }
        var positive = promotion.positive_evidence || [];
        var negative = promotion.negative_evidence || [];
        function factorList(items) {
            if (!items.length) {
                return '<span class="pondsec-empty-inline">-</span>';
            }
            return items.slice(0, 8).map(function(item) {
                return '<span class="pondsec-token">' + escapeHtml(humanKey(item.name || 'factor')) + ' +' + escapeHtml(item.value || 0) + '</span>';
            }).join('');
        }
        return '<div class="pondsec-decision">' +
            '<div class="pondsec-decision-head">' + badge(promotion.decision || 'recorded') + '<strong>Promotion decision</strong></div>' +
            '<div class="pondsec-decision-grid">' +
                '<div><span>Promotion score</span><strong>' + escapeHtml(hasValue(promotion.promotion_score) ? promotion.promotion_score : '-') + '</strong></div>' +
                '<div><span>Threshold</span><strong>' + escapeHtml(hasValue(promotion.promotion_threshold) ? promotion.promotion_threshold : '-') + '</strong></div>' +
                '<div><span>Decision</span><strong>' + escapeHtml(promotion.decision || '-') + '</strong></div>' +
                '<div><span>Reason</span><strong>' + escapeHtml(humanKey(promotion.reason || '-')) + '</strong></div>' +
            '</div>' +
            '<div class="pondsec-promotion-factors">' +
                '<div><span>Positive evidence</span>' + factorList(positive) + '</div>' +
                '<div><span>Negative evidence</span>' + factorList(negative) + '</div>' +
            '</div>' +
        '</div>';
    }

    function renderCaseActions(incident, caseSummary) {
        var id = encodeURIComponent(incident.incident_id || '');
        var response = (caseSummary || {}).response || {};
        var buttons = [];
        buttons.push('<button id="incident_detail_inline_close" class="btn btn-sm btn-default pondsec-inline-close" type="button"><i class="fa fa-times"></i> Back to incidents</button>');
        if (incident.status === 'open') {
            buttons.push('<button class="btn btn-sm btn-default pondsec-row-action" data-action="close-incident" data-id="' + id + '"><i class="fa fa-check"></i> Close</button>');
            buttons.push('<button class="btn btn-sm btn-warning pondsec-row-action" data-action="false-positive" data-id="' + id + '"><i class="fa fa-ban"></i> False positive</button>');
            buttons.push('<button class="btn btn-sm btn-default pondsec-row-action" data-action="archive-incident" data-id="' + id + '"><i class="fa fa-archive"></i> Archive</button>');
        } else {
            buttons.push('<button class="btn btn-sm btn-default pondsec-row-action" data-action="reopen-incident" data-id="' + id + '"><i class="fa fa-undo"></i> Reopen</button>');
        }
        buttons.push('<button class="btn btn-sm btn-primary pondsec-row-action" data-action="propose-block" data-id="' + id + '"><i class="fa fa-shield"></i> Propose block</button>');
        buttons.push('<button class="btn btn-sm btn-default pondsec-row-action" data-action="propose-sinkhole" data-id="' + id + '"><i class="fa fa-filter"></i> Propose DNS sinkhole</button>');
        buttons.push('<button class="btn btn-sm btn-danger pondsec-row-action" data-action="manual-block" data-id="' + id + '"><i class="fa fa-lock"></i> Manual block</button>');
        if (response.release_available) {
            buttons.push('<button class="btn btn-sm btn-danger pondsec-row-action" data-action="release-case" data-id="' + id + '"><i class="fa fa-unlock"></i> Release block/isolation</button>');
        }
        buttons.push('<button class="btn btn-sm btn-danger pondsec-row-action" data-action="delete-incident" data-id="' + id + '"><i class="fa fa-trash"></i> Delete</button>');
        $('#incident_case_actions').html(buttons.join(''));
    }

    function renderCertainty(summaryData) {
        var certainty = (summaryData || {}).certainty || {};
        var order = ['confirmed', 'observed', 'inferred', 'not_claimed'];
        $('#incident_certainty').html(order.map(function(key) {
            var values = certainty[key] || [];
            return '<div class="pondsec-certainty-card">' +
                '<strong>' + escapeHtml(humanKey(key)) + '</strong>' +
                '<p>' + escapeHtml(values.length ? values.join(', ') : '-') + '</p>' +
            '</div>';
        }).join(''));
    }

    function renderNarrative(narrative) {
        narrative = narrative || {};
        $('#incident_narrative').html(
            '<p>' + escapeHtml(narrative.what_happened || 'No narrative generated for this case yet.') + '</p>' +
            '<div class="pondsec-certainty-grid">' +
                '<div class="pondsec-certainty-card"><strong>Confirmed</strong><p>' + escapeHtml((narrative.confirmed || []).join(', ') || '-') + '</p></div>' +
                '<div class="pondsec-certainty-card"><strong>Not confirmed</strong><p>' + escapeHtml((narrative.not_confirmed || []).join(', ') || '-') + '</p></div>' +
            '</div>'
        );
    }

    function renderRelatedCases(cases, currentId) {
        cases = cases || [];
        if (!cases.length) {
            $('#incident_related_cases').html('<div class="pondsec-empty">No related cases found in the current window.</div>');
            return;
        }
        $('#incident_related_cases').html(cases.map(function(item) {
            var pair = String(currentId || '') + '|' + String(item.incident_id || '');
            return '<div class="pondsec-related-case">' +
                '<button class="pondsec-link-button pondsec-open-incident" data-id="' + encodeURIComponent(item.incident_id || '') + '"><strong>' + escapeHtml(item.title || item.incident_id) + '</strong><span>' + escapeHtml((item.reasons || []).join(', ')) + '</span></button>' +
                '<div class="pondsec-actions">' +
                    '<button class="btn btn-xs btn-primary pondsec-row-action" data-action="merge-case" data-id="' + escapeAttr(pair) + '">Merge</button>' +
                    '<button class="btn btn-xs btn-default pondsec-row-action" data-action="link-case" data-id="' + escapeAttr(pair) + '">Link</button>' +
                    '<button class="btn btn-xs btn-default pondsec-row-action" data-action="keep-separate-case" data-id="' + escapeAttr(pair) + '">Keep separate</button>' +
                '</div>' +
            '</div>';
        }).join(''));
    }

    function renderThreatIntel(intel) {
        intel = intel || {};
        var cves = intel.cves || [];
        if (!intel.enabled) {
            $('#incident_threat_intel').html('<div class="pondsec-empty">CVE enrichment is disabled.</div>');
            return;
        }
        if (!cves.length) {
            $('#incident_threat_intel').html('<div class="pondsec-empty">No CVE references found in local evidence for this case.</div>');
            return;
        }
        $('#incident_threat_intel').html(cves.map(function(cve) {
            return '<div class="pondsec-cve-card">' +
                '<div><strong>' + escapeHtml(cve.cve_id) + '</strong> ' + badge(cve.evidence_level || 'referenced') + (cve.cisa_kev ? badge('CISA KEV') : '') + '</div>' +
                '<p>' + escapeHtml(cve.short_description || '-') + '</p>' +
                '<div class="pondsec-cve-grid">' +
                    '<span>CVSS <strong>' + escapeHtml(hasValue(cve.cvss) ? cve.cvss : '-') + '</strong></span>' +
                    '<span>EPSS <strong>' + escapeHtml(hasValue(cve.epss) ? formatPercent(cve.epss) : '-') + '</strong></span>' +
                    '<span>Percentile <strong>' + escapeHtml(hasValue(cve.epss_percentile) ? formatPercent(cve.epss_percentile) : '-') + '</strong></span>' +
                    '<span>Confidence <strong>' + escapeHtml(formatPercent(cve.match_confidence || 0)) + '</strong></span>' +
                '</div>' +
                '<em>' + escapeHtml(cve.claim_limit || '') + '</em>' +
            '</div>';
        }).join(''));
    }

    function renderFileSandboxEvidence(items) {
        items = items || [];
        if (!items.length) {
            return '<div class="pondsec-empty">No file, AV or sandbox verdict evidence was recorded for this incident.</div>';
        }
        function verdictBadge(value) {
            var text = String(value || 'unrecorded').toLowerCase();
            var cls = 'neutral';
            if (['malicious', 'malware', 'blocked', 'infected', 'eicar'].indexOf(text) !== -1 || text.indexOf('mal') !== -1) {
                cls = 'bad';
            } else if (['suspicious', 'risky', 'timeout', 'pending'].indexOf(text) !== -1) {
                cls = 'info';
            } else if (['clean', 'benign', 'allowed'].indexOf(text) !== -1) {
                cls = 'good';
            }
            return '<span class="pondsec-badge ' + cls + '">' + escapeHtml(value || 'unrecorded') + '</span>';
        }
        return items.map(function(item) {
            var verdict = item.sandbox_verdict || item.file_verdict || item.av_verdict || (item.suspicious_extension ? 'suspicious' : 'unrecorded');
            var hashes = [
                item.sha256 ? 'sha256 ' + item.sha256 : null,
                item.sha1 ? 'sha1 ' + item.sha1 : null,
                item.md5 ? 'md5 ' + item.md5 : null
            ].filter(hasValue);
            var findings = Array.isArray(item.sandbox_findings) ? item.sandbox_findings : [];
            return '<div class="pondsec-file-evidence">' +
                '<div class="pondsec-file-evidence-head">' +
                    verdictBadge(verdict) +
                    '<strong>' + escapeHtml(item.filename || item.threat_name || item.title || 'File verdict evidence') + '</strong>' +
                    '<span>' + escapeHtml(formatDate(item.timestamp)) + '</span>' +
                '</div>' +
                '<div class="pondsec-decision-grid">' +
                    '<div><span>Provider</span><strong>' + compactValue(item.provider_id || item.sandbox_source || item.detector_id) + '</strong></div>' +
                    '<div><span>Sandbox status</span><strong>' + compactValue(item.sandbox_status) + '</strong></div>' +
                    '<div><span>Sandbox confidence</span><strong>' + (hasValue(item.sandbox_confidence) ? escapeHtml(formatPercent(item.sandbox_confidence)) : '-') + '</strong></div>' +
                    '<div><span>Detection confidence</span><strong>' + escapeHtml(formatPercent(item.confidence || 0)) + '</strong></div>' +
                    '<div><span>Threat name</span><strong>' + compactValue(item.threat_name) + '</strong></div>' +
                    '<div><span>MIME type</span><strong>' + compactValue(item.mime_type) + '</strong></div>' +
                    '<div><span>File size</span><strong>' + compactValue(item.file_size) + '</strong></div>' +
                    '<div><span>Analysis ID</span><strong>' + compactValue(item.sandbox_analysis_id) + '</strong></div>' +
                '</div>' +
                '<div class="pondsec-file-evidence-extra">' +
                    '<span>Hashes</span>' + tokens(hashes, 'No file hashes recorded.') +
                    '<span>Findings</span>' + tokens(findings, item.safe_test_file ? 'Safe test marker recorded.' : 'No sandbox findings recorded.') +
                '</div>' +
            '</div>';
        }).join('');
    }

    function renderGraphLegend(graph) {
        var legend = (graph || {}).legend || {};
        $('#incident_graph_legend').html(Object.keys(legend).map(function(key) {
            return '<span class="pondsec-legend-item ' + className(key) + '"><i></i>' + escapeHtml(key) + '</span>';
        }).join(''));
    }

    function renderAttackGraph(graph) {
        graph = graph || {};
        var nodes = (graph.nodes || []).slice(0, 24);
        var edges = (graph.edges || []).slice(0, 60);
        if (!nodes.length) {
            return '<div class="pondsec-empty">No graph data recorded for this incident.</div>';
        }
        var nodeById = {};
        nodes.forEach(function(node) { nodeById[node.id] = node; });
        var columns = {
            external_actor: 0,
            source_host: 0,
            internal_network: 1,
            affected_host: 1,
            victim_host: 1,
            pivot_host: 2,
            behavior_model: 2,
            target_host: 2,
            external_target: 3,
            external_group: 3,
            response_target: 3,
            target: 2,
            response: 3
        };
        var buckets = [[], [], [], []];
        nodes.forEach(function(node) {
            var column = columns[node.type] === undefined ? 2 : columns[node.type];
            buckets[column].push(node);
        });
        var maxBucket = Math.max(1, buckets[0].length, buckets[1].length, buckets[2].length, buckets[3].length);
        var width = 980;
        var height = Math.max(300, maxBucket * 82 + 80);
        var xs = [92, 330, 620, 880];
        var positions = {};
        buckets.forEach(function(bucket, column) {
            var gap = height / (bucket.length + 1);
            bucket.forEach(function(node, index) {
                positions[node.id] = {x: xs[column], y: Math.round(gap * (index + 1))};
            });
        });
        var edgeHtml = edges.filter(function(edge) {
            return positions[edge.source] && positions[edge.target];
        }).map(function(edge, index) {
            var source = positions[edge.source];
            var target = positions[edge.target];
            var dx = Math.max(80, Math.abs(target.x - source.x) * 0.45);
            var path = 'M ' + source.x + ' ' + source.y + ' C ' + (source.x + dx) + ' ' + source.y + ', ' + (target.x - dx) + ' ' + target.y + ', ' + target.x + ' ' + target.y;
            var detailId = registerCaseDetail('Relationship', edge.kind || 'relationship', edge);
            var midX = Math.round((source.x + target.x) / 2);
            var midY = Math.round((source.y + target.y) / 2) - 7;
            return '<g class="pondsec-graph-edge-wrap pondsec-analysis-click" data-detail-id="' + escapeAttr(detailId) + '">' +
                '<path class="pondsec-graph-edge ' + className(edge.status) + ' kind-' + className(edge.kind) + '" d="' + escapeAttr(path) + '" marker-end="url(#pondsec_arrow)"></path>' +
                '<path class="pondsec-graph-hit" d="' + escapeAttr(path) + '"></path>' +
                '<text x="' + midX + '" y="' + midY + '">' + escapeHtml(shortLabel(edge.kind || edge.stage || 'related', 18)) + '</text>' +
            '</g>';
        }).join('');
        var nodeHtml = nodes.map(function(node) {
            var pos = positions[node.id] || {x: 40, y: 40};
            var detailId = registerCaseDetail('Node', node.label || node.id, node);
            return '<g class="pondsec-graph-node pondsec-analysis-click ' + className(node.status) + ' type-' + className(node.type) + '" data-detail-id="' + escapeAttr(detailId) + '" transform="translate(' + pos.x + ',' + pos.y + ')">' +
                '<circle r="25"></circle>' +
                '<text text-anchor="middle" y="-34">' + escapeHtml(shortLabel(node.type || 'node', 18)) + '</text>' +
                '<text text-anchor="middle" y="5">' + escapeHtml(shortLabel(node.label || node.id, 20)) + '</text>' +
            '</g>';
        }).join('');
        return '<svg class="pondsec-attack-svg" viewBox="0 0 ' + width + ' ' + height + '" role="img" aria-label="Incident attack graph">' +
            '<defs><marker id="pondsec_arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 Z"></path></marker></defs>' +
            edgeHtml + nodeHtml +
        '</svg>';
    }

    function renderAttackStages(stages) {
        stages = (stages || []).filter(function(stage) { return stage.status !== 'not_seen'; });
        if (!stages.length) {
            return '<div class="pondsec-empty">No attack stage analysis recorded.</div>';
        }
        return stages.map(function(stage) {
            var detailId = registerCaseDetail('Attack stage', stageLabel(stage.stage), stage);
            return '<button type="button" class="pondsec-stage-item pondsec-analysis-click ' + className(stage.status) + '" data-detail-id="' + escapeAttr(detailId) + '">' +
                '<span>' + escapeHtml(stageLabel(stage.stage)) + '</span>' +
                '<strong>' + escapeHtml(stage.status || 'not_seen') + '</strong>' +
                '<em>' + formatPercent(stage.confidence || 0) + ' · ' + formatNumber(stage.detection_count || 0) + '</em>' +
            '</button>';
        }).join('');
    }

    function renderVisualTimeline(timeline) {
        timeline = timeline || [];
        if (!timeline.length) {
            return '<div class="pondsec-empty">No detection timeline recorded.</div>';
        }
        return timeline.map(function(item) {
            var detailId = registerCaseDetail('Timeline event', item.title || item.detector_id || item.stage, item);
            return '<button type="button" class="pondsec-timeline-item pondsec-analysis-click ' + className(item.status || item.stage_status) + '" data-detail-id="' + escapeAttr(detailId) + '">' +
                '<span>' + escapeHtml(formatDate(item.first_seen || item.timestamp)) + (item.last_seen && item.last_seen !== item.first_seen ? ' - ' + escapeHtml(formatDate(item.last_seen)) : '') + '</span>' +
                '<strong>' + escapeHtml(item.title || item.detector_id || 'Detection') + '</strong>' +
                '<p>' + escapeHtml(item.summary || '-') + '</p>' +
                '<em>' + escapeHtml(stageLabel(item.stage)) + ' · ' + escapeHtml(item.edge_kind || item.kind || 'event') + ' · risk +' + escapeHtml(item.risk_delta || 0) + ' · ' + formatNumber(item.count || 1) + ' event(s)</em>' +
            '</button>';
        }).join('');
    }

    function primaryColumns(kind) {
        if (kind === 'incidents') {
            return [
                {label: 'Status', render: function(row) { return badge(row.status); }},
                {label: 'Risk', render: function(row) { return riskCell(row.risk_score); }},
                {label: 'Source', render: function(row) { return mono(row.source_ip); }},
                {label: 'Destination', render: function(row) { return mono(row.destination_ip); }},
                {label: 'Category', render: function(row) { return compactValue(row.category); }},
                {label: 'Incident', render: function(row) { return '<button class="pondsec-link-button pondsec-open-incident" data-id="' + encodeURIComponent(row.incident_id || '') + '"><strong>' + escapeHtml(row.title || row.incident_id) + '</strong><span>Open case view</span></button>'; }},
                {label: 'Updated', render: function(row) { return formatDate(row.updated_at || row.created_at); }},
                {label: 'Action', render: incidentActions}
            ];
        }
        if (kind === 'detections') {
            return [
                {label: 'Detector', render: function(row) { return compactValue(row.detector_id); }},
                {label: 'Category', render: function(row) { return compactValue(row.category); }},
                {label: 'Severity', render: function(row) { return formatNumber(row.severity); }},
                {label: 'Confidence', render: function(row) { return formatPercent(row.confidence); }},
                {label: 'Source', render: function(row) { return mono(row.source_ip); }},
                {label: 'Destination', render: function(row) { return mono(row.destination_ip); }},
                {label: 'Time', render: function(row) { return formatDate(row.timestamp); }}
            ];
        }
        if (kind === 'hosts') {
            return [
                {label: 'Host', render: hostSummaryCell},
                {label: 'Peer group', render: function(row) { return badge(row.peer_group || 'unknown') + '<span class="pondsec-subtle">Confidence ' + escapeHtml(formatPercent(row.peer_group_confidence || 0)) + '</span>'; }},
                {label: 'Protection', render: function(row) { return hostProtection(row); }},
                {label: 'Risk', render: function(row) { return riskCell(row.risk_score); }},
                {label: 'Open incidents', render: function(row) { return formatNumber(row.open_incidents); }},
                {label: 'Interface', render: function(row) { return compactValue(row.interface); }},
                {label: 'Last seen', render: function(row) { return formatDate(row.last_seen); }}
            ];
        }
        if (kind === 'blocklist') {
            return [
                {label: 'Status', render: function(row) { return badge(row.status); }},
                {label: 'Source', render: function(row) { return mono(row.source_ip); }},
                {label: 'Risk', render: function(row) { return riskCell(row.risk_score); }},
                {label: 'Confidence', render: function(row) { return formatPercent(row.confidence); }},
                {label: 'Expires', render: function(row) { return formatDate(row.expires_at); }},
                {label: 'Reason', render: function(row) { return compactValue(row.reason); }},
                {label: 'Action', render: blockActions}
            ];
        }
        if (kind === 'allowlist') {
            return [
                {label: 'Trusted value', render: function(row) { return mono(row.value || row.network || row.source_ip); }},
                {label: 'Reason', render: function(row) { return compactValue(row.reason); }},
                {label: 'Expires', render: function(row) { return formatDate(row.expires_at); }},
                {label: 'Created by', render: function(row) { return compactValue(row.created_by); }},
                {label: 'Created', render: function(row) { return formatDate(row.created_at); }}
            ];
        }
        if (kind === 'models') {
            return [
                {label: 'Status', render: function(row) { return badge(row.status || (row.active ? 'active' : 'catalog')); }},
                {label: 'Model', render: function(row) { return '<strong>' + escapeHtml(row.model_id) + '</strong>'; }},
                {label: 'Provider', render: function(row) { return compactValue(row.provider); }},
                {label: 'Type', render: function(row) { return compactValue(row.model_type); }},
                {label: 'Trained on', render: function(row) { return compactValue(row.trained_on); }},
                {label: 'License', render: function(row) { return compactValue(row.license); }}
            ];
        }
        if (kind === 'interfaces') {
            return [
                {label: 'Interface', render: function(row) { return mono(row.name); }},
                {label: 'Configured', render: function(row) { return badge(row.configured ? 'selected' : 'available'); }}
            ];
        }
        if (kind === 'logs') {
            return [
                {label: 'Time', render: function(row) { return formatDate(row.timestamp || row.time); }},
                {label: 'Level', render: function(row) { return badge(row.level || row.severity || 'info'); }},
                {label: 'Component', render: function(row) { return compactValue(row.component || row.event); }},
                {label: 'Message', render: function(row) { return compactValue(row.message || row.msg || row.error); }}
            ];
        }
        return Object.keys(rows[0] || {}).slice(0, 7).map(function(key) {
            return {label: humanKey(key), render: function(row) { return compactValue(row[key]); }};
        });
    }

    function mono(value) {
        return hasValue(value) ? '<span class="pondsec-mono">' + escapeHtml(value) + '</span>' : '-';
    }

    function hostSummaryCell(row) {
        var title = hostIdentityTitle(row);
        var details = [];
        if (hasValue(row.primary_ip || row.ip) && title !== (row.primary_ip || row.ip)) {
            details.push(row.primary_ip || row.ip);
        }
        if (hasValue(row.mac)) {
            details.push(row.mac);
        }
        if (hasValue(row.os_name)) {
            details.push(row.os_name);
        }
        return '<button class="pondsec-link-button" type="button"><strong>' + escapeHtml(title) + '</strong><span>' + escapeHtml(details.join(' · ') || row.entity_id || 'Open entity resolution') + '</span></button>';
    }

    function hostProtection(row) {
        var badges = [];
        if (row.block_status && row.block_status !== 'none') {
            badges.push(badge(row.block_status === 'active' ? 'isolated' : row.block_status));
        }
        if (row.allowlist_status && row.allowlist_status !== 'none') {
            badges.push(badge('allowlisted'));
        }
        return badges.length ? badges.join(' ') : badge('normal');
    }

    function incidentActions(row) {
        var id = encodeURIComponent(row.incident_id || '');
        var buttons = '';
        if (row.status === 'open') {
            buttons += '<button class="btn btn-xs btn-default pondsec-row-action" data-action="close-incident" data-id="' + id + '">Close</button>';
            buttons += '<button class="btn btn-xs btn-primary pondsec-row-action" data-action="propose-block" data-id="' + id + '">Propose block</button>';
            buttons += '<button class="btn btn-xs btn-default pondsec-row-action" data-action="propose-sinkhole" data-id="' + id + '">DNS sinkhole</button>';
            buttons += '<button class="btn btn-xs btn-default pondsec-row-action" data-action="archive-incident" data-id="' + id + '">Archive</button>';
        } else {
            buttons += '<button class="btn btn-xs btn-default pondsec-row-action" data-action="reopen-incident" data-id="' + id + '">Reopen</button>';
        }
        buttons += '<button class="btn btn-xs btn-danger pondsec-row-action" data-action="delete-incident" data-id="' + id + '">Delete</button>';
        return '<div class="pondsec-actions">' + buttons + '</div>';
    }

    function blockActions(row) {
        var id = encodeURIComponent(row.block_id || '');
        var buttons = '';
        if (row.status === 'proposed') {
            buttons += '<button class="btn btn-xs btn-primary pondsec-row-action" data-action="activate-block" data-id="' + id + '">Activate</button>';
        }
        if (row.status === 'active' || row.status === 'proposed') {
            buttons += '<button class="btn btn-xs btn-default pondsec-row-action" data-action="remove-block" data-id="' + id + '">Remove</button>';
        }
        return buttons ? '<div class="pondsec-actions">' + buttons + '</div>' : '-';
    }

    function actionEndpoint(action, id) {
        if (action === 'close-incident') {
            return '/api/pondsecndr/incidents/close/' + id;
        }
        if (action === 'reopen-incident') {
            return '/api/pondsecndr/incidents/reopen/' + id;
        }
        if (action === 'archive-incident') {
            return '/api/pondsecndr/incidents/archive/' + id;
        }
        if (action === 'delete-incident') {
            return '/api/pondsecndr/incidents/delete/' + id;
        }
        if (action === 'false-positive') {
            return '/api/pondsecndr/incidents/falsePositive/' + id;
        }
        if (action === 'propose-block') {
            return '/api/pondsecndr/blocklist/propose/' + id;
        }
        if (action === 'manual-block') {
            return '/api/pondsecndr/blocklist/manualIncident/' + id;
        }
        if (action === 'propose-sinkhole') {
            return '/api/pondsecndr/sinkhole/propose/' + id;
        }
        if (action === 'activate-block') {
            return '/api/pondsecndr/blocklist/activate/' + id;
        }
        if (action === 'remove-block') {
            return '/api/pondsecndr/blocklist/remove/' + id;
        }
        if (action === 'release-case') {
            return '/api/pondsecndr/incidents/release/' + id;
        }
        if (action === 'merge-case' || action === 'link-case' || action === 'keep-separate-case') {
            var parts = String(id || '').split('|');
            if (parts.length !== 2) {
                return null;
            }
            if (action === 'merge-case') {
                return '/api/pondsecndr/incidents/merge/' + encodeURIComponent(parts[0]) + '/' + encodeURIComponent(parts[1]);
            }
            if (action === 'link-case') {
                return '/api/pondsecndr/incidents/link/' + encodeURIComponent(parts[0]) + '/' + encodeURIComponent(parts[1]);
            }
            return '/api/pondsecndr/incidents/keepSeparate/' + encodeURIComponent(parts[0]) + '/' + encodeURIComponent(parts[1]);
        }
        return null;
    }

    function runAction(action, id) {
        if (action === 'delete-incident' && !window.confirm(t('Delete this incident? Active responses must be released first.'))) {
            return;
        }
        if (action === 'manual-block' && !window.confirm(t('Manually block this incident response target now?'))) {
            return;
        }
        if (action === 'propose-sinkhole' && !window.confirm(t('Create a DNS sinkhole proposal from this incident evidence?'))) {
            return;
        }
        var url = actionEndpoint(action, id);
        if (!url) {
            return;
        }
        var plainId = decodeId(id);
        ajaxCall(url, {}, function(data) {
            $('#pondsec_action_result').html(renderActionResult(data));
            loadRows();
            if (plainId && currentIncidentId === plainId) {
                if (action === 'delete-incident' && data && data.status === 'ok') {
                    $('#incident_detail_panel').removeClass('open');
                    currentIncidentId = null;
                } else {
                    openIncidentDetail(id);
                }
            }
        });
    }

    function renderActionResult(data) {
        if (!data) {
            return '';
        }
        var state = data.status || (data.item && data.item.status) || 'ok';
        var message = data.message || data.reason || data.block_id || data.sinkhole_id || data.domain || (data.item && (data.item.block_id || data.item.sinkhole_id || data.item.source_ip || data.item.domain)) || t('Action completed');
        if (data.raw_excerpt) {
            message += ': ' + data.raw_excerpt;
        }
        return '<div class="pondsec-notice ' + statusClass(state) + '">' + badge(state) + '<span>' + escapeHtml(message) + '</span></div>';
    }

    function renderStats(kind) {
        var total = rows.length;
        var open = rows.filter(function(row) { return row.status === 'open'; }).length;
        var active = rows.filter(function(row) { return row.status === 'active'; }).length;
        var highRisk = rows.filter(function(row) { return Number(row.risk_score) >= 70; }).length;
        var configured = rows.filter(function(row) { return row.configured; }).length;
        var stats = [
            {label: 'Records', value: total},
            {label: 'Open', value: open},
            {label: 'Active', value: active},
            {label: 'High risk', value: highRisk}
        ];
        if (kind === 'incidents' && summary.open !== undefined) {
            stats = [
                {label: 'Shown', value: total},
                {label: 'Open', value: summary.open || 0},
                {label: 'Active', value: summary.active || 0},
                {label: 'High risk', value: summary.high_risk || 0}
            ];
        }
        if (kind === 'interfaces') {
            stats = [{label: 'Interfaces', value: total}, {label: 'Selected', value: configured}];
        }
        $('#pondsec_stats').html(stats.map(function(item) {
            return '<div class="pondsec-stat"><span>' + escapeHtml(item.label) + '</span><strong>' + formatNumber(item.value) + '</strong></div>';
        }).join(''));
    }

    function rowSearchText(row) {
        return Object.keys(row).map(function(key) {
            var value = row[key];
            if (typeof value === 'object' && value !== null) {
                return JSON.stringify(value);
            }
            return value;
        }).join(' ').toLowerCase();
    }

    function rebuildFilters() {
        var statuses = {};
        var categories = {};
        allRows.forEach(function(row) {
            if (hasValue(row.status)) {
                statuses[row.status] = true;
            }
            if (hasValue(row.category)) {
                categories[row.category] = true;
            }
            if (hasValue(row.block_status) && row.block_status !== 'none') {
                statuses[row.block_status] = true;
            }
            if (hasValue(row.allowlist_status) && row.allowlist_status !== 'none') {
                statuses[row.allowlist_status] = true;
            }
        });
        function options(values, allLabel) {
            return '<option value="">' + escapeHtml(allLabel) + '</option>' + Object.keys(values).sort().map(function(value) {
                return '<option value="' + escapeHtml(value) + '">' + escapeHtml(value) + '</option>';
            }).join('');
        }
        $('#pondsec_filter_status').html(options(statuses, 'All statuses'));
        $('#pondsec_filter_category').html(options(categories, 'All categories'));
        $('#pondsec_filter_category').closest('.pondsec-filter-field').toggle(Object.keys(categories).length > 0);
    }

    function applyFilters() {
        var query = String($('#pondsec_filter_search').val() || '').toLowerCase().trim();
        var status = $('#pondsec_filter_status').val();
        var category = $('#pondsec_filter_category').val();
        rows = allRows.filter(function(row) {
            if (query && rowSearchText(row).indexOf(query) === -1) {
                return false;
            }
            if (status) {
                var values = [row.status, row.block_status, row.allowlist_status];
                if (values.indexOf(status) === -1) {
                    return false;
                }
            }
            if (category && row.category !== category) {
                return false;
            }
            return true;
        });
        renderRows();
    }

    function renderRows() {
        var kind = pageKind();
        renderStats(kind);
        if (!rows.length) {
            $('#pondsec_table').html('<tbody><tr><td class="pondsec-empty">No records available.</td></tr></tbody>');
            return;
        }
        var columns = primaryColumns(kind);
        var header = '<thead><tr>' + columns.map(function(column) {
            return '<th>' + escapeHtml(column.label) + '</th>';
        }).join('') + '</tr></thead>';
        var body = '<tbody>' + rows.map(function(row) {
            var attrs = '';
            if (kind === 'incidents') {
                attrs = ' class="pondsec-clickable-row" data-id="' + encodeURIComponent(row.incident_id || '') + '"';
            } else if (kind === 'hosts') {
                attrs = ' class="pondsec-clickable-row" data-id="' + encodeURIComponent(row.entity_id || row.primary_ip || row.ip || row.mac || row.hostname || '') + '"';
            }
            return '<tr' + attrs + '>' + columns.map(function(column) {
                return '<td>' + column.render(row) + '</td>';
            }).join('') + '</tr>';
        }).join('') + '</tbody>';
        $('#pondsec_table').html(header + body);
    }

    function hostIdentityTitle(host) {
        return host.hostname || host.primary_ip || host.ip || host.mac || host.entity_id || 'Host';
    }

    function renderHostRecordRows(records) {
        records = records || [];
        if (!records.length) {
            return '<div class="pondsec-empty">No IP-oriented host records are linked to this entity.</div>';
        }
        return '<table class="pondsec-mini-table"><thead><tr><th>IP</th><th>Risk</th><th>Open</th><th>Interface</th><th>Baseline</th><th>Protection</th><th>Last seen</th></tr></thead><tbody>' +
            records.map(function(record) {
                return '<tr>' +
                    '<td>' + mono(record.ip) + '</td>' +
                    '<td>' + riskCell(record.risk_score) + '</td>' +
                    '<td>' + formatNumber(record.open_incidents || 0) + '</td>' +
                    '<td>' + compactValue(record.interface) + '</td>' +
                    '<td>' + compactValue(record.learning_status || record.baseline_deviation) + '</td>' +
                    '<td>' + hostProtection(record) + '</td>' +
                    '<td>' + formatDate(record.last_seen) + '</td>' +
                '</tr>';
            }).join('') +
        '</tbody></table>';
    }

    function renderEntityHistory(history) {
        history = history || [];
        if (!history.length) {
            return '<div class="pondsec-empty">No entity history recorded yet.</div>';
        }
        return history.slice(-12).reverse().map(function(item) {
            return '<div class="pondsec-history-item">' +
                '<strong>' + escapeHtml(item.source || item.event_type || 'observation') + '</strong>' +
                '<span>' + escapeHtml(formatDate(item.timestamp || item.last_seen || item.first_seen)) + '</span>' +
                '<p>' + compactValue(item.summary || item.hostname || item.ip || item.mac || item) + '</p>' +
            '</div>';
        }).join('');
    }

    function renderHostDetail(host) {
        host = host || {};
        $('#host_detail_title').text(hostIdentityTitle(host));
        $('#host_detail_meta').html(
            badge(host.peer_group || 'unknown') +
            badge(host.criticality || 'normal') +
            '<span class="pondsec-case-meta">Confidence ' + escapeHtml(formatPercent(host.confidence || 0)) + '</span>' +
            '<span class="pondsec-case-meta">Peer ' + escapeHtml(formatPercent(host.peer_group_confidence || 0)) + '</span>'
        );
        $('#host_identity_grid').html([
            ['Entity ID', mono(host.entity_id)],
            ['Primary IP', mono(host.primary_ip || host.ip)],
            ['Hostname', compactValue(host.hostname)],
            ['MAC', mono(host.mac)],
            ['OS', compactValue(host.os_name)],
            ['Interface', compactValue(host.interface)],
            ['VLAN', compactValue(host.vlan)],
            ['Zone', compactValue(host.zone)],
            ['First seen', formatDate(host.first_seen)],
            ['Last seen', formatDate(host.last_seen)]
        ].map(function(row) {
            return '<div class="pondsec-case-kv"><span>' + escapeHtml(row[0]) + '</span><strong>' + row[1] + '</strong></div>';
        }).join(''));
        $('#host_ip_sets').html(
            '<div class="pondsec-case-kv"><span>Current IPs</span><strong>' + tokens(host.current_ips, 'No current IPs recorded.') + '</strong></div>' +
            '<div class="pondsec-case-kv"><span>Previous IPs</span><strong>' + tokens(host.previous_ips, 'No previous IPs recorded.') + '</strong></div>'
        );
        $('#host_entity_traits').html(
            '<div class="pondsec-case-kv"><span>Roles</span><strong>' + tokens(host.roles, 'No roles recorded.') + '</strong></div>' +
            '<div class="pondsec-case-kv"><span>Known services</span><strong>' + tokens(host.known_services, 'No services recorded.') + '</strong></div>' +
            '<div class="pondsec-case-kv"><span>Tags</span><strong>' + tokens(host.tags, 'No tags recorded.') + '</strong></div>' +
            '<div class="pondsec-case-kv"><span>Peer group source</span><strong>' + compactValue(host.peer_group_source) + '</strong></div>'
        );
        $('#host_records').html(renderHostRecordRows(host.host_records || []));
        $('#host_history').html(renderEntityHistory(host.history || []));
        $('#host_detail_panel').scrollTop(0).addClass('open');
    }

    function openHostDetail(id) {
        var plainId = decodeId(id);
        var local = allRows.find(function(row) {
            var values = [row.entity_id, row.primary_ip, row.ip, row.mac, row.hostname].concat(row.current_ips || [], row.previous_ips || []);
            return values.some(function(value) { return hasValue(value) && String(value) === plainId; });
        });
        if (local) {
            renderHostDetail(local);
            return;
        }
        if (!plainId) {
            return;
        }
        ajaxGet('/api/pondsecndr/hosts/get/' + encodeURIComponent(plainId), {}, function(data) {
            if (data.status !== 'ok') {
                $('#pondsec_action_result').html(renderActionResult(data));
                return;
            }
            renderHostDetail(data.item || {});
        });
    }

    function renderIncidentDetail(data) {
        var incident = data.item || {};
        var analysis = data.analysis || {};
        var caseSummary = analysis.case_summary || {};
        var story = analysis.host_story || {};
        var timeline = analysis.visual_timeline || analysis.timeline || [];
        var targets = story.affected_targets || [];
        var guidance = analysis.administrator_guidance || [];
        var features = analysis.notable_features || [];
        var riskFactors = analysis.risk_factors || [];
        var narrative = analysis.case_narrative || {};
        var relatedCases = analysis.related_cases || [];
        var threatIntel = analysis.threat_intelligence || {};
        var responseDecisions = analysis.response_decisions || [];
        var promotion = analysis.promotion || {};
        resetCaseDetails();
        currentIncidentId = incident.incident_id || null;
        $('#incident_detail_title').text(incident.title || incident.incident_id || 'Incident');
        $('#incident_detail_meta').html(
            badge(incident.status) + badge(story.attack_stage || incident.category || 'unknown') +
            '<span class="pondsec-case-meta">Source ' + escapeHtml(story.source_ip || '-') + '</span>' +
            '<span class="pondsec-case-meta">Risk ' + escapeHtml(incident.risk_score || '-') + '</span>' +
            '<span class="pondsec-case-meta">Confidence ' + escapeHtml(formatPercent(incident.confidence)) + '</span>' +
            '<span class="pondsec-case-meta">Window ' + escapeHtml(formatDate(story.first_seen)) + ' - ' + escapeHtml(formatDate(story.last_seen)) + '</span>'
        );
        renderCaseActions(incident, caseSummary);
        renderNarrative(narrative);
        renderCaseSummary(caseSummary, incident);
        renderCertainty(caseSummary);
        $('#incident_story').html([
            ['Risk score', riskCell(incident.risk_score)],
            ['Detections', formatNumber(story.detection_count || 0)],
            ['Events', formatNumber(story.event_count || 0)],
            ['Suppressed duplicates', formatNumber(story.suppressed_count || 0)],
            ['Primary destination', mono(story.destination_ip)]
        ].map(function(row) {
            return '<div class="pondsec-case-kv"><span>' + escapeHtml(row[0]) + '</span><strong>' + row[1] + '</strong></div>';
        }).join(''));
        $('#incident_targets').html(targets.length ? targets.map(function(target) {
            return '<span class="pondsec-token">' + escapeHtml(target) + '</span>';
        }).join('') : '<span class="pondsec-empty-inline">No target list recorded.</span>');
        $('#incident_file_sandbox_evidence').html(renderFileSandboxEvidence(analysis.file_sandbox_evidence || []));
        $('#incident_attack_graph').html(renderAttackGraph(analysis.attack_graph || {}));
        renderGraphLegend(analysis.attack_graph || {});
        $('#incident_attack_stages').html(renderAttackStages(analysis.attack_stages || []));
        $('#incident_timeline').html(renderVisualTimeline(timeline));
        renderThreatIntel(threatIntel);
        renderRelatedCases(relatedCases, incident.incident_id);
        $('#incident_guidance').html(guidance.length ? guidance.map(function(item) {
            return '<li>' + escapeHtml(item) + '</li>';
        }).join('') : '<li>No guidance recorded.</li>');
        $('#incident_features').html(features.length ? features.slice(0, 12).map(function(item) {
            return '<div class="pondsec-feature"><span>' + escapeHtml(item.name || 'feature') + '</span><strong>' + compactValue(item.value) + '</strong></div>';
        }).join('') : '<div class="pondsec-empty">No notable feature list recorded.</div>');
        $('#incident_risk_factors').html(riskFactors.length ? riskFactors.map(function(item) {
            return '<div class="pondsec-feature"><span>' + escapeHtml(item.name || item.factor || 'risk') + '</span><strong>' + compactValue(item.value || item.score || item.weight || item) + '</strong></div>';
        }).join('') : '<div class="pondsec-empty">No risk factors recorded.</div>');
        $('#incident_promotion_decision').html(renderPromotionDecision(promotion));
        $('#incident_response_decisions').html(renderResponseDecisions(responseDecisions));
        renderCaseDetail({type: 'Case summary', title: 'Case overview', item: caseSummary});
        $('#incident_detail_panel').scrollTop(0).addClass('open');
        activateCaseTab('overview');
    }

    function openIncidentDetail(id) {
        if (!id) {
            return;
        }
        ajaxGet('/api/pondsecndr/incidents/get/' + id, {}, function(data) {
            if (data.status !== 'ok') {
                $('#pondsec_action_result').html(renderActionResult(data));
                return;
            }
            renderIncidentDetail(data);
        });
    }

    function loadRows() {
        ajaxGet(endpoint, {}, function(data) {
            allRows = data.items || data.records || data.events || [];
            summary = data.summary || {};
            $('#pondsec_page_message').text(data.message || '');
            rebuildFilters();
            applyFilters();
        });
    }

    $(document).on('input change', '#pondsec_filter_search, #pondsec_filter_status, #pondsec_filter_category', applyFilters);
    $('#pondsec_filter_reset').on('click', function() {
        $('#pondsec_filter_search').val('');
        $('#pondsec_filter_status').val('');
        $('#pondsec_filter_category').val('');
        applyFilters();
    });

    $(document).on('click', '.pondsec-row-action', function(event) {
        event.stopPropagation();
        runAction($(this).data('action'), $(this).data('id'));
    });
    $(document).on('click', '.pondsec-open-incident, .pondsec-clickable-row', function(event) {
        if ($(event.target).closest('.pondsec-row-action').length) {
            return;
        }
        if (pageKind() === 'hosts') {
            openHostDetail($(this).data('id'));
        } else {
            openIncidentDetail($(this).data('id'));
        }
    });
    $(document).on('click', '.pondsec-analysis-click', function(event) {
        event.stopPropagation();
        renderCaseDetail(caseDetailLookup[$(this).data('detail-id')]);
    });
    function closeIncidentDetail() {
        $('#incident_detail_panel').removeClass('open');
        currentIncidentId = null;
    }
    function closeHostDetail() {
        $('#host_detail_panel').removeClass('open');
    }
    $('#incident_detail_close, #incident_detail_back').on('click', function() {
        closeIncidentDetail();
    });
    $(document).on('click', '#incident_detail_inline_close', function() {
        closeIncidentDetail();
    });
    $('#host_detail_close, #host_detail_back').on('click', function() {
        closeHostDetail();
    });
    $(document).on('keydown', function(event) {
        if (event.key === 'Escape') {
            closeIncidentDetail();
            closeHostDetail();
        }
    });
    function activateCaseTab(tab) {
        tab = tab || 'overview';
        $('.pondsec-case-tab').toggleClass('active', false);
        $('.pondsec-case-tab[data-case-tab="' + tab + '"]').toggleClass('active', true);
        $('[data-case-tab-panel]').hide();
        $('[data-case-tab-panel="' + tab + '"]').show();
    }
    $(document).on('click', '.pondsec-case-tab', function() {
        activateCaseTab($(this).data('case-tab'));
    });

    observeTranslations();
    translateVisibleUi();
    ajaxGet('/api/pondsecndr/settings/get', {}, function(data) {
        var selected = extractLanguage(data);
        if (selected) {
            setLanguage(selected);
        }
    });
    loadRows();
});
</script>

<style>
.pondsec-list-page {
    background: #151d26;
    color: #c8d2dc;
    min-height: 720px;
    padding: 18px;
}
.pondsec-list-page * {
    box-sizing: border-box;
}
.pondsec-pagehead {
    align-items: flex-end;
    background: #202a36;
    border: 1px solid #2a3544;
    border-radius: 6px;
    display: flex;
    gap: 18px;
    justify-content: space-between;
    margin-bottom: 14px;
    padding: 18px;
}
.pondsec-pagehead h2 {
    color: #f5f8fb;
    font-size: 24px;
    font-weight: 600;
    margin: 0;
}
.pondsec-pagehead p {
    color: #8f9dac;
    margin: 7px 0 0;
}
.pondsec-stat-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
}
.pondsec-stat {
    background: #1b2430;
    border: 1px solid #2a3544;
    border-radius: 6px;
    min-width: 116px;
    padding: 10px 12px;
}
.pondsec-stat span {
    color: #8f9dac;
    display: block;
    font-size: 12px;
    text-transform: uppercase;
}
.pondsec-stat strong {
    color: #f4f8fc;
    display: block;
    font-size: 22px;
    margin-top: 4px;
}
.pondsec-tablebox {
    background: #202a36;
    border: 1px solid #2a3544;
    border-radius: 6px;
    overflow: hidden;
}
.pondsec-filterbar {
    align-items: end;
    background: #202a36;
    border: 1px solid #2a3544;
    border-radius: 6px;
    display: grid;
    gap: 12px;
    grid-template-columns: minmax(220px, 1fr) 180px 180px auto;
    margin-bottom: 14px;
    padding: 12px;
}
.pondsec-filter-field label {
    color: #8f9dac;
    display: block;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
}
.pondsec-filter-field input,
.pondsec-filter-field select {
    background: #151d26;
    border: 1px solid #334153;
    border-radius: 5px;
    color: #e5edf5;
    height: 34px;
    padding: 6px 8px;
    width: 100%;
}
.pondsec-table {
    border-collapse: collapse;
    margin: 0;
    width: 100%;
}
.pondsec-table th,
.pondsec-table td {
    border-bottom: 1px solid #2b3746;
    color: #c8d2dc;
    padding: 12px 14px;
    vertical-align: middle;
}
.pondsec-table th {
    background: #1b2430;
    color: #8f9dac;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
}
.pondsec-table tbody tr:hover td {
    background: #24303e;
}
.pondsec-mono {
    color: #dbe6f0;
    font-family: Menlo, Monaco, Consolas, monospace;
}
.pondsec-badge {
    border: 1px solid #3a4654;
    border-radius: 6px;
    color: #d9e3ec;
    display: inline-block;
    font-size: 11px;
    font-weight: 700;
    line-height: 1;
    padding: 6px 8px;
    text-transform: uppercase;
}
.pondsec-badge.good {
    background: rgba(76, 201, 112, 0.13);
    border-color: rgba(76, 201, 112, 0.4);
    color: #79df8f;
}
.pondsec-badge.info {
    background: rgba(73, 166, 255, 0.13);
    border-color: rgba(73, 166, 255, 0.4);
    color: #65b7ff;
}
.pondsec-badge.bad {
    background: rgba(246, 86, 97, 0.13);
    border-color: rgba(246, 86, 97, 0.45);
    color: #ff7a83;
}
.pondsec-badge.neutral {
    background: #263241;
    color: #b8c4cf;
}
.pondsec-risk {
    background: #111821;
    border-radius: 6px;
    display: inline-block;
    height: 7px;
    margin-right: 9px;
    overflow: hidden;
    vertical-align: middle;
    width: 112px;
}
.pondsec-risk span {
    background: linear-gradient(90deg, #49a6ff, #f2a84a, #f15f6b);
    display: block;
    height: 100%;
}
.pondsec-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
}
.pondsec-inline-close {
    margin-right: 12px;
}
.pondsec-actions .btn {
    border-radius: 5px;
}
.pondsec-clickable-row {
    cursor: pointer;
}
.pondsec-link-button {
    background: transparent;
    border: 0;
    color: #e7eef7;
    padding: 0;
    text-align: left;
}
.pondsec-link-button span {
    color: #65b7ff;
    display: block;
    font-size: 12px;
    margin-top: 3px;
}
.pondsec-subtle {
    color: #8f9dac;
    display: block;
    font-size: 12px;
    margin-top: 5px;
}
.pondsec-empty {
    color: #8f9dac;
    padding: 18px;
}
.pondsec-empty-inline {
    color: #8f9dac;
}
.pondsec-notice {
    align-items: center;
    background: #202a36;
    border: 1px solid #2a3544;
    border-radius: 6px;
    display: flex;
    gap: 10px;
    margin-bottom: 14px;
    padding: 11px 12px;
}
.pondsec-notice span:last-child {
    color: #d9e3ec;
}
.pondsec-case-panel {
    background: #151d26;
    border-left: 0;
    bottom: 0;
    box-shadow: 0 0 44px rgba(0, 0, 0, 0.48);
    left: 0;
    max-width: none;
    overscroll-behavior: contain;
    overflow-y: auto;
    padding: 24px 34px 34px;
    position: fixed;
    right: 0;
    top: 96px;
    transform: translateX(105%);
    transition: transform 0.22s ease;
    width: 100vw;
    z-index: 9999;
}
.pondsec-case-panel.open {
    transform: translateX(0);
}
.pondsec-case-head {
    align-items: flex-start;
    background: #151d26;
    display: flex;
    gap: 16px;
    justify-content: space-between;
    margin-bottom: 14px;
    padding: 4px 0 12px;
    position: sticky;
    top: 0;
    z-index: 20;
}
.pondsec-case-head-main {
    flex: 1 1 auto;
    min-width: 0;
}
.pondsec-case-head-controls {
    align-items: center;
    background: #151d26;
    display: flex;
    flex: 0 0 auto;
    gap: 10px;
    justify-content: flex-end;
    padding-top: 0;
    position: sticky;
    right: 0;
    top: 0;
    z-index: 25;
}
.pondsec-panel-back,
.pondsec-panel-close {
    box-shadow: 0 8px 22px rgba(0, 0, 0, 0.22);
}
.pondsec-panel-close {
    align-items: center;
    background: #202a36;
    border: 1px solid #506174;
    border-radius: 6px;
    color: #f4f8fc;
    display: inline-flex;
    flex: 0 0 auto;
    height: 42px;
    justify-content: center;
    min-width: 42px;
    width: 42px;
}
.pondsec-panel-back {
    align-items: center;
    background: #202a36;
    border: 1px solid #506174;
    border-radius: 6px;
    color: #f4f8fc;
    display: inline-flex;
    gap: 8px;
    height: 42px;
    justify-content: center;
    padding: 0 13px;
    white-space: nowrap;
}
.pondsec-panel-back:hover,
.pondsec-panel-back:focus,
.pondsec-panel-close:hover,
.pondsec-panel-close:focus {
    background: #2a3544;
    border-color: #65b7ff;
    color: #ffffff;
}
.pondsec-panel-close i {
    font-size: 16px;
    line-height: 1;
}
.pondsec-panel-back i {
    font-size: 14px;
}
.pondsec-case-head h3 {
    color: #f5f8fb;
    font-size: 22px;
    margin: 0 0 10px;
}
.pondsec-case-actions {
    background: #1b2430;
    border: 1px solid #2a3544;
    border-radius: 6px;
    margin-bottom: 12px;
    padding: 10px;
}
.pondsec-case-tabs {
    align-items: center;
    border-bottom: 1px solid #2a3544;
    display: flex;
    gap: 8px;
    margin: 0 0 14px;
    overflow-x: auto;
    padding-bottom: 10px;
}
.pondsec-case-tab {
    background: transparent;
    border: 1px solid transparent;
    border-radius: 6px;
    color: #9fafbf;
    font-weight: 700;
    padding: 9px 12px;
    white-space: nowrap;
}
.pondsec-case-tab:hover {
    background: #1b2430;
    color: #e7eef7;
}
.pondsec-case-tab.active {
    background: rgba(73, 166, 255, 0.13);
    border-color: rgba(73, 166, 255, 0.42);
    color: #65b7ff;
}
.pondsec-case-meta-row {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
}
.pondsec-case-meta {
    background: #202a36;
    border: 1px solid #2a3544;
    border-radius: 6px;
    color: #c8d2dc;
    display: inline-block;
    font-size: 12px;
    padding: 6px 8px;
}
.pondsec-case-section {
    background: #202a36;
    border: 1px solid #2a3544;
    border-radius: 6px;
    margin-bottom: 12px;
    padding: 14px;
}
.pondsec-case-section h4 {
    color: #f1f6fb;
    font-size: 15px;
    margin: 0 0 12px;
}
.pondsec-case-grid,
.pondsec-feature-grid {
    display: grid;
    gap: 10px;
    grid-template-columns: repeat(2, minmax(0, 1fr));
}
.pondsec-case-grid.wide {
    grid-template-columns: repeat(3, minmax(0, 1fr));
}
.pondsec-case-kv,
.pondsec-feature {
    background: #1b2430;
    border: 1px solid #2a3544;
    border-radius: 6px;
    padding: 10px;
}
.pondsec-case-kv span,
.pondsec-feature span {
    color: #8f9dac;
    display: block;
    font-size: 12px;
    text-transform: uppercase;
}
.pondsec-case-kv strong,
.pondsec-feature strong {
    color: #edf3f8;
    display: block;
    margin-top: 6px;
    overflow-wrap: anywhere;
}
.pondsec-mini-table {
    border-collapse: collapse;
    width: 100%;
}
.pondsec-mini-table th,
.pondsec-mini-table td {
    border-bottom: 1px solid #2a3544;
    padding: 9px 8px;
    text-align: left;
    vertical-align: middle;
}
.pondsec-mini-table th {
    color: #8f9dac;
    font-size: 11px;
    text-transform: uppercase;
}
.pondsec-history-item {
    background: #1b2430;
    border: 1px solid #2a3544;
    border-left: 4px solid #65b7ff;
    border-radius: 6px;
    margin-bottom: 8px;
    padding: 10px;
}
.pondsec-history-item strong {
    color: #edf3f8;
}
.pondsec-history-item span {
    color: #8f9dac;
    display: block;
    font-size: 12px;
    margin-top: 3px;
}
.pondsec-history-item p {
    color: #c8d2dc;
    margin: 7px 0 0;
}
.pondsec-decision-list {
    display: grid;
    gap: 10px;
}
.pondsec-decision {
    background: #1b2430;
    border: 1px solid #2a3544;
    border-radius: 6px;
    padding: 12px;
}
.pondsec-decision-head {
    align-items: center;
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-bottom: 10px;
}
.pondsec-decision-head strong {
    color: #edf3f8;
}
.pondsec-decision-head span {
    color: #8f9dac;
    font-size: 12px;
}
.pondsec-decision-grid {
    display: grid;
    gap: 8px;
    grid-template-columns: repeat(4, minmax(0, 1fr));
}
.pondsec-decision-grid div {
    border-top: 1px solid #2a3544;
    padding-top: 8px;
}
.pondsec-decision-grid span {
    color: #8f9dac;
    display: block;
    font-size: 11px;
    text-transform: uppercase;
}
.pondsec-decision-grid strong {
    color: #edf3f8;
    display: block;
    margin-top: 4px;
    overflow-wrap: anywhere;
}
.pondsec-decision ul {
    color: #c8d2dc;
    margin: 10px 0 0 18px;
    padding: 0;
}
.pondsec-promotion-factors {
    display: grid;
    gap: 10px;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    margin-top: 10px;
}
.pondsec-promotion-factors div {
    border-top: 1px solid #2a3544;
    padding-top: 8px;
}
.pondsec-promotion-factors span:first-child {
    color: #8f9dac;
    display: block;
    font-size: 11px;
    margin-bottom: 6px;
    text-transform: uppercase;
}
.pondsec-file-evidence {
    background: #1b2430;
    border: 1px solid #2a3544;
    border-left: 4px solid #65b7ff;
    border-radius: 6px;
    margin-bottom: 10px;
    padding: 12px;
}
.pondsec-file-evidence-head {
    align-items: center;
    display: flex;
    flex-wrap: wrap;
    gap: 9px;
    margin-bottom: 10px;
}
.pondsec-file-evidence-head strong {
    color: #edf3f8;
}
.pondsec-file-evidence-head span:last-child {
    color: #8f9dac;
    font-size: 12px;
}
.pondsec-file-evidence-extra {
    border-top: 1px solid #2a3544;
    margin-top: 10px;
    padding-top: 10px;
}
.pondsec-file-evidence-extra > span {
    color: #8f9dac;
    display: block;
    font-size: 11px;
    margin: 0 0 6px;
    text-transform: uppercase;
}
.pondsec-file-evidence-extra > span:not(:first-child) {
    margin-top: 10px;
}
.pondsec-case-kv em,
.pondsec-certainty {
    border-radius: 999px;
    display: inline-block;
    font-size: 10px;
    font-style: normal;
    font-weight: 700;
    margin-top: 8px;
    padding: 4px 7px;
    text-transform: uppercase;
}
.pondsec-narrative p {
    color: #d9e3ec;
    font-size: 14px;
    line-height: 1.55;
    margin: 0 0 12px;
}
.pondsec-related-case,
.pondsec-cve-card {
    background: #171f2a;
    border: 1px solid #2a3544;
    border-radius: 6px;
    margin-bottom: 10px;
    padding: 12px;
}
.pondsec-related-case {
    align-items: center;
    display: flex;
    gap: 12px;
    justify-content: space-between;
}
.pondsec-related-case .pondsec-link-button {
    flex: 1;
    text-align: left;
}
.pondsec-cve-card p {
    color: #c8d2dc;
    margin: 8px 0;
}
.pondsec-cve-card em {
    color: #8f9dac;
    display: block;
    font-size: 12px;
    margin-top: 8px;
}
.pondsec-cve-grid {
    display: grid;
    gap: 8px;
    grid-template-columns: repeat(4, minmax(0, 1fr));
}
.pondsec-cve-grid span {
    background: #202a36;
    border: 1px solid #2a3544;
    border-radius: 6px;
    color: #8f9dac;
    padding: 8px;
}
.pondsec-cve-grid strong {
    color: #f1f6fb;
    display: block;
    margin-top: 3px;
}
.pondsec-case-action strong {
    align-items: center;
    display: flex;
}
.pondsec-certainty.confirmed,
.pondsec-certainty.observed {
    background: rgba(76, 201, 112, 0.13);
    color: #79df8f;
}
.pondsec-certainty.inferred,
.pondsec-certainty.correlated,
.pondsec-certainty.suspected {
    background: rgba(73, 166, 255, 0.13);
    color: #65b7ff;
}
.pondsec-certainty.not_claimed,
.pondsec-certainty.not-seen,
.pondsec-certainty.none {
    background: rgba(143, 157, 172, 0.16);
    color: #aeb9c5;
}
.pondsec-token {
    background: #1b2430;
    border: 1px solid #334153;
    border-radius: 6px;
    color: #dbe6f0;
    display: inline-block;
    font-family: Menlo, Monaco, Consolas, monospace;
    margin: 0 6px 6px 0;
    padding: 6px 8px;
}
.pondsec-case-event {
    border-left: 3px solid #49a6ff;
    margin-bottom: 12px;
    padding-left: 12px;
}
.pondsec-case-event span,
.pondsec-case-event em {
    color: #8f9dac;
    display: block;
    font-size: 12px;
    font-style: normal;
}
.pondsec-case-event strong {
    color: #f1f6fb;
    display: block;
    margin: 4px 0;
}
.pondsec-case-event p {
    color: #c8d2dc;
    margin: 0 0 5px;
}
.pondsec-analysis-grid {
    display: grid;
    gap: 12px;
    grid-template-columns: minmax(0, 1.7fr) minmax(280px, 0.9fr);
}
.pondsec-graph-card {
    min-height: 360px;
}
.pondsec-attack-svg {
    background: #171f2a;
    border: 1px solid #2a3544;
    border-radius: 6px;
    display: block;
    min-height: 300px;
    width: 100%;
}
.pondsec-attack-svg marker path {
    fill: #7da2c9;
}
.pondsec-graph-edge {
    fill: none;
    stroke: #7da2c9;
    stroke-width: 2.2;
}
.pondsec-graph-edge.confirmed {
    stroke: #79df8f;
}
.pondsec-graph-edge.correlated {
    stroke: #b38cff;
}
.pondsec-graph-edge.inferred {
    stroke: #8f9dac;
    stroke-dasharray: 6 5;
}
.pondsec-graph-hit {
    cursor: pointer;
    fill: none;
    opacity: 0;
    stroke: #fff;
    stroke-width: 18;
}
.pondsec-graph-edge-wrap text {
    fill: #9fafbf;
    font-size: 12px;
    pointer-events: none;
}
.pondsec-graph-node {
    cursor: pointer;
}
.pondsec-graph-node circle {
    fill: #202a36;
    stroke: #65b7ff;
    stroke-width: 2;
}
.pondsec-graph-node.confirmed circle {
    stroke: #79df8f;
}
.pondsec-graph-node.correlated circle {
    stroke: #b38cff;
}
.pondsec-graph-node.inferred circle {
    stroke: #8f9dac;
    stroke-dasharray: 5 4;
}
.pondsec-graph-node.type-response circle {
    fill: rgba(246, 86, 97, 0.12);
    stroke: #ff7a83;
}
.pondsec-graph-node text {
    fill: #e7eef7;
    font-size: 12px;
    pointer-events: none;
}
.pondsec-graph-node text:first-of-type {
    fill: #8f9dac;
    font-size: 10px;
    text-transform: uppercase;
}
.pondsec-legend-row {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: 10px;
}
.pondsec-legend-item {
    align-items: center;
    color: #aeb9c5;
    display: inline-flex;
    font-size: 12px;
    gap: 6px;
    text-transform: uppercase;
}
.pondsec-legend-item i {
    background: #8f9dac;
    border-radius: 999px;
    display: inline-block;
    height: 8px;
    width: 8px;
}
.pondsec-legend-item.confirmed i,
.pondsec-legend-item.observed i {
    background: #79df8f;
}
.pondsec-legend-item.correlated i {
    background: #b38cff;
}
.pondsec-stage-lane {
    display: grid;
    gap: 8px;
    grid-template-columns: repeat(4, minmax(0, 1fr));
}
.pondsec-stage-item,
.pondsec-timeline-item {
    background: #1b2430;
    border: 1px solid #2a3544;
    border-left: 4px solid #8f9dac;
    border-radius: 6px;
    color: #c8d2dc;
    cursor: pointer;
    display: block;
    padding: 10px;
    text-align: left;
    width: 100%;
}
.pondsec-stage-item.observed,
.pondsec-timeline-item.observed {
    border-left-color: #65b7ff;
}
.pondsec-stage-item.confirmed,
.pondsec-stage-item.prevented,
.pondsec-timeline-item.confirmed {
    border-left-color: #79df8f;
}
.pondsec-stage-item.suspected,
.pondsec-timeline-item.suspected,
.pondsec-timeline-item.inferred {
    border-left-color: #f2a84a;
}
.pondsec-stage-item.not_seen {
    opacity: 0.64;
}
.pondsec-stage-item span,
.pondsec-timeline-item span {
    color: #8f9dac;
    display: block;
    font-size: 12px;
}
.pondsec-stage-item strong,
.pondsec-timeline-item strong {
    color: #f1f6fb;
    display: block;
    margin: 5px 0;
}
.pondsec-stage-item em,
.pondsec-timeline-item em {
    color: #8f9dac;
    display: block;
    font-size: 12px;
    font-style: normal;
}
.pondsec-timeline-stack {
    display: grid;
    gap: 9px;
}
.pondsec-timeline-item p {
    margin: 0 0 6px;
}
.pondsec-focus-row {
    border-bottom: 1px solid #2a3544;
    padding: 8px 0;
}
.pondsec-focus-row span {
    color: #8f9dac;
    display: block;
    font-size: 12px;
    text-transform: uppercase;
}
.pondsec-focus-row strong {
    color: #eef4fa;
    display: block;
    font-weight: 600;
    margin-top: 4px;
    overflow-wrap: anywhere;
}
.pondsec-focus-evidence pre {
    background: #101820;
    border: 1px solid #2a3544;
    border-radius: 6px;
    color: #c8d2dc;
    margin: 10px 0 0;
    max-height: 240px;
    overflow: auto;
    padding: 10px;
}
.pondsec-certainty-grid {
    display: grid;
    gap: 10px;
    grid-template-columns: repeat(4, minmax(0, 1fr));
}
.pondsec-certainty-card {
    background: #1b2430;
    border: 1px solid #2a3544;
    border-radius: 6px;
    padding: 10px;
}
.pondsec-certainty-card strong {
    color: #f1f6fb;
}
.pondsec-certainty-card p {
    color: #aeb9c5;
    margin: 6px 0 0;
}
.pondsec-entry-reason {
    color: #8f9dac;
    margin: 10px 0 0;
}
.pondsec-guidance {
    color: #c8d2dc;
    margin-bottom: 0;
    padding-left: 18px;
}
.pondsec-guidance li {
    margin-bottom: 8px;
}
@media (max-width: 900px) {
    .pondsec-pagehead {
        align-items: stretch;
        flex-direction: column;
    }
    .pondsec-filterbar {
        grid-template-columns: 1fr;
    }
    .pondsec-case-panel {
        bottom: 0;
        left: 0;
        top: 72px;
        padding: 16px;
        width: 100vw;
    }
    .pondsec-case-head {
        flex-direction: column;
    }
    .pondsec-case-head-controls {
        justify-content: space-between;
        order: -1;
        width: 100%;
    }
    .pondsec-analysis-grid,
    .pondsec-case-grid.wide,
    .pondsec-stage-lane,
    .pondsec-certainty-grid,
    .pondsec-decision-grid,
    .pondsec-promotion-factors {
        grid-template-columns: 1fr;
    }
}
</style>

<div class="pondsec-list-page">
    <div class="pondsec-pagehead">
        <div>
            <h2>PondSec NDR: {{ lang._(title) }}</h2>
            <p id="pondsec_page_message"></p>
        </div>
        <div class="pondsec-stat-grid" id="pondsec_stats"></div>
    </div>
    <div id="pondsec_action_result"></div>
    <div class="pondsec-filterbar">
        <div class="pondsec-filter-field">
            <label for="pondsec_filter_search">Search</label>
            <input id="pondsec_filter_search" type="search" placeholder="IP, category, detector, message">
        </div>
        <div class="pondsec-filter-field">
            <label for="pondsec_filter_status">Status</label>
            <select id="pondsec_filter_status"><option value="">All statuses</option></select>
        </div>
        <div class="pondsec-filter-field">
            <label for="pondsec_filter_category">Category</label>
            <select id="pondsec_filter_category"><option value="">All categories</option></select>
        </div>
        <button class="btn btn-default" id="pondsec_filter_reset" type="button"><i class="fa fa-undo"></i> Reset</button>
    </div>
    <div class="pondsec-tablebox">
        <div class="table-responsive">
            <table id="pondsec_table" class="pondsec-table">
                <tbody><tr><td class="pondsec-empty">Loading</td></tr></tbody>
            </table>
        </div>
    </div>
</div>

<aside id="incident_detail_panel" class="pondsec-case-panel">
    <div class="pondsec-case-head">
        <div class="pondsec-case-head-main">
            <h3 id="incident_detail_title">Incident</h3>
            <div id="incident_detail_meta" class="pondsec-case-meta-row"></div>
        </div>
        <div class="pondsec-case-head-controls">
            <button id="incident_detail_back" class="pondsec-panel-back" type="button" aria-label="Back to incidents"><i class="fa fa-arrow-left"></i><span>Back to incidents</span></button>
            <button id="incident_detail_close" class="pondsec-panel-close" type="button" aria-label="Close case detail"><i class="fa fa-times"></i></button>
        </div>
    </div>
    <div id="incident_case_actions" class="pondsec-actions pondsec-case-actions"></div>
    <nav class="pondsec-case-tabs" aria-label="Case analysis tabs">
        <button class="pondsec-case-tab active" type="button" data-case-tab="overview">Overview</button>
        <button class="pondsec-case-tab" type="button" data-case-tab="graph">Attack graph</button>
        <button class="pondsec-case-tab" type="button" data-case-tab="timeline">Timeline</button>
        <button class="pondsec-case-tab" type="button" data-case-tab="evidence">Evidence</button>
        <button class="pondsec-case-tab" type="button" data-case-tab="intel">CVE context</button>
        <button class="pondsec-case-tab" type="button" data-case-tab="related">Related cases</button>
    </nav>
    <div data-case-tab-panel="overview">
        <section class="pondsec-case-section">
            <h4>Case narrative</h4>
            <div id="incident_narrative" class="pondsec-narrative"></div>
        </section>
        <section class="pondsec-case-section">
            <h4>Case summary</h4>
            <div id="incident_case_summary" class="pondsec-case-grid wide"></div>
            <p id="incident_entry_reason" class="pondsec-entry-reason"></p>
        </section>
        <section class="pondsec-case-section">
            <h4>Host story</h4>
            <div id="incident_story" class="pondsec-case-grid"></div>
        </section>
        <section class="pondsec-case-section">
            <h4>Attack stages</h4>
            <div id="incident_attack_stages" class="pondsec-stage-lane"></div>
        </section>
        <section class="pondsec-case-section">
            <h4>What to check next</h4>
            <ul id="incident_guidance" class="pondsec-guidance"></ul>
        </section>
    </div>
    <div data-case-tab-panel="graph" style="display:none">
        <div class="pondsec-analysis-grid">
            <section class="pondsec-case-section pondsec-graph-card">
                <h4>Attack graph</h4>
                <div id="incident_attack_graph"></div>
                <div id="incident_graph_legend" class="pondsec-legend-row"></div>
            </section>
            <section class="pondsec-case-section">
                <h4>Selected evidence</h4>
                <div id="incident_focus_title" class="pondsec-focus-title">Case overview</div>
                <div id="incident_focus_body"></div>
                <div id="incident_focus_evidence" class="pondsec-focus-evidence"></div>
            </section>
        </div>
    </div>
    <div data-case-tab-panel="timeline" style="display:none">
        <section class="pondsec-case-section">
            <h4>Visual timeline</h4>
            <div id="incident_timeline" class="pondsec-timeline-stack"></div>
        </section>
    </div>
    <div data-case-tab-panel="evidence" style="display:none">
        <section class="pondsec-case-section">
            <h4>Affected targets</h4>
            <div id="incident_targets"></div>
        </section>
        <section class="pondsec-case-section">
            <h4>File sandbox and file verdicts</h4>
            <div id="incident_file_sandbox_evidence"></div>
        </section>
        <section class="pondsec-case-section">
            <h4>Confidence boundaries</h4>
            <div id="incident_certainty" class="pondsec-certainty-grid"></div>
        </section>
        <section class="pondsec-case-section">
            <h4>Notable features</h4>
            <div id="incident_features" class="pondsec-feature-grid"></div>
        </section>
        <section class="pondsec-case-section">
            <h4>Risk factors</h4>
            <div id="incident_risk_factors" class="pondsec-feature-grid"></div>
        </section>
        <section class="pondsec-case-section">
            <h4>Promotion decision</h4>
            <div id="incident_promotion_decision" class="pondsec-decision-list"></div>
        </section>
        <section class="pondsec-case-section">
            <h4>Response policy decisions</h4>
            <div id="incident_response_decisions" class="pondsec-decision-list"></div>
        </section>
    </div>
    <div data-case-tab-panel="intel" style="display:none">
        <section class="pondsec-case-section">
            <h4>CVE context</h4>
            <div id="incident_threat_intel"></div>
        </section>
    </div>
    <div data-case-tab-panel="related" style="display:none">
        <section class="pondsec-case-section">
            <h4>Related cases</h4>
            <div id="incident_related_cases"></div>
        </section>
    </div>
</aside>

<aside id="host_detail_panel" class="pondsec-case-panel">
    <div class="pondsec-case-head">
        <div class="pondsec-case-head-main">
            <h3 id="host_detail_title">Host</h3>
            <div id="host_detail_meta" class="pondsec-case-meta-row"></div>
        </div>
        <div class="pondsec-case-head-controls">
            <button id="host_detail_back" class="pondsec-panel-back" type="button" aria-label="Back to hosts"><i class="fa fa-arrow-left"></i><span>Back to hosts</span></button>
            <button id="host_detail_close" class="pondsec-panel-close" type="button" aria-label="Close host detail"><i class="fa fa-times"></i></button>
        </div>
    </div>
    <section class="pondsec-case-section">
        <h4>Entity resolution</h4>
        <div id="host_identity_grid" class="pondsec-case-grid wide"></div>
    </section>
    <section class="pondsec-case-section">
        <h4>IP identity</h4>
        <div id="host_ip_sets" class="pondsec-case-grid"></div>
    </section>
    <section class="pondsec-case-section">
        <h4>Roles and context</h4>
        <div id="host_entity_traits" class="pondsec-case-grid"></div>
    </section>
    <section class="pondsec-case-section">
        <h4>Linked host records</h4>
        <div id="host_records"></div>
    </section>
    <section class="pondsec-case-section">
        <h4>Resolution history</h4>
        <div id="host_history"></div>
    </section>
</aside>
