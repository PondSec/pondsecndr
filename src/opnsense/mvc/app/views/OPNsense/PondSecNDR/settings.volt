<script>
$(function() {
    var activeSection = 'engine';
    var uiLanguage = 'en';

    var sections = {
        engine: {
            icon: 'fa-sliders',
            title: 'Engine',
            description: 'Core service behavior, limits, retention, privacy defaults and Suricata EVE input.'
        },
        interfaces: {
            icon: 'fa-sitemap',
            title: 'Interfaces',
            description: 'Network roles, protected management areas and traffic direction used by detection and response.'
        },
        detection: {
            icon: 'fa-shield',
            title: 'Detection',
            description: 'Deterministic detections, learning mode, AI activation and correlation windows.'
        },
        intel: {
            icon: 'fa-crosshairs',
            title: 'Threat intelligence',
            description: 'Local enrichment and opt-in external refresh behavior for intelligence data.'
        },
        zeek: {
            icon: 'fa-search',
            title: 'Zeek telemetry',
            description: 'Local or external Zeek log paths for flow, DNS, TLS, HTTP, file, notice and weird logs.'
        },
        zenarmor: {
            icon: 'fa-eye',
            title: 'Zenarmor telemetry',
            description: 'Documented reporting exports from Zenarmor without changing policies, licensing or TLS inspection.'
        },
        netflow: {
            icon: 'fa-random',
            title: 'NetFlow and IPFIX',
            description: 'UDP flow collector settings, exporter allowlists, template health and bounded ingestion.'
        },
        dnsmasq: {
            icon: 'fa-server',
            title: 'dnsmasq DNS and DHCP',
            description: 'dnsmasq DNS query logs, DHCP event logs and lease files for entity context.'
        },
        response: {
            icon: 'fa-ban',
            title: 'Response policy',
            description: 'Observe, recommend and enforce controls with conservative safeguards for PF actions.'
        },
        reset: {
            icon: 'fa-refresh',
            title: 'Runtime reset',
            description: 'Clear runtime state and restart learning while keeping configuration, policies and models.'
        }
    };

    var headingToSection = {
        'Engine': 'engine',
        'Interfaces': 'interfaces',
        'Detection': 'detection',
        'Threat intelligence enrichment': 'intel',
        'Zeek telemetry': 'zeek',
        'Zenarmor telemetry': 'zenarmor',
        'NetFlow and IPFIX': 'netflow',
        'dnsmasq DNS and DHCP': 'dnsmasq',
        'Response': 'response'
    };

    var de = {
        page_title: 'PondSec NDR: Einstellungen',
        page_subtitle: 'Telemetrie, Schnittstellen, Erkennung, Reaktion und Datenschutz in einer gefuehrten Ansicht konfigurieren.',
        pill_suricata: 'Suricata EVE erforderlich',
        pill_learning: 'Lernphase aktiv',
        pill_tls: 'TLS-Inspection optional',
        pill_failopen: 'Fail-open Standard',
        required: 'Erforderlich',
        optional: 'Optional',
        safety: 'Sicherheit',
        ai: 'KI',
        ai_safety: 'KI-Schutz',
        card_suricata_title: 'Suricata EVE JSON',
        card_suricata_body: 'PondSec braucht Suricata EVE-Telemetrie. Aktiviere Suricata und EVE JSON vor dem Produktivbetrieb.',
        card_interfaces_title: 'Schnittstellen',
        card_interfaces_body: 'Rollen fuer WAN, intern, DMZ, VLAN und Management setzen, damit Schutzregeln die richtigen Netze kennen.',
        card_model_title: 'Vortrainiertes Modell',
        card_model_body: 'ML-Erkennungen brauchen das verifizierte lokale Modell und einen erfolgreichen Selbsttest.',
        card_learning_title: 'Lernmodus',
        card_learning_body: 'KI-Alarme 14 Tage im Lernmodus lassen. Fruehe Aktivierung ist moeglich, aber mit hoeherem False-Positive-Risiko.',
        card_tls_title: 'TLS-Inspection',
        card_tls_body: 'Zenarmor- oder Proxy-TLS-Inspection kann HTTP/TLS-Sichtbarkeit verbessern, wenn sie rechtlich und sauber betrieben wird.',
        card_observe_title: 'Zuerst beobachten',
        card_observe_body: 'Mit Observe starten. Auto-Isolation braucht Enforce, stabile Baselines, KI-Entscheidung und Schutzpruefungen.',
        ready: 'bereit',
        review_changes: 'Aenderungen vor dem Speichern pruefen.',
        save_apply: 'Speichern und anwenden',
        saving_config: 'Konfiguration wird gespeichert...',
        saved_config: 'Konfiguration gespeichert und Dienst neu konfiguriert.',
        save_failed: 'Speichern fehlgeschlagen.',
        ok: 'ok',
        saving: 'speichert',
        failed: 'fehlgeschlagen',
        reset_title: 'PondSec-Lernphase neu starten',
        reset_body: 'Loescht Laufzeit-Telemetrie, Detections, Incidents, Response-Blocks, Hoststatus und KI-Baselines. Konfiguration, Allowlist, Policies und Modellartefakte bleiben erhalten.',
        reset_button: 'Laufzeitdaten zuruecksetzen und Lernen neu starten',
        reset_confirm: 'PondSec-Laufzeitdaten, Incidents, Detections, Blocks, Hosts und Lern-Baselines wirklich zuruecksetzen? Konfiguration, Allowlist, Policies und Modelle bleiben erhalten. Die KI-Lernphase startet wieder bei Tag 0.',
        resetting: 'Laufzeitdaten werden zurueckgesetzt...',
        reset_done: 'Laufzeitdaten zurueckgesetzt. Die Lernphase startet wieder bei Tag 0.',
        reset_failed: 'Zuruecksetzen fehlgeschlagen.',
        form: {
            'Engine': 'Engine',
            'Enable PondSec NDR': 'PondSec NDR aktivieren',
            'Operating mode': 'Betriebsmodus',
            'Global risk threshold': 'Globaler Risiko-Schwellwert',
            'Maximum event rate': 'Maximale Eventrate',
            'Maximum queue length': 'Maximale Queue-Laenge',
            'Retention days': 'Aufbewahrung in Tagen',
            'Maximum database size MB': 'Maximale Datenbankgroesse in MB',
            'Incident rate limit per minute': 'Incident-Limit pro Minute',
            'PF action rate limit per minute': 'PF-Aktionslimit pro Minute',
            'Memory warning MB': 'RAM-Warnung in MB',
            'CPU warning percent': 'CPU-Warnung in Prozent',
            'Privacy mode': 'Datenschutzmodus',
            'Anonymized storage': 'Anonymisierte Speicherung',
            'Debug logging': 'Debug-Logging',
            'Fail open': 'Fail-open',
            'Timezone': 'Zeitzone',
            'Language': 'Sprache',
            'English': 'Englisch',
            'Deutsch': 'Deutsch',
            'monitor': 'Monitor',
            'alert': 'Alarm',
            'interactive': 'Interaktiv',
            'prevent': 'Prevent',
            'ingress': 'Eingehend',
            'egress': 'Ausgehend',
            'both': 'Beide Richtungen',
            'Suricata EVE path': 'Suricata-EVE-Pfad',
            'Interfaces': 'Schnittstellen',
            'Monitored interfaces': 'Ueberwachte Schnittstellen',
            'Direction': 'Richtung',
            'Internal interfaces': 'Interne Schnittstellen',
            'WAN interfaces': 'WAN-Schnittstellen',
            'Management interfaces': 'Management-Schnittstellen',
            'Excluded interfaces': 'Ausgeschlossene Schnittstellen',
            'Excluded networks': 'Ausgeschlossene Netze',
            'Excluded hosts': 'Ausgeschlossene Hosts',
            'Detection': 'Erkennung',
            'Suricata events': 'Suricata-Events',
            'DNS analysis': 'DNS-Analyse',
            'TLS analysis': 'TLS-Analyse',
            'HTTP metadata analysis': 'HTTP-Metadatenanalyse',
            'Port scan detection': 'Portscan-Erkennung',
            'Lateral movement detection': 'Lateral-Movement-Erkennung',
            'Beaconing detection': 'Beaconing-Erkennung',
            'DNS tunneling detection': 'DNS-Tunneling-Erkennung',
            'Exfiltration': 'Exfiltration',
            'Unusual destinations': 'Ungewoehnliche Ziele',
            'Unusual services': 'Ungewoehnliche Dienste',
            'Unusual internal connections': 'Ungewoehnliche interne Verbindungen',
            'Machine learning': 'Machine Learning',
            'Learning mode': 'Lernmodus',
            'Learning started at': 'Lernphase gestartet am',
            'Learning days': 'Lerntage',
            'Early AI activation override': 'Fruehe KI-Aktivierung erlauben',
            'Learning phase observations': 'Beobachtungen in der Lernphase',
            'Minimum observations': 'Mindestbeobachtungen',
            'Minimum incident confidence': 'Minimale Incident-Confidence',
            'False-positive feedback days': 'False-Positive-Feedback in Tagen',
            'Case correlation window': 'Korrelationsfenster',
            'Threat intelligence enrichment': 'Threat-Intelligence-Anreicherung',
            'CVE enrichment': 'CVE-Anreicherung',
            'External CVE lookups': 'Externe CVE-Abfragen',
            'Threat intel cache TTL': 'Threat-Intel-Cache-TTL',
            'Threat intel API timeout': 'Threat-Intel-API-Timeout',
            'Zeek telemetry': 'Zeek-Telemetrie',
            'Enable Zeek provider': 'Zeek-Provider aktivieren',
            'Zeek mode': 'Zeek-Modus',
            'External sensor': 'Externer Sensor',
            'Local package': 'Lokales Paket',
            'Zeek parser': 'Zeek-Parser',
            'TSV logs': 'TSV-Logs',
            'Zeek sensor name': 'Zeek-Sensorname',
            'Zeek sensor interface': 'Zeek-Sensorschnittstelle',
            'Zeek remote target': 'Zeek-Remote-Ziel',
            'Zeek log directory': 'Zeek-Logverzeichnis',
            'Start at end': 'Am Dateiende starten',
            'Zeek conn.log': 'Zeek conn.log',
            'Zeek dns.log': 'Zeek dns.log',
            'Zeek ssl.log': 'Zeek ssl.log',
            'Zeek x509.log': 'Zeek x509.log',
            'Zeek http.log': 'Zeek http.log',
            'Zeek files.log': 'Zeek files.log',
            'Zeek notice.log': 'Zeek notice.log',
            'Zeek weird.log': 'Zeek weird.log',
            'Zenarmor telemetry': 'Zenarmor-Telemetrie',
            'Enable Zenarmor provider': 'Zenarmor-Provider aktivieren',
            'Zenarmor source': 'Zenarmor-Quelle',
            'Syslog / reporting export': 'Syslog-/Reporting-Export',
            'Zenarmor sensor name': 'Zenarmor-Sensorname',
            'Zenarmor remote target': 'Zenarmor-Remote-Ziel',
            'Zenarmor Syslog export path': 'Zenarmor-Syslog-Exportpfad',
            'Enable Zenarmor API metadata': 'Zenarmor-API-Metadaten aktivieren',
            'Zenarmor API base URL': 'Zenarmor-API-Basis-URL',
            'Zenarmor API key reference': 'Zenarmor-API-Key-Referenz',
            'NetFlow and IPFIX': 'NetFlow und IPFIX',
            'Enable NetFlow/IPFIX collector': 'NetFlow/IPFIX-Collector aktivieren',
            'Collector listen address': 'Collector-Listen-Adresse',
            'Collector UDP port': 'Collector-UDP-Port',
            'Allowed exporters': 'Erlaubte Exporter',
            'Sampling rate': 'Sampling-Rate',
            'Template TTL seconds': 'Template-TTL in Sekunden',
            'Flow retention days': 'Flow-Aufbewahrung in Tagen',
            'Max datagrams per run': 'Maximale Datagramme pro Lauf',
            'dnsmasq DNS and DHCP': 'dnsmasq DNS und DHCP',
            'Enable dnsmasq provider': 'dnsmasq-Provider aktivieren',
            'dnsmasq sensor name': 'dnsmasq-Sensorname',
            'DNS query log path': 'DNS-Query-Logpfad',
            'DHCP event log path': 'DHCP-Event-Logpfad',
            'dnsmasq lease file path': 'dnsmasq-Lease-Dateipfad',
            'Response': 'Reaktion',
            'Response mode': 'Response-Modus',
            'Observe': 'Observe',
            'Recommend': 'Recommend',
            'Enforce': 'Enforce',
            'AI full decision mode': 'Vollstaendige KI-Entscheidung',
            'Response kill switch': 'Response-Kill-Switch',
            'Maintenance mode': 'Wartungsmodus',
            'Automatic blocking': 'Automatisches Blockieren',
            'Minimum response confidence': 'Minimale Response-Confidence',
            'Minimum response risk score': 'Minimaler Response-Risiko-Score',
            'Minimum response severity': 'Minimale Response-Severity',
            'Minimum internal evidence events': 'Minimale interne Evidence-Events',
            'Minimum internal detections': 'Minimale interne Detections',
            'Minimum internal categories': 'Minimale interne Kategorien',
            'Minimum supporting indicators': 'Minimale stuetzende Indikatoren',
            'Minimum independent engines': 'Minimale unabhaengige Engines',
            'Baseline stable observations': 'Stabile Baseline-Beobachtungen',
            'Default block seconds': 'Standard-Blockdauer in Sekunden',
            'Maximum block seconds': 'Maximale Blockdauer in Sekunden',
            'Automatic isolation seconds': 'Automatische Isolationsdauer in Sekunden',
            'Maximum concurrent blocks': 'Maximale gleichzeitige Blocks',
            'Internal isolation cooldown seconds': 'Cooldown fuer interne Isolation in Sekunden',
            'Maximum internal isolations per hour': 'Maximale interne Isolationen pro Stunde',
            'Maximum auto-isolation candidates per run': 'Maximale Auto-Isolationskandidaten pro Lauf',
            'Block external addresses': 'Externe Adressen blockieren',
            'Isolate internal hosts': 'Interne Hosts isolieren',
            'Manual confirmation': 'Manuelle Bestaetigung',
            'Protect management networks': 'Management-Netze schuetzen',
            'Forbid blocking on service error': 'Blockieren bei Dienstfehler verbieten',
            'Enforce allowlist': 'Allowlist erzwingen',
            'Protected networks': 'Geschuetzte Netze',
            'Protected hosts': 'Geschuetzte Hosts',
            'Break glass values': 'Break-Glass-Werte',
            'Suppress AI and baseline anomaly incidents while PondSec learns normal network behavior.': 'Unterdrueckt KI- und Baseline-Anomalie-Incidents, waehrend PondSec normales Netzwerkverhalten lernt.',
            'ISO timestamp. Leave empty on first install; PondSec treats an empty value as learning not yet complete.': 'ISO-Zeitstempel. Beim ersten Setup leer lassen; PondSec wertet leer als noch nicht abgeschlossene Lernphase.',
            'Recommended default is 14 days before enabling AI alarms for production response.': 'Empfohlener Standard sind 14 Tage vor KI-Alarmen fuer produktive Response.',
            'Use only if you accept a high false-positive risk before enough baseline history exists.': 'Nur verwenden, wenn ein hoeheres False-Positive-Risiko vor ausreichender Baseline-Historie akzeptiert wird.',
            'Host-local feedback window. Marking an incident false-positive can help future baseline updates for that host without changing global rules.': 'Host-lokales Feedbackfenster. False-Positive-Markierungen helfen kuenftigen Baseline-Updates fuer diesen Host ohne globale Regeln zu aendern.',
            'Minutes in which related detections across categories can be combined into one attack case. Default: 30.': 'Minuten, in denen verwandte Detections aus mehreren Kategorien zu einem Fall zusammengefasst werden. Standard: 30.',
            'Reads configured Zeek logs only. PondSec does not change packet capture interfaces automatically.': 'Liest nur konfigurierte Zeek-Logs. PondSec aendert keine Capture-Schnittstellen automatisch.',
            'Informational label for correlation. It does not configure or modify the interface.': 'Informative Bezeichnung fuer Korrelation. Die Schnittstelle wird dadurch nicht konfiguriert oder veraendert.',
            'Optional source or host description when logs are produced by an external sensor.': 'Optionale Quellen- oder Hostbeschreibung, wenn Logs von einem externen Sensor stammen.',
            'Recommended for production so existing historical logs are not ingested unexpectedly.': 'Fuer Produktion empfohlen, damit vorhandene historische Logs nicht unerwartet importiert werden.',
            'Reads documented Zenarmor reporting exports such as Syslog data. PondSec does not change Zenarmor policies, TLS inspection, licensing, or engine files.': 'Liest dokumentierte Zenarmor-Reporting-Exporte wie Syslog-Daten. PondSec aendert keine Zenarmor-Policies, TLS-Inspection, Lizenzierung oder Engine-Dateien.',
            'Optional external Syslog sender, export target, or instance label for correlation.': 'Optionaler externer Syslog-Sender, Export-Ziel oder Instanzlabel fuer Korrelation.',
            'Path to a local file written by the configured Syslog/reporting export receiver.': 'Pfad zu einer lokalen Datei, die vom konfigurierten Syslog-/Reporting-Empfaenger geschrieben wird.',
            'Reserved for documented API reads only. It does not store API secrets in this form.': 'Nur fuer dokumentierte API-Lesezugriffe vorgesehen. API-Secrets werden hier nicht gespeichert.',
            'Name of an external credential reference. Do not paste API keys, SASE keys, certificates, or passwords here.': 'Name einer externen Credential-Referenz. Hier keine API-Keys, SASE-Keys, Zertifikate oder Passwoerter einfuegen.',
            'Use 127.0.0.1 for local testing or a firewall interface address for trusted exporters.': '127.0.0.1 fuer lokale Tests oder eine Firewall-Schnittstellenadresse fuer vertrauenswuerdige Exporter verwenden.',
            'Reads dnsmasq DNS, DHCP and lease files only. PondSec does not change resolver or DHCP settings.': 'Liest nur dnsmasq-DNS-, DHCP- und Lease-Dateien. PondSec aendert keine Resolver- oder DHCP-Einstellungen.',
            'Recommended for production so existing DNS and DHCP history is not ingested unexpectedly.': 'Fuer Produktion empfohlen, damit vorhandene DNS- und DHCP-Historie nicht unerwartet importiert wird.',
            'Observe never changes PF, Recommend creates proposals, Enforce can execute only eligible policies after learning, baseline stability, and safety checks.': 'Observe aendert PF nie. Recommend erstellt Vorschlaege. Enforce fuehrt nur geeignete Policies nach Lernphase, Baseline-Stabilitaet und Sicherheitschecks aus.',
            'Required for internal auto-isolation in Enforce mode after the 14-day learning phase. AI evidence never bypasses multi-source safety checks.': 'Erforderlich fuer interne Auto-Isolation im Enforce-Modus nach 14 Tagen Lernphase. KI-Evidence umgeht nie Multi-Source-Sicherheitschecks.',
            'Keep disabled during learning. Automatic PF changes require Enforce mode and all response-policy conditions to pass.': 'Waehrend der Lernphase deaktiviert lassen. Automatische PF-Aenderungen brauchen Enforce und alle bestandenen Response-Policy-Bedingungen.',
            'Minimum time between executed internal auto-isolations. Recommendations do not consume this cooldown.': 'Mindestzeit zwischen ausgefuehrten internen Auto-Isolationen. Empfehlungen verbrauchen diesen Cooldown nicht.'
        }
    };

    var sectionTranslations = {
        de: {
            engine: ['Engine', 'Basisverhalten, Limits, Aufbewahrung, Datenschutz und Suricata-EVE-Eingang.'],
            interfaces: ['Schnittstellen', 'Netzwerkrollen, geschuetzte Managementbereiche und Traffic-Richtung fuer Erkennung und Response.'],
            detection: ['Erkennung', 'Deterministische Detections, Lernmodus, KI-Aktivierung und Korrelationsfenster.'],
            intel: ['Threat Intelligence', 'Lokale Anreicherung und optionale externe Aktualisierung fuer Intelligence-Daten.'],
            zeek: ['Zeek-Telemetrie', 'Lokale oder externe Zeek-Logpfade fuer Flow, DNS, TLS, HTTP, File, Notice und Weird.'],
            zenarmor: ['Zenarmor-Telemetrie', 'Dokumentierte Zenarmor-Reporting-Exporte ohne Aenderungen an Policies, Lizenzierung oder TLS-Inspection.'],
            netflow: ['NetFlow und IPFIX', 'UDP-Flow-Collector, Exporter-Allowlist, Template-Health und begrenzter Ingest.'],
            dnsmasq: ['dnsmasq DNS und DHCP', 'dnsmasq-DNS-Queries, DHCP-Events und Lease-Dateien fuer Entity-Kontext.'],
            response: ['Response-Policy', 'Observe, Recommend und Enforce mit konservativen Schutzregeln fuer PF-Aktionen.'],
            reset: ['Laufzeitdaten zuruecksetzen', 'Laufzeitstatus loeschen und Lernphase neu starten, ohne Konfiguration, Policies oder Modelle zu entfernen.']
        }
    };

    function t(key) {
        if (uiLanguage === 'de' && de[key]) {
            return de[key];
        }
        return key;
    }

    function normalizeText(value) {
        return $.trim(String(value || '').replace(/\s+/g, ' '));
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

    function languageField() {
        return $('#pondsecndr\\.general\\.language, [name="pondsecndr.general.language"], [data-field="pondsecndr.general.language"]').first();
    }

    function currentLanguage() {
        var value = languageField().val();
        return value === 'de' ? 'de' : 'en';
    }

    function applyLanguage() {
        $('[data-i18n]').each(function() {
            $(this).text(t($(this).data('i18n')));
        });
        $('.pondsec-settings-nav button[data-section]').each(function() {
            var section = $(this).data('section');
            var translated = sectionTranslations[uiLanguage] && sectionTranslations[uiLanguage][section];
            $(this).find('span').first().text(translated ? translated[0] : (sections[section] || {}).title || section);
        });
        translateNativeForm();
        updateSectionHeader(activeSection);
    }

    function translateNativeForm() {
        var formMap = uiLanguage === 'de' ? de.form : {};
        $('#frm_GeneralSettings').find('label, .control-label, legend, h1, h2, h3, h4, th b, .help-block, .text-muted, option').each(function() {
            var $item = $(this);
            var original = $item.attr('data-pondsec-original-text');
            if (!original) {
                original = normalizeText($item.text());
                $item.attr('data-pondsec-original-text', original);
            }
            $item.text(formMap[original] || original);
        });
    }

    function sectionFromFieldId(fieldId) {
        fieldId = String(fieldId || '').replace(/^row_/, '');
        if (fieldId.indexOf('pondsecndr.general.') === 0) {
            return 'engine';
        }
        if (fieldId.indexOf('pondsecndr.interfaces.') === 0) {
            return 'interfaces';
        }
        if (fieldId.indexOf('pondsecndr.detection.') === 0) {
            return 'detection';
        }
        if (fieldId.indexOf('pondsecndr.threat_intel.') === 0) {
            return 'intel';
        }
        if (fieldId.indexOf('pondsecndr.zeek.') === 0) {
            return 'zeek';
        }
        if (fieldId.indexOf('pondsecndr.zenarmor.') === 0) {
            return 'zenarmor';
        }
        if (fieldId.indexOf('pondsecndr.netflow.') === 0) {
            return 'netflow';
        }
        if (fieldId.indexOf('pondsecndr.dnsmasq.') === 0) {
            return 'dnsmasq';
        }
        if (fieldId.indexOf('pondsecndr.response.') === 0) {
            return 'response';
        }
        return '';
    }

    function fieldIdFromRow($row) {
        var rowId = $row.attr('id') || '';
        if (rowId.indexOf('row_pondsecndr.') === 0) {
            return rowId.substring(4);
        }
        var $field = $row.find('input[id^="pondsecndr."], select[id^="pondsecndr."], textarea[id^="pondsecndr."], span[id^="pondsecndr."]').first();
        return $field.attr('id') || '';
    }

    function sectionFromGroup($group, fallback) {
        var heading = normalizeText($group.find('thead th b, thead th').first().text());
        if (headingToSection[heading]) {
            return headingToSection[heading];
        }
        var section = '';
        $group.find('tr').each(function() {
            if (section) {
                return false;
            }
            section = sectionFromFieldId(fieldIdFromRow($(this)));
        });
        return section || fallback || 'engine';
    }

    function updateSectionHeader(section) {
        var meta = sections[section] || sections.engine;
        var translated = sectionTranslations[uiLanguage] && sectionTranslations[uiLanguage][section];
        $('#pondsec_section_icon').attr('class', 'fa ' + meta.icon);
        $('#pondsec_section_title').text(translated ? translated[0] : meta.title);
        $('#pondsec_section_description').text(translated ? translated[1] : meta.description);
    }

    function showSaveState(state, messageKey) {
        var tone = state === 'ok' ? 'good' : (state === 'saving' ? 'info' : 'bad');
        $('#pondsec_save_state').html('<span class="pondsec-badge ' + tone + '">' + t(state) + '</span><span>' + t(messageKey) + '</span>');
    }

    function enhanceFormSections() {
        var $form = $('#frm_GeneralSettings');
        if (!$form.length || $form.data('pondsec-section-ready')) {
            return;
        }
        $form.addClass('pondsec-native-form').data('pondsec-section-ready', true);
        var current = 'engine';
        $form.children('.table-responsive').each(function() {
            var $group = $(this);
            current = sectionFromGroup($group, current);
            $group.addClass('pondsec-section-group').attr('data-section', current);
            $group.find('thead tr').addClass('pondsec-form-heading').attr('data-section', current);
            $group.find('tbody tr').each(function() {
                var rowSection = sectionFromFieldId(fieldIdFromRow($(this))) || current;
                $(this).addClass('pondsec-form-row').attr('data-section', rowSection);
            });
        });
        $form.find('tr').each(function() {
            var $row = $(this);
            var label = normalizeText($row.find('label, .control-label, legend, h1, h2, h3, h4, th b, th').first().text());
            if (headingToSection[label]) {
                current = headingToSection[label];
                $row.addClass('pondsec-form-heading').attr('data-section', current);
            } else {
                var rowSection = sectionFromFieldId(fieldIdFromRow($row)) || $row.attr('data-section') || current;
                $row.addClass('pondsec-form-row').attr('data-section', rowSection);
            }
        });
        $('.pondsec-settings-nav button[data-section]').each(function() {
            var section = $(this).data('section');
            var count = $form.find('[data-section="' + section + '"].pondsec-form-row').length;
            $(this).find('.pondsec-nav-count').text(count || '');
        });
        activateSection(activeSection);
        applyLanguage();
    }

    function activateSection(section) {
        activeSection = section || 'engine';
        $('.pondsec-settings-nav button').removeClass('active');
        $('.pondsec-settings-nav button[data-section="' + activeSection + '"]').addClass('active');
        $('.pondsec-setup-card').toggleClass('active', false);
        $('.pondsec-setup-card[data-section-link="' + activeSection + '"]').toggleClass('active', true);
        if (activeSection === 'reset') {
            $('#frm_GeneralSettings').hide();
            $('.pondsec-reset-panel').show();
        } else {
            $('#frm_GeneralSettings').show();
            $('#frm_GeneralSettings').find('.pondsec-section-group').hide();
            $('#frm_GeneralSettings').find('.pondsec-section-group[data-section="' + activeSection + '"]').show();
            $('.pondsec-reset-panel').hide();
        }
        updateSectionHeader(activeSection);
    }

    mapDataToFormUI({'frm_GeneralSettings': '/api/pondsecndr/settings/get'});

    ajaxGet('/api/pondsecndr/settings/get', {}, function(data) {
        var selected = extractLanguage(data);
        uiLanguage = selected === 'de' ? 'de' : 'en';
        applyLanguage();
    });

    $(document).on('change', '#pondsecndr\\.general\\.language, [name="pondsecndr.general.language"], [data-field="pondsecndr.general.language"]', function() {
        uiLanguage = currentLanguage();
        applyLanguage();
    });

    $('.pondsec-settings-nav button[data-section]').on('click', function() {
        activateSection($(this).data('section'));
    });

    $('.pondsec-setup-card[data-section-link]').on('click', function() {
        activateSection($(this).data('section-link'));
    });

    $('#saveAct').click(function() {
        showSaveState('saving', 'saving_config');
        saveFormToEndpoint('/api/pondsecndr/settings/set', 'frm_GeneralSettings', function() {
            ajaxCall(url='/api/pondsecndr/service/reconfigure', sendData={}, callback=function() {
                showSaveState('ok', 'saved_config');
                uiLanguage = currentLanguage();
                applyLanguage();
            });
        });
    });

    $('#pondsec_runtime_reset').on('click', function() {
        var confirmed = window.confirm(t('reset_confirm'));
        if (!confirmed) {
            return;
        }
        showSaveState('saving', 'resetting');
        ajaxCall('/api/pondsecndr/service/resetRuntime', {}, function(data) {
            if (data && data.status === 'ok') {
                showSaveState('ok', 'reset_done');
            } else {
                showSaveState('failed', (data && (data.message || data.status)) ? (data.message || data.status) : 'reset_failed');
            }
        });
    });

    setTimeout(enhanceFormSections, 250);
    setTimeout(function() {
        uiLanguage = currentLanguage();
        enhanceFormSections();
        applyLanguage();
    }, 700);
});
</script>

<style>
.pondsec-settings-page {
    background: #151d26;
    color: #c8d2dc;
    min-height: 760px;
    padding: 18px;
}
.pondsec-settings-page * {
    box-sizing: border-box;
    letter-spacing: 0;
}
.pondsec-settings-head,
.pondsec-settings-shell,
.pondsec-setup-card,
.pondsec-savebar,
.pondsec-reset-panel {
    background: #202a36;
    border: 1px solid #2a3544;
    border-radius: 6px;
    box-shadow: 0 1px 0 rgba(255, 255, 255, 0.03) inset;
}
.pondsec-settings-head {
    align-items: center;
    display: flex;
    gap: 18px;
    justify-content: space-between;
    margin-bottom: 14px;
    padding: 18px;
}
.pondsec-eyebrow,
.pondsec-setup-card span,
.pondsec-kpi-label {
    color: #8f9dac;
    font-size: 12px;
    text-transform: uppercase;
}
.pondsec-settings-head h2 {
    color: #f5f8fb;
    font-size: 24px;
    font-weight: 600;
    margin: 8px 0 10px;
}
.pondsec-settings-head p {
    color: #b8c4cf;
    font-size: 15px;
    line-height: 1.45;
    margin: 0;
    max-width: 760px;
}
.pondsec-mode-pills {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    justify-content: flex-end;
}
.pondsec-badge {
    border: 1px solid #3a4654;
    border-radius: 6px;
    color: #d9e3ec;
    display: inline-block;
    font-size: 12px;
    font-weight: 700;
    line-height: 1;
    padding: 7px 10px;
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
.pondsec-setup-grid {
    display: grid;
    gap: 12px;
    grid-template-columns: repeat(6, minmax(0, 1fr));
    margin-bottom: 14px;
}
.pondsec-setup-card {
    cursor: pointer;
    min-height: 138px;
    padding: 14px;
    transition: border-color .18s ease, background .18s ease, transform .18s ease;
}
.pondsec-setup-card:hover,
.pondsec-setup-card.active {
    background: #24303e;
    border-color: rgba(73, 166, 255, 0.48);
}
.pondsec-setup-card.active {
    transform: translateY(-1px);
}
.pondsec-setup-card strong {
    color: #f1f6fb;
    display: block;
    font-size: 16px;
    margin: 10px 0 8px;
}
.pondsec-setup-card p {
    color: #9ba8b6;
    line-height: 1.4;
    margin: 0;
}
.pondsec-settings-shell {
    display: grid;
    grid-template-columns: 285px minmax(0, 1fr);
    overflow: hidden;
}
.pondsec-settings-nav {
    background: #18212c;
    border-right: 1px solid #2a3544;
    padding: 14px;
}
.pondsec-settings-nav button {
    align-items: center;
    background: transparent;
    border: 0;
    border-left: 3px solid transparent;
    color: #aab6c4;
    display: grid;
    font-size: 14px;
    gap: 9px;
    grid-template-columns: 20px minmax(0, 1fr) auto;
    min-height: 44px;
    padding: 11px 10px;
    text-align: left;
    width: 100%;
}
.pondsec-settings-nav button.active,
.pondsec-settings-nav button:hover {
    background: #202a36;
    border-left-color: #49a6ff;
    color: #edf3f8;
}
.pondsec-settings-nav i {
    color: #65b7ff;
    text-align: center;
}
.pondsec-nav-count {
    color: #7f8c9b;
    font-size: 12px;
}
.pondsec-settings-main {
    min-width: 0;
}
.pondsec-section-intro {
    align-items: center;
    border-bottom: 1px solid #2a3544;
    display: grid;
    gap: 16px;
    grid-template-columns: 44px minmax(0, 1fr);
    padding: 22px 28px;
}
.pondsec-section-icon {
    align-items: center;
    background: rgba(73, 166, 255, 0.13);
    border: 1px solid rgba(73, 166, 255, 0.35);
    border-radius: 6px;
    color: #65b7ff;
    display: flex;
    height: 44px;
    justify-content: center;
    width: 44px;
}
.pondsec-section-intro h3 {
    color: #f1f6fb;
    font-size: 20px;
    margin: 0 0 7px;
}
.pondsec-section-intro p {
    color: #91a0b0;
    line-height: 1.45;
    margin: 0;
}
.pondsec-form-wrap {
    padding: 18px 28px 86px;
}
.pondsec-native-form {
    max-width: 1180px;
}
.pondsec-native-form .form-group,
.pondsec-native-form tr {
    border-bottom: 1px solid #2a3544;
    margin-bottom: 0;
    min-height: 52px;
    padding-bottom: 12px;
    padding-top: 12px;
}
.pondsec-native-form .control-label,
.pondsec-native-form label {
    color: #aab6c4;
    font-weight: 600;
}
.pondsec-native-form input,
.pondsec-native-form select,
.pondsec-native-form textarea,
.pondsec-native-form .select2-choice,
.pondsec-native-form .select2-choices,
.pondsec-native-form .select2-container-multi .select2-choices {
    background: #151d26 !important;
    border-color: #334153 !important;
    border-radius: 5px !important;
    color: #e5edf5 !important;
}
.pondsec-native-form .help-block,
.pondsec-native-form .text-muted {
    color: #8795a5;
}
.pondsec-form-heading {
    background: #18212c;
    border-bottom: 1px solid #334153 !important;
    margin-top: 0;
    padding: 15px !important;
}
.pondsec-form-heading label,
.pondsec-form-heading .control-label,
.pondsec-form-heading h1,
.pondsec-form-heading h2,
.pondsec-form-heading h3,
.pondsec-form-heading h4,
.pondsec-form-heading legend {
    color: #f1f6fb !important;
    font-size: 18px;
    text-align: left !important;
}
.pondsec-reset-panel {
    border-color: rgba(246, 86, 97, 0.45);
    display: none;
    max-width: 920px;
    padding: 18px;
}
.pondsec-reset-panel h4 {
    color: #f5f8fb;
    margin: 0 0 8px;
}
.pondsec-reset-panel p {
    color: #9ba8b6;
    line-height: 1.45;
    margin: 0 0 14px;
}
.pondsec-savebar {
    align-items: center;
    bottom: 18px;
    display: flex;
    gap: 14px;
    justify-content: space-between;
    margin-top: 18px;
    padding: 12px 14px;
    position: sticky;
    z-index: 5;
}
#pondsec_save_state {
    align-items: center;
    color: #9ba8b6;
    display: flex;
    gap: 10px;
}
@media (max-width: 1450px) {
    .pondsec-setup-grid {
        grid-template-columns: repeat(3, minmax(0, 1fr));
    }
}
@media (max-width: 1150px) {
    .pondsec-settings-head,
    .pondsec-savebar {
        align-items: stretch;
        flex-direction: column;
    }
    .pondsec-mode-pills {
        justify-content: flex-start;
    }
    .pondsec-settings-shell {
        grid-template-columns: 1fr;
    }
    .pondsec-settings-nav {
        border-bottom: 1px solid #2a3544;
        border-right: 0;
        display: grid;
        gap: 6px;
        grid-template-columns: repeat(2, minmax(0, 1fr));
    }
}
@media (max-width: 760px) {
    .pondsec-settings-page {
        padding: 12px;
    }
    .pondsec-setup-grid,
    .pondsec-settings-nav {
        grid-template-columns: 1fr;
    }
    .pondsec-section-intro {
        grid-template-columns: 1fr;
    }
}
</style>

<div class="pondsec-settings-page">
    <div class="pondsec-settings-head">
        <div>
            <div class="pondsec-eyebrow">PondSec NDR</div>
            <h2 data-i18n="page_title">PondSec NDR: Settings</h2>
            <p data-i18n="page_subtitle">Configure telemetry, interfaces, AI detection, response policy, and privacy defaults from one guided view.</p>
        </div>
        <div class="pondsec-mode-pills">
            <span class="pondsec-badge info" data-i18n="pill_suricata">Suricata EVE required</span>
            <span class="pondsec-badge info" data-i18n="pill_learning">AI learning phase default</span>
            <span class="pondsec-badge info" data-i18n="pill_tls">TLS inspection optional</span>
            <span class="pondsec-badge good" data-i18n="pill_failopen">Fail open default</span>
        </div>
    </div>

    <div class="pondsec-setup-grid">
        <div class="pondsec-setup-card active" data-section-link="engine">
            <span data-i18n="required">Required</span>
            <strong data-i18n="card_suricata_title">Suricata EVE JSON</strong>
            <p data-i18n="card_suricata_body">PondSec needs Suricata EVE telemetry. Enable Suricata and EVE JSON logging before production use.</p>
        </div>
        <div class="pondsec-setup-card" data-section-link="interfaces">
            <span data-i18n="required">Required</span>
            <strong data-i18n="card_interfaces_title">Interfaces</strong>
            <p data-i18n="card_interfaces_body">Select WAN, internal, DMZ, VLAN, and management roles so response policies know what to protect.</p>
        </div>
        <div class="pondsec-setup-card" data-section-link="detection">
            <span data-i18n="ai">AI</span>
            <strong data-i18n="card_model_title">Pretrained model</strong>
            <p data-i18n="card_model_body">Machine-learning detections require the verified local pretrained model and a successful self-test.</p>
        </div>
        <div class="pondsec-setup-card" data-section-link="detection">
            <span data-i18n="ai_safety">AI safety</span>
            <strong data-i18n="card_learning_title">Learning mode</strong>
            <p data-i18n="card_learning_body">Keep AI alarms in learning mode for 14 days. Early activation is possible, but should be treated as a high false-positive risk.</p>
        </div>
        <div class="pondsec-setup-card" data-section-link="zenarmor">
            <span data-i18n="optional">Optional</span>
            <strong data-i18n="card_tls_title">TLS inspection</strong>
            <p data-i18n="card_tls_body">Zenarmor or Squid TLS inspection can improve HTTP visibility when deployed legally and safely.</p>
        </div>
        <div class="pondsec-setup-card" data-section-link="response">
            <span data-i18n="safety">Safety</span>
            <strong data-i18n="card_observe_title">Observe first</strong>
            <p data-i18n="card_observe_body">Start in Observe mode. Internal auto-isolation requires Enforce mode, AI full decision mode, stable baselines, and protected asset checks.</p>
        </div>
    </div>

    <div class="pondsec-settings-shell">
        <nav class="pondsec-settings-nav">
            <button type="button" class="active" data-section="engine"><i class="fa fa-sliders"></i><span>Engine</span><em class="pondsec-nav-count"></em></button>
            <button type="button" data-section="interfaces"><i class="fa fa-sitemap"></i><span>Interfaces</span><em class="pondsec-nav-count"></em></button>
            <button type="button" data-section="detection"><i class="fa fa-shield"></i><span>Detection</span><em class="pondsec-nav-count"></em></button>
            <button type="button" data-section="intel"><i class="fa fa-crosshairs"></i><span>Threat intelligence</span><em class="pondsec-nav-count"></em></button>
            <button type="button" data-section="zeek"><i class="fa fa-search"></i><span>Zeek telemetry</span><em class="pondsec-nav-count"></em></button>
            <button type="button" data-section="zenarmor"><i class="fa fa-eye"></i><span>Zenarmor telemetry</span><em class="pondsec-nav-count"></em></button>
            <button type="button" data-section="netflow"><i class="fa fa-random"></i><span>NetFlow and IPFIX</span><em class="pondsec-nav-count"></em></button>
            <button type="button" data-section="dnsmasq"><i class="fa fa-server"></i><span>dnsmasq DNS/DHCP</span><em class="pondsec-nav-count"></em></button>
            <button type="button" data-section="response"><i class="fa fa-ban"></i><span>Response policy</span><em class="pondsec-nav-count"></em></button>
            <button type="button" data-section="reset"><i class="fa fa-refresh"></i><span>Reset</span><em class="pondsec-nav-count"></em></button>
        </nav>
        <main class="pondsec-settings-main">
            <div class="pondsec-section-intro">
                <div class="pondsec-section-icon"><i id="pondsec_section_icon" class="fa fa-sliders"></i></div>
                <div>
                    <h3 id="pondsec_section_title">Engine</h3>
                    <p id="pondsec_section_description">Core service behavior, limits, retention, privacy defaults and Suricata EVE input.</p>
                </div>
            </div>
            <div class="pondsec-form-wrap">
                {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_GeneralSettings']) }}
                <div class="pondsec-reset-panel">
                    <h4><i class="fa fa-refresh"></i> <span data-i18n="reset_title">Start PondSec learning from scratch</span></h4>
                    <p data-i18n="reset_body">Clears runtime telemetry, detections, incidents, response blocks, host state, and AI baselines. Configuration, allowlist, policies, and model artifacts are kept.</p>
                    <button class="btn btn-danger" id="pondsec_runtime_reset" type="button"><i class="fa fa-warning"></i> <span data-i18n="reset_button">Reset runtime data and restart learning</span></button>
                </div>
                <div class="pondsec-savebar">
                    <div id="pondsec_save_state"><span class="pondsec-badge info" data-i18n="ready">ready</span><span data-i18n="review_changes">Review changes before saving.</span></div>
                    <button class="btn btn-primary" id="saveAct" type="button"><i class="fa fa-save"></i> <b data-i18n="save_apply">Save and apply</b></button>
                </div>
            </div>
        </main>
    </div>
</div>
