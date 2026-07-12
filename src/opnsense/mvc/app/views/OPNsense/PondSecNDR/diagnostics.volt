<script>
$(function() {
    var latestDiagnostics = null;

    function escapeHtml(value) {
        return $('<div/>').text(value === null || value === undefined ? '' : String(value)).html();
    }

    function hasValue(value) {
        return value !== null && value !== undefined && value !== '';
    }

    function numberValue(value) {
        var parsed = Number(value);
        return Number.isFinite(parsed) ? parsed : 0;
    }

    function formatBytes(value) {
        var bytes = Number(value);
        if (!Number.isFinite(bytes) || bytes <= 0) {
            return '0 B';
        }
        var units = ['B', 'KB', 'MB', 'GB', 'TB'];
        var index = 0;
        while (bytes >= 1024 && index < units.length - 1) {
            bytes = bytes / 1024;
            index++;
        }
        return bytes.toFixed(bytes >= 10 || index === 0 ? 0 : 1) + ' ' + units[index];
    }

    function formatDuration(value) {
        var seconds = Number(value);
        if (!Number.isFinite(seconds)) {
            return '-';
        }
        if (seconds < 60) {
            return Math.max(0, seconds) + 's';
        }
        if (seconds < 3600) {
            return Math.floor(seconds / 60) + 'm';
        }
        return Math.floor(seconds / 3600) + 'h ' + Math.floor((seconds % 3600) / 60) + 'm';
    }

    function statusClass(value) {
        value = String(value || '').toLowerCase();
        if (['ok', 'ready', 'healthy', 'active', 'running', 'available', 'armed'].indexOf(value) !== -1) {
            return 'good';
        }
        if (['warning', 'needs_attention', 'info', 'disabled', 'missing', 'unavailable', 'learning', 'override', 'suppressed_by_learning_mode'].indexOf(value) !== -1) {
            return 'info';
        }
        if (['failed', 'error', 'not_ready', 'stopped'].indexOf(value) !== -1) {
            return 'bad';
        }
        return 'neutral';
    }

    function badge(value) {
        return '<span class="pondsec-badge ' + statusClass(value) + '">' + escapeHtml(value || 'unknown') + '</span>';
    }

    function renderReadiness(data) {
        var readiness = data.readiness || {};
        var checks = readiness.checks || [];
        $('#readiness_badge').html(badge(readiness.status || 'unknown'));
        $('#readiness_text').text((readiness.required_ok || 0) + ' of ' + (readiness.required_total || 0) + ' required checks are ready');
        $('#mode_value').text(readiness.mode || data.mode || 'monitor');
        $('#service_value').html(badge(readiness.service_status || data.status || 'unknown'));

        $('#required_checks').html(checks.filter(function(item) {
            return String(item.requirement || '').indexOf('required') === 0;
        }).map(renderCheck).join('') || '<div class="pondsec-empty">No required checks reported.</div>');
        $('#optional_checks').html(checks.filter(function(item) {
            return String(item.requirement || '') === 'optional';
        }).map(renderCheck).join('') || '<div class="pondsec-empty">No optional checks reported.</div>');
    }

    function renderCheck(item) {
        return '<div class="pondsec-check">' +
            '<div class="pondsec-check-main">' +
                '<div>' +
                    '<strong>' + escapeHtml(item.label || item.id || 'Check') + '</strong>' +
                    '<p>' + escapeHtml(item.detail || '-') + '</p>' +
                '</div>' +
                badge(item.status || 'unknown') +
            '</div>' +
            (item.recommendation ? '<div class="pondsec-recommendation">' + escapeHtml(item.recommendation) + '</div>' : '') +
        '</div>';
    }

    function renderRuntime(data) {
        var ml = data.ml_runtime || {};
        var tls = data.tls_inspection || {};
        var eve = data.eve_access || {};
        var pf = data.pf_blocking || {};
        var baselines = data.host_baselines || {};
        var learning = data.learning_status || (ml.learning_status || {});
        var coverage = ((data.telemetry_coverage || {}).coverage) || {};
        $('#runtime_grid').html([
            {label: 'EVE telemetry', value: eve.status || 'unknown', detail: eve.path || data.suricata_eve_path || '-'},
            {label: 'AI model', value: ml.external_model_status || 'unknown', detail: ml.external_model_id || 'No model selected'},
            {label: 'AI learning mode', value: learning.status || 'unknown', detail: learning.warning || ((learning.remaining_days || 0) + ' days remaining')},
            {label: 'Model runtime', value: ml.external_model_runtime || ml.numpy_status || 'unknown', detail: 'NumPy ' + (ml.numpy_version || ml.numpy_status || '-') + ' · PyTorch optional ' + (ml.pytorch_status || 'unknown')},
            {label: 'PF blocking', value: pf.rule_present ? 'active' : 'missing', detail: pf.table || '-'},
            {label: 'TLS visibility', value: tls.status || 'unknown', detail: 'HTTP ' + numberValue(tls.http_events_24h) + ' / TLS ' + numberValue(tls.tls_events_24h) + ' events in 24h'},
            {label: 'File sandbox', value: numberValue(coverage.sandbox_verdict) > 0 ? 'verdicts seen' : 'waiting', detail: numberValue(coverage.fileinfo).toLocaleString() + ' file events · ' + numberValue(coverage.sandbox_verdict).toLocaleString() + ' sandbox verdicts in 24h'},
            {label: 'Host baselines', value: baselines.established_hosts + '/' + baselines.total_hosts, detail: baselines.learning_hosts + ' learning hosts'}
        ].map(function(item) {
            return '<div class="pondsec-runtime-card">' +
                '<span>' + escapeHtml(item.label) + '</span>' +
                '<strong>' + escapeHtml(item.value) + '</strong>' +
                '<p>' + escapeHtml(item.detail) + '</p>' +
            '</div>';
        }).join(''));
    }

    function renderHealth(data) {
        $('#health_table tbody').html([
            ['Uptime', formatDuration(data.uptime_seconds)],
            ['Event rate', numberValue(data.eventrate).toFixed(numberValue(data.eventrate) >= 10 ? 0 : 2) + '/s'],
            ['Queue size', numberValue(data.queue_size).toLocaleString()],
            ['Queue drops', numberValue(data.queue_drops).toLocaleString()],
            ['Parser errors', numberValue(data.parser_errors).toLocaleString()],
            ['Database size', formatBytes(data.database_size)],
            ['Feature schema', data.feature_version || '-'],
            ['Active model', data.active_model_version || 'No active model'],
            ['Learning state', ((data.learning_status || {}).status || '-')],
            ['AI detectors suppressed', (data.learning_suppressed_detectors || []).join(', ') || 'None']
        ].map(function(row) {
            return '<tr><td>' + escapeHtml(row[0]) + '</td><td>' + escapeHtml(row[1]) + '</td></tr>';
        }).join(''));

        $('#error_table tbody').html([
            ['Collector', data.last_collector_errors || []],
            ['Machine learning', data.last_ml_errors || []],
            ['Response', data.last_response_errors || []]
        ].map(function(row) {
            var messages = row[1].length ? row[1].join('; ') : 'None';
            return '<tr><td>' + escapeHtml(row[0]) + '</td><td>' + escapeHtml(messages) + '</td></tr>';
        }).join(''));
    }

    function renderProviders(data) {
        var providers = data.providers || [];
        $('#providers_table tbody').html(providers.map(function(item) {
            var configuration = item.configuration || {};
            var stats = item.statistics || {};
            var detail = [
                configuration.path || configuration.input || configuration.requires_configuration || '-',
                'events ' + numberValue(stats.accepted_events).toLocaleString(),
                'errors ' + (numberValue(stats.parser_errors) + numberValue(stats.normalization_errors)).toLocaleString()
            ].join(' · ');
            return '<tr>' +
                '<td><strong>' + escapeHtml(item.display_name || item.provider_id) + '</strong><div class="pondsec-muted">' + escapeHtml(item.provider_id || '-') + '</div></td>' +
                '<td>' + badge(item.health_status || 'unknown') + '</td>' +
                '<td>' + escapeHtml(item.input_type || '-') + '</td>' +
                '<td>' + escapeHtml((item.event_types || []).join(', ') || '-') + '</td>' +
                '<td>' + escapeHtml(detail) + (item.last_error ? '<div class="pondsec-error-text">' + escapeHtml(item.last_error) + '</div>' : '') + '</td>' +
            '</tr>';
        }).join('') || '<tr><td colspan="5" class="pondsec-empty">No providers reported.</td></tr>');
    }

    function renderTelemetryCoverage(data) {
        var coverage = data.telemetry_coverage || {};
        var byProvider = coverage.by_provider || {};
        var runtime = coverage.collector_runtime || {};
        var aliases = {
            suricata: 'suricata_eve'
        };
        var providers = {};
        Object.keys(byProvider).forEach(function(key) { providers[key] = true; });
        Object.keys(runtime).forEach(function(key) { providers[key] = true; });

        function countsFor(provider, windowName) {
            return (((byProvider[provider] || {}).windows || {})[windowName]) || {};
        }
        function runtimeFor(provider) {
            return runtime[provider] || runtime[aliases[provider]] || {};
        }
        function typeDetail(counts) {
            counts = counts || {};
            var pieces = [
                ['Flow', counts.flow],
                ['DNS', counts.dns],
                ['TLS', counts.tls],
                ['HTTP', counts.http],
                ['File', counts.fileinfo],
                ['SMTP', counts.smtp],
                ['DHCP', counts.dhcp],
                ['Auth', counts.authentication],
                ['Sandbox', counts.sandbox_verdict],
                ['Threat Intel', counts.threat_intel],
                ['Incomplete', counts.incomplete]
            ].filter(function(item) {
                return numberValue(item[1]) > 0;
            });
            return pieces.length ? pieces.map(function(item) {
                return item[0] + ' ' + numberValue(item[1]).toLocaleString();
            }).join(' · ') : '-';
        }
        function providerStatus(provider) {
            var c24 = countsFor(provider, '24h');
            var stats = runtimeFor(provider);
            if (numberValue(c24.total) > 0 || numberValue(stats.matched_results) > 0 || numberValue(stats.accepted_events) > 0) {
                return 'active';
            }
            if (numberValue(stats.parser_errors) > 0 || numberValue(stats.normalization_errors) > 0 || numberValue(stats.queue_drops) > 0) {
                return 'warning';
            }
            return 'idle';
        }

        var rows = Object.keys(providers).sort().map(function(provider) {
            var item = byProvider[provider] || {};
            var c1 = countsFor(provider, '1h');
            var c6 = countsFor(provider, '6h');
            var c24 = countsFor(provider, '24h');
            var stats = runtimeFor(provider);
            var errors = numberValue(stats.parser_errors) + numberValue(stats.normalization_errors);
            var collectorDetail = [
                'accepted ' + numberValue(stats.accepted_events).toLocaleString(),
                'errors ' + errors.toLocaleString(),
                'drops ' + numberValue(stats.queue_drops).toLocaleString()
            ];
            if (numberValue(stats.pending_requests) > 0 || numberValue(stats.matched_results) > 0) {
                collectorDetail.push('pending ' + numberValue(stats.pending_requests).toLocaleString());
                collectorDetail.push('matched ' + numberValue(stats.matched_results).toLocaleString());
            }
            return '<tr>' +
                '<td><strong>' + escapeHtml(provider) + '</strong><div class="pondsec-muted">last ' + escapeHtml(item.last_event_at || '-') + '</div></td>' +
                '<td>' + badge(providerStatus(provider)) + '</td>' +
                '<td>' + numberValue(c1.total).toLocaleString() + '</td>' +
                '<td>' + numberValue(c6.total).toLocaleString() + '</td>' +
                '<td><strong>' + numberValue(c24.total).toLocaleString() + '</strong><div class="pondsec-muted">' + escapeHtml(typeDetail(c24)) + '</div></td>' +
                '<td>' + escapeHtml(collectorDetail.join(' · ')) + (stats.last_error ? '<div class="pondsec-error-text">' + escapeHtml(stats.last_error) + '</div>' : '') + '</td>' +
            '</tr>';
        }).join('');

        var ready = coverage.email_url_file_ready || {};
        $('#coverage_readiness').html([
            ['DNS', ready.dns_metadata],
            ['TLS', ready.tls_metadata],
            ['HTTP', ready.http_metadata],
            ['Fileinfo', ready.file_metadata],
            ['SMTP', ready.smtp_metadata],
            ['DHCP', ready.dhcp_metadata],
            ['Signatures/drops', ready.signature_or_drop_metadata],
            ['Sandbox verdicts', ready.sandbox_verdict_metadata],
            ['Threat Intel', ready.threat_intel_metadata]
        ].map(function(item) {
            return '<span class="pondsec-badge ' + (item[1] ? 'good' : 'neutral') + '">' + escapeHtml(item[0]) + '</span>';
        }).join(''));
        $('#coverage_table tbody').html(rows || '<tr><td colspan="6" class="pondsec-empty">No provider telemetry was observed in the last 24 hours.</td></tr>');
    }

    function renderRaw(data) {
        var compact = {
            status: data.status,
            readiness: data.readiness,
            providers: data.providers,
            telemetry_coverage: data.telemetry_coverage,
            eve_access: data.eve_access,
            ml_runtime: data.ml_runtime,
            learning_status: data.learning_status,
            learning_suppressed_detectors: data.learning_suppressed_detectors,
            pf_blocking: data.pf_blocking,
            tls_inspection: data.tls_inspection,
            last_collector_errors: data.last_collector_errors,
            last_ml_errors: data.last_ml_errors,
            last_response_errors: data.last_response_errors
        };
        $('#raw_json').text(JSON.stringify(compact, null, 2));
    }

    function renderDiagnosticsError(message, data) {
        var detail = data || {};
        var text = message || detail.message || 'Diagnostics backend did not return data.';
        $('#readiness_badge').html(badge('error'));
        $('#readiness_text').text(text);
        $('#mode_value').text('-');
        $('#service_value').html(badge(detail.status || 'unknown'));
        $('#required_checks').html('<div class="pondsec-empty">' + escapeHtml(text) + '</div>');
        $('#optional_checks').html('<div class="pondsec-empty">' + escapeHtml(detail.action || 'Check backend logs and retry diagnostics.') + '</div>');
        $('#runtime_grid').html('<div class="pondsec-runtime-card"><span>Diagnostics</span><strong>Error</strong><p>' + escapeHtml(text) + '</p></div>');
        $('#providers_table tbody').html('<tr><td colspan="5" class="pondsec-empty">' + escapeHtml(text) + '</td></tr>');
        $('#coverage_table tbody').html('<tr><td colspan="6" class="pondsec-empty">' + escapeHtml(text) + '</td></tr>');
        $('#coverage_readiness').html('');
        $('#health_table tbody').html('<tr><td>' + escapeHtml(text) + '</td></tr>');
        $('#error_table tbody').html('<tr><td>' + escapeHtml(detail.raw_excerpt || detail.json_error || 'No backend detail available.') + '</td></tr>');
        $('#raw_json').text(JSON.stringify(detail, null, 2));
    }

    function refreshDiagnostics() {
        var completed = false;
        var timeout = window.setTimeout(function() {
            if (!completed) {
                renderDiagnosticsError('Diagnostics backend is still loading. Retry in a moment or run the self-test for a narrower check.', {});
            }
        }, 30000);
        ajaxGet('/api/pondsecndr/diagnostics/get', {}, function(data) {
            completed = true;
            window.clearTimeout(timeout);
            latestDiagnostics = data;
            if (!data || data.status === 'error') {
                renderDiagnosticsError((data || {}).message, data || {});
                return;
            }
            renderReadiness(data);
            renderRuntime(data);
            renderHealth(data);
            renderProviders(data);
            renderTelemetryCoverage(data);
            renderRaw(data);
        });
    }

    function renderActionResult(target, data) {
        $(target).html('<div class="pondsec-notice"><span>' + badge(data.status || 'ok') + '</span><span>' + escapeHtml(data.message || data.reason || 'Action finished') + '</span></div><pre>' + escapeHtml(JSON.stringify(data, null, 2)) + '</pre>');
    }

    $('#selfTestAct').SimpleActionButton({
        onAction: function(data) {
            renderActionResult('#selftest_result', data);
            refreshDiagnostics();
        }
    });
    $('#protectionValidateAct').SimpleActionButton({
        onAction: function(data) {
            renderActionResult('#protectiontest_result', data);
            refreshDiagnostics();
        }
    });
    $('#toggle_raw').on('click', function() {
        $('#raw_panel').toggleClass('hidden');
    });

    refreshDiagnostics();
});
</script>

<style>
.pondsec-diag-page {
    background: #151d26;
    color: #c8d2dc;
    min-height: 760px;
    padding: 18px;
}
.pondsec-diag-page * {
    box-sizing: border-box;
}
.pondsec-pagehead,
.pondsec-panel {
    background: #202a36;
    border: 1px solid #2a3544;
    border-radius: 6px;
    margin-bottom: 14px;
}
.pondsec-pagehead {
    align-items: center;
    display: flex;
    gap: 18px;
    justify-content: space-between;
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
.pondsec-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
}
.pondsec-panel {
    padding: 16px;
}
.pondsec-readiness {
    align-items: center;
    display: flex;
    gap: 14px;
}
.pondsec-readiness strong {
    color: #f4f8fc;
    display: block;
    font-size: 20px;
    margin-bottom: 4px;
}
.pondsec-grid,
.pondsec-runtime-grid,
.pondsec-table-grid {
    display: grid;
    gap: 14px;
}
.pondsec-grid {
    grid-template-columns: 1fr 1fr;
}
.pondsec-runtime-grid {
    grid-template-columns: repeat(3, minmax(0, 1fr));
}
.pondsec-table-grid {
    grid-template-columns: 1fr 1fr;
}
.pondsec-check {
    background: #1b2430;
    border: 1px solid #2a3544;
    border-radius: 6px;
    margin-bottom: 10px;
    padding: 12px;
}
.pondsec-check-main {
    align-items: flex-start;
    display: flex;
    gap: 12px;
    justify-content: space-between;
}
.pondsec-check strong,
.pondsec-runtime-card strong {
    color: #f1f6fb;
}
.pondsec-check p,
.pondsec-runtime-card p,
.pondsec-recommendation,
.pondsec-muted {
    color: #9ba8b6;
    margin: 5px 0 0;
}
.pondsec-recommendation {
    border-top: 1px solid #2a3544;
    margin-top: 10px;
    padding-top: 10px;
}
.pondsec-runtime-card {
    background: #1b2430;
    border: 1px solid #2a3544;
    border-radius: 6px;
    min-height: 108px;
    padding: 14px;
}
.pondsec-runtime-card span {
    color: #8f9dac;
    display: block;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
}
.pondsec-runtime-card strong {
    display: block;
    font-size: 18px;
    margin-top: 10px;
    overflow-wrap: anywhere;
}
.pondsec-table {
    border-collapse: collapse;
    margin: 0;
    width: 100%;
}
.pondsec-coverage-badges {
    display: flex;
    flex-wrap: wrap;
    gap: 7px;
    margin: 0 0 12px;
}
.pondsec-table th,
.pondsec-table td {
    border-bottom: 1px solid #2b3746;
    color: #c8d2dc;
    padding: 11px 10px;
    vertical-align: top;
}
.pondsec-table th {
    color: #8f9dac;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
}
.pondsec-badge {
    border: 1px solid #3a4654;
    border-radius: 6px;
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
.pondsec-notice {
    background: #1b2430;
    border: 1px solid #2a3544;
    border-radius: 6px;
    display: flex;
    gap: 10px;
    margin: 12px 0;
    padding: 11px 12px;
}
.pondsec-empty {
    color: #8f9dac;
    padding: 14px;
}
.pondsec-error-text {
    color: #ff9da4;
    margin-top: 6px;
    overflow-wrap: anywhere;
}
.pondsec-diag-page pre {
    background: #111821;
    border: 1px solid #2a3544;
    border-radius: 6px;
    color: #c8d2dc;
    max-height: 360px;
    overflow: auto;
    padding: 12px;
}
.hidden {
    display: none;
}
@media (max-width: 1100px) {
    .pondsec-grid,
    .pondsec-runtime-grid,
    .pondsec-table-grid {
        grid-template-columns: 1fr;
    }
    .pondsec-pagehead {
        align-items: stretch;
        flex-direction: column;
    }
}
</style>

<div class="pondsec-diag-page">
    <div class="pondsec-pagehead">
        <div>
            <h2>PondSec NDR: {{ lang._('Diagnostics') }}</h2>
            <p>{{ lang._('Readiness checks, data-source visibility, model state, and safe validation actions.') }}</p>
        </div>
        <div class="pondsec-actions">
            <button class="btn btn-primary" id="selfTestAct" data-endpoint="/api/pondsecndr/diagnostics/self_test" data-label="{{ lang._('Self-test') }}"></button>
            <button class="btn btn-danger" id="protectionValidateAct" data-endpoint="/api/pondsecndr/diagnostics/protection_validate" data-label="{{ lang._('Validate protection') }}"></button>
            <button class="btn btn-default" id="toggle_raw" type="button"><i class="fa fa-code"></i> {{ lang._('Debug JSON') }}</button>
        </div>
    </div>

    <section class="pondsec-panel pondsec-readiness">
        <div id="readiness_badge"></div>
        <div>
            <strong>{{ lang._('Deployment readiness') }}</strong>
            <div id="readiness_text">{{ lang._('Loading') }}</div>
            <div>{{ lang._('Mode') }}: <span id="mode_value">-</span> · {{ lang._('Service') }}: <span id="service_value"></span></div>
        </div>
    </section>

    <div class="pondsec-grid">
        <section class="pondsec-panel">
            <h3>{{ lang._('Required before production use') }}</h3>
            <div id="required_checks"><div class="pondsec-empty">{{ lang._('Loading') }}</div></div>
        </section>
        <section class="pondsec-panel">
            <h3>{{ lang._('Optional visibility improvements') }}</h3>
            <div id="optional_checks"><div class="pondsec-empty">{{ lang._('Loading') }}</div></div>
        </section>
    </div>

    <section class="pondsec-panel">
        <h3>{{ lang._('Runtime overview') }}</h3>
        <div class="pondsec-runtime-grid" id="runtime_grid"></div>
    </section>

    <section class="pondsec-panel">
        <h3>{{ lang._('Data source providers') }}</h3>
        <table id="providers_table" class="pondsec-table">
            <thead>
                <tr>
                    <th>{{ lang._('Provider') }}</th>
                    <th>{{ lang._('Status') }}</th>
                    <th>{{ lang._('Input') }}</th>
                    <th>{{ lang._('Event types') }}</th>
                    <th>{{ lang._('Details') }}</th>
                </tr>
            </thead>
            <tbody><tr><td colspan="5" class="pondsec-empty">{{ lang._('Loading') }}</td></tr></tbody>
        </table>
    </section>

    <section class="pondsec-panel">
        <h3>{{ lang._('Telemetry coverage by provider') }}</h3>
        <div id="coverage_readiness" class="pondsec-coverage-badges"></div>
        <table id="coverage_table" class="pondsec-table">
            <thead>
                <tr>
                    <th>{{ lang._('Provider') }}</th>
                    <th>{{ lang._('State') }}</th>
                    <th>{{ lang._('1 h') }}</th>
                    <th>{{ lang._('6 h') }}</th>
                    <th>{{ lang._('24 h detail') }}</th>
                    <th>{{ lang._('Collector quality') }}</th>
                </tr>
            </thead>
            <tbody><tr><td colspan="6" class="pondsec-empty">{{ lang._('Loading') }}</td></tr></tbody>
        </table>
    </section>

    <div class="pondsec-table-grid">
        <section class="pondsec-panel">
            <h3>{{ lang._('Service health') }}</h3>
            <table id="health_table" class="pondsec-table">
                <tbody><tr><td class="pondsec-empty">{{ lang._('Loading') }}</td></tr></tbody>
            </table>
        </section>
        <section class="pondsec-panel">
            <h3>{{ lang._('Recent errors') }}</h3>
            <table id="error_table" class="pondsec-table">
                <tbody><tr><td class="pondsec-empty">{{ lang._('Loading') }}</td></tr></tbody>
            </table>
        </section>
    </div>

    <div id="selftest_result"></div>
    <div id="protectiontest_result"></div>

    <section class="pondsec-panel hidden" id="raw_panel">
        <h3>{{ lang._('Debug JSON') }}</h3>
        <pre id="raw_json">{{ lang._('Loading') }}</pre>
    </section>
</div>
