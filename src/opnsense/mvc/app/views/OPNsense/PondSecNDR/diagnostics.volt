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
        if (['ok', 'ready', 'healthy', 'active', 'running', 'available'].indexOf(value) !== -1) {
            return 'good';
        }
        if (['warning', 'needs_attention', 'info', 'disabled', 'missing', 'unavailable'].indexOf(value) !== -1) {
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
        $('#runtime_grid').html([
            {label: 'EVE telemetry', value: eve.status || 'unknown', detail: eve.path || data.suricata_eve_path || '-'},
            {label: 'AI model', value: ml.external_model_status || 'unknown', detail: ml.external_model_id || 'No model selected'},
            {label: 'PyTorch runtime', value: ml.pytorch_status || 'unknown', detail: ml.pytorch_version || ml.python_executable || '-'},
            {label: 'PF blocking', value: pf.rule_present ? 'active' : 'missing', detail: pf.table || '-'},
            {label: 'TLS visibility', value: tls.status || 'unknown', detail: 'HTTP ' + numberValue(tls.http_events_24h) + ' / TLS ' + numberValue(tls.tls_events_24h) + ' events in 24h'},
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
            ['Active model', data.active_model_version || 'No active model']
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

    function renderRaw(data) {
        var compact = {
            status: data.status,
            readiness: data.readiness,
            eve_access: data.eve_access,
            ml_runtime: data.ml_runtime,
            pf_blocking: data.pf_blocking,
            tls_inspection: data.tls_inspection,
            last_collector_errors: data.last_collector_errors,
            last_ml_errors: data.last_ml_errors,
            last_response_errors: data.last_response_errors
        };
        $('#raw_json').text(JSON.stringify(compact, null, 2));
    }

    function refreshDiagnostics() {
        ajaxGet('/api/pondsecndr/diagnostics/get', {}, function(data) {
            latestDiagnostics = data;
            renderReadiness(data);
            renderRuntime(data);
            renderHealth(data);
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
.pondsec-recommendation {
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
