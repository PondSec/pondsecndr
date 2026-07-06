<script>
$(function() {
    function escapeHtml(value) {
        return $('<div/>').text(value === null || value === undefined ? '' : String(value)).html();
    }

    function hasValue(value) {
        return value !== null && value !== undefined && value !== '';
    }

    function display(value, fallback) {
        return hasValue(value) ? value : (fallback || 'No data');
    }

    function numberValue(value) {
        var parsed = Number(value);
        return Number.isFinite(parsed) ? parsed : 0;
    }

    function formatNumber(value) {
        if (!hasValue(value)) {
            return 'No data';
        }
        return Number(value).toLocaleString();
    }

    function formatRate(value) {
        if (!hasValue(value)) {
            return '0/s';
        }
        var number = Number(value);
        return Number.isFinite(number) ? number.toFixed(number >= 10 ? 0 : 2) + '/s' : '0/s';
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
            return 'No data';
        }
        if (seconds < 60) {
            return Math.max(0, seconds) + 's';
        }
        if (seconds < 3600) {
            return Math.floor(seconds / 60) + 'm ' + (seconds % 60) + 's';
        }
        return Math.floor(seconds / 3600) + 'h ' + Math.floor((seconds % 3600) / 60) + 'm';
    }

    function statusClass(value) {
        value = String(value || '').toLowerCase();
        if (value === 'healthy' || value === 'ok' || value === 'running' || value === 'active') {
            return 'good';
        }
        if (value === 'monitor' || value === 'interactive' || value === 'alert') {
            return 'info';
        }
        if (value === 'prevent') {
            return 'good';
        }
        if (value === 'failed' || value === 'error' || value === 'critical' || value === 'stopped' || value === 'isolated' || value === 'blocked') {
            return 'bad';
        }
        return 'neutral';
    }

    function badge(value, extraClass) {
        var text = display(value);
        return '<span class="pondsec-badge ' + statusClass(value) + (extraClass ? ' ' + extraClass : '') + '">' + escapeHtml(text) + '</span>';
    }

    function renderSummary(data) {
        var metrics = data.metrics || {};
        var categories = data.detections_by_category || [];
        var topHosts = data.top_hosts || [];
        var detectionsTotal = categories.reduce(function(total, item) {
            return total + numberValue(item.count);
        }, 0);
        var events24h = numberValue(metrics.events_last_24h);
        var blocked = numberValue(metrics.blocked_sources);
        var isolated = numberValue(metrics.isolated_clients);
        var openIncidents = numberValue(metrics.open_incidents);
        var critical = numberValue(metrics.critical_incidents);

        $('#hero_sentence').html(
            'Today, <strong>PondSec NDR</strong> analyzed <span>' + formatNumber(events24h) +
            '</span> network events, detected <span>' + formatNumber(detectionsTotal) +
            '</span> suspicious activities and is actively blocking <span>' + formatNumber(blocked) +
            '</span> source' + (blocked === 1 ? '' : 's') + '.'
        );
        $('#service_status_badge').html(badge(metrics.service_status || 'unknown'));
        $('#mode_badge').html(badge(metrics.operating_mode || 'monitor'));
        $('#model_value').text(display(metrics.active_model_version, 'No active model'));
        $('#interfaces_value').text((metrics.interfaces || []).length ? metrics.interfaces.join(', ') : 'Not selected');

        $('#events_24h').text(formatNumber(events24h));
        $('#detections_total').text(formatNumber(detectionsTotal));
        $('#open_incidents').text(formatNumber(openIncidents));
        $('#critical_incidents').text(formatNumber(critical));
        $('#blocked_sources').text(formatNumber(blocked));
        $('#isolated_clients').text(formatNumber(isolated));
        $('#telemetry_delay').text(formatDuration(metrics.telemetry_delay_seconds));
        $('#event_rate').text(formatRate(metrics.event_rate_per_second));
        $('#database_size').text(formatBytes(metrics.database_size_bytes));
        $('#queue').text(formatNumber(metrics.queue_utilization || 0));
        $('#collector_errors').text((metrics.last_collector_errors || []).length ? metrics.last_collector_errors.join('; ') : 'None');
        $('#response_errors').text((metrics.last_response_errors || []).length ? metrics.last_response_errors.join('; ') : 'None');

        renderThreatCards(categories);
        renderHostRows(topHosts);
        renderCategoryRows(categories);
    }

    function renderDiagnostics(data) {
        var pf = data.pf_blocking || {};
        var eve = data.eve_access || {};
        var pfState = pf.rule_present ? 'active' : 'missing';
        $('#pf_status_badge').html(badge(pfState));
        $('#pf_table').text(display(pf.table, 'virusprot'));
        $('#eve_status_badge').html(badge(eve.status || 'unknown'));
        $('#db_status_badge').html(badge(data.status || 'unknown'));
    }

    function renderThreatCards(categories) {
        var total = categories.reduce(function(sum, item) {
            return sum + numberValue(item.count);
        }, 0);
        var cards = '';
        categories.slice(0, 3).forEach(function(item, index) {
            var count = numberValue(item.count);
            var percent = total > 0 ? Math.round((count / total) * 100) : 0;
            cards += '<div class="pondsec-mini-card">' +
                '<div class="pondsec-donut tone-' + (index + 1) + '" style="--value:' + percent + '"><span>' + percent + '%</span></div>' +
                '<div><div class="pondsec-muted">Top threat</div><div class="pondsec-card-title">' + escapeHtml(item.category || 'unknown') + '</div>' +
                '<div class="pondsec-small">' + formatNumber(count) + ' detections</div></div>' +
                '</div>';
        });
        if (!cards) {
            cards = '<div class="pondsec-empty">No detections recorded.</div>';
        }
        $('#threat_cards').html(cards);
    }

    function renderHostRows(topHosts) {
        var rows = '';
        topHosts.slice(0, 8).forEach(function(host) {
            var risk = numberValue(host.risk_score);
            var protection = host.block_status && host.block_status !== 'none' ? host.block_status : (host.allowlist_status && host.allowlist_status !== 'none' ? 'allowlisted' : 'normal');
            rows += '<tr><td class="pondsec-mono">' + escapeHtml(host.ip) + '</td>' +
                '<td>' + badge(protection) + '</td>' +
                '<td><div class="pondsec-risk"><span style="width:' + Math.min(100, risk) + '%"></span></div><strong>' + formatNumber(risk) + '</strong></td>' +
                '<td>' + formatNumber(host.open_incidents || 0) + '</td></tr>';
        });
        $('#top_hosts tbody').html(rows || '<tr><td colspan="4" class="pondsec-empty">No hosts observed.</td></tr>');
    }

    function renderCategoryRows(categories) {
        var max = categories.reduce(function(value, item) {
            return Math.max(value, numberValue(item.count));
        }, 1);
        var rows = '';
        categories.slice(0, 8).forEach(function(item) {
            var count = numberValue(item.count);
            rows += '<tr><td>' + escapeHtml(item.category || 'unknown') + '</td>' +
                '<td><div class="pondsec-bar"><span style="width:' + Math.round((count / max) * 100) + '%"></span></div></td>' +
                '<td>' + formatNumber(count) + '</td></tr>';
        });
        $('#detections_by_category tbody').html(rows || '<tr><td colspan="3" class="pondsec-empty">No detections recorded.</td></tr>');
    }

    function renderTimeline(data) {
        var items = data.items || [];
        var max = items.reduce(function(value, item) {
            return Math.max(value, numberValue(item.events));
        }, 1);
        var total = items.reduce(function(value, item) {
            return value + numberValue(item.events);
        }, 0);
        var recent = items.slice(-24);
        var peak = recent.reduce(function(value, item) {
            return Math.max(value, numberValue(item.events));
        }, 0);
        var bars = '';
        recent.forEach(function(item, index) {
            var events = numberValue(item.events);
            var height = Math.max(events > 0 ? 8 : 2, Math.round((events / max) * 100));
            var label = String(item.hour || '').slice(-2) + ':00';
            var showLabel = index === 0 || index === recent.length - 1 || index % 4 === 0;
            bars += '<div class="pondsec-timeline-bar" title="' + escapeHtml(label + ' - ' + events + ' events') + '">' +
                '<span style="height:' + height + '%"><i>' + (events ? escapeHtml(events) : '') + '</i></span><em>' + (showLabel ? escapeHtml(label) : '') + '</em></div>';
        });
        $('#event_timeline_total').text(formatNumber(total));
        $('#event_timeline_peak').text(formatNumber(peak));
        $('#event_timeline').html(bars || '<div class="pondsec-empty">No event timeline yet.</div>');
    }

    ajaxGet('/api/pondsecndr/dashboard/summary', {}, renderSummary);
    ajaxGet('/api/pondsecndr/dashboard/timeline', {}, renderTimeline);
    ajaxGet('/api/pondsecndr/diagnostics/get', {}, renderDiagnostics);
});
</script>

<style>
.pondsec-dashboard {
    background: #151d26;
    color: #c8d2dc;
    padding: 18px;
    min-height: 760px;
}
.pondsec-dashboard * {
    box-sizing: border-box;
}
.pondsec-hero-grid,
.pondsec-main-grid,
.pondsec-kpi-grid {
    display: grid;
    gap: 14px;
}
.pondsec-hero-grid {
    grid-template-columns: minmax(0, 1.35fr) minmax(320px, 0.65fr);
    margin-bottom: 14px;
}
.pondsec-main-grid {
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
}
.pondsec-kpi-grid {
    grid-template-columns: repeat(4, minmax(0, 1fr));
    margin-bottom: 14px;
}
.pondsec-panel,
.pondsec-kpi {
    background: #202a36;
    border: 1px solid #2a3544;
    border-radius: 6px;
    box-shadow: 0 1px 0 rgba(255, 255, 255, 0.03) inset;
}
.pondsec-panel {
    padding: 18px;
}
.pondsec-hero {
    min-height: 166px;
    display: flex;
    flex-direction: column;
    justify-content: center;
}
.pondsec-eyebrow,
.pondsec-muted,
.pondsec-kpi-label {
    color: #8f9dac;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0;
}
.pondsec-hero h2 {
    color: #f5f8fb;
    font-size: 24px;
    font-weight: 600;
    margin: 8px 0 14px;
}
.pondsec-hero p {
    color: #b8c4cf;
    font-size: 18px;
    line-height: 1.45;
    margin: 0;
    max-width: 760px;
}
.pondsec-hero p span {
    color: #49a6ff;
    font-weight: 700;
}
.pondsec-status-list {
    display: grid;
    gap: 12px;
}
.pondsec-status-row {
    border-bottom: 1px solid #2b3746;
    display: flex;
    align-items: center;
    justify-content: space-between;
    min-height: 36px;
    gap: 12px;
}
.pondsec-status-row:last-child {
    border-bottom: 0;
}
.pondsec-status-value {
    color: #edf3f8;
    font-weight: 600;
    text-align: right;
    overflow-wrap: anywhere;
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
.pondsec-badge.neutral {
    background: #263241;
    color: #b8c4cf;
}
.pondsec-kpi {
    min-height: 96px;
    padding: 14px 16px;
    position: relative;
}
.pondsec-kpi:before {
    background: #49a6ff;
    border-radius: 6px 0 0 6px;
    bottom: -1px;
    content: "";
    left: -1px;
    position: absolute;
    top: -1px;
    width: 4px;
}
.pondsec-kpi.warning:before {
    background: #f2a84a;
}
.pondsec-kpi.danger:before {
    background: #f15f6b;
}
.pondsec-kpi.success:before {
    background: #55d17a;
}
.pondsec-kpi-value {
    color: #f4f8fc;
    font-size: 26px;
    font-weight: 700;
    line-height: 1.2;
    margin-top: 12px;
}
.pondsec-section-title {
    color: #e6edf4;
    font-size: 17px;
    font-weight: 600;
    margin: 0 0 14px;
}
.pondsec-threat-grid {
    display: grid;
    gap: 12px;
    grid-template-columns: repeat(3, minmax(0, 1fr));
}
.pondsec-mini-card {
    align-items: center;
    background: #1b2430;
    border: 1px solid #2a3544;
    border-radius: 6px;
    display: flex;
    gap: 14px;
    min-height: 132px;
    padding: 16px;
}
.pondsec-card-title {
    color: #edf3f8;
    font-size: 17px;
    font-weight: 600;
    margin: 4px 0 6px;
    overflow-wrap: anywhere;
}
.pondsec-small {
    color: #9ba8b6;
    font-size: 13px;
}
.pondsec-donut {
    --value: 0;
    align-items: center;
    aspect-ratio: 1;
    background: conic-gradient(#49a6ff calc(var(--value) * 1%), #2b3746 0);
    border-radius: 50%;
    display: flex;
    flex: 0 0 84px;
    justify-content: center;
    position: relative;
    width: 84px;
}
.pondsec-donut.tone-2 {
    background: conic-gradient(#a166d9 calc(var(--value) * 1%), #2b3746 0);
}
.pondsec-donut.tone-3 {
    background: conic-gradient(#ff928e calc(var(--value) * 1%), #2b3746 0);
}
.pondsec-donut:after {
    background: #1b2430;
    border-radius: 50%;
    content: "";
    height: 52px;
    position: absolute;
    width: 52px;
}
.pondsec-donut span {
    color: #edf3f8;
    font-size: 14px;
    font-weight: 700;
    position: relative;
    z-index: 1;
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
    vertical-align: middle;
}
.pondsec-table th {
    color: #8f9dac;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
}
.pondsec-table tbody tr:hover td {
    background: #24303e;
}
.pondsec-mono {
    color: #dbe6f0;
    font-family: Menlo, Monaco, Consolas, monospace;
}
.pondsec-risk,
.pondsec-bar {
    background: #111821;
    border-radius: 6px;
    display: inline-block;
    height: 7px;
    margin-right: 9px;
    overflow: hidden;
    vertical-align: middle;
    width: 110px;
}
.pondsec-risk span,
.pondsec-bar span {
    background: linear-gradient(90deg, #49a6ff, #f2a84a, #f15f6b);
    display: block;
    height: 100%;
}
.pondsec-bar {
    width: 100%;
}
.pondsec-bar span {
    background: #49a6ff;
}
.pondsec-timeline {
    align-items: end;
    background:
        linear-gradient(to top, rgba(143, 157, 172, 0.16) 1px, transparent 1px) 0 0 / 100% 33%,
        #1b2430;
    border: 1px solid #2a3544;
    border-radius: 6px;
    display: grid;
    gap: 5px;
    grid-auto-flow: column;
    grid-auto-columns: minmax(18px, 1fr);
    height: 154px;
    padding: 14px 10px 8px;
}
.pondsec-timeline-bar {
    align-items: center;
    display: flex;
    flex-direction: column;
    height: 100%;
    justify-content: flex-end;
    min-width: 0;
}
.pondsec-timeline-bar span {
    background: linear-gradient(180deg, #49a6ff, #2f76be);
    border-radius: 5px 5px 0 0;
    display: block;
    min-height: 3px;
    position: relative;
    width: 100%;
}
.pondsec-timeline-bar span i {
    color: #d8e9fa;
    display: none;
    font-size: 10px;
    font-style: normal;
    font-weight: 700;
    left: 50%;
    position: absolute;
    top: -18px;
    transform: translateX(-50%);
}
.pondsec-timeline-bar:hover span i {
    display: block;
}
.pondsec-timeline-bar em {
    color: #7f8c9b;
    font-size: 10px;
    font-style: normal;
    margin-top: 6px;
    min-height: 12px;
}
.pondsec-chart-head {
    align-items: center;
    display: flex;
    gap: 12px;
    justify-content: space-between;
    margin-bottom: 12px;
}
.pondsec-chart-metrics {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
}
.pondsec-chart-metric {
    background: #1b2430;
    border: 1px solid #2a3544;
    border-radius: 6px;
    color: #9ba8b6;
    font-size: 12px;
    padding: 7px 9px;
}
.pondsec-chart-metric strong {
    color: #edf3f8;
    margin-left: 6px;
}
.pondsec-empty {
    color: #8f9dac;
    padding: 16px 0;
}
.pondsec-detail-grid {
    display: grid;
    gap: 14px;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
    margin-top: 14px;
}
@media (max-width: 1200px) {
    .pondsec-hero-grid,
    .pondsec-main-grid,
    .pondsec-detail-grid {
        grid-template-columns: 1fr;
    }
    .pondsec-kpi-grid,
    .pondsec-threat-grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
    }
}
@media (max-width: 760px) {
    .pondsec-dashboard {
        padding: 12px;
    }
    .pondsec-kpi-grid,
    .pondsec-threat-grid {
        grid-template-columns: 1fr;
    }
}
</style>

<div class="pondsec-dashboard">
    <div class="pondsec-hero-grid">
        <section class="pondsec-panel pondsec-hero">
            <div class="pondsec-eyebrow">PondSec NDR</div>
            <h2>Network Detection & Response</h2>
            <p id="hero_sentence">Loading current protection posture...</p>
        </section>
        <section class="pondsec-panel">
            <h3 class="pondsec-section-title">Protection posture</h3>
            <div class="pondsec-status-list">
                <div class="pondsec-status-row"><span>Engine</span><span id="service_status_badge"></span></div>
                <div class="pondsec-status-row"><span>Mode</span><span id="mode_badge"></span></div>
                <div class="pondsec-status-row"><span>PF blocking</span><span id="pf_status_badge"></span></div>
                <div class="pondsec-status-row"><span>EVE telemetry</span><span id="eve_status_badge"></span></div>
                <div class="pondsec-status-row"><span>Database</span><span id="db_status_badge"></span></div>
            </div>
        </section>
    </div>

    <div class="pondsec-kpi-grid">
        <div class="pondsec-kpi"><div class="pondsec-kpi-label">Events 24h</div><div class="pondsec-kpi-value" id="events_24h">Loading</div></div>
        <div class="pondsec-kpi"><div class="pondsec-kpi-label">Suspicious detections</div><div class="pondsec-kpi-value" id="detections_total">Loading</div></div>
        <div class="pondsec-kpi warning"><div class="pondsec-kpi-label">Open incidents</div><div class="pondsec-kpi-value" id="open_incidents">Loading</div></div>
        <div class="pondsec-kpi danger"><div class="pondsec-kpi-label">Critical incidents</div><div class="pondsec-kpi-value" id="critical_incidents">Loading</div></div>
        <div class="pondsec-kpi success"><div class="pondsec-kpi-label">Blocked sources</div><div class="pondsec-kpi-value" id="blocked_sources">Loading</div></div>
        <div class="pondsec-kpi danger"><div class="pondsec-kpi-label">Isolated clients</div><div class="pondsec-kpi-value" id="isolated_clients">Loading</div></div>
        <div class="pondsec-kpi"><div class="pondsec-kpi-label">Event rate</div><div class="pondsec-kpi-value" id="event_rate">Loading</div></div>
        <div class="pondsec-kpi"><div class="pondsec-kpi-label">Telemetry delay</div><div class="pondsec-kpi-value" id="telemetry_delay">Loading</div></div>
    </div>

    <div class="pondsec-main-grid">
        <section class="pondsec-panel">
            <h3 class="pondsec-section-title">Top threat categories</h3>
            <div class="pondsec-threat-grid" id="threat_cards"></div>
        </section>
        <section class="pondsec-panel">
            <div class="pondsec-chart-head">
                <h3 class="pondsec-section-title" style="margin:0;">Event activity</h3>
                <div class="pondsec-chart-metrics">
                    <div class="pondsec-chart-metric">24h total <strong id="event_timeline_total">0</strong></div>
                    <div class="pondsec-chart-metric">Peak hour <strong id="event_timeline_peak">0</strong></div>
                </div>
            </div>
            <div class="pondsec-timeline" id="event_timeline"></div>
        </section>
    </div>

    <div class="pondsec-detail-grid">
        <section class="pondsec-panel">
            <h3 class="pondsec-section-title">Highest-risk hosts</h3>
            <table id="top_hosts" class="pondsec-table">
                <thead><tr><th>IP address</th><th>Protection</th><th>Risk</th><th>Open incidents</th></tr></thead>
                <tbody><tr><td colspan="4" class="pondsec-empty">Loading</td></tr></tbody>
            </table>
        </section>
        <section class="pondsec-panel">
            <h3 class="pondsec-section-title">Detections by category</h3>
            <table id="detections_by_category" class="pondsec-table">
                <thead><tr><th>Category</th><th>Volume</th><th>Count</th></tr></thead>
                <tbody><tr><td colspan="3" class="pondsec-empty">Loading</td></tr></tbody>
            </table>
        </section>
    </div>

    <section class="pondsec-panel" style="margin-top:14px;">
        <h3 class="pondsec-section-title">Operational details</h3>
        <div class="pondsec-status-list">
            <div class="pondsec-status-row"><span>Active model</span><span class="pondsec-status-value" id="model_value">Loading</span></div>
            <div class="pondsec-status-row"><span>Monitored interfaces</span><span class="pondsec-status-value" id="interfaces_value">Loading</span></div>
            <div class="pondsec-status-row"><span>PF block table</span><span class="pondsec-status-value" id="pf_table">Loading</span></div>
            <div class="pondsec-status-row"><span>Queue</span><span class="pondsec-status-value" id="queue">Loading</span></div>
            <div class="pondsec-status-row"><span>Collector errors</span><span class="pondsec-status-value" id="collector_errors">Loading</span></div>
            <div class="pondsec-status-row"><span>Response errors</span><span class="pondsec-status-value" id="response_errors">Loading</span></div>
        </div>
    </section>
</div>
