<script>
$(function() {
    var pageTitle = '{{ title }}';
    var endpoint = '{{ endpoint }}';
    var rows = [];

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
        if (['failed', 'error', 'blocked', 'critical', 'removed', 'closed', 'stopped'].indexOf(value) !== -1) {
            return 'bad';
        }
        return 'neutral';
    }

    function badge(value) {
        if (!hasValue(value)) {
            return '<span class="pondsec-badge neutral">unknown</span>';
        }
        return '<span class="pondsec-badge ' + statusClass(value) + '">' + escapeHtml(value) + '</span>';
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

    function primaryColumns(kind) {
        if (kind === 'incidents') {
            return [
                {label: 'Status', render: function(row) { return badge(row.status); }},
                {label: 'Risk', render: function(row) { return riskCell(row.risk_score); }},
                {label: 'Source', render: function(row) { return mono(row.source_ip); }},
                {label: 'Destination', render: function(row) { return mono(row.destination_ip); }},
                {label: 'Category', render: function(row) { return compactValue(row.category); }},
                {label: 'Incident', render: function(row) { return '<strong>' + escapeHtml(row.title || row.incident_id) + '</strong>'; }},
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
                {label: 'Host', render: function(row) { return mono(row.ip); }},
                {label: 'Risk', render: function(row) { return riskCell(row.risk_score); }},
                {label: 'Open incidents', render: function(row) { return formatNumber(row.open_incidents); }},
                {label: 'First seen', render: function(row) { return formatDate(row.first_seen); }},
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

    function incidentActions(row) {
        var id = encodeURIComponent(row.incident_id || '');
        var buttons = '';
        if (row.status === 'open') {
            buttons += '<button class="btn btn-xs btn-default pondsec-row-action" data-action="close-incident" data-id="' + id + '">Close</button>';
            buttons += '<button class="btn btn-xs btn-primary pondsec-row-action" data-action="propose-block" data-id="' + id + '">Propose block</button>';
        } else {
            buttons += '<button class="btn btn-xs btn-default pondsec-row-action" data-action="reopen-incident" data-id="' + id + '">Reopen</button>';
        }
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
        if (action === 'propose-block') {
            return '/api/pondsecndr/blocklist/propose/' + id;
        }
        if (action === 'activate-block') {
            return '/api/pondsecndr/blocklist/activate/' + id;
        }
        if (action === 'remove-block') {
            return '/api/pondsecndr/blocklist/remove/' + id;
        }
        return null;
    }

    function runAction(action, id) {
        var url = actionEndpoint(action, id);
        if (!url) {
            return;
        }
        ajaxCall(url, {}, function(data) {
            $('#pondsec_action_result').html(renderActionResult(data));
            loadRows();
        });
    }

    function renderActionResult(data) {
        if (!data) {
            return '';
        }
        var state = data.status || (data.item && data.item.status) || 'ok';
        var message = data.message || data.reason || data.block_id || (data.item && (data.item.block_id || data.item.source_ip)) || 'Action completed';
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
        if (kind === 'interfaces') {
            stats = [{label: 'Interfaces', value: total}, {label: 'Selected', value: configured}];
        }
        $('#pondsec_stats').html(stats.map(function(item) {
            return '<div class="pondsec-stat"><span>' + escapeHtml(item.label) + '</span><strong>' + formatNumber(item.value) + '</strong></div>';
        }).join(''));
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
            return '<tr>' + columns.map(function(column) {
                return '<td>' + column.render(row) + '</td>';
            }).join('') + '</tr>';
        }).join('') + '</tbody>';
        $('#pondsec_table').html(header + body);
    }

    function loadRows() {
        ajaxGet(endpoint, {}, function(data) {
            rows = data.items || data.records || data.events || [];
            $('#pondsec_page_message').text(data.message || '');
            renderRows();
        });
    }

    $(document).on('click', '.pondsec-row-action', function() {
        runAction($(this).data('action'), $(this).data('id'));
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
.pondsec-actions .btn {
    border-radius: 5px;
}
.pondsec-empty {
    color: #8f9dac;
    padding: 18px;
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
@media (max-width: 900px) {
    .pondsec-pagehead {
        align-items: stretch;
        flex-direction: column;
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
    <div class="pondsec-tablebox">
        <div class="table-responsive">
            <table id="pondsec_table" class="pondsec-table">
                <tbody><tr><td class="pondsec-empty">Loading</td></tr></tbody>
            </table>
        </div>
    </div>
</div>
