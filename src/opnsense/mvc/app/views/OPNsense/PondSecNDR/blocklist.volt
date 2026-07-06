<script>
$(function() {
    var allRows = [];
    var rows = [];

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

    function mono(value) {
        return hasValue(value) ? '<span class="pondsec-mono">' + escapeHtml(value) + '</span>' : '-';
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
        if (value === 'active') {
            return 'bad';
        }
        if (value === 'proposed') {
            return 'info';
        }
        if (value === 'removed' || value === 'expired') {
            return 'neutral';
        }
        return 'good';
    }

    function badge(value) {
        return '<span class="pondsec-badge ' + statusClass(value) + '">' + escapeHtml(value || 'unknown') + '</span>';
    }

    function riskCell(value) {
        var risk = numberValue(value);
        return '<div class="pondsec-risk"><span style="width:' + Math.max(0, Math.min(100, risk)) + '%"></span></div><strong>' + risk + '</strong>';
    }

    function renderResult(data) {
        if (!data) {
            $('#pondsec_action_result').empty();
            return;
        }
        var state = data.status || (data.item && data.item.status) || 'ok';
        var message = data.message || (data.item && (data.item.source_ip || data.item.block_id)) || data.block_id || 'Action completed';
        $('#pondsec_action_result').html('<div class="pondsec-notice"><span class="pondsec-badge ' + statusClass(state) + '">' + escapeHtml(state) + '</span><span>' + escapeHtml(message) + '</span></div>');
    }

    function renderStats() {
        var active = rows.filter(function(row) { return row.status === 'active'; }).length;
        var proposed = rows.filter(function(row) { return row.status === 'proposed'; }).length;
        var manual = rows.filter(function(row) { return row.policy_id === 'manual'; }).length;
        $('#pondsec_stats').html([
            {label: 'Entries', value: rows.length},
            {label: 'Active', value: active},
            {label: 'Proposed', value: proposed},
            {label: 'Manual', value: manual}
        ].map(function(item) {
            return '<div class="pondsec-stat"><span>' + item.label + '</span><strong>' + item.value.toLocaleString() + '</strong></div>';
        }).join(''));
    }

    function renderRows() {
        renderStats();
        if (!rows.length) {
            $('#pondsec_blocklist_rows').html('<tr><td colspan="8" class="pondsec-empty">No block proposals or active blocks.</td></tr>');
            return;
        }
        $('#pondsec_blocklist_rows').html(rows.map(function(row) {
            var id = encodeURIComponent(row.block_id || '');
            var actions = '';
            if (row.status === 'proposed') {
                actions += '<button class="btn btn-xs btn-primary pondsec-block-action" data-action="activate" data-id="' + id + '"><i class="fa fa-play"></i> Activate</button>';
            }
            if (row.status === 'active' || row.status === 'proposed') {
                actions += '<button class="btn btn-xs btn-default pondsec-block-action" data-action="remove" data-id="' + id + '"><i class="fa fa-ban"></i> Remove</button>';
            }
            return '<tr>' +
                '<td>' + badge(row.status) + '</td>' +
                '<td>' + mono(row.source_ip) + '</td>' +
                '<td>' + riskCell(row.risk_score) + '</td>' +
                '<td>' + escapeHtml(Math.round(numberValue(row.confidence) * 100) + '%') + '</td>' +
                '<td>' + escapeHtml(row.reason || '-') + '</td>' +
                '<td>' + formatDate(row.expires_at) + '</td>' +
                '<td>' + escapeHtml(row.created_by || '-') + '</td>' +
                '<td><div class="pondsec-actions">' + (actions || '-') + '</div></td>' +
            '</tr>';
        }).join(''));
    }

    function rowSearchText(row) {
        return Object.keys(row).map(function(key) {
            return row[key];
        }).join(' ').toLowerCase();
    }

    function applyFilters() {
        var query = String($('#pondsec_block_search').val() || '').toLowerCase().trim();
        var status = $('#pondsec_block_status').val();
        rows = allRows.filter(function(row) {
            if (query && rowSearchText(row).indexOf(query) === -1) {
                return false;
            }
            if (status && row.status !== status) {
                return false;
            }
            return true;
        });
        renderRows();
    }

    function loadRows() {
        ajaxGet('/api/pondsecndr/blocklist/list', {}, function(data) {
            allRows = data.items || [];
            applyFilters();
        });
    }

    $('#pondsec_blocklist_form').on('submit', function(event) {
        event.preventDefault();
        ajaxCall('/api/pondsecndr/blocklist/add', {
            value: $('#pondsec_block_value').val(),
            reason: $('#pondsec_block_reason').val(),
            duration_seconds: $('#pondsec_block_duration').val() || 3600
        }, function(data) {
            renderResult(data);
            if (data && data.status === 'ok') {
                $('#pondsec_block_value').val('');
                $('#pondsec_block_reason').val('');
                loadRows();
            }
        });
    });

    $(document).on('click', '.pondsec-block-action', function() {
        var action = $(this).data('action');
        var id = $(this).data('id');
        var endpoint = action === 'activate' ? '/api/pondsecndr/blocklist/activate/' + id : '/api/pondsecndr/blocklist/remove/' + id;
        ajaxCall(endpoint, {}, function(data) {
            renderResult(data);
            loadRows();
        });
    });
    $('#pondsec_block_search, #pondsec_block_status').on('input change', applyFilters);
    $('#pondsec_block_reset').on('click', function() {
        $('#pondsec_block_search').val('');
        $('#pondsec_block_status').val('');
        applyFilters();
    });

    loadRows();
});
</script>

<style>
.pondsec-ops-page {
    background: #151d26;
    color: #c8d2dc;
    min-height: 720px;
    padding: 18px;
}
.pondsec-ops-page * {
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
    align-items: flex-end;
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
.pondsec-panel {
    padding: 16px;
}
.pondsec-filterbar {
    align-items: end;
    display: grid;
    gap: 12px;
    grid-template-columns: minmax(220px, 1fr) 180px auto;
}
.pondsec-form-grid {
    align-items: end;
    display: grid;
    gap: 12px;
    grid-template-columns: 1.1fr 1.5fr 170px auto;
}
.pondsec-form-grid label,
.pondsec-filterbar label {
    color: #8f9dac;
    display: block;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
}
.pondsec-form-grid input,
.pondsec-filterbar input,
.pondsec-filterbar select {
    background: #151d26;
    border: 1px solid #334153;
    border-radius: 5px;
    color: #e5edf5;
    height: 34px;
    padding: 6px 8px;
    width: 100%;
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
    width: 90px;
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
.pondsec-empty {
    color: #8f9dac;
    padding: 18px;
}
@media (max-width: 1080px) {
    .pondsec-pagehead,
    .pondsec-form-grid,
    .pondsec-filterbar {
        align-items: stretch;
        display: flex;
        flex-direction: column;
    }
}
</style>

<div class="pondsec-ops-page">
    <div class="pondsec-pagehead">
        <div>
            <h2>PondSec NDR: {{ lang._('Blocklist') }}</h2>
            <p>{{ lang._('Create safe block proposals, activate PF enforcement, and remove temporary blocks.') }}</p>
        </div>
        <div class="pondsec-stat-grid" id="pondsec_stats"></div>
    </div>
    <div id="pondsec_action_result"></div>
    <div class="pondsec-panel pondsec-filterbar">
        <div>
            <label for="pondsec_block_search">{{ lang._('Search') }}</label>
            <input id="pondsec_block_search" type="search" placeholder="{{ lang._('IP, reason, creator') }}">
        </div>
        <div>
            <label for="pondsec_block_status">{{ lang._('Status') }}</label>
            <select id="pondsec_block_status">
                <option value="">{{ lang._('All') }}</option>
                <option value="active">{{ lang._('Active') }}</option>
                <option value="proposed">{{ lang._('Proposed') }}</option>
                <option value="removed">{{ lang._('Removed') }}</option>
                <option value="expired">{{ lang._('Expired') }}</option>
            </select>
        </div>
        <button class="btn btn-default" id="pondsec_block_reset" type="button"><i class="fa fa-undo"></i> {{ lang._('Reset') }}</button>
    </div>
    <div class="pondsec-panel">
        <form id="pondsec_blocklist_form" class="pondsec-form-grid">
            <div>
                <label for="pondsec_block_value">{{ lang._('IP or network') }}</label>
                <input id="pondsec_block_value" type="text" placeholder="203.0.113.15" autocomplete="off" required>
            </div>
            <div>
                <label for="pondsec_block_reason">{{ lang._('Reason') }}</label>
                <input id="pondsec_block_reason" type="text" placeholder="{{ lang._('Confirmed malicious source, test block') }}" autocomplete="off">
            </div>
            <div>
                <label for="pondsec_block_duration">{{ lang._('Seconds') }}</label>
                <input id="pondsec_block_duration" type="number" min="60" value="3600">
            </div>
            <button class="btn btn-primary" type="submit"><i class="fa fa-plus"></i> {{ lang._('Propose block') }}</button>
        </form>
    </div>
    <div class="pondsec-tablebox">
        <div class="table-responsive">
            <table class="pondsec-table">
                <thead>
                    <tr>
                        <th>{{ lang._('Status') }}</th>
                        <th>{{ lang._('Source') }}</th>
                        <th>{{ lang._('Risk') }}</th>
                        <th>{{ lang._('Confidence') }}</th>
                        <th>{{ lang._('Reason') }}</th>
                        <th>{{ lang._('Expires') }}</th>
                        <th>{{ lang._('Created by') }}</th>
                        <th>{{ lang._('Action') }}</th>
                    </tr>
                </thead>
                <tbody id="pondsec_blocklist_rows">
                    <tr><td colspan="8" class="pondsec-empty">{{ lang._('Loading') }}</td></tr>
                </tbody>
            </table>
        </div>
    </div>
</div>
