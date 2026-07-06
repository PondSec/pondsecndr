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

    function normalizeDateInput(value) {
        if (!value) {
            return '';
        }
        var parsed = new Date(value);
        return Number.isNaN(parsed.getTime()) ? value : parsed.toISOString();
    }

    function badge(value) {
        var label = value || 'active';
        return '<span class="pondsec-badge good">' + escapeHtml(label) + '</span>';
    }

    function renderResult(data) {
        if (!data) {
            $('#pondsec_action_result').empty();
            return;
        }
        var state = data.status || 'ok';
        var message = data.message || (data.item && data.item.value) || 'Action completed';
        var tone = state === 'ok' ? 'good' : 'bad';
        $('#pondsec_action_result').html('<div class="pondsec-notice ' + tone + '"><span class="pondsec-badge ' + tone + '">' + escapeHtml(state) + '</span><span>' + escapeHtml(message) + '</span></div>');
    }

    function renderStats() {
        var active = rows.filter(function(row) { return !row.expires_at || new Date(row.expires_at) > new Date(); }).length;
        var expiring = rows.filter(function(row) {
            if (!row.expires_at) {
                return false;
            }
            var delta = new Date(row.expires_at) - new Date();
            return delta > 0 && delta < 86400000;
        }).length;
        $('#pondsec_stats').html([
            {label: 'Protected entries', value: rows.length},
            {label: 'Active', value: active},
            {label: 'Expiring 24h', value: expiring}
        ].map(function(item) {
            return '<div class="pondsec-stat"><span>' + item.label + '</span><strong>' + item.value.toLocaleString() + '</strong></div>';
        }).join(''));
    }

    function renderRows() {
        renderStats();
        if (!rows.length) {
            $('#pondsec_allowlist_rows').html('<tr><td colspan="6" class="pondsec-empty">No protected values configured.</td></tr>');
            return;
        }
        $('#pondsec_allowlist_rows').html(rows.map(function(row) {
            var id = encodeURIComponent(row.allowlist_id || '');
            return '<tr>' +
                '<td>' + badge('protected') + '</td>' +
                '<td>' + mono(row.value) + '</td>' +
                '<td>' + escapeHtml(row.reason || '-') + '</td>' +
                '<td>' + formatDate(row.expires_at) + '</td>' +
                '<td>' + formatDate(row.created_at) + '</td>' +
                '<td><button class="btn btn-xs btn-default pondsec-delete-allow" data-id="' + id + '"><i class="fa fa-trash"></i> Remove</button></td>' +
            '</tr>';
        }).join(''));
    }

    function rowSearchText(row) {
        return Object.keys(row).map(function(key) {
            return row[key];
        }).join(' ').toLowerCase();
    }

    function applyFilters() {
        var query = String($('#pondsec_allow_search').val() || '').toLowerCase().trim();
        var state = $('#pondsec_allow_state').val();
        var now = new Date();
        rows = allRows.filter(function(row) {
            var active = !row.expires_at || new Date(row.expires_at) > now;
            if (query && rowSearchText(row).indexOf(query) === -1) {
                return false;
            }
            if (state === 'active' && !active) {
                return false;
            }
            if (state === 'expired' && active) {
                return false;
            }
            return true;
        });
        renderRows();
    }

    function loadRows() {
        ajaxGet('/api/pondsecndr/allowlist/list', {}, function(data) {
            allRows = data.items || [];
            applyFilters();
        });
    }

    $('#pondsec_allowlist_form').on('submit', function(event) {
        event.preventDefault();
        ajaxCall('/api/pondsecndr/allowlist/add', {
            value: $('#pondsec_allow_value').val(),
            reason: $('#pondsec_allow_reason').val(),
            expires_at: normalizeDateInput($('#pondsec_allow_expires').val())
        }, function(data) {
            renderResult(data);
            if (data && data.status === 'ok') {
                $('#pondsec_allow_value').val('');
                $('#pondsec_allow_reason').val('');
                $('#pondsec_allow_expires').val('');
                loadRows();
            }
        });
    });

    $(document).on('click', '.pondsec-delete-allow', function() {
        ajaxCall('/api/pondsecndr/allowlist/delete/' + $(this).data('id'), {}, function(data) {
            renderResult(data);
            loadRows();
        });
    });
    $('#pondsec_allow_search, #pondsec_allow_state').on('input change', applyFilters);
    $('#pondsec_allow_reset').on('click', function() {
        $('#pondsec_allow_search').val('');
        $('#pondsec_allow_state').val('');
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
    min-width: 132px;
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
    grid-template-columns: 1.2fr 1.5fr 1fr auto;
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
.pondsec-badge.bad {
    background: rgba(246, 86, 97, 0.13);
    border-color: rgba(246, 86, 97, 0.45);
    color: #ff7a83;
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
@media (max-width: 1000px) {
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
            <h2>PondSec NDR: {{ lang._('Allowlist') }}</h2>
            <p>{{ lang._('Protect trusted infrastructure from automated response actions.') }}</p>
        </div>
        <div class="pondsec-stat-grid" id="pondsec_stats"></div>
    </div>
    <div id="pondsec_action_result"></div>
    <div class="pondsec-panel pondsec-filterbar">
        <div>
            <label for="pondsec_allow_search">{{ lang._('Search') }}</label>
            <input id="pondsec_allow_search" type="search" placeholder="{{ lang._('IP, network, reason') }}">
        </div>
        <div>
            <label for="pondsec_allow_state">{{ lang._('State') }}</label>
            <select id="pondsec_allow_state">
                <option value="">{{ lang._('All') }}</option>
                <option value="active">{{ lang._('Active') }}</option>
                <option value="expired">{{ lang._('Expired') }}</option>
            </select>
        </div>
        <button class="btn btn-default" id="pondsec_allow_reset" type="button"><i class="fa fa-undo"></i> {{ lang._('Reset') }}</button>
    </div>
    <div class="pondsec-panel">
        <form id="pondsec_allowlist_form" class="pondsec-form-grid">
            <div>
                <label for="pondsec_allow_value">{{ lang._('IP or network') }}</label>
                <input id="pondsec_allow_value" type="text" placeholder="192.168.99.0/24" autocomplete="off" required>
            </div>
            <div>
                <label for="pondsec_allow_reason">{{ lang._('Reason') }}</label>
                <input id="pondsec_allow_reason" type="text" placeholder="{{ lang._('Management network, scanner, backup server') }}" autocomplete="off">
            </div>
            <div>
                <label for="pondsec_allow_expires">{{ lang._('Expires') }}</label>
                <input id="pondsec_allow_expires" type="datetime-local">
            </div>
            <button class="btn btn-primary" type="submit"><i class="fa fa-plus"></i> {{ lang._('Protect') }}</button>
        </form>
    </div>
    <div class="pondsec-tablebox">
        <div class="table-responsive">
            <table class="pondsec-table">
                <thead>
                    <tr>
                        <th>{{ lang._('Status') }}</th>
                        <th>{{ lang._('Value') }}</th>
                        <th>{{ lang._('Reason') }}</th>
                        <th>{{ lang._('Expires') }}</th>
                        <th>{{ lang._('Created') }}</th>
                        <th>{{ lang._('Action') }}</th>
                    </tr>
                </thead>
                <tbody id="pondsec_allowlist_rows">
                    <tr><td colspan="6" class="pondsec-empty">{{ lang._('Loading') }}</td></tr>
                </tbody>
            </table>
        </div>
    </div>
</div>
