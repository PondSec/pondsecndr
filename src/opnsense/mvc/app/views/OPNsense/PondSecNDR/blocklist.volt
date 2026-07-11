<script>
$(function() {
    var allRows = [];
    var rows = [];
    var blockLookup = {};
    var allSinkholeRows = [];
    var sinkholeRows = [];
    var sinkholeLookup = {};
    var permanentExpiresAt = '9999-12-31T23:59:59+00:00';

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

    function isPermanentExpires(value) {
        var text = String(value || '').trim().toLowerCase();
        return !text || text === 'never' || text === 'permanent' || text === 'unlimited' || text === 'infinite' || text.indexOf('9999-12-31') === 0 || text === permanentExpiresAt.toLowerCase();
    }

    function formatExpires(value) {
        return isPermanentExpires(value) ? 'Unbegrenzt' : formatDate(value);
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
        var message = data.message || (data.item && (data.item.source_ip || data.item.domain || data.item.block_id || data.item.sinkhole_id)) || data.block_id || data.sinkhole_id || data.domain || 'Action completed';
        if (data.raw_excerpt) {
            message += ': ' + data.raw_excerpt;
        }
        $('#pondsec_action_result').html('<div class="pondsec-notice"><span class="pondsec-badge ' + statusClass(state) + '">' + escapeHtml(state) + '</span><span>' + escapeHtml(message) + '</span></div>');
    }

    function renderStats() {
        var active = rows.filter(function(row) { return row.status === 'active'; }).length;
        var proposed = rows.filter(function(row) { return row.status === 'proposed'; }).length;
        var activeSinkholes = sinkholeRows.filter(function(row) { return row.status === 'active'; }).length;
        var proposedSinkholes = sinkholeRows.filter(function(row) { return row.status === 'proposed'; }).length;
        $('#pondsec_stats').html([
            {label: 'Blocks', value: rows.length},
            {label: 'Aktive Blocks', value: active},
            {label: 'Vorgeschlagen', value: proposed},
            {label: 'DNS-Sinkholes', value: activeSinkholes + proposedSinkholes}
        ].map(function(item) {
            return '<div class="pondsec-stat"><span>' + item.label + '</span><strong>' + item.value.toLocaleString() + '</strong></div>';
        }).join(''));
    }

    function renderRows() {
        renderStats();
        blockLookup = {};
        if (!rows.length) {
            $('#pondsec_blocklist_rows').html('<tr><td colspan="8" class="pondsec-empty">No block proposals or active blocks.</td></tr>');
            return;
        }
        $('#pondsec_blocklist_rows').html(rows.map(function(row) {
            var id = encodeURIComponent(row.block_id || '');
            blockLookup[id] = row;
            var actions = '';
            if (row.status === 'proposed') {
                actions += '<button class="btn btn-xs btn-primary pondsec-block-action" data-action="activate" data-id="' + id + '"><i class="fa fa-play"></i> Activate</button>';
            }
            if (row.status === 'active' || row.status === 'proposed') {
                actions += '<button class="btn btn-xs btn-default pondsec-block-action pondsec-icon-button" data-action="edit" data-id="' + id + '" title="Block bearbeiten"><i class="fa fa-pencil"></i></button>';
                actions += '<button class="btn btn-xs btn-default pondsec-block-action" data-action="remove" data-id="' + id + '"><i class="fa fa-ban"></i> Remove</button>';
            }
            return '<tr>' +
                '<td>' + badge(row.status) + '</td>' +
                '<td>' + mono(row.source_ip) + '</td>' +
                '<td>' + riskCell(row.risk_score) + '</td>' +
                '<td>' + escapeHtml(Math.round(numberValue(row.confidence) * 100) + '%') + '</td>' +
                '<td>' + escapeHtml(row.reason || '-') + '</td>' +
                '<td>' + escapeHtml(formatExpires(row.expires_at)) + '</td>' +
                '<td>' + escapeHtml(row.created_by || '-') + '</td>' +
                '<td><div class="pondsec-actions">' + (actions || '-') + '</div></td>' +
            '</tr>';
        }).join(''));
    }

    function renderSinkholeRows() {
        renderStats();
        sinkholeLookup = {};
        if (!sinkholeRows.length) {
            $('#pondsec_sinkhole_rows').html('<tr><td colspan="8" class="pondsec-empty">Keine DNS-Sinkhole-Vorschlaege oder aktiven Sinkholes.</td></tr>');
            return;
        }
        $('#pondsec_sinkhole_rows').html(sinkholeRows.map(function(row) {
            var id = encodeURIComponent(row.sinkhole_id || '');
            sinkholeLookup[id] = row;
            var actions = '';
            if (row.status === 'proposed') {
                actions += '<button class="btn btn-xs btn-primary pondsec-sinkhole-action" data-action="activate" data-id="' + id + '"><i class="fa fa-play"></i> Activate</button>';
            }
            if (row.status === 'active' || row.status === 'proposed') {
                actions += '<button class="btn btn-xs btn-default pondsec-sinkhole-action pondsec-icon-button" data-action="edit" data-id="' + id + '" title="DNS-Sinkhole bearbeiten"><i class="fa fa-pencil"></i></button>';
                actions += '<button class="btn btn-xs btn-default pondsec-sinkhole-action" data-action="remove" data-id="' + id + '"><i class="fa fa-ban"></i> Remove</button>';
            }
            return '<tr>' +
                '<td>' + badge(row.status) + '</td>' +
                '<td>' + mono(row.domain) + '</td>' +
                '<td>' + riskCell(row.risk_score) + '</td>' +
                '<td>' + escapeHtml(Math.round(numberValue(row.confidence) * 100) + '%') + '</td>' +
                '<td>' + escapeHtml(row.reason || '-') + '</td>' +
                '<td>' + escapeHtml(formatExpires(row.expires_at)) + '</td>' +
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

    function applySinkholeFilters() {
        var query = String($('#pondsec_sinkhole_search').val() || '').toLowerCase().trim();
        var status = $('#pondsec_sinkhole_status').val();
        sinkholeRows = allSinkholeRows.filter(function(row) {
            if (query && rowSearchText(row).indexOf(query) === -1) {
                return false;
            }
            if (status && row.status !== status) {
                return false;
            }
            return true;
        });
        renderSinkholeRows();
    }

    function loadRows() {
        ajaxGet('/api/pondsecndr/blocklist/list', {}, function(data) {
            allRows = data.items || [];
            applyFilters();
        });
    }

    function loadSinkholes() {
        ajaxGet('/api/pondsecndr/sinkhole/list', {}, function(data) {
            allSinkholeRows = data.items || [];
            applySinkholeFilters();
        });
    }

    function openEdit(row) {
        $('#pondsec_edit_block_id').val(row.block_id || '');
        $('#pondsec_edit_source').val(row.source_ip || '');
        $('#pondsec_edit_reason').val(row.reason || '');
        $('#pondsec_edit_expires').val(isPermanentExpires(row.expires_at) ? '' : (row.expires_at || ''));
        $('#pondsec_block_edit_panel').show();
        $('#pondsec_edit_reason').trigger('focus');
    }

    function openSinkholeEdit(row) {
        $('#pondsec_edit_sinkhole_id').val(row.sinkhole_id || '');
        $('#pondsec_edit_domain').val(row.domain || '');
        $('#pondsec_edit_sinkhole_reason').val(row.reason || '');
        $('#pondsec_edit_sinkhole_expires').val(isPermanentExpires(row.expires_at) ? '' : (row.expires_at || ''));
        $('#pondsec_sinkhole_edit_panel').show();
        $('#pondsec_edit_sinkhole_reason').trigger('focus');
    }

    function closeEdit() {
        $('#pondsec_block_edit_panel').hide();
        $('#pondsec_block_edit_form')[0].reset();
    }

    function closeSinkholeEdit() {
        $('#pondsec_sinkhole_edit_panel').hide();
        $('#pondsec_sinkhole_edit_form')[0].reset();
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
    $('#pondsec_sinkhole_form').on('submit', function(event) {
        event.preventDefault();
        ajaxCall('/api/pondsecndr/sinkhole/add', {
            domain: $('#pondsec_sinkhole_domain').val(),
            reason: $('#pondsec_sinkhole_reason').val(),
            duration_seconds: $('#pondsec_sinkhole_duration').val() || 3600
        }, function(data) {
            renderResult(data);
            if (data && data.status === 'ok') {
                $('#pondsec_sinkhole_domain').val('');
                $('#pondsec_sinkhole_reason').val('');
                loadSinkholes();
            }
        });
    });

    $(document).on('click', '.pondsec-block-action', function() {
        var action = $(this).data('action');
        var id = $(this).attr('data-id');
        if (action === 'edit') {
            openEdit(blockLookup[id] || {});
            return;
        }
        var endpoint = action === 'activate' ? '/api/pondsecndr/blocklist/activate/' + id : '/api/pondsecndr/blocklist/remove/' + id;
        ajaxCall(endpoint, {}, function(data) {
            renderResult(data);
            closeEdit();
            loadRows();
        });
    });
    $(document).on('click', '.pondsec-sinkhole-action', function() {
        var action = $(this).data('action');
        var id = $(this).attr('data-id');
        if (action === 'edit') {
            openSinkholeEdit(sinkholeLookup[id] || {});
            return;
        }
        var endpoint = action === 'activate' ? '/api/pondsecndr/sinkhole/activate/' + id : '/api/pondsecndr/sinkhole/remove/' + id;
        ajaxCall(endpoint, {}, function(data) {
            renderResult(data);
            closeSinkholeEdit();
            loadSinkholes();
        });
    });
    $('#pondsec_block_edit_form').on('submit', function(event) {
        event.preventDefault();
        var id = encodeURIComponent($('#pondsec_edit_block_id').val() || '');
        ajaxCall('/api/pondsecndr/blocklist/edit/' + id, {
            reason: $('#pondsec_edit_reason').val(),
            expires_at: $('#pondsec_edit_expires').val()
        }, function(data) {
            renderResult(data);
            if (data && data.status === 'ok') {
                closeEdit();
                loadRows();
            }
        });
    });
    $('#pondsec_sinkhole_edit_form').on('submit', function(event) {
        event.preventDefault();
        var id = encodeURIComponent($('#pondsec_edit_sinkhole_id').val() || '');
        ajaxCall('/api/pondsecndr/sinkhole/edit/' + id, {
            reason: $('#pondsec_edit_sinkhole_reason').val(),
            expires_at: $('#pondsec_edit_sinkhole_expires').val()
        }, function(data) {
            renderResult(data);
            if (data && data.status === 'ok') {
                closeSinkholeEdit();
                loadSinkholes();
            }
        });
    });
    $('#pondsec_edit_cancel').on('click', closeEdit);
    $('#pondsec_sinkhole_edit_cancel').on('click', closeSinkholeEdit);
    $('#pondsec_block_search, #pondsec_block_status').on('input change', applyFilters);
    $('#pondsec_sinkhole_search, #pondsec_sinkhole_status').on('input change', applySinkholeFilters);
    $('#pondsec_block_reset').on('click', function() {
        $('#pondsec_block_search').val('');
        $('#pondsec_block_status').val('');
        applyFilters();
    });
    $('#pondsec_sinkhole_reset').on('click', function() {
        $('#pondsec_sinkhole_search').val('');
        $('#pondsec_sinkhole_status').val('');
        applySinkholeFilters();
    });

    loadRows();
    loadSinkholes();
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
.pondsec-section-title {
    margin: 18px 0 10px;
}
.pondsec-section-title h3 {
    color: #f5f8fb;
    font-size: 18px;
    margin: 0;
}
.pondsec-section-title p {
    color: #8f9dac;
    margin: 5px 0 0;
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
.pondsec-icon-button {
    min-width: 28px;
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
.pondsec-edit-grid {
    align-items: end;
    display: grid;
    gap: 12px;
    grid-template-columns: 1fr 1.4fr 1.3fr auto auto;
}
.pondsec-edit-grid label {
    color: #8f9dac;
    display: block;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
}
.pondsec-edit-grid input {
    background: #151d26;
    border: 1px solid #334153;
    border-radius: 5px;
    color: #e5edf5;
    height: 34px;
    padding: 6px 8px;
    width: 100%;
}
.pondsec-edit-grid input[readonly] {
    background: #1b2430;
    color: #9ca9b7;
}
.pondsec-help {
    color: #8f9dac;
    grid-column: 1 / -1;
    margin: 0;
}
@media (max-width: 1080px) {
    .pondsec-pagehead,
    .pondsec-form-grid,
    .pondsec-edit-grid,
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
    <div id="pondsec_block_edit_panel" class="pondsec-panel" style="display:none">
        <form id="pondsec_block_edit_form" class="pondsec-edit-grid">
            <input id="pondsec_edit_block_id" type="hidden">
            <div>
                <label for="pondsec_edit_source">{{ lang._('Source') }}</label>
                <input id="pondsec_edit_source" type="text" readonly>
            </div>
            <div>
                <label for="pondsec_edit_reason">{{ lang._('Reason') }}</label>
                <input id="pondsec_edit_reason" type="text" autocomplete="off">
            </div>
            <div>
                <label for="pondsec_edit_expires">{{ lang._('Expires') }}</label>
                <input id="pondsec_edit_expires" type="text" placeholder="2026-07-12T12:00:00+00:00" autocomplete="off">
            </div>
            <button class="btn btn-primary" type="submit"><i class="fa fa-save"></i> {{ lang._('Save') }}</button>
            <button class="btn btn-default" id="pondsec_edit_cancel" type="button"><i class="fa fa-times"></i> {{ lang._('Cancel') }}</button>
            <p class="pondsec-help">{{ lang._('Ablauf leer lassen fuer einen unbegrenzten Block, bis er entfernt wird.') }}</p>
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
    <div class="pondsec-section-title">
        <h3>{{ lang._('DNS Sinkholes') }}</h3>
        <p>{{ lang._('Block malicious domains at DNS level without isolating an entire host.') }}</p>
    </div>
    <div class="pondsec-panel pondsec-filterbar">
        <div>
            <label for="pondsec_sinkhole_search">{{ lang._('Search') }}</label>
            <input id="pondsec_sinkhole_search" type="search" placeholder="{{ lang._('Domain, reason, creator') }}">
        </div>
        <div>
            <label for="pondsec_sinkhole_status">{{ lang._('Status') }}</label>
            <select id="pondsec_sinkhole_status">
                <option value="">{{ lang._('All') }}</option>
                <option value="active">{{ lang._('Active') }}</option>
                <option value="proposed">{{ lang._('Proposed') }}</option>
                <option value="removed">{{ lang._('Removed') }}</option>
                <option value="expired">{{ lang._('Expired') }}</option>
            </select>
        </div>
        <button class="btn btn-default" id="pondsec_sinkhole_reset" type="button"><i class="fa fa-undo"></i> {{ lang._('Reset') }}</button>
    </div>
    <div class="pondsec-panel">
        <form id="pondsec_sinkhole_form" class="pondsec-form-grid">
            <div>
                <label for="pondsec_sinkhole_domain">{{ lang._('Domain') }}</label>
                <input id="pondsec_sinkhole_domain" type="text" placeholder="malicious.example.test" autocomplete="off" required>
            </div>
            <div>
                <label for="pondsec_sinkhole_reason">{{ lang._('Reason') }}</label>
                <input id="pondsec_sinkhole_reason" type="text" placeholder="{{ lang._('Confirmed phishing URL, malware callback domain') }}" autocomplete="off">
            </div>
            <div>
                <label for="pondsec_sinkhole_duration">{{ lang._('Seconds') }}</label>
                <input id="pondsec_sinkhole_duration" type="number" min="60" value="3600">
            </div>
            <button class="btn btn-primary" type="submit"><i class="fa fa-plus"></i> {{ lang._('Propose DNS sinkhole') }}</button>
        </form>
    </div>
    <div id="pondsec_sinkhole_edit_panel" class="pondsec-panel" style="display:none">
        <form id="pondsec_sinkhole_edit_form" class="pondsec-edit-grid">
            <input id="pondsec_edit_sinkhole_id" type="hidden">
            <div>
                <label for="pondsec_edit_domain">{{ lang._('Domain') }}</label>
                <input id="pondsec_edit_domain" type="text" readonly>
            </div>
            <div>
                <label for="pondsec_edit_sinkhole_reason">{{ lang._('Reason') }}</label>
                <input id="pondsec_edit_sinkhole_reason" type="text" autocomplete="off">
            </div>
            <div>
                <label for="pondsec_edit_sinkhole_expires">{{ lang._('Expires') }}</label>
                <input id="pondsec_edit_sinkhole_expires" type="text" placeholder="2026-07-12T12:00:00+00:00" autocomplete="off">
            </div>
            <button class="btn btn-primary" type="submit"><i class="fa fa-save"></i> {{ lang._('Save') }}</button>
            <button class="btn btn-default" id="pondsec_sinkhole_edit_cancel" type="button"><i class="fa fa-times"></i> {{ lang._('Cancel') }}</button>
            <p class="pondsec-help">{{ lang._('Ablauf leer lassen fuer einen unbegrenzten DNS-Sinkhole, bis er entfernt wird.') }}</p>
        </form>
    </div>
    <div class="pondsec-tablebox">
        <div class="table-responsive">
            <table class="pondsec-table">
                <thead>
                    <tr>
                        <th>{{ lang._('Status') }}</th>
                        <th>{{ lang._('Domain') }}</th>
                        <th>{{ lang._('Risk') }}</th>
                        <th>{{ lang._('Confidence') }}</th>
                        <th>{{ lang._('Reason') }}</th>
                        <th>{{ lang._('Expires') }}</th>
                        <th>{{ lang._('Created by') }}</th>
                        <th>{{ lang._('Action') }}</th>
                    </tr>
                </thead>
                <tbody id="pondsec_sinkhole_rows">
                    <tr><td colspan="8" class="pondsec-empty">{{ lang._('Loading') }}</td></tr>
                </tbody>
            </table>
        </div>
    </div>
</div>
