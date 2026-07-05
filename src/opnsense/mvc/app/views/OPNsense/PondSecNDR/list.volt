<script>
$(function() {
    ajaxGet('{{ endpoint }}', {}, function(data) {
        var rows = data.items || data.records || data.events || [];
        if (!rows.length) {
            $('#pondsec_table').html('<tbody><tr><td>{{ lang._('No records available') }}</td></tr></tbody>');
            return;
        }
        var keys = Object.keys(rows[0]);
        var header = '<thead><tr>';
        keys.forEach(function(key) {
            header += '<th>' + key + '</th>';
        });
        header += '</tr></thead>';
        var body = '<tbody>';
        rows.forEach(function(row) {
            body += '<tr>';
            keys.forEach(function(key) {
                var value = row[key];
                if (typeof value === 'object' && value !== null) {
                    value = JSON.stringify(value);
                }
                body += '<td>' + (value === null || value === undefined ? '' : value) + '</td>';
            });
            body += '</tr>';
        });
        body += '</tbody>';
        $('#pondsec_table').html(header + body);
    });
});
</script>

<style>
.pondsec-pagehead {
    background: #17212f;
    color: #f7fbff;
    border-radius: 6px;
    padding: 14px 16px;
    margin-bottom: 14px;
}
.pondsec-pagehead h2 {
    margin: 0;
    font-size: 22px;
    font-weight: 600;
}
.pondsec-tablebox {
    background: #ffffff;
    border: 1px solid #d8dee6;
    border-radius: 6px;
    padding: 12px;
}
</style>

<div class="pondsec-pagehead">
    <h2>{{ lang._(title) }}</h2>
</div>

<div class="pondsec-tablebox">
    <div class="table-responsive">
        <table id="pondsec_table" class="table table-striped">
            <tbody><tr><td>{{ lang._('Loading') }}</td></tr></tbody>
        </table>
    </div>
</div>
