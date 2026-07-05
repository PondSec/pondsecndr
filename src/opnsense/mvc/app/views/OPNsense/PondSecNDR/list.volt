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

<div class="content-box">
    <h2>{{ lang._(title) }}</h2>
    <div class="table-responsive">
        <table id="pondsec_table" class="table table-striped">
            <tbody><tr><td>{{ lang._('Loading') }}</td></tr></tbody>
        </table>
    </div>
</div>
