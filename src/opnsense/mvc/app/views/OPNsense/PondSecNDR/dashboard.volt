<script>
$(function() {
    function valueOrEmpty(value) {
        if (value === null || value === undefined || value === '') {
            return '{{ lang._('No data') }}';
        }
        return value;
    }

    ajaxGet('/api/pondsecndr/dashboard/summary', {}, function(data) {
        var metrics = data.metrics || {};
        $('#service_status').text(valueOrEmpty(metrics.service_status));
        $('#operating_mode').text(valueOrEmpty(metrics.operating_mode));
        $('#interfaces').text(valueOrEmpty((metrics.interfaces || []).join(', ')));
        $('#event_rate').text(valueOrEmpty(metrics.event_rate_per_second));
        $('#events_24h').text(valueOrEmpty(metrics.events_last_24h));
        $('#open_incidents').text(valueOrEmpty(metrics.open_incidents));
        $('#critical_incidents').text(valueOrEmpty(metrics.critical_incidents));
        $('#blocked_sources').text(valueOrEmpty(metrics.blocked_sources));
        $('#active_model').text(valueOrEmpty(metrics.active_model_version));
        $('#telemetry_delay').text(valueOrEmpty(metrics.telemetry_delay_seconds));
        $('#queue').text(valueOrEmpty(metrics.queue_utilization));
        $('#database_size').text(valueOrEmpty(metrics.database_size_bytes));
        $('#collector_errors').text(valueOrEmpty((metrics.last_collector_errors || []).join('; ')));
        $('#response_errors').text(valueOrEmpty((metrics.last_response_errors || []).join('; ')));

        var topHosts = data.top_hosts || [];
        var hostRows = '';
        topHosts.forEach(function(host) {
            hostRows += '<tr><td>' + host.ip + '</td><td>' + host.risk_score + '</td><td>' + host.open_incidents + '</td></tr>';
        });
        $('#top_hosts tbody').html(hostRows || '<tr><td colspan="3">{{ lang._('No hosts observed') }}</td></tr>');

        var categories = data.detections_by_category || [];
        var categoryRows = '';
        categories.forEach(function(item) {
            categoryRows += '<tr><td>' + item.category + '</td><td>' + item.count + '</td></tr>';
        });
        $('#detections_by_category tbody').html(categoryRows || '<tr><td colspan="2">{{ lang._('No detections recorded') }}</td></tr>');
    });
});
</script>

<div class="content-box">
    <div class="table-responsive">
        <table class="table table-striped">
            <tbody>
                <tr><th>{{ lang._('Service status') }}</th><td id="service_status">{{ lang._('Loading') }}</td></tr>
                <tr><th>{{ lang._('Operating mode') }}</th><td id="operating_mode">{{ lang._('Loading') }}</td></tr>
                <tr><th>{{ lang._('Monitored interfaces') }}</th><td id="interfaces">{{ lang._('Loading') }}</td></tr>
                <tr><th>{{ lang._('Event rate per second') }}</th><td id="event_rate">{{ lang._('Loading') }}</td></tr>
                <tr><th>{{ lang._('Events last 24 hours') }}</th><td id="events_24h">{{ lang._('Loading') }}</td></tr>
                <tr><th>{{ lang._('Open incidents') }}</th><td id="open_incidents">{{ lang._('Loading') }}</td></tr>
                <tr><th>{{ lang._('Critical incidents') }}</th><td id="critical_incidents">{{ lang._('Loading') }}</td></tr>
                <tr><th>{{ lang._('Blocked sources') }}</th><td id="blocked_sources">{{ lang._('Loading') }}</td></tr>
                <tr><th>{{ lang._('Active model version') }}</th><td id="active_model">{{ lang._('Loading') }}</td></tr>
                <tr><th>{{ lang._('Telemetry delay seconds') }}</th><td id="telemetry_delay">{{ lang._('Loading') }}</td></tr>
                <tr><th>{{ lang._('Queue utilization') }}</th><td id="queue">{{ lang._('Loading') }}</td></tr>
                <tr><th>{{ lang._('Database size bytes') }}</th><td id="database_size">{{ lang._('Loading') }}</td></tr>
                <tr><th>{{ lang._('Last collector errors') }}</th><td id="collector_errors">{{ lang._('Loading') }}</td></tr>
                <tr><th>{{ lang._('Last response errors') }}</th><td id="response_errors">{{ lang._('Loading') }}</td></tr>
            </tbody>
        </table>
    </div>
</div>

<div class="content-box">
    <h3>{{ lang._('Hosts with highest risk') }}</h3>
    <table id="top_hosts" class="table table-striped">
        <thead><tr><th>{{ lang._('IP address') }}</th><th>{{ lang._('Risk score') }}</th><th>{{ lang._('Open incidents') }}</th></tr></thead>
        <tbody><tr><td colspan="3">{{ lang._('Loading') }}</td></tr></tbody>
    </table>
</div>

<div class="content-box">
    <h3>{{ lang._('Detections by category') }}</h3>
    <table id="detections_by_category" class="table table-striped">
        <thead><tr><th>{{ lang._('Category') }}</th><th>{{ lang._('Count') }}</th></tr></thead>
        <tbody><tr><td colspan="2">{{ lang._('Loading') }}</td></tr></tbody>
    </table>
</div>
