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
        $('[data-metric="event_rate"]').text(valueOrEmpty(metrics.event_rate_per_second));
        $('[data-metric="events_24h"]').text(valueOrEmpty(metrics.events_last_24h));
        $('[data-metric="open_incidents"]').text(valueOrEmpty(metrics.open_incidents));
        $('[data-metric="critical_incidents"]').text(valueOrEmpty(metrics.critical_incidents));
        $('[data-metric="blocked_sources"]').text(valueOrEmpty(metrics.blocked_sources));
        $('[data-metric="telemetry_delay"]').text(valueOrEmpty(metrics.telemetry_delay_seconds));
        $('[data-metric="queue"]').text(valueOrEmpty(metrics.queue_utilization));
        $('[data-metric="database_size"]').text(valueOrEmpty(metrics.database_size_bytes));
        $('#hero_status').text(valueOrEmpty(metrics.service_status));
        $('#hero_mode').text(valueOrEmpty(metrics.operating_mode));
        $('#hero_model').text(valueOrEmpty(metrics.active_model_version));

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

<style>
.pondsec-hero {
    background: #17212f;
    color: #f7fbff;
    border-radius: 6px;
    padding: 18px 20px;
    margin-bottom: 16px;
}
.pondsec-hero h2 {
    margin: 0 0 12px 0;
    font-size: 24px;
    font-weight: 600;
}
.pondsec-statusbar {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 10px;
}
.pondsec-statusitem {
    background: rgba(255, 255, 255, 0.08);
    border: 1px solid rgba(255, 255, 255, 0.14);
    border-radius: 6px;
    padding: 10px 12px;
}
.pondsec-label {
    color: #9fb2c8;
    font-size: 12px;
    text-transform: uppercase;
}
.pondsec-value {
    font-size: 20px;
    font-weight: 600;
    line-height: 1.3;
}
.pondsec-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 12px;
    margin-bottom: 16px;
}
.pondsec-kpi {
    background: #ffffff;
    border: 1px solid #d8dee6;
    border-left: 4px solid #2f80ed;
    border-radius: 6px;
    padding: 12px;
    min-height: 88px;
}
.pondsec-kpi.warning { border-left-color: #f2994a; }
.pondsec-kpi.danger { border-left-color: #d64545; }
.pondsec-kpi.neutral { border-left-color: #6b7785; }
.pondsec-kpi .pondsec-value {
    color: #17212f;
    font-size: 26px;
}
.pondsec-panels {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 16px;
}
.pondsec-panel {
    background: #ffffff;
    border: 1px solid #d8dee6;
    border-radius: 6px;
    padding: 14px;
}
.pondsec-panel h3 {
    margin-top: 0;
    font-size: 18px;
}
@media (max-width: 991px) {
    .pondsec-grid,
    .pondsec-panels,
    .pondsec-statusbar {
        grid-template-columns: 1fr;
    }
}
</style>

<div class="pondsec-hero">
    <h2>{{ lang._('PondSec NDR') }}</h2>
    <div class="pondsec-statusbar">
        <div class="pondsec-statusitem">
            <div class="pondsec-label">{{ lang._('Service') }}</div>
            <div class="pondsec-value" id="hero_status">{{ lang._('Loading') }}</div>
        </div>
        <div class="pondsec-statusitem">
            <div class="pondsec-label">{{ lang._('Mode') }}</div>
            <div class="pondsec-value" id="hero_mode">{{ lang._('Loading') }}</div>
        </div>
        <div class="pondsec-statusitem">
            <div class="pondsec-label">{{ lang._('Active model') }}</div>
            <div class="pondsec-value" id="hero_model">{{ lang._('Loading') }}</div>
        </div>
    </div>
</div>

<div class="pondsec-grid">
    <div class="pondsec-kpi">
        <div class="pondsec-label">{{ lang._('Event rate') }}</div>
        <div class="pondsec-value" data-metric="event_rate">{{ lang._('Loading') }}</div>
    </div>
    <div class="pondsec-kpi">
        <div class="pondsec-label">{{ lang._('Events 24h') }}</div>
        <div class="pondsec-value" data-metric="events_24h">{{ lang._('Loading') }}</div>
    </div>
    <div class="pondsec-kpi warning">
        <div class="pondsec-label">{{ lang._('Open incidents') }}</div>
        <div class="pondsec-value" data-metric="open_incidents">{{ lang._('Loading') }}</div>
    </div>
    <div class="pondsec-kpi danger">
        <div class="pondsec-label">{{ lang._('Critical incidents') }}</div>
        <div class="pondsec-value" data-metric="critical_incidents">{{ lang._('Loading') }}</div>
    </div>
    <div class="pondsec-kpi neutral">
        <div class="pondsec-label">{{ lang._('Blocked sources') }}</div>
        <div class="pondsec-value" data-metric="blocked_sources">{{ lang._('Loading') }}</div>
    </div>
    <div class="pondsec-kpi neutral">
        <div class="pondsec-label">{{ lang._('Telemetry delay') }}</div>
        <div class="pondsec-value" data-metric="telemetry_delay">{{ lang._('Loading') }}</div>
    </div>
    <div class="pondsec-kpi neutral">
        <div class="pondsec-label">{{ lang._('Queue') }}</div>
        <div class="pondsec-value" data-metric="queue">{{ lang._('Loading') }}</div>
    </div>
    <div class="pondsec-kpi neutral">
        <div class="pondsec-label">{{ lang._('Database bytes') }}</div>
        <div class="pondsec-value" data-metric="database_size">{{ lang._('Loading') }}</div>
    </div>
</div>

<div class="pondsec-panels">
    <div class="pondsec-panel">
        <h3>{{ lang._('Hosts with highest risk') }}</h3>
        <table id="top_hosts" class="table table-striped">
            <thead><tr><th>{{ lang._('IP address') }}</th><th>{{ lang._('Risk score') }}</th><th>{{ lang._('Open incidents') }}</th></tr></thead>
            <tbody><tr><td colspan="3">{{ lang._('Loading') }}</td></tr></tbody>
        </table>
    </div>
    <div class="pondsec-panel">
        <h3>{{ lang._('Detections by category') }}</h3>
        <table id="detections_by_category" class="table table-striped">
            <thead><tr><th>{{ lang._('Category') }}</th><th>{{ lang._('Count') }}</th></tr></thead>
            <tbody><tr><td colspan="2">{{ lang._('Loading') }}</td></tr></tbody>
        </table>
    </div>
</div>

<div class="pondsec-panel" style="margin-top:16px;">
    <h3>{{ lang._('Operational detail') }}</h3>
    <div class="table-responsive">
        <table class="table table-striped">
            <tbody>
                <tr><th>{{ lang._('Service status') }}</th><td id="service_status">{{ lang._('Loading') }}</td></tr>
                <tr><th>{{ lang._('Operating mode') }}</th><td id="operating_mode">{{ lang._('Loading') }}</td></tr>
                <tr><th>{{ lang._('Monitored interfaces') }}</th><td id="interfaces">{{ lang._('Loading') }}</td></tr>
                <tr><th>{{ lang._('Active model version') }}</th><td id="active_model">{{ lang._('Loading') }}</td></tr>
                <tr><th>{{ lang._('Last collector errors') }}</th><td id="collector_errors">{{ lang._('Loading') }}</td></tr>
                <tr><th>{{ lang._('Last response errors') }}</th><td id="response_errors">{{ lang._('Loading') }}</td></tr>
            </tbody>
        </table>
    </div>
</div>
