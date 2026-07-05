<script>
$(function() {
    function refreshStatus() {
        ajaxGet('/api/pondsecndr/service/health', {}, function(data) {
            $('#service_health').text(JSON.stringify(data, null, 2));
        });
    }
    $('#startAct').SimpleActionButton({onAction: refreshStatus});
    $('#stopAct').SimpleActionButton({onAction: refreshStatus});
    $('#restartAct').SimpleActionButton({onAction: refreshStatus});
    refreshStatus();
});
</script>

<style>
.pondsec-console {
    background: #17212f;
    color: #f7fbff;
    border-radius: 6px;
    padding: 14px;
}
.pondsec-console pre {
    background: #0f1722;
    border: 1px solid #2a394c;
    color: #f7fbff;
    margin-top: 14px;
}
</style>

<div class="pondsec-console">
    <div class="btn-group">
        <button class="btn btn-primary" id="startAct" data-endpoint="/api/pondsecndr/service/start" data-label="{{ lang._('Start') }}"></button>
        <button class="btn btn-primary" id="stopAct" data-endpoint="/api/pondsecndr/service/stop" data-label="{{ lang._('Stop') }}"></button>
        <button class="btn btn-primary" id="restartAct" data-endpoint="/api/pondsecndr/service/restart" data-label="{{ lang._('Restart') }}"></button>
    </div>
    <pre id="service_health">{{ lang._('Loading') }}</pre>
</div>
