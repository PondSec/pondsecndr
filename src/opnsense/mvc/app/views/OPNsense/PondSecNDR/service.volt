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

<div class="content-box">
    <div class="btn-group">
        <button class="btn btn-primary" id="startAct" data-endpoint="/api/pondsecndr/service/start" data-label="{{ lang._('Start') }}"></button>
        <button class="btn btn-primary" id="stopAct" data-endpoint="/api/pondsecndr/service/stop" data-label="{{ lang._('Stop') }}"></button>
        <button class="btn btn-primary" id="restartAct" data-endpoint="/api/pondsecndr/service/restart" data-label="{{ lang._('Restart') }}"></button>
    </div>
    <pre id="service_health">{{ lang._('Loading') }}</pre>
</div>
