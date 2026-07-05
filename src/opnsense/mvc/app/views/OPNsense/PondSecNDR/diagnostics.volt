<script>
$(function() {
    function refreshDiagnostics() {
        ajaxGet('/api/pondsecndr/diagnostics/get', {}, function(data) {
            $('#diagnostics').text(JSON.stringify(data, null, 2));
        });
    }
    $('#selfTestAct').SimpleActionButton({
        onAction: function(data) {
            $('#selftest').text(JSON.stringify(data, null, 2));
            refreshDiagnostics();
        }
    });
    refreshDiagnostics();
});
</script>

<div class="content-box">
    <button class="btn btn-primary" id="selfTestAct" data-endpoint="/api/pondsecndr/diagnostics/self_test" data-label="{{ lang._('Self-test') }}"></button>
    <h3>{{ lang._('Diagnostics') }}</h3>
    <pre id="diagnostics">{{ lang._('Loading') }}</pre>
    <h3>{{ lang._('Self-test result') }}</h3>
    <pre id="selftest">{{ lang._('No self-test result') }}</pre>
</div>
