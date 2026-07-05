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
    $('#protectionValidateAct').SimpleActionButton({
        onAction: function(data) {
            $('#protectiontest').text(JSON.stringify(data, null, 2));
            refreshDiagnostics();
        }
    });
    refreshDiagnostics();
});
</script>

<style>
.pondsec-diag {
    background: #ffffff;
    border: 1px solid #d8dee6;
    border-radius: 6px;
    padding: 14px;
}
.pondsec-diag pre {
    background: #f6f8fb;
    border: 1px solid #d8dee6;
}
</style>

<div class="pondsec-diag">
    <button class="btn btn-primary" id="selfTestAct" data-endpoint="/api/pondsecndr/diagnostics/self_test" data-label="{{ lang._('Self-test') }}"></button>
    <button class="btn btn-danger" id="protectionValidateAct" data-endpoint="/api/pondsecndr/diagnostics/protection_validate" data-label="{{ lang._('Validate protection') }}"></button>
    <h3>{{ lang._('Diagnostics') }}</h3>
    <pre id="diagnostics">{{ lang._('Loading') }}</pre>
    <h3>{{ lang._('Self-test result') }}</h3>
    <pre id="selftest">{{ lang._('No self-test result') }}</pre>
    <h3>{{ lang._('Protection validation result') }}</h3>
    <pre id="protectiontest">{{ lang._('No protection validation result') }}</pre>
</div>
