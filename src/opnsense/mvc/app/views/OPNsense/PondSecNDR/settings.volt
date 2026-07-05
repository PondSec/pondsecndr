<script>
$(function() {
    mapDataToFormUI({'frm_GeneralSettings': '/api/pondsecndr/settings/get'});
    $('#saveAct').click(function() {
        saveFormToEndpoint('/api/pondsecndr/settings/set', 'frm_GeneralSettings', function() {
            ajaxCall(url='/api/pondsecndr/service/reconfigure', sendData={}, callback=function(){});
        });
    });
});
</script>

<div class="content-box">
    {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_GeneralSettings']) }}
    <div class="col-md-12">
        <button class="btn btn-primary" id="saveAct" type="button"><b>{{ lang._('Save') }}</b></button>
    </div>
</div>
