<script>
$(function() {
    mapDataToFormUI({'frm_GeneralSettings': '/api/pondsecndr/settings/get'});

    function showSaveState(state, message) {
        var tone = state === 'ok' ? 'good' : (state === 'saving' ? 'info' : 'bad');
        $('#pondsec_save_state').html('<span class="pondsec-badge ' + tone + '">' + state + '</span><span>' + message + '</span>');
    }

    function enhanceFormSections() {
        var headers = $('#frm_GeneralSettings').find('.control-label, h1, h2, h3, h4, legend, label').filter(function() {
            return ['Engine', 'Interfaces', 'Detection', 'Threat intelligence enrichment', 'Zeek telemetry', 'Response'].indexOf($.trim($(this).text())) !== -1;
        });
        headers.each(function() {
            var text = $.trim($(this).text());
            $(this).closest('.form-group, tr, div').addClass('pondsec-form-heading').attr('data-heading', text);
        });
        $('#frm_GeneralSettings').addClass('pondsec-native-form');
    }

    $('.pondsec-settings-nav button').on('click', function() {
        $('.pondsec-settings-nav button').removeClass('active');
        $(this).addClass('active');
        var selector = $(this).data('target');
        if (selector) {
            var target = $(selector);
            if (target.length) {
                $('html, body').animate({scrollTop: target.offset().top - 90}, 250);
            }
        }
    });

    $('#saveAct').click(function() {
        showSaveState('saving', 'Saving configuration...');
        saveFormToEndpoint('/api/pondsecndr/settings/set', 'frm_GeneralSettings', function() {
            ajaxCall(url='/api/pondsecndr/service/reconfigure', sendData={}, callback=function() {
                showSaveState('ok', 'Configuration saved and service reconfigured.');
            });
        });
    });

    $('#pondsec_runtime_reset').on('click', function() {
        var confirmed = window.confirm('Reset PondSec runtime data, incidents, detections, blocks, hosts, and learning baselines? Configuration, allowlist, policies, and models are kept. The AI learning phase starts from day 0.');
        if (!confirmed) {
            return;
        }
        showSaveState('saving', 'Resetting runtime state...');
        ajaxCall('/api/pondsecndr/service/resetRuntime', {}, function(data) {
            if (data && data.status === 'ok') {
                showSaveState('ok', 'Runtime reset completed. Learning starts again from day 0.');
            } else {
                showSaveState('failed', (data && (data.message || data.status)) ? (data.message || data.status) : 'Runtime reset failed.');
            }
        });
    });

    setTimeout(enhanceFormSections, 250);
});
</script>

<style>
.pondsec-settings-page {
    background: #151d26;
    color: #c8d2dc;
    min-height: 760px;
    padding: 18px;
}
.pondsec-settings-page * {
    box-sizing: border-box;
}
.pondsec-settings-head,
.pondsec-settings-shell,
.pondsec-settings-main,
.pondsec-setup-card,
.pondsec-savebar {
    background: #202a36;
    border: 1px solid #2a3544;
    border-radius: 6px;
}
.pondsec-settings-head {
    align-items: center;
    display: flex;
    gap: 18px;
    justify-content: space-between;
    margin-bottom: 14px;
    padding: 18px;
}
.pondsec-settings-head h2 {
    color: #f5f8fb;
    font-size: 24px;
    font-weight: 600;
    margin: 0;
}
.pondsec-settings-head p {
    color: #8f9dac;
    margin: 7px 0 0;
}
.pondsec-mode-pills {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
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
.pondsec-setup-grid {
    display: grid;
    gap: 12px;
    grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
    margin-bottom: 14px;
}
.pondsec-setup-card {
    min-height: 132px;
    padding: 14px;
}
.pondsec-danger-card {
    border-color: rgba(246, 86, 97, 0.45);
}
.pondsec-setup-card span {
    color: #8f9dac;
    display: block;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
}
.pondsec-setup-card strong {
    color: #f1f6fb;
    display: block;
    font-size: 16px;
    margin: 10px 0 8px;
}
.pondsec-setup-card p {
    color: #9ba8b6;
    margin: 0;
}
.pondsec-settings-shell {
    display: grid;
    grid-template-columns: 270px minmax(0, 1fr);
    overflow: hidden;
}
.pondsec-settings-nav {
    background: #18212c;
    border-right: 1px solid #2a3544;
    padding: 14px;
}
.pondsec-settings-nav button {
    align-items: center;
    background: transparent;
    border: 0;
    border-left: 3px solid transparent;
    color: #aab6c4;
    display: flex;
    font-size: 14px;
    gap: 10px;
    padding: 12px 10px;
    text-align: left;
    width: 100%;
}
.pondsec-settings-nav button.active,
.pondsec-settings-nav button:hover {
    background: #202a36;
    border-left-color: #49a6ff;
    color: #edf3f8;
}
.pondsec-settings-main {
    border: 0;
    border-radius: 0;
    padding: 0;
}
.pondsec-settings-intro {
    border-bottom: 1px solid #2a3544;
    padding: 22px 28px;
}
.pondsec-settings-intro h3 {
    color: #f1f6fb;
    font-size: 20px;
    margin: 0 0 8px;
}
.pondsec-settings-intro p {
    color: #91a0b0;
    margin: 0;
}
.pondsec-form-wrap {
    padding: 18px 28px 82px;
}
.pondsec-native-form {
    max-width: 1180px;
}
.pondsec-native-form .form-group,
.pondsec-native-form tr {
    border-bottom: 1px solid #2a3544;
    margin-bottom: 0;
    padding-bottom: 12px;
    padding-top: 12px;
}
.pondsec-native-form .control-label,
.pondsec-native-form label {
    color: #aab6c4;
    font-weight: 600;
}
.pondsec-native-form input,
.pondsec-native-form select,
.pondsec-native-form textarea,
.pondsec-native-form .select2-choice,
.pondsec-native-form .select2-choices,
.pondsec-native-form .select2-container-multi .select2-choices {
    background: #151d26 !important;
    border-color: #334153 !important;
    border-radius: 5px !important;
    color: #e5edf5 !important;
}
.pondsec-native-form .help-block,
.pondsec-native-form .text-muted {
    color: #8795a5;
}
.pondsec-form-heading {
    background: #18212c;
    border-bottom: 1px solid #334153 !important;
    margin-top: 18px;
    padding: 15px !important;
}
.pondsec-form-heading label,
.pondsec-form-heading .control-label,
.pondsec-form-heading h1,
.pondsec-form-heading h2,
.pondsec-form-heading h3,
.pondsec-form-heading h4,
.pondsec-form-heading legend {
    color: #f1f6fb !important;
    font-size: 18px;
    text-align: left !important;
}
.pondsec-savebar {
    align-items: center;
    bottom: 18px;
    display: flex;
    gap: 14px;
    justify-content: space-between;
    left: 610px;
    padding: 12px 14px;
    position: sticky;
    right: 28px;
    z-index: 5;
}
.pondsec-reset-panel {
    background: #18212c;
    border: 1px solid rgba(246, 86, 97, 0.45);
    border-radius: 6px;
    margin-top: 18px;
    max-width: 1180px;
    padding: 16px;
}
.pondsec-reset-panel h4 {
    color: #f5f8fb;
    margin: 0 0 8px;
}
.pondsec-reset-panel p {
    color: #9ba8b6;
    margin: 0 0 12px;
}
#pondsec_save_state {
    align-items: center;
    color: #9ba8b6;
    display: flex;
    gap: 10px;
}
@media (max-width: 1250px) {
    .pondsec-setup-grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
    }
    .pondsec-settings-shell {
        grid-template-columns: 1fr;
    }
    .pondsec-settings-nav {
        border-right: 0;
        border-bottom: 1px solid #2a3544;
        display: grid;
        gap: 6px;
        grid-template-columns: repeat(2, minmax(0, 1fr));
    }
}
@media (max-width: 760px) {
    .pondsec-settings-head,
    .pondsec-savebar {
        align-items: stretch;
        flex-direction: column;
    }
    .pondsec-setup-grid,
    .pondsec-settings-nav {
        grid-template-columns: 1fr;
    }
}
</style>

<div class="pondsec-settings-page">
    <div class="pondsec-settings-head">
        <div>
            <h2>PondSec NDR: {{ lang._('Settings') }}</h2>
            <p>{{ lang._('Configure telemetry, interfaces, AI detection, response policy, and privacy defaults from one guided view.') }}</p>
        </div>
        <div class="pondsec-mode-pills">
            <span class="pondsec-badge info">{{ lang._('Suricata EVE required') }}</span>
            <span class="pondsec-badge info">{{ lang._('AI learning phase default') }}</span>
            <span class="pondsec-badge info">{{ lang._('TLS inspection optional') }}</span>
            <span class="pondsec-badge good">{{ lang._('Fail open default') }}</span>
        </div>
    </div>

    <div class="pondsec-setup-grid">
        <div class="pondsec-setup-card">
            <span>{{ lang._('Required') }}</span>
            <strong>{{ lang._('Suricata EVE JSON') }}</strong>
            <p>{{ lang._('PondSec needs Suricata EVE telemetry. Enable Suricata and EVE JSON logging before production use.') }}</p>
        </div>
        <div class="pondsec-setup-card">
            <span>{{ lang._('Required') }}</span>
            <strong>{{ lang._('Interfaces') }}</strong>
            <p>{{ lang._('Select WAN, internal, DMZ, VLAN, and management roles so response policies know what to protect.') }}</p>
        </div>
        <div class="pondsec-setup-card">
            <span>{{ lang._('AI') }}</span>
            <strong>{{ lang._('Pretrained model') }}</strong>
            <p>{{ lang._('Machine-learning detections require the verified local pretrained model and a successful self-test.') }}</p>
        </div>
        <div class="pondsec-setup-card">
            <span>{{ lang._('AI safety') }}</span>
            <strong>{{ lang._('Learning mode') }}</strong>
            <p>{{ lang._('Keep AI alarms in learning mode for 14 days. Early activation is possible, but should be treated as a high false-positive risk.') }}</p>
        </div>
        <div class="pondsec-setup-card">
            <span>{{ lang._('Optional') }}</span>
            <strong>{{ lang._('TLS inspection') }}</strong>
            <p>{{ lang._('Zenarmor or Squid TLS inspection can improve HTTP visibility when deployed legally and safely.') }}</p>
        </div>
        <div class="pondsec-setup-card">
            <span>{{ lang._('Safety') }}</span>
            <strong>{{ lang._('Observe first') }}</strong>
            <p>{{ lang._('Start in Observe mode. Internal auto-isolation requires Enforce mode, AI full decision mode, stable baselines, and protected asset checks.') }}</p>
        </div>
    </div>

    <div class="pondsec-settings-shell">
        <nav class="pondsec-settings-nav">
            <button type="button" class="active" data-target=".pondsec-settings-intro"><i class="fa fa-sliders"></i> {{ lang._('Configuration') }}</button>
            <button type="button" data-target=".pondsec-native-form"><i class="fa fa-database"></i> {{ lang._('Reporting and data') }}</button>
            <button type="button" data-target=".pondsec-native-form"><i class="fa fa-shield"></i> {{ lang._('Detection') }}</button>
            <button type="button" data-target=".pondsec-native-form"><i class="fa fa-plug"></i> {{ lang._('Interfaces') }}</button>
            <button type="button" data-target=".pondsec-native-form"><i class="fa fa-ban"></i> {{ lang._('Response policy') }}</button>
            <button type="button" data-target=".pondsec-native-form"><i class="fa fa-lock"></i> {{ lang._('Privacy') }}</button>
            <button type="button" data-target=".pondsec-reset-panel"><i class="fa fa-refresh"></i> {{ lang._('Reset') }}</button>
        </nav>
        <main class="pondsec-settings-main">
            <div class="pondsec-settings-intro">
                <h3>{{ lang._('Deployment configuration') }}</h3>
                <p>{{ lang._('Start in monitor mode, verify Diagnostics, then move to alert, interactive, or prevent mode when Allowlist and PF response are proven.') }}</p>
            </div>
            <div class="pondsec-form-wrap">
                {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_GeneralSettings']) }}
                <div class="pondsec-reset-panel">
                    <h4><i class="fa fa-refresh"></i> {{ lang._('Start PondSec learning from scratch') }}</h4>
                    <p>{{ lang._('Clears runtime telemetry, detections, incidents, response blocks, host state, and AI baselines. Configuration, allowlist, policies, and model artifacts are kept.') }}</p>
                    <button class="btn btn-danger" id="pondsec_runtime_reset" type="button"><i class="fa fa-warning"></i> {{ lang._('Reset runtime data and restart learning') }}</button>
                </div>
                <div class="pondsec-savebar">
                    <div id="pondsec_save_state"><span class="pondsec-badge info">{{ lang._('ready') }}</span><span>{{ lang._('Review changes before saving.') }}</span></div>
                    <button class="btn btn-primary" id="saveAct" type="button"><i class="fa fa-save"></i> <b>{{ lang._('Save and apply') }}</b></button>
                </div>
            </div>
        </main>
    </div>
</div>
