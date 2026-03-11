/* ═══════════════════════════════════════════════════════════════
   GRC Compliance Engine — Frontend Logic
   ═══════════════════════════════════════════════════════════════ */

// ─── State ───────────────────────────────────────────────────
let currentTaskId = null;
let pollInterval = null;

// ═══════════════════════════════════════════════════════════════
//  Credential Validation
// ═══════════════════════════════════════════════════════════════

async function validateAWS() {
    const accessKey = document.getElementById('aws_access_key').value.trim();
    const secretKey = document.getElementById('aws_secret_key').value.trim();
    const statusEl = document.getElementById('aws_status');

    if (!accessKey || !secretKey) {
        setStatus(statusEl, 'error', 'Both fields are required');
        return;
    }

    setStatus(statusEl, 'loading', 'Validating AWS credentials...');

    try {
        const resp = await fetch('/api/validate/aws', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ access_key_id: accessKey, secret_access_key: secretKey }),
        });
        const data = await resp.json();
        setStatus(statusEl, data.valid ? 'success' : 'error', data.message);
    } catch (err) {
        setStatus(statusEl, 'error', `Network error: ${err.message}`);
    }
}

async function validateAzure() {
    const clientId = document.getElementById('azure_client_id').value.trim();
    const tenantId = document.getElementById('azure_tenant_id').value.trim();
    const clientSecret = document.getElementById('azure_client_secret').value.trim();
    const statusEl = document.getElementById('azure_status');

    if (!clientId || !tenantId || !clientSecret) {
        setStatus(statusEl, 'error', 'All three fields are required');
        return;
    }

    setStatus(statusEl, 'loading', 'Validating Azure SP credentials...');

    try {
        const resp = await fetch('/api/validate/azure', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ client_id: clientId, tenant_id: tenantId, client_secret: clientSecret }),
        });
        const data = await resp.json();
        setStatus(statusEl, data.valid ? 'success' : 'error', data.message);
    } catch (err) {
        setStatus(statusEl, 'error', `Network error: ${err.message}`);
    }
}

async function validateOpenAI() {
    const apiKey = document.getElementById('openai_key').value.trim();
    const model = document.getElementById('openai_model').value;
    const statusEl = document.getElementById('openai_status');

    if (!apiKey) {
        setStatus(statusEl, 'error', 'API key is required');
        return;
    }

    setStatus(statusEl, 'loading', 'Validating OpenAI key...');

    try {
        const resp = await fetch('/api/validate/openai', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ api_key: apiKey, model: model }),
        });
        const data = await resp.json();
        setStatus(statusEl, data.valid ? 'success' : 'error', data.message);
    } catch (err) {
        setStatus(statusEl, 'error', `Network error: ${err.message}`);
    }
}


// ═══════════════════════════════════════════════════════════════
//  Framework Selection (split AWS / Azure)
// ═══════════════════════════════════════════════════════════════

function updateFwCounter(provider) {
    const count = document.querySelectorAll(`#${provider}_fw_grid input[type="checkbox"]:checked`).length;
    document.getElementById(`${provider}_fw_counter`).textContent = `${count} selected`;
    updateFrameworkCounter();
}

function updateFrameworkCounter() {
    const awsCount = document.querySelectorAll('#aws_fw_grid input[type="checkbox"]:checked').length;
    const azureCount = document.querySelectorAll('#azure_fw_grid input[type="checkbox"]:checked').length;
    document.getElementById('fw_counter').textContent = `${awsCount + azureCount} selected total`;
}

function selectAllFw(provider) {
    document.querySelectorAll(`#${provider}_fw_grid .fw-checkbox`).forEach(label => {
        if (label.style.display !== 'none') {
            label.querySelector('input[type="checkbox"]').checked = true;
        }
    });
    updateFwCounter(provider);
}

function clearAllFw(provider) {
    document.querySelectorAll(`#${provider}_fw_grid input[type="checkbox"]`).forEach(cb => cb.checked = false);
    updateFwCounter(provider);
}

function filterFw(provider) {
    const search = document.getElementById(`${provider}_fw_search`).value.toLowerCase();
    document.querySelectorAll(`#${provider}_fw_grid .fw-checkbox`).forEach(label => {
        const name = label.querySelector('.fw-name').textContent.toLowerCase();
        const tag = label.querySelector('.fw-tag').textContent.toLowerCase();
        label.style.display = (name.includes(search) || tag.includes(search)) ? '' : 'none';
    });
}

// Legacy compat (no-ops if old code references them)
function selectAllFrameworks() { selectAllFw('aws'); selectAllFw('azure'); }
function clearAllFrameworks() { clearAllFw('aws'); clearAllFw('azure'); }

// Attach change listeners
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('#aws_fw_grid input[type="checkbox"]').forEach(cb => {
        cb.addEventListener('change', () => updateFwCounter('aws'));
    });
    document.querySelectorAll('#azure_fw_grid input[type="checkbox"]').forEach(cb => {
        cb.addEventListener('change', () => updateFwCounter('azure'));
    });
    updateColumnPills();

    // Update pills when textarea changes
    document.getElementById('steampipe_columns').addEventListener('input', updateColumnPills);
});


// ═══════════════════════════════════════════════════════════════
//  Rego Policy Upload
// ═══════════════════════════════════════════════════════════════

function toggleRegoUpload() {
    const isCustom = document.querySelector('input[name="rego_option"][value="custom"]').checked;
    document.getElementById('rego_upload_area').style.display = isCustom ? 'block' : 'none';

    const statusEl = document.getElementById('rego_status');
    if (!isCustom) {
        statusEl.innerHTML = '<span class="status-icon info">&#x2139;</span><span>Using default security_policy.rego from repository</span>';
        statusEl.className = 'status-box';
    }
}

async function uploadRego() {
    const fileInput = document.getElementById('rego_file');
    const statusEl = document.getElementById('rego_status');

    if (!fileInput.files.length) return;

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);

    setStatus(statusEl, 'loading', 'Uploading and sanitizing policy...');

    try {
        const resp = await fetch('/api/upload/rego', { method: 'POST', body: formData });
        const data = await resp.json();
        setStatus(statusEl, data.valid ? 'success' : 'error', data.message);
    } catch (err) {
        setStatus(statusEl, 'error', `Upload error: ${err.message}`);
    }
}


// ═══════════════════════════════════════════════════════════════
//  Scan Scope — Service / Tag / Severity / Region Helpers
// ═══════════════════════════════════════════════════════════════

const _resourceTags = [];
const _regions = [];
const _excludedServices = [];

function switchScopeTab(btn) {
    const target = btn.getAttribute('data-target');
    btn.parentElement.querySelectorAll('.scope-tab').forEach(t => t.classList.remove('active'));
    btn.classList.add('active');
    btn.closest('.scope-card').querySelectorAll('.scope-panel').forEach(p => p.style.display = 'none');
    document.getElementById(target).style.display = 'block';
}

function filterServices(provider) {
    const search = document.getElementById(`${provider}_svc_search`).value.toLowerCase();
    document.querySelectorAll(`#${provider}_svc_grid .svc-checkbox`).forEach(label => {
        const name = label.querySelector('.svc-name').textContent.toLowerCase();
        label.style.display = name.includes(search) ? '' : 'none';
    });
}

function selectAllServices(provider) {
    document.querySelectorAll(`#${provider}_svc_grid input[type="checkbox"]`).forEach(cb => {
        if (cb.closest('.svc-checkbox').style.display !== 'none') cb.checked = true;
    });
    updateServiceCounter(provider);
    updateServiceComplianceNote();
}

function clearAllServices(provider) {
    document.querySelectorAll(`#${provider}_svc_grid input[type="checkbox"]`).forEach(cb => cb.checked = false);
    updateServiceCounter(provider);
    updateServiceComplianceNote();
}

function updateServiceCounter(provider) {
    const count = document.querySelectorAll(`#${provider}_svc_grid input[type="checkbox"]:checked`).length;
    document.getElementById(`${provider}_svc_counter`).textContent = `${count} selected`;
}

function updateServiceComplianceNote() {
    const awsCount = document.querySelectorAll('#aws_svc_grid input[type="checkbox"]:checked').length;
    const azureCount = document.querySelectorAll('#azure_svc_grid input[type="checkbox"]:checked').length;
    const note = document.getElementById('service_compliance_note');
    note.style.display = (awsCount + azureCount > 0) ? 'flex' : 'none';
}

function getSelectedServices() {
    const services = [];
    document.querySelectorAll('#aws_svc_grid input[type="checkbox"]:checked').forEach(cb => services.push(cb.value));
    document.querySelectorAll('#azure_svc_grid input[type="checkbox"]:checked').forEach(cb => services.push(cb.value));
    return services;
}

function getSelectedSeverity() {
    const severity = [];
    document.querySelectorAll('input[name="severity"]:checked').forEach(cb => severity.push(cb.value));
    return severity;
}

/* Tag-pill helpers (shared pattern) */
function _addPill(list, inputId, containerId) {
    const input = document.getElementById(inputId);
    const val = input.value.trim();
    if (!val || list.includes(val)) return;
    list.push(val);
    input.value = '';
    _renderPills(list, containerId);
}

function _removePill(list, index, containerId) {
    list.splice(index, 1);
    _renderPills(list, containerId);
}

function _renderPills(list, containerId) {
    const container = document.getElementById(containerId);
    container.innerHTML = list.map((v, i) =>
        `<span class="tag-pill">${escapeHtml(v)}<button class="pill-remove" onclick="_removePill(${containerId === 'resource_tag_pills' ? '_resourceTags' : containerId === 'region_pills' ? '_regions' : '_excludedServices'}, ${i}, '${containerId}')">&times;</button></span>`
    ).join('');
}

function addResourceTag() { _addPill(_resourceTags, 'resource_tag_input', 'resource_tag_pills'); }
function addRegion()       { _addPill(_regions, 'region_input', 'region_pills'); }
function addExcludedService() { _addPill(_excludedServices, 'excluded_svc_input', 'excluded_svc_pills'); }

// Attach service checkbox listeners on DOM ready
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('#aws_svc_grid input[type="checkbox"]').forEach(cb => {
        cb.addEventListener('change', () => { updateServiceCounter('aws'); updateServiceComplianceNote(); });
    });
    document.querySelectorAll('#azure_svc_grid input[type="checkbox"]').forEach(cb => {
        cb.addEventListener('change', () => { updateServiceCounter('azure'); updateServiceComplianceNote(); });
    });
});


// ═══════════════════════════════════════════════════════════════
//  Steampipe Columns
// ═══════════════════════════════════════════════════════════════

function updateColumnPills() {
    const text = document.getElementById('steampipe_columns').value;
    const container = document.getElementById('column_pills');
    const cols = text.split(',').map(c => c.trim()).filter(Boolean);

    container.innerHTML = cols.map(c => `<span class="tag-pill">${c}</span>`).join('');
}


// ═══════════════════════════════════════════════════════════════
//  Pipeline Execution
// ═══════════════════════════════════════════════════════════════

async function runPipeline() {
    // Gather framework selections (split by provider)
    const awsFrameworks = [];
    document.querySelectorAll('#aws_fw_grid input[type="checkbox"]:checked').forEach(cb => {
        awsFrameworks.push(cb.value);
    });
    const azureFrameworks = [];
    document.querySelectorAll('#azure_fw_grid input[type="checkbox"]:checked').forEach(cb => {
        azureFrameworks.push(cb.value);
    });

    if (awsFrameworks.length === 0 && azureFrameworks.length === 0) {
        const fwStatus = document.getElementById('fw_status');
        setStatus(fwStatus, 'error', 'Select at least one compliance framework (AWS or Azure)');
        return;
    }

    const awsAccessKey = document.getElementById('aws_access_key').value.trim();
    const awsSecretKey = document.getElementById('aws_secret_key').value.trim();
    const azureClientId = document.getElementById('azure_client_id').value.trim();
    const azureTenantId = document.getElementById('azure_tenant_id').value.trim();
    const azureClientSecret = document.getElementById('azure_client_secret').value.trim();
    const openaiKey = document.getElementById('openai_key').value.trim();
    const openaiModel = document.getElementById('openai_model').value;

    if (!awsAccessKey && !azureClientId) {
        alert('Provide at least one cloud provider credentials (AWS or Azure)');
        return;
    }

    if (!openaiKey) {
        alert('OpenAI API key is required');
        return;
    }

    const columnsText = document.getElementById('steampipe_columns').value;
    const columns = columnsText.split(',').map(c => c.trim()).filter(Boolean);

    const useDefaultRego = document.querySelector('input[name="rego_option"][value="default"]').checked;

    // Prepare payload
    const payload = {
        aws_frameworks: awsFrameworks,
        azure_frameworks: azureFrameworks,
        steampipe_columns: columns,
        use_default_rego: useDefaultRego,
        openai_api_key: openaiKey,
        openai_model: openaiModel,
        // Scan scope filters
        services: getSelectedServices(),
        severity: getSelectedSeverity(),
        resource_tags: [..._resourceTags],
        regions: [..._regions],
        excluded_services: [..._excludedServices],
    };

    if (awsAccessKey && awsSecretKey) {
        payload.aws_access_key_id = awsAccessKey;
        payload.aws_secret_access_key = awsSecretKey;
    }
    if (azureClientId && azureTenantId && azureClientSecret) {
        payload.azure_client_id = azureClientId;
        payload.azure_tenant_id = azureTenantId;
        payload.azure_client_secret = azureClientSecret;
    }

    // Disable button
    const scanBtn = document.getElementById('scan_btn');
    scanBtn.disabled = true;
    scanBtn.innerHTML = '<span class="spinner"></span> Pipeline Running...';

    // Show results section
    document.getElementById('results_section').style.display = 'block';
    resetPipelineUI();

    // Clear logs
    document.getElementById('log_output').innerHTML = '';

    try {
        const resp = await fetch('/api/run-pipeline', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const data = await resp.json();

        if (data.error) {
            addLog('ERROR: ' + data.error);
            scanBtn.disabled = false;
            scanBtn.innerHTML = '<span class="btn-icon">&#x1F50D;</span> SCAN, REMEDIATE & ANALYZE';
            return;
        }

        currentTaskId = data.task_id;
        addLog(`Pipeline started (task: ${data.task_id})`);

        // Start polling
        pollInterval = setInterval(() => pollPipelineStatus(data.task_id), 1500);
    } catch (err) {
        addLog(`Failed to start pipeline: ${err.message}`);
        scanBtn.disabled = false;
        scanBtn.innerHTML = '<span class="btn-icon">&#x1F50D;</span> SCAN, REMEDIATE & ANALYZE';
    }
}


async function pollPipelineStatus(taskId) {
    try {
        const resp = await fetch(`/api/pipeline-status/${taskId}`);
        const task = await resp.json();

        if (task.error) {
            clearInterval(pollInterval);
            return;
        }

        // Update steps
        const steps = ['prowler', 'embeddings', 'remediation', 'opa_validation',
                       'steampipe', 'risk_quantification', 'report', 'dashboard'];

        steps.forEach(step => {
            const stepData = task.steps[step];
            if (!stepData) return;

            const rowEl = document.getElementById(`step_${step}`);
            const indicator = rowEl.querySelector('.step-indicator');
            const msgEl = document.getElementById(`msg_${step}`);
            const downloadBtn = rowEl.querySelector('button');

            // Update indicator
            indicator.className = `step-indicator ${stepData.status}`;
            rowEl.className = `step-row ${stepData.status === 'running' ? 'active' : stepData.status}`;
            msgEl.textContent = stepData.message || capitalizeStatus(stepData.status);

            // Enable download button when completed
            if (stepData.status === 'completed' && downloadBtn) {
                downloadBtn.disabled = false;
            }
        });

        // Update logs
        const logEl = document.getElementById('log_output');
        logEl.innerHTML = task.logs.map(l =>
            `<div class="log-line"><span class="log-time">${l.time}</span>${escapeHtml(l.message)}</div>`
        ).join('');
        logEl.scrollTop = logEl.scrollHeight;

        // Update summary if risk data available
        if (task.outputs && task.outputs.risk_quantification) {
            updateSummary(task.outputs);
        }

        // Check if done
        if (task.status === 'completed' || task.status === 'failed') {
            clearInterval(pollInterval);
            const scanBtn = document.getElementById('scan_btn');
            scanBtn.disabled = false;
            scanBtn.innerHTML = '<span class="btn-icon">&#x1F50D;</span> SCAN, REMEDIATE & ANALYZE';

            if (task.status === 'completed') {
                addLog('Pipeline completed successfully!');
            } else {
                addLog('Pipeline failed: ' + (task.error || 'Unknown error'));
            }
        }
    } catch (err) {
        // Silently retry
    }
}


// ═══════════════════════════════════════════════════════════════
//  Downloads & Dashboard
// ═══════════════════════════════════════════════════════════════

function downloadStep(step) {
    if (!currentTaskId) return;
    window.open(`/api/download/${currentTaskId}/${step}`, '_blank');
}

async function launchDashboard() {
    if (!currentTaskId) return;

    try {
        const resp = await fetch('/api/launch-dashboard', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ task_id: currentTaskId }),
        });
        const data = await resp.json();

        if (data.success) {
            addLog(`Dashboard launched at ${data.url}`);
            setTimeout(() => window.open(data.url, '_blank'), 2000);
        } else {
            addLog(`Dashboard error: ${data.message}`);
        }
    } catch (err) {
        addLog(`Dashboard launch failed: ${err.message}`);
    }
}


// ═══════════════════════════════════════════════════════════════
//  UI Helpers
// ═══════════════════════════════════════════════════════════════

function setStatus(el, type, message) {
    const icons = { success: '&#x2714;', error: '&#x2718;', loading: '', info: '&#x2139;' };
    const iconHtml = type === 'loading'
        ? '<span class="spinner"></span>'
        : `<span class="status-icon ${type}">${icons[type] || ''}</span>`;
    el.innerHTML = `${iconHtml}<span>${escapeHtml(message)}</span>`;
    el.className = `status-box ${type}`;
}

function addLog(message) {
    const logEl = document.getElementById('log_output');
    const now = new Date().toTimeString().slice(0, 8);
    logEl.innerHTML += `<div class="log-line"><span class="log-time">${now}</span>${escapeHtml(message)}</div>`;
    logEl.scrollTop = logEl.scrollHeight;
}

function resetPipelineUI() {
    const steps = ['prowler', 'embeddings', 'remediation', 'opa_validation',
                   'steampipe', 'risk_quantification', 'report', 'dashboard'];

    steps.forEach(step => {
        const rowEl = document.getElementById(`step_${step}`);
        rowEl.className = 'step-row';
        rowEl.querySelector('.step-indicator').className = 'step-indicator pending';
        document.getElementById(`msg_${step}`).textContent = 'Pending...';
        const btn = rowEl.querySelector('button');
        if (btn) btn.disabled = true;
    });

    document.getElementById('summary_grid').style.display = 'none';
}

function updateSummary(outputs) {
    const grid = document.getElementById('summary_grid');
    grid.style.display = 'grid';

    const risk = outputs.risk_quantification || {};
    const sev = risk.severity_distribution || {};

    document.getElementById('sum_findings').textContent = risk.total_findings || 0;
    document.getElementById('sum_critical').textContent = sev.Critical || 0;
    document.getElementById('sum_high').textContent = sev.High || 0;

    const ale = risk.total_ale || 0;
    document.getElementById('sum_ale').textContent = ale >= 1000000
        ? `$${(ale / 1000000).toFixed(1)}M`
        : ale >= 1000
            ? `$${(ale / 1000).toFixed(0)}K`
            : `$${ale.toFixed(0)}`;

    const rem = outputs.remediation || {};
    document.getElementById('sum_remediations').textContent = rem.generated || 0;

    const opa = outputs.opa_validation || {};
    document.getElementById('sum_opa_pass').textContent = `${opa.compliant || 0}/${opa.total_checked || 0}`;
}

function capitalizeStatus(s) {
    if (!s) return '';
    return s.charAt(0).toUpperCase() + s.slice(1).replace('_', ' ');
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
