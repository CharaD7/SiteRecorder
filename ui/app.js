// Wait for Tauri API to be available
let invoke;

// DOM Elements (will be initialized in DOMContentLoaded)
let urlInput, maxPagesInput, delayInput, outputDirInput, headlessCheckbox;
let startBtn, stopBtn, recordingState, sessionId, currentUrl;
let pagesVisited, pagesDiscovered, progressBar, logContainer;
let requiresAuthCheckbox, authFields, authUrl, username, password;
let usernameSelector, passwordSelector, submitSelector;
let recordingModeSelect, enableAudioCheckbox, screenWidthInput, screenHeightInput;

let statusInterval = null;
let scanInterval = null;

// Add log entry
function addLog(message, type = 'info') {
    const logEntry = document.createElement('div');
    logEntry.className = `log-entry ${type}`;
    
    const time = new Date().toLocaleTimeString();
    logEntry.innerHTML = `
        <span class="log-time">[${time}]</span>
        <span class="log-message">${message}</span>
    `;
    
    logContainer.appendChild(logEntry);
    logContainer.scrollTop = logContainer.scrollHeight;
}

// Update status display
async function updateStatus() {
    try {
        const status = await invoke('get_status');
        
        if (status.is_running) {
            recordingState.textContent = 'Recording';
            recordingState.classList.add('recording');
        } else {
            recordingState.textContent = 'Idle';
            recordingState.classList.remove('recording');
        }
        
        sessionId.textContent = status.session_id || '—';
        currentUrl.textContent = status.current_url || '—';
        pagesVisited.textContent = status.pages_visited;
        pagesDiscovered.textContent = status.pages_discovered;
        
        // Update progress bar
        if (status.pages_discovered > 0) {
            const progress = (status.pages_visited / Math.max(status.pages_discovered, 1)) * 100;
            progressBar.style.width = `${Math.min(progress, 100)}%`;
        } else {
            progressBar.style.width = '0%';
        }
        
    } catch (error) {
        console.error('Failed to update status:', error);
    }
}

// Start recording
async function startRecording() {
    console.log('startRecording called');
    const settings = {
        url: urlInput.value.trim(),
        max_pages: parseInt(maxPagesInput.value),
        delay_ms: parseInt(delayInput.value),
        headless: headlessCheckbox.checked,
        output_dir: outputDirInput.value.trim(),
        fps: parseInt(document.getElementById('fps').value),
        requires_auth: requiresAuthCheckbox.checked,
        auth_url: requiresAuthCheckbox.checked ? authUrl.value.trim() : null,
        username: requiresAuthCheckbox.checked ? username.value.trim() : null,
        password: requiresAuthCheckbox.checked ? password.value : null,
        username_selector: requiresAuthCheckbox.checked ? usernameSelector.value.trim() : null,
        password_selector: requiresAuthCheckbox.checked ? passwordSelector.value.trim() : null,
        submit_selector: requiresAuthCheckbox.checked ? submitSelector.value.trim() : null,
        recording_mode: recordingModeSelect.value,
        enable_audio: enableAudioCheckbox.checked,
        screen_width: parseInt(screenWidthInput.value),
        screen_height: parseInt(screenHeightInput.value),
        proxy: null,
        sitemap: null,
        scan_url: null
    };
    
    console.log('Settings:', settings);
    
    // Validation
    if (!settings.url) {
        addLog('Please enter a URL', 'error');
        return;
    }
    
    if (!settings.url.startsWith('http://') && !settings.url.startsWith('https://')) {
        addLog('URL must start with http:// or https://', 'error');
        return;
    }
    
    // Auth validation
    if (settings.requires_auth) {
        if (!settings.auth_url) {
            addLog('Please enter login page URL', 'error');
            return;
        }
        if (!settings.username || !settings.password) {
            addLog('Please enter username and password', 'error');
            return;
        }
    }
    
    try {
        addLog(`Starting recording for ${settings.url}`, 'info');
        console.log('Calling invoke with settings:', settings);
        
        const sessionId = await invoke('start_recording', { settings });
        
        console.log('Received session ID:', sessionId);
        addLog(`Recording started! Session ID: ${sessionId}`, 'success');
        
        // Update UI
        startBtn.disabled = true;
        stopBtn.disabled = false;
        disableInputs(true);
        
        // Start status polling
        statusInterval = setInterval(updateStatus, 1000);
        
    } catch (error) {
        console.error('Error in startRecording:', error);
        addLog(`Failed to start recording: ${error}`, 'error');
    }
}

// Stop recording
async function stopRecording() {
    try {
        await invoke('stop_recording');
        addLog('Recording stopped by user', 'warning');
        
        // Update UI
        startBtn.disabled = false;
        stopBtn.disabled = true;
        disableInputs(false);
        
        // Stop status polling
        if (statusInterval) {
            clearInterval(statusInterval);
            statusInterval = null;
        }
        
        // Final status update
        await updateStatus();
        
    } catch (error) {
        addLog(`Failed to stop recording: ${error}`, 'error');
    }
}

// Disable/enable inputs
function disableInputs(disabled) {
    urlInput.disabled = disabled;
    maxPagesInput.disabled = disabled;
    delayInput.disabled = disabled;
    outputDirInput.disabled = disabled;
    headlessCheckbox.disabled = disabled;
}

// ==================== VULNERABILITY SCANNER ====================

// Start vulnerability scan
async function startVulnerabilityScan() {
    const scanUrl = document.getElementById('scanUrl').value.trim();
    
    if (!scanUrl) {
        addLog('Please enter a URL to scan', 'error');
        return;
    }
    
    if (!scanUrl.startsWith('http://') && !scanUrl.startsWith('https://')) {
        addLog('Scan URL must start with http:// or https://', 'error');
        return;
    }
    
    const startScanBtn = document.getElementById('startScanBtn');
    const stopScanBtn = document.getElementById('stopScanBtn');
    const scanProgress = document.getElementById('scanProgress');
    const scanStatus = document.getElementById('scanStatus');
    const scanSummary = document.getElementById('scanSummary');
    const vulnResults = document.getElementById('vulnResults');
    
    startScanBtn.disabled = true;
    stopScanBtn.disabled = false;
    scanProgress.style.display = 'flex';
    scanSummary.style.display = 'none';
    vulnResults.style.display = 'none';
    
    addLog(`Starting vulnerability scan on: ${scanUrl}`, 'info');
    scanStatus.textContent = 'Initializing scanner...';
    
    try {
        scanStatus.textContent = 'Running security checks (15 checks)...';
        
        const report = await invoke('run_vulnerability_scan', { url: scanUrl });
        
        scanProgress.style.display = 'none';
        displayScanResults(report);
        
        addLog(`Scan completed! Risk score: ${report.summary.risk_score.toFixed(1)}/10`, 
            report.summary.vulnerable > 0 ? 'warning' : 'success');
        
    } catch (error) {
        scanProgress.style.display = 'none';
        startScanBtn.disabled = false;
        stopScanBtn.disabled = true;
        addLog(`Scan failed: ${error}`, 'error');
        console.error('Scan error:', error);
    }
}

// Display scan results
function displayScanResults(report) {
    const scanSummary = document.getElementById('scanSummary');
    const vulnResults = document.getElementById('vulnResults');
    const startScanBtn = document.getElementById('startScanBtn');
    const stopScanBtn = document.getElementById('stopScanBtn');
    
    startScanBtn.disabled = false;
    stopScanBtn.disabled = true;
    
    // Show summary
    scanSummary.style.display = 'block';
    vulnResults.style.display = 'block';
    
    // Update summary values
    const riskScore = document.getElementById('riskScore');
    riskScore.textContent = report.summary.risk_score.toFixed(1);
    
    // Color risk score
    if (report.summary.risk_score >= 7) {
        riskScore.style.color = '#f44336';
    } else if (report.summary.risk_score >= 4) {
        riskScore.style.color = '#ff9800';
    } else {
        riskScore.style.color = '#4CAF50';
    }
    
    document.getElementById('criticalCount').textContent = report.summary.critical_count;
    document.getElementById('highCount').textContent = report.summary.high_count;
    document.getElementById('mediumCount').textContent = report.summary.medium_count;
    document.getElementById('lowCount').textContent = report.summary.low_count;
    document.getElementById('infoCount').textContent = report.summary.info_count;
    document.getElementById('totalChecks').textContent = report.summary.total_checks;
    document.getElementById('vulnerableCount').textContent = report.summary.vulnerable;
    document.getElementById('warningCount').textContent = report.summary.warnings;
    
    // Calculate total scan duration
    const totalDuration = report.results.reduce((sum, r) => sum + r.scan_duration_ms, 0);
    document.getElementById('scanDuration').textContent = `${totalDuration}ms`;
    
    // Update severity bar
    const total = report.summary.total_checks || 1;
    document.getElementById('criticalBar').style.width = `${(report.summary.critical_count / total) * 100}%`;
    document.getElementById('highBar').style.width = `${(report.summary.high_count / total) * 100}%`;
    document.getElementById('mediumBar').style.width = `${(report.summary.medium_count / total) * 100}%`;
    document.getElementById('lowBar').style.width = `${(report.summary.low_count / total) * 100}%`;
    document.getElementById('infoBar').style.width = `${(report.summary.info_count / total) * 100}%`;
    
    // Build vulnerability list
    const vulnList = document.getElementById('vulnList');
    vulnList.innerHTML = '';
    
    // Sort: vulnerable first, then by severity
    const severityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4 };
    const sortedResults = [...report.results].sort((a, b) => {
        if (a.status === 'VULNERABLE' && b.status !== 'VULNERABLE') return -1;
        if (a.status !== 'VULNERABLE' && b.status === 'VULNERABLE') return 1;
        return (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5);
    });
    
    for (const result of sortedResults) {
        const item = createVulnerabilityItem(result);
        vulnList.appendChild(item);
    }
    
    // Setup filter buttons
    setupFilters();
}

// Create a vulnerability list item
function createVulnerabilityItem(result) {
    const item = document.createElement('div');
    item.className = `vuln-item ${result.status.toLowerCase()}`;
    item.dataset.status = result.status.toLowerCase();
    item.dataset.severity = result.severity.toLowerCase();
    
    const statusClass = result.status === 'VULNERABLE' ? 'vulnerable' : 
                       result.status === 'WARNING' ? 'warning' : 'safe';
    const statusIcon = result.status === 'VULNERABLE' ? '🔴' : 
                      result.status === 'WARNING' ? '🟡' : '🟢';
    const severityClass = result.severity.toLowerCase();
    
    let findingsHtml = '';
    for (const finding of result.findings) {
        const findingClass = finding.status === 'Vulnerable' ? 'vulnerable' : 
                           finding.status === 'Warning' ? 'warning' : 'safe';
        
        let detailsHtml = '';
        if (finding.details && finding.details.length > 0) {
            detailsHtml = `<div class="finding-details">
                ${finding.details.map(d => `<div class="detail-item">• ${escapeHtml(d)}</div>`).join('')}
            </div>`;
        }
        
        findingsHtml += `
            <div class="finding ${findingClass}">
                <div class="finding-header">
                    <span class="finding-icon">${finding.status === 'Vulnerable' ? '⚠️' : finding.status === 'Warning' ? '⚡' : '✅'}</span>
                    <span class="finding-title">${escapeHtml(finding.title)}</span>
                    <span class="finding-severity badge-${finding.severity.toLowerCase()}">${finding.severity}</span>
                </div>
                <div class="finding-description">${escapeHtml(finding.description)}</div>
                ${detailsHtml}
                <div class="finding-remediation">
                    <strong>Remediation:</strong> ${escapeHtml(finding.remediation)}
                </div>
                ${finding.cwe_id ? `<div class="finding-cwe">CWE: ${escapeHtml(finding.cwe_id)}</div>` : ''}
                ${finding.references.length > 0 ? `
                    <div class="finding-refs">
                        ${finding.references.map(r => `<a href="${escapeHtml(r)}" target="_blank" class="ref-link">Reference</a>`).join(' ')}
                    </div>
                ` : ''}
            </div>
        `;
    }
    
    item.innerHTML = `
        <div class="vuln-item-header" onclick="this.parentElement.classList.toggle('expanded')">
            <div class="vuln-item-main">
                <span class="status-icon">${statusIcon}</span>
                <span class="vuln-check-name">${escapeHtml(result.check_name)}</span>
                <span class="badge badge-${severityClass}">${result.severity}</span>
                <span class="badge badge-${statusClass}">${result.status}</span>
            </div>
            <div class="vuln-item-meta">
                <span class="scan-time">${result.scan_duration_ms}ms</span>
                <span class="expand-icon">▼</span>
            </div>
        </div>
        <div class="vuln-item-details">
            <div class="findings-container">
                <h4>Findings (${result.findings.length})</h4>
                ${findingsHtml}
            </div>
        </div>
    `;
    
    return item;
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Setup filter buttons
function setupFilters() {
    const filterBtns = document.querySelectorAll('.filter-btn');
    filterBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            filterBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            const filter = btn.dataset.filter;
            const items = document.querySelectorAll('.vuln-item');
            
            items.forEach(item => {
                if (filter === 'all') {
                    item.style.display = '';
                } else if (filter === 'vulnerable') {
                    item.style.display = item.dataset.status === 'vulnerable' ? '' : 'none';
                } else if (filter === 'warning') {
                    item.style.display = item.dataset.status === 'warning' ? '' : 'none';
                } else if (filter === 'not-vulnerable') {
                    item.style.display = item.dataset.status === 'not-vulnerable' ? '' : 'none';
                }
            });
        });
    });
}

// ==================== TAB NAVIGATION ====================

function setupTabs() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const tabId = btn.dataset.tab;
            
            // Update active button
            tabBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            // Show/hide tab content
            tabContents.forEach(content => {
                if (content.id === `tab-${tabId}`) {
                    content.style.display = '';
                    content.classList.add('active');
                } else {
                    content.style.display = 'none';
                    content.classList.remove('active');
                }
            });
        });
    });
}

// Get default recordings directory based on platform
async function getDefaultRecordingsDir() {
    try {
        const homeDir = await window.__TAURI__.path.homeDir();
        const platform = await window.__TAURI__.os.platform();
        
        let recordingsDir;
        if (platform === 'darwin') {
            recordingsDir = await window.__TAURI__.path.join(homeDir, 'Movies', 'SiteRecorder');
        } else if (platform === 'win32') {
            recordingsDir = await window.__TAURI__.path.join(homeDir, 'Videos', 'SiteRecorder');
        } else {
            recordingsDir = await window.__TAURI__.path.join(homeDir, 'Videos', 'SiteRecorder');
        }
        
        return recordingsDir;
    } catch (error) {
        console.error('Failed to get default directory:', error);
        return './recordings';
    }
}

// Event Listeners
document.addEventListener('DOMContentLoaded', async () => {
    console.log('DOM loaded, initializing...');
    
    // Wait for Tauri API
    if (!window.__TAURI__) {
        console.error('ERROR: Tauri API not found!');
        addLog('ERROR: Tauri API not available', 'error');
        return;
    }
    
    // Initialize Tauri invoke - try multiple paths
    if (window.__TAURI__.tauri && window.__TAURI__.tauri.invoke) {
        invoke = window.__TAURI__.tauri.invoke;
    } else if (window.__TAURI__.invoke) {
        invoke = window.__TAURI__.invoke;
    } else {
        console.error('ERROR: Cannot find invoke function!');
        addLog('ERROR: Cannot find Tauri invoke function', 'error');
        return;
    }
    console.log('Tauri API loaded');
    
    // Initialize DOM elements
    urlInput = document.getElementById('url');
    maxPagesInput = document.getElementById('maxPages');
    delayInput = document.getElementById('delay');
    outputDirInput = document.getElementById('outputDir');
    headlessCheckbox = document.getElementById('headless');
    startBtn = document.getElementById('startBtn');
    stopBtn = document.getElementById('stopBtn');
    recordingState = document.getElementById('recordingState');
    sessionId = document.getElementById('sessionId');
    currentUrl = document.getElementById('currentUrl');
    pagesVisited = document.getElementById('pagesVisited');
    pagesDiscovered = document.getElementById('pagesDiscovered');
    progressBar = document.getElementById('progressBar');
    logContainer = document.getElementById('logContainer');
    
    // Initialize auth elements
    requiresAuthCheckbox = document.getElementById('requiresAuth');
    authFields = document.getElementById('authFields');
    authUrl = document.getElementById('authUrl');
    username = document.getElementById('username');
    password = document.getElementById('password');
    usernameSelector = document.getElementById('usernameSelector');
    passwordSelector = document.getElementById('passwordSelector');
    submitSelector = document.getElementById('submitSelector');
    
    // Initialize recording mode elements
    recordingModeSelect = document.getElementById('recordingMode');
    enableAudioCheckbox = document.getElementById('enableAudio');
    screenWidthInput = document.getElementById('screenWidth');
    screenHeightInput = document.getElementById('screenHeight');
    
    console.log('DOM elements initialized');
    
    if (!startBtn) {
        console.error('ERROR: Start button not found!');
        return;
    }
    
    // Set default output directory based on platform
    const defaultDir = await getDefaultRecordingsDir();
    outputDirInput.value = defaultDir;
    
    // Set default scan URL to match main URL
    const scanUrlInput = document.getElementById('scanUrl');
    if (scanUrlInput && urlInput) {
        scanUrlInput.value = urlInput.value;
        urlInput.addEventListener('change', () => {
            scanUrlInput.value = urlInput.value;
        });
    }
    
    // Setup tabs
    setupTabs();
    
    // Attach event listeners after DOM is ready
    startBtn.addEventListener('click', () => {
        console.log('Start button clicked!');
        startRecording();
    });
    stopBtn.addEventListener('click', () => {
        console.log('Stop button clicked!');
        stopRecording();
    });
    
    // Directory picker button
    const selectDirBtn = document.getElementById('selectDirBtn');
    if (selectDirBtn) {
        selectDirBtn.addEventListener('click', async () => {
            try {
                const selected = await window.__TAURI__.dialog.open({
                    directory: true,
                    multiple: false,
                    defaultPath: outputDirInput.value || defaultDir
                });
                
                if (selected) {
                    outputDirInput.value = selected;
                    addLog(`Output directory changed to: ${selected}`, 'info');
                }
            } catch (error) {
                console.error('Failed to open directory picker:', error);
                addLog('Failed to open directory picker', 'error');
            }
        });
    }
    
    // Auth checkbox toggle
    if (requiresAuthCheckbox && authFields) {
        requiresAuthCheckbox.addEventListener('change', () => {
            if (requiresAuthCheckbox.checked) {
                authFields.style.display = 'block';
                addLog('Authentication enabled - auto-detection active', 'info');
            } else {
                authFields.style.display = 'none';
                addLog('Authentication disabled', 'info');
            }
        });
    }
    
    // Recording mode change handler
    if (recordingModeSelect) {
        recordingModeSelect.addEventListener('change', () => {
            const mode = recordingModeSelect.value;
            let description = '';
            
            if (mode === 'screen') {
                description = 'Screen recording only - Real-time capture like OBS/Kazam';
                enableAudioCheckbox.disabled = false;
            } else if (mode === 'browser') {
                description = 'Browser screenshots only - Lower resource usage';
                enableAudioCheckbox.disabled = true;
                enableAudioCheckbox.checked = false;
            } else { // both
                description = 'Both modes - Complete session coverage (recommended)';
                enableAudioCheckbox.disabled = false;
            }
            
            addLog(`Recording mode: ${description}`, 'info');
        });
    }
    
    // Advanced auth options toggle
    const showAdvancedAuth = document.getElementById('showAdvancedAuth');
    const advancedAuthFields = document.getElementById('advancedAuthFields');
    
    if (showAdvancedAuth && advancedAuthFields) {
        showAdvancedAuth.addEventListener('click', (e) => {
            e.preventDefault();
            if (advancedAuthFields.style.display === 'none') {
                advancedAuthFields.style.display = 'block';
                showAdvancedAuth.textContent = 'Hide Advanced Options';
            } else {
                advancedAuthFields.style.display = 'none';
                showAdvancedAuth.textContent = 'Show Advanced Options';
            }
        });
    }
    
    // Theme toggle
    const themeToggle = document.getElementById('themeToggle');
    const themeIcon = document.querySelector('.theme-icon');
    
    function applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        document.body.setAttribute('data-theme', theme);
        
        if (theme === 'light') {
            document.documentElement.style.colorScheme = 'light';
        } else {
            document.documentElement.style.colorScheme = 'dark';
        }
        
        const selects = document.querySelectorAll('select');
        selects.forEach(select => {
            const value = select.value;
            select.style.display = 'none';
            setTimeout(() => {
                select.style.display = '';
                select.value = value;
            }, 0);
        });
    }
    
    const savedTheme = localStorage.getItem('theme') || 'dark';
    applyTheme(savedTheme);
    themeIcon.textContent = savedTheme === 'dark' ? '🌙' : '☀️';
    
    if (themeToggle) {
        themeToggle.addEventListener('click', () => {
            const currentTheme = document.documentElement.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            
            applyTheme(newTheme);
            localStorage.setItem('theme', newTheme);
            themeIcon.textContent = newTheme === 'dark' ? '🌙' : '☀️';
            
            addLog(`Switched to ${newTheme} mode`, 'info');
        });
    }
    
    // Vulnerability scan button handlers
    const startScanBtn = document.getElementById('startScanBtn');
    const stopScanBtn = document.getElementById('stopScanBtn');
    
    if (startScanBtn) {
        startScanBtn.addEventListener('click', startVulnerabilityScan);
    }
    if (stopScanBtn) {
        stopScanBtn.addEventListener('click', () => {
            if (scanInterval) {
                clearInterval(scanInterval);
                scanInterval = null;
            }
            startScanBtn.disabled = false;
            stopScanBtn.disabled = true;
            document.getElementById('scanProgress').style.display = 'none';
            addLog('Scan stopped by user', 'warning');
        });
    }
    
    console.log('Event listeners attached');
    addLog('SiteRecorder initialized', 'success');
    await updateStatus();
});

// Cleanup on window close
window.addEventListener('beforeunload', () => {
    if (statusInterval) {
        clearInterval(statusInterval);
    }
    if (scanInterval) {
        clearInterval(scanInterval);
    }
});
