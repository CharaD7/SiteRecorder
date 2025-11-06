// Wait for Tauri API to be available
let invoke;

// DOM Elements (will be initialized in DOMContentLoaded)
let urlInput, maxPagesInput, delayInput, outputDirInput, headlessCheckbox;
let startBtn, stopBtn, recordingState, sessionId, currentUrl;
let pagesVisited, pagesDiscovered, progressBar, logContainer;
let requiresAuthCheckbox, authFields, authUrl, username, password;
let usernameSelector, passwordSelector, submitSelector;

let statusInterval = null;

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
        submit_selector: requiresAuthCheckbox.checked ? submitSelector.value.trim() : null
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

// Get default recordings directory based on platform
async function getDefaultRecordingsDir() {
    try {
        // Get user's home directory
        const homeDir = await window.__TAURI__.path.homeDir();
        
        // Get platform
        const platform = await window.__TAURI__.os.platform();
        
        let recordingsDir;
        if (platform === 'darwin') {
            // macOS: ~/Movies/SiteRecorder
            recordingsDir = await window.__TAURI__.path.join(homeDir, 'Movies', 'SiteRecorder');
        } else if (platform === 'win32') {
            // Windows: ~/Videos/SiteRecorder
            recordingsDir = await window.__TAURI__.path.join(homeDir, 'Videos', 'SiteRecorder');
        } else {
            // Linux: ~/Videos/SiteRecorder
            recordingsDir = await window.__TAURI__.path.join(homeDir, 'Videos', 'SiteRecorder');
        }
        
        return recordingsDir;
    } catch (error) {
        console.error('Failed to get default directory:', error);
        return './recordings'; // Fallback
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
    
    console.log('DOM elements initialized');
    console.log('startBtn:', startBtn);
    console.log('stopBtn:', stopBtn);
    
    if (!startBtn) {
        console.error('ERROR: Start button not found!');
        alert('ERROR: Start button not found in DOM!');
        return;
    }
    
    // Set default output directory based on platform
    const defaultDir = await getDefaultRecordingsDir();
    outputDirInput.value = defaultDir;
    
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
    
    // Advanced auth options toggle
    const showAdvancedAuth = document.getElementById('showAdvancedAuth');
    const advancedAuthFields = document.getElementById('advancedAuthFields');
    
    if (showAdvancedAuth && advancedAuthFields) {
        showAdvancedAuth.addEventListener('click', (e) => {
            e.preventDefault();
            if (advancedAuthFields.style.display === 'none') {
                advancedAuthFields.style.display = 'block';
                showAdvancedAuth.textContent = 'Hide Advanced Options';
                addLog('Advanced auth options shown', 'info');
            } else {
                advancedAuthFields.style.display = 'none';
                showAdvancedAuth.textContent = 'Show Advanced Options';
                addLog('Advanced auth options hidden', 'info');
            }
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
});
