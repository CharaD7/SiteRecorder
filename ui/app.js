// Wait for Tauri API to be available
let invoke;

// DOM Elements (will be initialized in DOMContentLoaded)
let urlInput, maxPagesInput, delayInput, outputDirInput, headlessCheckbox;
let startBtn, stopBtn, recordingState, sessionId, currentUrl;
let pagesVisited, pagesDiscovered, progressBar, logContainer;

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
        output_dir: outputDirInput.value.trim()
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

// Event Listeners
document.addEventListener('DOMContentLoaded', async () => {
    console.log('DOM loaded, initializing...');
    
    // Wait for Tauri API
    if (!window.__TAURI__) {
        console.error('ERROR: Tauri API not found!');
        alert('ERROR: Tauri API not available. Make sure you are running this in Tauri.');
        return;
    }
    
    // Initialize Tauri invoke
    invoke = window.__TAURI__.tauri.invoke;
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
    
    console.log('DOM elements initialized');
    console.log('startBtn:', startBtn);
    console.log('stopBtn:', stopBtn);
    
    if (!startBtn) {
        console.error('ERROR: Start button not found!');
        alert('ERROR: Start button not found in DOM!');
        return;
    }
    
    // Attach event listeners after DOM is ready
    startBtn.addEventListener('click', () => {
        console.log('Start button clicked!');
        startRecording();
    });
    stopBtn.addEventListener('click', () => {
        console.log('Stop button clicked!');
        stopRecording();
    });
    
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
