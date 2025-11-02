const { invoke } = window.__TAURI__.tauri;

// DOM Elements
const urlInput = document.getElementById('url');
const maxPagesInput = document.getElementById('maxPages');
const delayInput = document.getElementById('delay');
const outputDirInput = document.getElementById('outputDir');
const headlessCheckbox = document.getElementById('headless');
const startBtn = document.getElementById('startBtn');
const stopBtn = document.getElementById('stopBtn');
const recordingState = document.getElementById('recordingState');
const sessionId = document.getElementById('sessionId');
const currentUrl = document.getElementById('currentUrl');
const pagesVisited = document.getElementById('pagesVisited');
const pagesDiscovered = document.getElementById('pagesDiscovered');
const progressBar = document.getElementById('progressBar');
const logContainer = document.getElementById('logContainer');

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
    const settings = {
        url: urlInput.value.trim(),
        max_pages: parseInt(maxPagesInput.value),
        delay_ms: parseInt(delayInput.value),
        headless: headlessCheckbox.checked,
        output_dir: outputDirInput.value.trim()
    };
    
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
        
        const sessionId = await invoke('start_recording', { settings });
        
        addLog(`Recording started! Session ID: ${sessionId}`, 'success');
        
        // Update UI
        startBtn.disabled = true;
        stopBtn.disabled = false;
        disableInputs(true);
        
        // Start status polling
        statusInterval = setInterval(updateStatus, 1000);
        
    } catch (error) {
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
startBtn.addEventListener('click', startRecording);
stopBtn.addEventListener('click', stopRecording);

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    addLog('SiteRecorder initialized', 'success');
    updateStatus();
});

// Cleanup on window close
window.addEventListener('beforeunload', () => {
    if (statusInterval) {
        clearInterval(statusInterval);
    }
});
