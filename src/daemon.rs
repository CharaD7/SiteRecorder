use anyhow::Result;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{error, info, warn};

pub struct DaemonManager {
    pid_file: Option<PathBuf>,
    should_stop: Arc<AtomicBool>,
}

impl DaemonManager {
    pub fn new(pid_file: Option<PathBuf>) -> Self {
        Self {
            pid_file,
            should_stop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Initialize daemon mode
    pub fn initialize(&self) -> Result<()> {
        info!("Initializing daemon mode");

        // Write PID file if specified
        if let Some(ref pid_file) = self.pid_file {
            let pid = std::process::id();
            fs::write(pid_file, pid.to_string())?;
            info!("PID {} written to {:?}", pid, pid_file);
        }

        // Set up signal handlers
        self.setup_signal_handlers()?;

        Ok(())
    }

    /// Set up signal handlers for graceful shutdown
    fn setup_signal_handlers(&self) -> Result<()> {
        let should_stop = self.should_stop.clone();

        // Handle SIGTERM and SIGINT
        #[cfg(unix)]
        {
            use signal_hook::consts::{SIGINT, SIGTERM};
            use signal_hook::iterator::Signals;

            let mut signals = Signals::new(&[SIGTERM, SIGINT])?;
            
            std::thread::spawn(move || {
                for sig in signals.forever() {
                    match sig {
                        SIGTERM | SIGINT => {
                            info!("Received shutdown signal ({}), initiating graceful shutdown", sig);
                            should_stop.store(true, Ordering::SeqCst);
                            break;
                        }
                        _ => {}
                    }
                }
            });
        }

        #[cfg(windows)]
        {
            // Windows signal handling
            let should_stop = should_stop.clone();
            ctrlc::set_handler(move || {
                info!("Received Ctrl+C, initiating graceful shutdown");
                should_stop.store(true, Ordering::SeqCst);
            })?;
        }

        Ok(())
    }

    /// Check if shutdown was requested
    pub fn should_stop(&self) -> bool {
        self.should_stop.load(Ordering::SeqCst)
    }

    /// Get a clone of the shutdown flag
    pub fn get_shutdown_flag(&self) -> Arc<AtomicBool> {
        self.should_stop.clone()
    }

    /// Clean up daemon resources
    pub fn cleanup(&self) {
        info!("Cleaning up daemon resources");

        // Remove PID file
        if let Some(ref pid_file) = self.pid_file {
            if let Err(e) = fs::remove_file(pid_file) {
                warn!("Failed to remove PID file: {}", e);
            } else {
                info!("PID file removed");
            }
        }
    }
}

impl Drop for DaemonManager {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Daemonize the process (Unix-specific)
#[cfg(unix)]
pub fn daemonize() -> Result<()> {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    info!("Daemonizing process");

    // Fork the process
    unsafe {
        let pid = libc::fork();
        
        if pid < 0 {
            return Err(anyhow::anyhow!("Fork failed"));
        }
        
        if pid > 0 {
            // Parent process exits
            std::process::exit(0);
        }
        
        // Child process continues
        
        // Create new session
        if libc::setsid() < 0 {
            return Err(anyhow::anyhow!("setsid failed"));
        }
        
        // Fork again to prevent acquiring a controlling terminal
        let pid = libc::fork();
        
        if pid < 0 {
            return Err(anyhow::anyhow!("Second fork failed"));
        }
        
        if pid > 0 {
            // First child exits
            std::process::exit(0);
        }
        
        // Change working directory to root
        std::env::set_current_dir("/")?;
        
        // Close standard file descriptors
        libc::close(0); // stdin
        libc::close(1); // stdout
        libc::close(2); // stderr
        
        // Redirect to /dev/null
        let devnull = std::ffi::CString::new("/dev/null").unwrap();
        libc::open(devnull.as_ptr(), libc::O_RDONLY); // stdin
        libc::open(devnull.as_ptr(), libc::O_WRONLY); // stdout
        libc::open(devnull.as_ptr(), libc::O_WRONLY); // stderr
    }

    Ok(())
}

/// Daemonize on Windows (simplified)
#[cfg(windows)]
pub fn daemonize() -> Result<()> {
    warn!("True daemonization not supported on Windows, running in background mode");
    // On Windows, we just detach from console
    unsafe {
        use windows_sys::Win32::System::Console::FreeConsole;
        FreeConsole();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_manager_creation() {
        let manager = DaemonManager::new(None);
        assert!(!manager.should_stop());
    }

    #[test]
    fn test_pid_file_path() {
        let pid_file = PathBuf::from("/tmp/test.pid");
        let manager = DaemonManager::new(Some(pid_file.clone()));
        assert_eq!(manager.pid_file, Some(pid_file));
    }
}
