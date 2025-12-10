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
        setup_platform_signal_handlers(should_stop)
    }

    /// Check if shutdown was requested
    pub fn should_stop(&self) -> bool {
        self.should_stop.load(Ordering::SeqCst)
    }

    /// Wait for shutdown signal
    pub fn wait_for_shutdown(&self) {
        while !self.should_stop() {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
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

#[cfg(unix)]
fn setup_platform_signal_handlers(should_stop: Arc<AtomicBool>) -> Result<()> {
    use signal_hook::consts::{SIGINT, SIGTERM};
    use signal_hook::iterator::Signals;

    let mut signals = Signals::new(&[SIGTERM, SIGINT])?;
    std::thread::spawn(move || {
        for sig in signals.forever() {
            if sig == SIGTERM || sig == SIGINT {
                info!(
                    "Received shutdown signal ({}), initiating graceful shutdown",
                    sig
                );
                should_stop.store(true, Ordering::SeqCst);
                break;
            }
        }
    });

    Ok(())
}

#[cfg(windows)]
fn setup_platform_signal_handlers(should_stop: Arc<AtomicBool>) -> Result<()> {
    ctrlc::set_handler(move || {
        info!("Received Ctrl+C, initiating graceful shutdown");
        should_stop.store(true, Ordering::SeqCst);
    })?;
    Ok(())
}

/// Daemonize the process (Unix-specific)
#[cfg(unix)]
pub fn daemonize() -> Result<()> {
    info!("Daemonizing process");
    unsafe { double_fork_and_detach()?; }
    Ok(())
}

#[cfg(unix)]
unsafe fn double_fork_and_detach() -> Result<()> {
    fork_or_error("fork")?;

    if libc::setsid() < 0 {
        return Err(anyhow::anyhow!("setsid failed"));
    }

    fork_or_error("second fork")?;
    std::env::set_current_dir("/")?;

    redirect_stdio_to_devnull()?;
    Ok(())
}

#[cfg(unix)]
unsafe fn fork_or_error(context: &str) -> Result<()> {
    let pid = libc::fork();
    if pid < 0 {
        return Err(anyhow::anyhow!("{} failed", context));
    }
    if pid > 0 {
        std::process::exit(0);
    }
    Ok(())
}

#[cfg(unix)]
unsafe fn redirect_stdio_to_devnull() -> Result<()> {
    use std::ffi::CString;

    // Close existing standard file descriptors
    for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        if libc::close(fd) == -1 {
            error!(
                "daemonize: failed to close fd {}: {}",
                fd,
                std::io::Error::last_os_error()
            );
        }
    }

    let dev_null = CString::new("/dev/null")
        .expect("daemonize: CString::new(\"/dev/null\") should not fail");

    // Open /dev/null for stdin
    let stdin_fd = libc::open(dev_null.as_ptr(), libc::O_RDONLY);
    if stdin_fd == -1 {
        let err = std::io::Error::last_os_error();
        error!("daemonize: failed to open /dev/null for stdin: {}", err);
        return Err(err.into());
    }

    // Duplicate stdin to stdout
    if libc::dup2(stdin_fd, libc::STDOUT_FILENO) == -1 {
        let err = std::io::Error::last_os_error();
        error!("daemonize: failed to dup2 stdin to stdout: {}", err);
        return Err(err.into());
    }

    // Duplicate stdin to stderr
    if libc::dup2(stdin_fd, libc::STDERR_FILENO) == -1 {
        let err = std::io::Error::last_os_error();
        error!("daemonize: failed to dup2 stdin to stderr: {}", err);
        return Err(err.into());
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
