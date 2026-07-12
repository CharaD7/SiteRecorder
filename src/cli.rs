use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "site-recorder")]
#[command(author = "CharaTech")]
#[command(version)]
#[command(about = "Automated site crawling and recording", long_about = None)]
pub struct Cli {
    /// Run mode: GUI or CLI
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Enable verbose logging
    #[arg(short, long, global = true, conflicts_with = "quiet")]
    pub verbose: bool,

    /// Quiet mode (minimal output)
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,
}

#[derive(Debug, Clone)]
pub struct CrawlArgs {
    pub url: String,
    pub max_pages: usize,
    pub delay: u64,
    pub output: PathBuf,
    pub recording_mode: RecordingModeArg,
    pub fps: u32,
    pub audio: bool,
    pub headless: bool,
    pub daemon: bool,
    pub progress: bool,
    pub log_file: Option<PathBuf>,
    pub pid_file: Option<PathBuf>,
    pub screen_width: u32,
    pub screen_height: u32,
    pub region: Option<(i32, i32, i32, i32)>,
    pub auth_url: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub sitemap: Option<String>,
    pub proxy: Option<String>,
    pub scan_url: Option<String>,
    pub login_script: Option<String>,
    pub concurrency: usize,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Start recording with GUI (default)
    Gui,
    
    /// Run in CLI mode without GUI
    Crawl {
        /// URL to start crawling from
        #[arg(value_name = "URL")]
        url: String,

        /// Maximum number of pages to visit
        #[arg(short = 'n', long, default_value = "50")]
        max_pages: usize,

        /// Delay between page visits in milliseconds
        #[arg(short, long, default_value = "2000")]
        delay: u64,

        /// Output directory for recordings
        #[arg(short, long, default_value = "./recordings")]
        output: PathBuf,

        /// Recording mode
        #[arg(short = 'm', long, default_value = "both")]
        recording_mode: RecordingModeArg,

        /// Frames per second for recording
        #[arg(short, long, default_value = "30")]
        fps: u32,

        /// Enable audio recording (screen mode only)
        #[arg(short, long)]
        audio: bool,

        /// Run browser in headless mode
        #[arg(long)]
        headless: bool,

        /// Run as a daemon (background process)
        #[arg(long)]
        daemon: bool,

        /// Show progress bar (disabled in daemon mode)
        #[arg(long, default_value = "true")]
        progress: bool,

        /// Log file path (for daemon mode)
        #[arg(long)]
        log_file: Option<PathBuf>,

        /// PID file path (for daemon mode)
        #[arg(long)]
        pid_file: Option<PathBuf>,

        /// Screen width for recording
        #[arg(long, default_value = "1920")]
        screen_width: u32,

        /// Screen height for recording
        #[arg(long, default_value = "1080")]
        screen_height: u32,

        /// Screen region to record as WxH+X+Y (e.g., 1280x720+100+50)
        #[arg(long, value_parser = parse_region)]
        region: Option<(i32, i32, i32, i32)>,

        /// Login URL (if authentication required)
        #[arg(long)]
        auth_url: Option<String>,

        /// Username for authentication
        #[arg(long)]
        username: Option<String>,

        /// Password for authentication
        #[arg(long)]
        password: Option<String>,

        /// Read URLs from sitemap.xml
        #[arg(long)]
        sitemap: Option<String>,

        /// Proxy URL (e.g., http://proxy:8080)
        #[arg(long)]
        proxy: Option<String>,

        /// Run vulnerability scan on URL after crawl
        #[arg(long)]
        scan_url: Option<String>,

        /// Path to a custom login script (JavaScript) executed in the page context
        #[arg(long)]
        login_script: Option<String>,

        /// Number of concurrent crawl workers for parallel link discovery
        #[arg(short = 'j', long, default_value = "1")]
        concurrency: usize,
    },
    
    /// Resume an interrupted session
    Resume {
        /// Session ID to resume
        #[arg(value_name = "SESSION_ID")]
        session_id: String,
    },
    
    /// List previous recording sessions
    List {
        /// Output directory to list sessions from
        #[arg(short, long, default_value = "./recordings")]
        output: PathBuf,
    },

    /// Run the vulnerability scanner standalone (no recording)
    Scan {
        /// Target URL to scan
        #[arg(short, long)]
        url: Option<String>,

        /// Output directory for saving scan reports
        #[arg(short, long, default_value = "./recordings")]
        output: PathBuf,

        /// Maximum crawl depth when discovering pages
        #[arg(long, default_value = "3")]
        max_depth: usize,

        /// Maximum number of pages to discover
        #[arg(long, default_value = "50")]
        max_pages: usize,

        /// List saved scans in the output directory
        #[arg(long)]
        list: bool,

        /// Export a saved scan by id (use with --format)
        #[arg(long)]
        export_id: Option<String>,

        /// Export format: json or csv
        #[arg(long, default_value = "json")]
        format: String,
    },
}

impl Commands {
    /// Convert Crawl command into CrawlArgs by consuming self
    pub fn into_crawl_args(self) -> CrawlArgs {
        match self {
            Commands::Crawl {
                url,
                max_pages,
                delay,
                output,
                recording_mode,
                fps,
                audio,
                headless,
                daemon,
                progress,
                log_file,
                pid_file,
                screen_width,
                screen_height,
                region,
                auth_url,
                username,
                password,
                sitemap,
                proxy,
                scan_url,
                login_script,
                concurrency,
            } => {
                let login_script = login_script
                    .map(|path| {
                        std::fs::read_to_string(&path)
                            .unwrap_or_else(|e| panic!("Failed to read login script {}: {}", path, e))
                    });
                CrawlArgs {
                    url,
                    max_pages,
                    delay,
                    output,
                    recording_mode,
                    fps,
                    audio,
                    headless,
                    daemon,
                    progress,
                    log_file,
                    pid_file,
                    screen_width,
                    screen_height,
                    auth_url,
                    username,
                    password,
                    sitemap,
                    proxy,
                    scan_url,
                    login_script,
                    concurrency,
                    region,
                }
            }
            _ => panic!("into_crawl_args called on non-Crawl command"),
        }
    }
}

/// Parse a screen region in the form `WxH+X+Y` (e.g. `1280x720+100+50`).
fn parse_region(s: &str) -> Result<(i32, i32, i32, i32), String> {
    let parts: Vec<&str> = s.split('+').collect();
    if parts.len() != 3 {
        return Err("Region must be in the form WxH+X+Y".to_string());
    }
    let dims: Vec<&str> = parts[0].split('x').collect();
    if dims.len() != 2 {
        return Err("Region size must be in the form WxH".to_string());
    }
    let w = dims[0]
        .trim()
        .parse::<i32>()
        .map_err(|_| "Invalid width".to_string())?;
    let h = dims[1]
        .trim()
        .parse::<i32>()
        .map_err(|_| "Invalid height".to_string())?;
    let x = parts[1]
        .trim()
        .parse::<i32>()
        .map_err(|_| "Invalid x offset".to_string())?;
    let y = parts[2]
        .trim()
        .parse::<i32>()
        .map_err(|_| "Invalid y offset".to_string())?;
    if w <= 0 || h <= 0 {
        return Err("Width and height must be positive".to_string());
    }
    Ok((x, y, w, h))
}

#[derive(Debug, Clone, ValueEnum)]
pub enum RecordingModeArg {
    /// Record screen only
    Screen,
    /// Record browser screenshots only
    Browser,
    /// Record both screen and screenshots
    Both,
}

impl Cli {
    pub fn parse_args() -> Self {
        Self::parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parsing() {
        // Test basic crawl command
        let cli = Cli::try_parse_from(&[
            "site-recorder",
            "crawl",
            "https://example.com",
            "--max-pages", "100",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_recording_modes() {
        let modes = vec!["screen", "browser", "both"];
        for mode in modes {
            let cli = Cli::try_parse_from(&[
                "site-recorder",
                "crawl",
                "https://example.com",
                "--recording-mode", mode,
            ]);
            assert!(cli.is_ok());
        }
    }
}
