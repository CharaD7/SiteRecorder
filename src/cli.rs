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
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Quiet mode (minimal output)
    #[arg(short, long, global = true)]
    pub quiet: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start recording with GUI (default)
    Gui,
    
    /// Run in CLI mode without GUI
    Crawl {
        /// URL to start crawling from
        #[arg(value_name = "URL")]
        url: String,

        /// Maximum number of pages to visit
        #[arg(short, long, default_value = "50")]
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

        /// Screen width for recording
        #[arg(long, default_value = "1920")]
        screen_width: u32,

        /// Screen height for recording
        #[arg(long, default_value = "1080")]
        screen_height: u32,

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
