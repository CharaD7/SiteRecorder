use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use browser::{Browser, NavigationOptions, ScrollBehavior};
use crawler::{CrawlConfig, Crawler};
use exporter::{ExportFormat, Exporter, RecordingData};
use notifier::{Notifier, NotificationConfig};
use recorder::{Recorder, RecordingConfig, VideoFormat};
use session::SessionManager;

#[derive(Parser, Debug)]
#[command(name = "SiteRecorder")]
#[command(author, version, about = "Record and crawl any website", long_about = None)]
struct Args {
    /// URL to crawl and record
    #[arg(value_name = "URL")]
    url: Option<String>,

    /// Maximum number of pages to visit
    #[arg(short, long, default_value = "50")]
    max_pages: usize,

    /// Delay between page visits in milliseconds
    #[arg(short, long, default_value = "2000")]
    delay: u64,

    /// Output directory for recordings
    #[arg(short, long, default_value = "./recordings")]
    output: String,

    /// Run in headless mode (no visible browser)
    #[arg(long)]
    headless: bool,
}

#[derive(Debug)]
struct AppConfig {
    base_url: String,
    max_pages: Option<usize>,
    delay_between_pages_ms: u64,
    output_dir: String,
    headless: bool,
}

impl From<Args> for AppConfig {
    fn from(args: Args) -> Self {
        let base_url = args.url.unwrap_or_else(|| {
            println!("No URL provided. Please enter the URL to record:");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).expect("Failed to read input");
            input.trim().to_string()
        });

        Self {
            base_url,
            max_pages: Some(args.max_pages),
            delay_between_pages_ms: args.delay,
            output_dir: args.output,
            headless: args.headless,
        }
    }
}

struct SiteRecorder {
    config: AppConfig,
    browser: Browser,
    crawler: Crawler,
    recorder: Recorder,
    session_manager: SessionManager,
    notifier: Notifier,
    exporter: Exporter,
}

impl SiteRecorder {
    fn new(config: AppConfig) -> Result<Self> {
        let browser = if config.headless {
            info!("Launching browser in headless mode");
            Browser::new_headless()?
        } else {
            info!("Launching browser in visible mode");
            Browser::new()?
        };
        
        let crawl_config = CrawlConfig::new(&config.base_url)?;
        let crawler = Crawler::new(crawl_config);
        
        let recording_config = RecordingConfig {
            output_dir: std::path::PathBuf::from(&config.output_dir),
            format: VideoFormat::Mp4,
            fps: 30,
            quality: 80,
            audio_enabled: false,
        };
        let recorder = Recorder::new(recording_config);
        
        let session_manager = SessionManager::new();
        
        let notification_config = NotificationConfig::default();
        let notifier = Notifier::new(notification_config);
        
        let exporter = Exporter::new();

        Ok(Self {
            config,
            browser,
            crawler,
            recorder,
            session_manager,
            notifier,
            exporter,
        })
    }

    async fn run(&mut self) -> Result<()> {
        info!("Starting SiteRecorder");
        info!("Target: {}", self.config.base_url);
        
        // Create session
        let session_id = format!("session_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S"));
        self.session_manager.create_session(session_id.clone()).await?;
        
        // Start recording
        self.recorder.start_recording(session_id.clone()).await?;
        self.notifier.notify_recording_started(&session_id)?;
        
        // Get browser tab
        let tab = self.browser.get_tab()?;
        
        // Navigation options
        let nav_options = NavigationOptions {
            timeout_ms: 30000,
            wait_for_idle: true,
            scroll_behavior: ScrollBehavior::Incremental {
                steps: 5,
                delay_ms: 500,
            },
        };

        let mut pages_visited = 0;
        let mut recording_data = Vec::new();

        self.notifier.notify_crawl_started(&self.config.base_url)?;

        // Main crawling loop
        while let Some(url) = self.crawler.get_next_url() {
            if let Some(max) = self.config.max_pages {
                if pages_visited >= max {
                    info!("Reached maximum page limit: {}", max);
                    break;
                }
            }

            info!("Visiting page {}: {}", pages_visited + 1, url);

            // Navigate to URL
            match self.browser.navigate(&tab, &url, &nav_options) {
                Ok(_) => {
                    pages_visited += 1;

                    // Record the visit
                    recording_data.push(RecordingData {
                        session_id: session_id.clone(),
                        timestamp: chrono::Utc::now(),
                        url: url.clone(),
                        action: "navigate".to_string(),
                        metadata: serde_json::json!({
                            "page_number": pages_visited,
                        }),
                    });

                    // Extract links from the page
                    if let Ok(content) = self.browser.get_page_content(&tab) {
                        if let Ok(links) = self.crawler.extract_links_from_html(&content, &url) {
                            info!("Found {} links on page", links.len());
                            self.crawler.add_discovered_links(links);
                        }
                    }

                    // Delay between pages
                    sleep(Duration::from_millis(self.config.delay_between_pages_ms)).await;
                }
                Err(e) => {
                    warn!("Failed to navigate to {}: {}", url, e);
                    recording_data.push(RecordingData {
                        session_id: session_id.clone(),
                        timestamp: chrono::Utc::now(),
                        url: url.clone(),
                        action: "error".to_string(),
                        metadata: serde_json::json!({
                            "error": e.to_string(),
                        }),
                    });
                }
            }
        }

        info!("Crawling completed. Visited {} pages", pages_visited);
        self.notifier.notify_crawl_completed(pages_visited)?;

        // Stop recording
        let video_path = self.recorder.stop_recording().await?;
        if let Some(metadata) = self.recorder.get_metadata().await {
            if let Some(duration) = metadata.duration_secs {
                self.notifier.notify_recording_stopped(&session_id, duration)?;
            }
        }

        // Export recording data
        let export_path = std::path::PathBuf::from(&self.config.output_dir)
            .join(format!("{}_data.json", session_id));
        self.exporter.export_to_json(&recording_data, &export_path)?;
        self.notifier.notify_export_completed(export_path.to_str().unwrap_or("unknown"))?;

        info!("SiteRecorder completed successfully");
        info!("Video saved to: {:?}", video_path);
        info!("Data exported to: {:?}", export_path);

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    info!("SiteRecorder - Desktop Application");
    
    // Parse command line arguments
    let args = Args::parse();
    let config = AppConfig::from(args);

    info!("Configuration:");
    info!("  Base URL: {}", config.base_url);
    info!("  Max pages: {:?}", config.max_pages);
    info!("  Delay: {}ms", config.delay_between_pages_ms);
    info!("  Output dir: {}", config.output_dir);
    info!("  Headless: {}", config.headless);

    // Create and run the recorder
    match SiteRecorder::new(config) {
        Ok(mut recorder) => {
            if let Err(e) = recorder.run().await {
                error!("Application error: {}", e);
                std::process::exit(1);
            }
        }
        Err(e) => {
            error!("Failed to initialize SiteRecorder: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}
