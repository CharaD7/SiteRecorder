use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::State;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use browser::{Browser, NavigationOptions, ScrollBehavior};
use crawler::{CrawlConfig, Crawler};
use exporter::{Exporter, RecordingData};
use notifier::{Notifier, NotificationConfig};
use recorder::{Recorder, RecordingConfig, VideoFormat};
use session::SessionManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecordingSettings {
    url: String,
    max_pages: usize,
    delay_ms: u64,
    headless: bool,
    output_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CrawlStatus {
    is_running: bool,
    current_url: String,
    pages_visited: usize,
    pages_discovered: usize,
    session_id: String,
}

impl Default for CrawlStatus {
    fn default() -> Self {
        Self {
            is_running: false,
            current_url: String::new(),
            pages_visited: 0,
            pages_discovered: 0,
            session_id: String::new(),
        }
    }
}

struct AppState {
    status: Arc<Mutex<CrawlStatus>>,
    session_manager: Arc<Mutex<SessionManager>>,
}

#[tauri::command]
async fn start_recording(
    settings: RecordingSettings,
    state: State<'_, AppState>,
) -> Result<String, String> {
    eprintln!("=== START RECORDING CALLED ===");
    eprintln!("Settings: {:?}", settings);
    info!("Starting recording with settings: {:?}", settings);

    let mut status = state.status.lock().await;
    eprintln!("Got status lock, is_running: {}", status.is_running);
    
    if status.is_running {
        eprintln!("ERROR: Recording already in progress");
        return Err("Recording already in progress".to_string());
    }

    status.is_running = true;
    status.session_id = format!("session_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S"));
    status.current_url = settings.url.clone();
    status.pages_visited = 0;
    status.pages_discovered = 0;
    let session_id = status.session_id.clone();
    eprintln!("Created session: {}", session_id);
    drop(status);

    let status_arc = state.status.clone();
    let session_manager_arc = state.session_manager.clone();

    eprintln!("Spawning background task...");
    // Spawn background task
    tokio::spawn(async move {
        eprintln!("Background task started");
        if let Err(e) = run_recording(settings, status_arc, session_manager_arc).await {
            eprintln!("Recording failed: {}", e);
            error!("Recording failed: {}", e);
        }
        eprintln!("Background task completed");
    });

    eprintln!("Returning session_id: {}", session_id);
    Ok(session_id)
}

#[tauri::command]
async fn stop_recording(state: State<'_, AppState>) -> Result<(), String> {
    let mut status = state.status.lock().await;
    status.is_running = false;
    Ok(())
}

#[tauri::command]
async fn get_status(state: State<'_, AppState>) -> Result<CrawlStatus, String> {
    let status = state.status.lock().await;
    Ok(status.clone())
}

async fn run_recording(
    settings: RecordingSettings,
    status: Arc<Mutex<CrawlStatus>>,
    session_manager: Arc<Mutex<SessionManager>>,
) -> Result<()> {
    eprintln!("=== RUN RECORDING STARTED ===");
    eprintln!("Settings: {:?}", settings);
    
    // Initialize components
    eprintln!("Creating browser...");
    let browser = if settings.headless {
        Browser::new_headless()?
    } else {
        Browser::new()?
    };
    eprintln!("Browser created successfully");

    let crawl_config = CrawlConfig::new(&settings.url)?;
    let mut crawler = Crawler::new(crawl_config);

    let recording_config = RecordingConfig {
        output_dir: std::path::PathBuf::from(&settings.output_dir),
        format: VideoFormat::Mp4,
        fps: 30,
        quality: 80,
        audio_enabled: false,
    };
    let recorder = Recorder::new(recording_config);

    let notifier = Notifier::new(NotificationConfig::default());
    let exporter = Exporter::new();

    // Get session ID
    let session_id = status.lock().await.session_id.clone();

    // Create session
    session_manager.lock().await.create_session(session_id.clone()).await?;

    // Start recording
    recorder.start_recording(session_id.clone()).await?;
    notifier.notify_recording_started(&session_id)?;

    // Get browser tab
    let tab = browser.get_tab()?;

    let nav_options = NavigationOptions {
        timeout_ms: 30000,
        wait_for_idle: true,
        scroll_behavior: ScrollBehavior::Incremental {
            steps: 5,
            delay_ms: 500,
        },
    };

    let mut recording_data = Vec::new();

    // Main crawling loop
    while let Some(url) = crawler.get_next_url() {
        // Check if stopped
        {
            let status_guard = status.lock().await;
            if !status_guard.is_running {
                info!("Recording stopped by user");
                break;
            }
        }

        // Check page limit
        let pages_visited = status.lock().await.pages_visited;
        if pages_visited >= settings.max_pages {
            info!("Reached maximum page limit: {}", settings.max_pages);
            break;
        }

        info!("Visiting page {}: {}", pages_visited + 1, url);

        // Update status
        {
            let mut status_guard = status.lock().await;
            status_guard.current_url = url.clone();
        }

        // Navigate to URL
        match browser.navigate(&tab, &url, &nav_options) {
            Ok(_) => {
                let mut status_guard = status.lock().await;
                status_guard.pages_visited += 1;
                drop(status_guard);

                recording_data.push(RecordingData {
                    session_id: session_id.clone(),
                    timestamp: chrono::Utc::now(),
                    url: url.clone(),
                    action: "navigate".to_string(),
                    metadata: serde_json::json!({
                        "page_number": pages_visited + 1,
                    }),
                });

                // Extract links
                if let Ok(content) = browser.get_page_content(&tab) {
                    if let Ok(links) = crawler.extract_links_from_html(&content, &url) {
                        info!("Found {} links on page", links.len());
                        crawler.add_discovered_links(links);

                        let mut status_guard = status.lock().await;
                        status_guard.pages_discovered = crawler.get_discovered_count();
                    }
                }

                sleep(Duration::from_millis(settings.delay_ms)).await;
            }
            Err(e) => {
                warn!("Failed to navigate to {}: {}", url, e);
            }
        }
    }

    let pages_visited = status.lock().await.pages_visited;
    info!("Crawling completed. Visited {} pages", pages_visited);
    notifier.notify_crawl_completed(pages_visited)?;

    // Stop recording
    let video_path = recorder.stop_recording().await?;
    if let Some(metadata) = recorder.get_metadata().await {
        if let Some(duration) = metadata.duration_secs {
            notifier.notify_recording_stopped(&session_id, duration)?;
        }
    }

    // Export data
    let export_path = std::path::PathBuf::from(&settings.output_dir)
        .join(format!("{}_data.json", session_id));
    exporter.export_to_json(&recording_data, &export_path)?;

    info!("Recording saved to: {:?}", video_path);
    info!("Data exported to: {:?}", export_path);

    // Update final status
    let mut status_guard = status.lock().await;
    status_guard.is_running = false;

    Ok(())
}

fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    info!("SiteRecorder GUI starting...");

    let app_state = AppState {
        status: Arc::new(Mutex::new(CrawlStatus::default())),
        session_manager: Arc::new(Mutex::new(SessionManager::new())),
    };

    tauri::Builder::default()
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            start_recording,
            stop_recording,
            get_status
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
