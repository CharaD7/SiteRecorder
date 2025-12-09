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

mod cli;
use cli::{Cli, Commands, RecordingModeArg};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecordingSettings {
    url: String,
    max_pages: usize,
    delay_ms: u64,
    headless: bool,
    output_dir: String,
    fps: Option<u32>,
    requires_auth: bool,
    auth_url: Option<String>,
    username: Option<String>,
    password: Option<String>,
    username_selector: Option<String>,
    password_selector: Option<String>,
    submit_selector: Option<String>,
    recording_mode: Option<String>, // "screen", "browser", or "both"
    enable_audio: Option<bool>,
    screen_width: Option<u32>,
    screen_height: Option<u32>,
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

    // Parse recording mode from settings
    let recording_mode = match settings.recording_mode.as_deref() {
        Some("screen") => recorder::RecordingMode::Screen,
        Some("browser") => recorder::RecordingMode::Browser,
        Some("both") => recorder::RecordingMode::Both,
        _ => recorder::RecordingMode::Both, // Default to Both
    };

    let recording_config = RecordingConfig {
        output_dir: std::path::PathBuf::from(&settings.output_dir),
        format: VideoFormat::Mp4,
        fps: settings.fps.unwrap_or(30),
        quality: 80,
        audio_enabled: settings.enable_audio.unwrap_or(false),
        mode: recording_mode,
        screen_width: settings.screen_width.or(Some(1920)),
        screen_height: settings.screen_height.or(Some(1080)),
    };
    let recorder = Recorder::new(recording_config);

    let notifier = Notifier::new(NotificationConfig::default());
    let exporter = Exporter::new();

    // Get session ID
    let session_id = status.lock().await.session_id.clone();

    // Create session
    session_manager.lock().await.create_session(session_id.clone()).await?;

    // Start recording
    recorder.start_recording(session_id.clone(), Some(settings.url.clone())).await?;
    notifier.notify_recording_started(&session_id)?;

    // Get browser tab
    let tab = browser.get_tab()?;
    
    // Set browser tab for recording
    recorder.set_browser_tab(tab.clone()).await;

    let nav_options = NavigationOptions {
        timeout_ms: 30000,
        wait_for_idle: true,
        scroll_behavior: ScrollBehavior::Incremental {
            steps: 5,
            delay_ms: 500,
        },
    };

    // Handle authentication if required
    if settings.requires_auth {
        if let Some(auth_url) = &settings.auth_url {
            info!("Navigating to login page: {}", auth_url);
            
            match browser.navigate(&tab, auth_url, &nav_options) {
                Ok(_) => {
                    info!("Login page loaded, attempting authentication...");
                    
                    // Fill in credentials
                    if let (Some(username), Some(password), Some(username_sel), Some(password_sel), Some(submit_sel)) = (
                        &settings.username,
                        &settings.password,
                        &settings.username_selector,
                        &settings.password_selector,
                        &settings.submit_selector,
                    ) {
                        match perform_login(&tab, username, password, username_sel, password_sel, submit_sel) {
                            Ok(_) => {
                                info!("Login successful!");
                                notifier.notify_info("Authentication", "Login successful")?;
                                sleep(Duration::from_millis(3000)).await; // Wait for redirect
                            }
                            Err(e) => {
                                warn!("Login failed: {}", e);
                                notifier.notify_error("Authentication", &format!("Login failed: {}", e))?;
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to navigate to login page: {}", e);
                }
            }
        }
    }

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

fn perform_login(
    tab: &std::sync::Arc<headless_chrome::Tab>,
    username: &str,
    password: &str,
    username_selector: &str,
    password_selector: &str,
    submit_selector: &str,
) -> Result<()> {
    // Check if we're on localhost - if so, check for pre-filled fields
    let current_url = tab.get_url();
    let is_localhost = current_url.contains("localhost") || current_url.contains("127.0.0.1");
    
    if is_localhost {
        info!("Detected localhost domain, checking for pre-filled form fields...");
        
        // Check if username field already has content
        let username_selectors: Vec<&str> = username_selector.split(',').map(|s| s.trim()).collect();
        let mut username_prefilled = false;
        
        for selector in &username_selectors {
            if let Ok(_element) = tab.find_element(selector) {
                // Try to get the value attribute to check if it's filled
                if let Ok(js_result) = tab.evaluate(&format!(
                    "document.querySelector('{}')?.value || ''", 
                    selector.replace("'", "\\'")
                ), false) {
                    if let Some(value) = js_result.value {
                        if let Some(s) = value.as_str() {
                            if !s.trim().is_empty() {
                                info!("Username field already contains: '{}'", s);
                                username_prefilled = true;
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        // Check if password field already has content
        let password_selectors: Vec<&str> = password_selector.split(',').map(|s| s.trim()).collect();
        let mut password_prefilled = false;
        
        for selector in &password_selectors {
            if let Ok(_element) = tab.find_element(selector) {
                if let Ok(js_result) = tab.evaluate(&format!(
                    "document.querySelector('{}')?.value || ''", 
                    selector.replace("'", "\\'")
                ), false) {
                    if let Some(value) = js_result.value {
                        if let Some(s) = value.as_str() {
                            if !s.trim().is_empty() {
                                info!("Password field already contains data");
                                password_prefilled = true;
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        if username_prefilled && password_prefilled {
            info!("Both username and password fields are pre-filled on localhost, skipping form filling...");
            // Skip to submit button
            std::thread::sleep(std::time::Duration::from_millis(500));
            
            info!("Clicking submit button...");
            let submit_selectors: Vec<&str> = submit_selector.split(',').map(|s| s.trim()).collect();
            let mut submit_clicked = false;
            
            for selector in submit_selectors {
                if let Ok(element) = tab.find_element(selector) {
                    if element.click().is_ok() {
                        info!("Submit button clicked using selector: {}", selector);
                        submit_clicked = true;
                        break;
                    }
                }
            }
            
            if !submit_clicked {
                return Err(anyhow::anyhow!("Could not find submit button"));
            }
            
            info!("Login form submitted with pre-filled data");
            return Ok(());
        } else {
            info!("Fields not pre-filled, proceeding with normal form filling...");
        }
    }

    info!("Filling username field...");
    // Try multiple selectors for username
    let username_selectors: Vec<&str> = username_selector.split(',').map(|s| s.trim()).collect();
    let mut username_filled = false;
    
    for selector in username_selectors {
        if let Ok(element) = tab.find_element(selector) {
            if element.type_into(username).is_ok() {
                info!("Username filled using selector: {}", selector);
                username_filled = true;
                break;
            }
        }
    }
    
    if !username_filled {
        return Err(anyhow::anyhow!("Could not find username field"));
    }
    
    std::thread::sleep(std::time::Duration::from_millis(500));
    
    info!("Filling password field...");
    // Try multiple selectors for password
    let password_selectors: Vec<&str> = password_selector.split(',').map(|s| s.trim()).collect();
    let mut password_filled = false;
    
    for selector in password_selectors {
        if let Ok(element) = tab.find_element(selector) {
            if element.type_into(password).is_ok() {
                info!("Password filled using selector: {}", selector);
                password_filled = true;
                break;
            }
        }
    }
    
    if !password_filled {
        return Err(anyhow::anyhow!("Could not find password field"));
    }
    
    std::thread::sleep(std::time::Duration::from_millis(500));
    
    info!("Clicking submit button...");
    // Try multiple selectors for submit button
    let submit_selectors: Vec<&str> = submit_selector.split(',').map(|s| s.trim()).collect();
    let mut submit_clicked = false;
    
    for selector in submit_selectors {
        if let Ok(element) = tab.find_element(selector) {
            if element.click().is_ok() {
                info!("Submit button clicked using selector: {}", selector);
                submit_clicked = true;
                break;
            }
        }
    }
    
    if !submit_clicked {
        return Err(anyhow::anyhow!("Could not find submit button"));
    }
    
    info!("Login form submitted");
    Ok(())
}

fn main() {
    // Parse CLI arguments
    let cli = Cli::parse_args();
    
    // Initialize tracing based on verbosity
    let log_level = if cli.verbose {
        tracing::Level::DEBUG
    } else if cli.quiet {
        tracing::Level::WARN
    } else {
        tracing::Level::INFO
    };
    
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(log_level.into()))
        .init();

    // Handle CLI commands or start GUI
    match cli.command {
        Some(Commands::Crawl { .. }) => {
            // Run CLI mode
            info!("Starting in CLI mode");
            if let Err(e) = run_cli_mode(cli) {
                error!("CLI mode failed: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::Resume { session_id }) => {
            info!("Resuming session: {}", session_id);
            if let Err(e) = resume_session(&session_id) {
                error!("Failed to resume session: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::List { output }) => {
            list_sessions(&output);
        }
        Some(Commands::Gui) | None => {
            // Start GUI mode (default)
            run_gui_mode();
        }
    }
}

fn run_gui_mode() {
    info!("SiteRecorder GUI starting...");

    let app_state = AppState {
        status: Arc::new(Mutex::new(CrawlStatus::default())),
        session_manager: Arc::new(Mutex::new(SessionManager::new())),
    };

    use tauri::{CustomMenuItem, SystemTray, SystemTrayMenu, SystemTrayEvent, Manager};
    
    // Create system tray menu
    let show = CustomMenuItem::new("show".to_string(), "Show Window");
    let hide = CustomMenuItem::new("hide".to_string(), "Hide Window");
    let quit = CustomMenuItem::new("quit".to_string(), "Quit");
    
    let tray_menu = SystemTrayMenu::new()
        .add_item(show)
        .add_item(hide)
        .add_native_item(tauri::SystemTrayMenuItem::Separator)
        .add_item(quit);
    
    let system_tray = SystemTray::new().with_menu(tray_menu);

    tauri::Builder::default()
        .manage(app_state)
        .system_tray(system_tray)
        .on_system_tray_event(|app, event| match event {
            SystemTrayEvent::MenuItemClick { id, .. } => {
                match id.as_str() {
                    "show" => {
                        if let Some(window) = app.get_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "hide" => {
                        if let Some(window) = app.get_window("main") {
                            let _ = window.hide();
                        }
                    }
                    "quit" => {
                        std::process::exit(0);
                    }
                    _ => {}
                }
            }
            _ => {}
        })
        .on_window_event(|event| match event.event() {
            tauri::WindowEvent::CloseRequested { api, .. } => {
                // Hide instead of close
                let _ = event.window().hide();
                api.prevent_close();
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            start_recording,
            stop_recording,
            get_status
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

// CLI Mode Implementation
fn run_cli_mode(cli: Cli) -> Result<()> {
    if let Some(Commands::Crawl {
        url,
        max_pages,
        delay,
        output,
        recording_mode,
        fps,
        audio,
        headless,
        screen_width,
        screen_height,
        auth_url,
        username,
        password,
        sitemap: _,
    }) = cli.command {
        info!("Starting CLI crawl of: {}", url);
        
        // Create runtime for async operations
        let runtime = tokio::runtime::Runtime::new()?;
        
        runtime.block_on(async {
            // Convert CLI args to recording settings
            let settings = RecordingSettings {
                url: url.clone(),
                max_pages,
                delay_ms: delay,
                headless,
                output_dir: output.to_string_lossy().to_string(),
                fps: Some(fps),
                requires_auth: auth_url.is_some(),
                auth_url,
                username,
                password,
                username_selector: None,
                password_selector: None,
                submit_selector: None,
                recording_mode: Some(match recording_mode {
                    RecordingModeArg::Screen => "screen".to_string(),
                    RecordingModeArg::Browser => "browser".to_string(),
                    RecordingModeArg::Both => "both".to_string(),
                }),
                enable_audio: Some(audio),
                screen_width: Some(screen_width),
                screen_height: Some(screen_height),
            };
            
            info!("Configuration:");
            info!("  URL: {}", settings.url);
            info!("  Max pages: {}", settings.max_pages);
            info!("  Output: {}", settings.output_dir);
            info!("  Recording mode: {:?}", settings.recording_mode);
            info!("  Headless: {}", settings.headless);
            
            // Run the recording
            match run_recording_cli(settings).await {
                Ok(session_id) => {
                    info!("✓ Recording completed successfully!");
                    info!("Session ID: {}", session_id);
                    Ok(())
                }
                Err(e) => {
                    error!("✗ Recording failed: {}", e);
                    Err(e)
                }
            }
        })
    } else {
        Ok(())
    }
}

async fn run_recording_cli(settings: RecordingSettings) -> Result<String> {
    // This is a simplified version of the GUI recording logic
    // Create session ID
    let session_id = format!("session_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S"));
    
    info!("Initializing browser...");
    let browser = if settings.headless {
        Browser::new_headless()?
    } else {
        Browser::new()?
    };
    
    info!("Setting up crawler...");
    let crawl_config = CrawlConfig::new(&settings.url)?;
    let mut crawler = Crawler::new(crawl_config);
    
    // Parse recording mode
    let recording_mode = match settings.recording_mode.as_deref() {
        Some("screen") => recorder::RecordingMode::Screen,
        Some("browser") => recorder::RecordingMode::Browser,
        Some("both") => recorder::RecordingMode::Both,
        _ => recorder::RecordingMode::Both,
    };
    
    info!("Configuring recorder...");
    let recording_config = RecordingConfig {
        output_dir: std::path::PathBuf::from(&settings.output_dir),
        format: VideoFormat::Mp4,
        fps: settings.fps.unwrap_or(30),
        quality: 80,
        audio_enabled: settings.enable_audio.unwrap_or(false),
        mode: recording_mode,
        screen_width: settings.screen_width.or(Some(1920)),
        screen_height: settings.screen_height.or(Some(1080)),
    };
    let recorder = Recorder::new(recording_config);
    
    let tab = browser.get_tab()?;
    recorder.set_browser_tab(tab.clone()).await;
    
    info!("Starting recording...");
    recorder.start_recording(session_id.clone(), Some(settings.url.clone())).await?;
    
    info!("Beginning crawl...");
    let nav_options = NavigationOptions::default();
    let mut pages_visited = 0;
    
    while pages_visited < settings.max_pages {
        if let Some(url) = crawler.get_next_url() {
            info!("[{}/{}] Crawling: {}", pages_visited + 1, settings.max_pages, url);
            
            match browser.navigate(&tab, &url, &nav_options) {
                Ok(_) => {
                    // Get page content and discover links
                    if let Ok(content) = browser.get_page_content(&tab) {
                        if let Ok(links) = crawler.extract_links_from_html(&content, &url) {
                            info!("  Found {} links", links.len());
                            crawler.add_discovered_links(links);
                        }
                    }
                    
                    crawler.mark_visited(&url);
                    pages_visited += 1;
                    
                    // Delay between pages
                    tokio::time::sleep(tokio::time::Duration::from_millis(settings.delay_ms)).await;
                }
                Err(e) => {
                    warn!("  Failed to navigate: {}", e);
                    crawler.mark_visited(&url);
                }
            }
        } else {
            info!("No more URLs to crawl");
            break;
        }
    }
    
    info!("Stopping recording...");
    let video_path = recorder.stop_recording().await?;
    
    info!("Recording saved to: {:?}", video_path);
    info!("Total pages visited: {}", pages_visited);
    
    Ok(session_id)
}

fn resume_session(session_id: &str) -> Result<()> {
    info!("Resume functionality not yet implemented");
    info!("Session ID: {}", session_id);
    warn!("This feature is coming soon!");
    Ok(())
}

fn list_sessions(output: &std::path::Path) {
    info!("Listing sessions in: {:?}", output);
    
    if let Ok(entries) = std::fs::read_dir(output) {
        let mut count = 0;
        println!("\n📁 Recording Sessions:");
        println!("─────────────────────────────────────────────────────");
        
        for entry in entries.flatten() {
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_dir() {
                    count += 1;
                    let path = entry.path();
                    let name = path.file_name().unwrap().to_string_lossy();
                    
                    if let Ok(modified) = metadata.modified() {
                        if let Ok(datetime) = modified.duration_since(std::time::UNIX_EPOCH) {
                            let secs = datetime.as_secs();
                            let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0);
                            if let Some(dt) = dt {
                                println!("  {} - {}", name, dt.format("%Y-%m-%d %H:%M:%S"));
                            } else {
                                println!("  {}", name);
                            }
                        } else {
                            println!("  {}", name);
                        }
                    } else {
                        println!("  {}", name);
                    }
                }
            }
        }
        
        println!("─────────────────────────────────────────────────────");
        println!("Total sessions: {}\n", count);
    } else {
        warn!("Could not read directory: {:?}", output);
    }
}
