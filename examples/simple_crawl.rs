// Simplified example demonstrating core SiteRecorder functionality
// This example can run without video recording dependencies

use anyhow::Result;
use tokio::time::{sleep, Duration};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use browser::{Browser, NavigationOptions, ScrollBehavior};
use crawler::{CrawlConfig, Crawler};
use exporter::{Exporter, RecordingData};
use notifier::{Notifier, NotificationConfig};
use session::SessionManager;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env()
            .add_directive(tracing::Level::INFO.into()))
        .init();

    info!("SiteRecorder Demo - Simplified Mode");
    info!("This demo crawls a site without video recording");

    // Get URL from command line or use default
    let base_url = std::env::args()
            .nth(1)
        .unwrap_or_else(|| "https://example.com".to_string());

    info!("Crawling: {}", base_url);

    // Initialize components
    let session_manager = SessionManager::new();
    let session_id = format!("demo_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S"));
    session_manager.create_session(session_id.clone()).await?;

    let notifier = Notifier::new(NotificationConfig::default());
    notifier.notify_crawl_started(&base_url)?;

    // Initialize crawler
    let crawl_config = CrawlConfig::new(&base_url)?;
    let mut crawler = Crawler::new(crawl_config);

    // Initialize browser
    info!("Launching browser...");
    let browser = Browser::new()?;
    let tab = browser.get_tab()?;

    let nav_options = NavigationOptions {
        timeout_ms: 30000,
        wait_for_idle: true,
        scroll_behavior: ScrollBehavior::Incremental {
            steps: 3,
            delay_ms: 500,
        },
    };

    let mut recording_data = Vec::new();
    let max_pages = 10;
    let mut pages_visited = 0;

    // Crawl loop
    while let Some(url) = crawler.get_next_url() {
        if pages_visited >= max_pages {
            info!("Reached maximum of {} pages", max_pages);
            break;
        }

        info!("[{}/{}] Visiting: {}", pages_visited + 1, max_pages, url);

        match browser.navigate(&tab, &url, &nav_options) {
            Ok(_) => {
                pages_visited += 1;

                // Record visit
                recording_data.push(RecordingData {
                    session_id: session_id.clone(),
                    timestamp: chrono::Utc::now(),
                    url: url.clone(),
                    action: "navigate".to_string(),
                    metadata: serde_json::json!({
                        "page_number": pages_visited,
                    }),
                });

                // Extract links
                if let Ok(content) = browser.get_page_content(&tab) {
                    if let Ok(links) = crawler.extract_links_from_html(&content, &url) {
                        info!("  Found {} internal links", links.len());
                        crawler.add_discovered_links(links);
                    }
                }

                // Show stats
                info!("  Discovered: {} | Visited: {} | Remaining: {}",
                    crawler.get_discovered_count(),
                    crawler.get_visited_count(),
                    crawler.get_remaining_count()
                );

                sleep(Duration::from_millis(1000)).await;
            }
            Err(e) => {
                warn!("Failed to visit {}: {}", url, e);
            }
        }
    }

    // Export results
    let exporter = Exporter::new();
    let output_path = format!("./{}_results.json", session_id);
    exporter.export_to_json(&recording_data, &output_path)?;

    info!("");
    info!("===========================================");
    info!("Crawl completed successfully!");
    info!("  Pages visited: {}", pages_visited);
    info!("  Total discovered: {}", crawler.get_discovered_count());
    info!("  Results saved to: {}", output_path);
    info!("===========================================");

    notifier.notify_crawl_completed(pages_visited)?;

    Ok(())
}
