use anyhow::Result;
use headless_chrome::Browser as ChromeBrowser;
use headless_chrome::protocol::cdp::Page;
use headless_chrome::{LaunchOptions, Tab};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, error, info, warn};
use url::Url;

#[derive(Debug, Error)]
pub enum BrowserError {
    #[error("Failed to launch browser: {0}")]
    LaunchFailed(String),
    #[error("Navigation error: {0}")]
    NavigationError(String),
    #[error("Timeout error: {0}")]
    Timeout(String),
    #[error("Browser error: {0}")]
    BrowserError(#[from] anyhow::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NavigationOptions {
    pub timeout_ms: u64,
    pub wait_for_idle: bool,
    pub scroll_behavior: ScrollBehavior,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScrollBehavior {
    None,
    ToBottom,
    Incremental { steps: u32, delay_ms: u64 },
}

impl Default for NavigationOptions {
    fn default() -> Self {
        Self {
            timeout_ms: 30000,
            wait_for_idle: true,
            scroll_behavior: ScrollBehavior::Incremental {
                steps: 5,
                delay_ms: 500,
            },
        }
    }
}

pub struct Browser {
    browser: ChromeBrowser,
}

impl Browser {
    pub fn new() -> Result<Self, BrowserError> {
        let launch_options = LaunchOptions::default_builder()
            .headless(false)
            .window_size(Some((1920, 1080)))
            .idle_browser_timeout(Duration::from_secs(300))
            .build()
            .map_err(|e| BrowserError::LaunchFailed(e.to_string()))?;

        let browser = ChromeBrowser::new(launch_options)
            .map_err(|e| BrowserError::LaunchFailed(e.to_string()))?;

        info!("Browser launched successfully");
        Ok(Self { browser })
    }

    pub fn new_headless() -> Result<Self, BrowserError> {
        let launch_options = LaunchOptions::default_builder()
            .headless(true)
            .window_size(Some((1920, 1080)))
            .idle_browser_timeout(Duration::from_secs(300))
            .build()
            .map_err(|e| BrowserError::LaunchFailed(e.to_string()))?;

        let browser = ChromeBrowser::new(launch_options)
            .map_err(|e| BrowserError::LaunchFailed(e.to_string()))?;

        info!("Headless browser launched successfully");
        Ok(Self { browser })
    }

    pub fn get_tab(&self) -> Result<Arc<Tab>, BrowserError> {
        self.browser
            .new_tab()
            .map_err(|e| BrowserError::BrowserError(anyhow::anyhow!(e.to_string())))
    }

    pub fn navigate(&self, tab: &Arc<Tab>, url: &str, options: &NavigationOptions) -> Result<(), BrowserError> {
        info!("Navigating to: {}", url);
        
        tab.navigate_to(url)
            .map_err(|e| BrowserError::NavigationError(e.to_string()))?;

        if options.wait_for_idle {
            tab.wait_until_navigated()
                .map_err(|e| BrowserError::NavigationError(e.to_string()))?;
        }

        std::thread::sleep(Duration::from_millis(1000));

        match &options.scroll_behavior {
            ScrollBehavior::None => {}
            ScrollBehavior::ToBottom => {
                self.scroll_to_bottom(tab)?;
            }
            ScrollBehavior::Incremental { steps, delay_ms } => {
                self.scroll_incremental(tab, *steps, *delay_ms)?;
            }
        }

        debug!("Navigation complete");
        Ok(())
    }

    pub fn scroll_to_bottom(&self, tab: &Arc<Tab>) -> Result<(), BrowserError> {
        tab.evaluate("window.scrollTo(0, document.body.scrollHeight);", false)
            .map_err(|e| BrowserError::BrowserError(anyhow::anyhow!(e.to_string())))?;
        std::thread::sleep(Duration::from_millis(500));
        Ok(())
    }

    pub fn scroll_incremental(&self, tab: &Arc<Tab>, steps: u32, delay_ms: u64) -> Result<(), BrowserError> {
        for i in 1..=steps {
            let script = format!(
                "window.scrollTo(0, document.body.scrollHeight * {} / {});",
                i, steps
            );
            tab.evaluate(&script, false)
                .map_err(|e| BrowserError::BrowserError(anyhow::anyhow!(e.to_string())))?;
            std::thread::sleep(Duration::from_millis(delay_ms));
        }
        Ok(())
    }

    pub fn get_page_content(&self, tab: &Arc<Tab>) -> Result<String, BrowserError> {
        let content = tab
            .get_content()
            .map_err(|e| BrowserError::BrowserError(anyhow::anyhow!(e.to_string())))?;
        Ok(content)
    }

    pub fn get_current_url(&self, tab: &Arc<Tab>) -> Result<String, BrowserError> {
        let url = tab
            .get_url()
            .to_string();
        Ok(url)
    }

    pub fn execute_script(&self, tab: &Arc<Tab>, script: &str) -> Result<serde_json::Value, BrowserError> {
        let result = tab
            .evaluate(script, false)
            .map_err(|e| BrowserError::BrowserError(anyhow::anyhow!(e.to_string())))?;
        Ok(result.value.unwrap_or(serde_json::Value::Null))
    }

    pub fn go_back(&self, tab: &Arc<Tab>) -> Result<(), BrowserError> {
        tab.evaluate("window.history.back();", false)
            .map_err(|e| BrowserError::BrowserError(anyhow::anyhow!(e.to_string())))?;
        std::thread::sleep(Duration::from_millis(1000));
        Ok(())
    }

    pub fn go_forward(&self, tab: &Arc<Tab>) -> Result<(), BrowserError> {
        tab.evaluate("window.history.forward();", false)
            .map_err(|e| BrowserError::BrowserError(anyhow::anyhow!(e.to_string())))?;
        std::thread::sleep(Duration::from_millis(1000));
        Ok(())
    }
}

impl Default for Browser {
    fn default() -> Self {
        Self::new().expect("Failed to create default browser")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_navigation_options_default() {
        let options = NavigationOptions::default();
        assert_eq!(options.timeout_ms, 30000);
        assert!(options.wait_for_idle);
    }
}
