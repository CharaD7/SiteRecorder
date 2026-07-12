use anyhow::Result;
use indexmap::IndexSet;
use scraper::{Html, Selector};
use std::collections::HashSet;
use thiserror::Error;
use tracing::{debug, info};
use url::Url;

#[derive(Debug, Error)]
pub enum CrawlerError {
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),
    #[error("Crawler error: {0}")]
    CrawlerError(String),
}

#[derive(Debug, Clone)]
pub struct CrawlConfig {
    pub base_url: Url,
    pub max_depth: usize,
    pub same_domain_only: bool,
    pub ignore_fragments: bool,
    pub ignore_query_params: bool,
    pub proxy_url: Option<String>,
    pub sitemap_url: Option<String>,
    pub concurrency: usize,
}

impl CrawlConfig {
    pub fn new(base_url: &str) -> Result<Self, CrawlerError> {
        let url = Url::parse(base_url)
            .map_err(|e| CrawlerError::InvalidUrl(e.to_string()))?;
        
        Ok(Self {
            base_url: url,
            max_depth: 10,
            same_domain_only: true,
            ignore_fragments: true,
            ignore_query_params: false,
            proxy_url: None,
            sitemap_url: None,
            concurrency: 1,
        })
    }

    pub fn with_proxy(mut self, proxy_url: &str) -> Self {
        self.proxy_url = Some(proxy_url.to_string());
        self
    }

    pub fn with_sitemap(mut self, sitemap_url: &str) -> Self {
        self.sitemap_url = Some(sitemap_url.to_string());
        self
    }

    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency.max(1);
        self
    }
}

pub struct Crawler {
    config: CrawlConfig,
    visited: HashSet<String>,
    discovered: IndexSet<String>,
    prefetched: HashSet<String>,
    client: reqwest::Client,
}

impl Crawler {
    pub fn new(config: CrawlConfig) -> Self {
        let mut discovered = IndexSet::new();
        discovered.insert(config.base_url.to_string());

        let mut client_builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::limited(10));

        if let Some(ref proxy_url) = config.proxy_url {
            if let Ok(proxy) = reqwest::Proxy::all(proxy_url) {
                client_builder = client_builder.proxy(proxy);
            }
        }

        let client = client_builder.build().expect("Failed to create HTTP client");

        Self {
            config,
            visited: HashSet::new(),
            discovered,
            prefetched: HashSet::new(),
            client,
        }
    }

    pub async fn fetch_page(&self, url: &str) -> Result<String, CrawlerError> {
        let response = self.client.get(url).send().await?;
        let body = response.text().await?;
        Ok(body)
    }

    pub async fn ingest_sitemap(&mut self) -> Result<usize, CrawlerError> {
        if let Some(ref sitemap_url) = self.config.sitemap_url.clone() {
            let body = self.fetch_page(sitemap_url).await?;
            let document = Html::parse_document(&body);
            let loc_selector = Selector::parse("url > loc, sitemap > loc")
                .map_err(|e| CrawlerError::ParseError(e.to_string()))?;

            let mut count = 0;
            for element in document.select(&loc_selector) {
                if let Some(text) = element.text().next() {
                    let url = text.trim().to_string();
                    if !url.is_empty() && !self.visited.contains(&url) && !self.discovered.contains(&url) {
                        if self.config.same_domain_only {
                            if let Ok(parsed) = Url::parse(&url) {
                                if parsed.domain() == self.config.base_url.domain() {
                                    self.discovered.insert(url);
                                    count += 1;
                                }
                            }
                        } else {
                            self.discovered.insert(url);
                            count += 1;
                        }
                    }
                }
            }
            info!("Ingested {} URLs from sitemap", count);
            Ok(count)
        } else {
            Ok(0)
        }
    }

    pub fn extract_links_from_html(&self, html: &str, current_url: &str) -> Result<Vec<String>, CrawlerError> {
        let document = Html::parse_document(html);
        let selector = Selector::parse("a[href]")
            .map_err(|e| CrawlerError::ParseError(e.to_string()))?;

        let current = Url::parse(current_url)
            .map_err(|e| CrawlerError::InvalidUrl(e.to_string()))?;

        let mut links = Vec::new();

        for element in document.select(&selector) {
            if let Some(href) = element.value().attr("href") {
                if let Ok(absolute_url) = current.join(href) {
                    let mut url = absolute_url.clone();

                    if self.config.ignore_fragments {
                        url.set_fragment(None);
                    }

                    if self.config.ignore_query_params {
                        url.set_query(None);
                    }

                    if self.config.same_domain_only {
                        if url.domain() == self.config.base_url.domain() {
                            links.push(url.to_string());
                        }
                    } else {
                        links.push(url.to_string());
                    }
                }
            }
        }

        debug!("Extracted {} links from {}", links.len(), current_url);
        Ok(links)
    }

    pub fn add_discovered_links(&mut self, links: Vec<String>) {
        for link in links {
            if !self.visited.contains(&link) && !self.discovered.contains(&link) {
                self.discovered.insert(link);
            }
        }
    }

    pub fn get_next_url(&mut self) -> Option<String> {
        // Get the first unvisited URL from discovered set
        for url in &self.discovered {
            if !self.visited.contains(url) {
                let next = url.clone();
                self.visited.insert(next.clone());
                info!("Next URL to visit: {}", next);
                return Some(next);
            }
        }
        None
    }

    pub fn mark_visited(&mut self, url: &str) {
        self.visited.insert(url.to_string());
    }

    pub fn is_visited(&self, url: &str) -> bool {
        self.visited.contains(url)
    }

    pub fn get_visited_count(&self) -> usize {
        self.visited.len()
    }

    pub fn get_discovered_count(&self) -> usize {
        self.discovered.len()
    }

    pub fn get_remaining_count(&self) -> usize {
        self.discovered.len() - self.visited.len()
    }

    /// Returns the next discovered URL that has neither been visited (recorded)
    /// nor prefetched yet, marking it as prefetched. Used by concurrent
    /// prefetch workers to expand the crawl frontier in parallel.
    pub fn next_prefetch_url(&mut self) -> Option<String> {
        for url in &self.discovered {
            if !self.visited.contains(url) && !self.prefetched.contains(url) {
                let next = url.clone();
                self.prefetched.insert(next.clone());
                return Some(next);
            }
        }
        None
    }

    /// Fetch a URL via HTTP and extract its links without mutating crawl state.
    /// Safe to call concurrently from multiple tasks.
    pub async fn prefetch_links(&self, url: &str) -> Vec<String> {
        match self.fetch_page(url).await {
            Ok(body) => match self.extract_links_from_html(&body, url) {
                Ok(links) => links,
                Err(_) => Vec::new(),
            },
            Err(_) => Vec::new(),
        }
    }

    pub fn get_concurrency(&self) -> usize {
        self.config.concurrency
    }

    pub fn get_all_discovered(&self) -> Vec<String> {
        self.discovered.iter().cloned().collect()
    }

    pub fn get_all_visited(&self) -> Vec<String> {
        self.visited.iter().cloned().collect()
    }

    pub fn is_same_domain(&self, url: &str) -> Result<bool, CrawlerError> {
        let parsed = Url::parse(url)
            .map_err(|e| CrawlerError::InvalidUrl(e.to_string()))?;
        Ok(parsed.domain() == self.config.base_url.domain())
    }

    pub fn has_more_urls(&self) -> bool {
        self.get_remaining_count() > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crawler_creation() {
        let config = CrawlConfig::new("https://example.com").unwrap();
        let crawler = Crawler::new(config);
        assert_eq!(crawler.get_discovered_count(), 1);
        assert_eq!(crawler.get_visited_count(), 0);
    }

    #[test]
    fn test_extract_links() {
        let config = CrawlConfig::new("https://example.com").unwrap();
        let crawler = Crawler::new(config);
        
        let html = r#"
            <html>
                <body>
                    <a href="/page1">Page 1</a>
                    <a href="https://example.com/page2">Page 2</a>
                    <a href="https://external.com/page">External</a>
                </body>
            </html>
        "#;
        
        let links = crawler.extract_links_from_html(html, "https://example.com").unwrap();
        assert!(links.len() >= 2);
    }

    #[test]
    fn test_is_same_domain() {
        let config = CrawlConfig::new("https://example.com").unwrap();
        let crawler = Crawler::new(config);
        
        assert!(crawler.is_same_domain("https://example.com/page").unwrap());
        assert!(!crawler.is_same_domain("https://other.com/page").unwrap());
    }
}
