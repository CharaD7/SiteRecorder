use indicatif::{ProgressBar, ProgressStyle};

pub struct CrawlProgress {
    bar: Option<ProgressBar>,
}

impl CrawlProgress {
    pub fn new(max_pages: u64, enabled: bool) -> Self {
        let bar = if enabled {
            let pb = ProgressBar::new(max_pages);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} pages ({eta})")
                    .expect("Invalid progress bar template")
                    .progress_chars("#>-")
            );
            Some(pb)
        } else {
            None
        };

        Self { bar }
    }

    pub fn inc(&self) {
        if let Some(ref pb) = self.bar {
            pb.inc(1);
        }
    }

    pub fn finish(&self) {
        if let Some(ref pb) = self.bar {
            pb.finish_with_message("✓ Crawl completed");
        }
    }

    pub fn set_message(&self, msg: String) {
        if let Some(ref pb) = self.bar {
            pb.set_message(msg);
        }
    }
}

impl Drop for CrawlProgress {
    fn drop(&mut self) {
        if let Some(ref pb) = self.bar {
            pb.finish_and_clear();
        }
    }
}
