use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExportError {
    #[error("Failed to export data: {0}")]
    ExportFailed(String),
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingData {
    pub session_id: String,
    pub timestamp: DateTime<Utc>,
    pub url: String,
    pub action: String,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone)]
pub enum ExportFormat {
    Json,
    Csv,
    Html,
}

pub struct Exporter;

impl Exporter {
    pub fn new() -> Self {
        Self
    }

    pub fn export_to_json<P: AsRef<Path>>(
        &self,
        data: &[RecordingData],
        path: P,
    ) -> Result<(), ExportError> {
        let json = serde_json::to_string_pretty(data)
            .map_err(|e| ExportError::ExportFailed(e.to_string()))?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn export_to_csv<P: AsRef<Path>>(
        &self,
        data: &[RecordingData],
        path: P,
    ) -> Result<(), ExportError> {
        let mut wtr = csv::Writer::from_path(path)?;
        
        wtr.write_record(&["session_id", "timestamp", "url", "action", "metadata"])?;
        
        for record in data {
            wtr.write_record(&[
                &record.session_id,
                &record.timestamp.to_rfc3339(),
                &record.url,
                &record.action,
                &record.metadata.to_string(),
            ])?;
        }
        
        wtr.flush()?;
        Ok(())
    }

    pub fn export_to_html<P: AsRef<Path>>(
        &self,
        data: &[RecordingData],
        path: P,
    ) -> Result<(), ExportError> {
        let mut html = String::from(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Recording Export</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Recording Export</h1>
    <table>
        <tr>
            <th>Session ID</th>
            <th>Timestamp</th>
            <th>URL</th>
            <th>Action</th>
            <th>Metadata</th>
        </tr>
"#,
        );

        for record in data {
            html.push_str(&format!(
                r#"        <tr>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
        </tr>
"#,
                record.session_id,
                record.timestamp.to_rfc3339(),
                record.url,
                record.action,
                record.metadata
            ));
        }

        html.push_str(
            r#"    </table>
</body>
</html>
"#,
        );

        std::fs::write(path, html)?;
        Ok(())
    }

    pub fn export<P: AsRef<Path>>(
        &self,
        data: &[RecordingData],
        path: P,
        format: ExportFormat,
    ) -> Result<(), ExportError> {
        match format {
            ExportFormat::Json => self.export_to_json(data, path),
            ExportFormat::Csv => self.export_to_csv(data, path),
            ExportFormat::Html => self.export_to_html(data, path),
        }
    }
}

impl Default for Exporter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exporter_creation() {
        let exporter = Exporter::new();
        assert!(std::mem::size_of_val(&exporter) == 0);
    }

    #[test]
    fn test_export_to_json() {
        let exporter = Exporter::new();
        let data = vec![RecordingData {
            session_id: "test-123".to_string(),
            timestamp: Utc::now(),
            url: "https://example.com".to_string(),
            action: "navigate".to_string(),
            metadata: serde_json::json!({"test": "data"}),
        }];

        let temp_path = std::env::temp_dir().join("test_export.json");
        let result = exporter.export_to_json(&data, &temp_path);
        assert!(result.is_ok());
        std::fs::remove_file(temp_path).ok();
    }
}
