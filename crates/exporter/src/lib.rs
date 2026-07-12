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
    #[error("CSV error: {0}")]
    CsvError(#[from] csv::Error),
    #[error("PDF error: {0}")]
    PdfError(String),
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
    Pdf,
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

    pub fn export_to_pdf<P: AsRef<Path>>(
        &self,
        data: &[RecordingData],
        path: P,
    ) -> Result<(), ExportError> {
        use printpdf::{PdfDocument, Mm};

        let (doc, page1, layer1) = PdfDocument::new(
            &format!("SiteRecorder Export - {}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S")),
            Mm(210.0),
            Mm(297.0),
            "Layer 1",
        );

        let current_layer = doc.get_page(page1).get_layer(layer1);

        let font = doc.add_builtin_font(printpdf::BuiltinFont::Helvetica).map_err(|e| ExportError::PdfError(e.to_string()))?;
        current_layer.use_text("SiteRecorder Recording Export", 18.0, Mm(20.0), Mm(260.0), &font);

        current_layer.use_text(&format!("Generated: {}", Utc::now().format("%Y-%m-%d %H:%M:%S")), 10.0, Mm(20.0), Mm(250.0), &font);
        current_layer.use_text(&format!("Total Records: {}", data.len()), 10.0, Mm(20.0), Mm(244.0), &font);

        let mut y_pos = 230.0;

        current_layer.use_text("Session ID", 9.0, Mm(20.0), Mm(y_pos), &font);
        current_layer.use_text("Timestamp", 9.0, Mm(60.0), Mm(y_pos), &font);
        current_layer.use_text("URL", 9.0, Mm(100.0), Mm(y_pos), &font);
        current_layer.use_text("Action", 9.0, Mm(150.0), Mm(y_pos), &font);

        y_pos -= 6.0;

        for record in data.iter().take(30) {
            if y_pos < 20.0 {
                break;
            }

            let session_display = if record.session_id.len() > 20 {
                format!("{}...", &record.session_id[..17])
            } else {
                record.session_id.clone()
            };

            let url_display = if record.url.len() > 30 {
                format!("{}...", &record.url[..27])
            } else {
                record.url.clone()
            };

            current_layer.use_text(&session_display, 8.0, Mm(20.0), Mm(y_pos), &font);
            current_layer.use_text(&record.timestamp.format("%Y-%m-%d %H:%M").to_string(), 8.0, Mm(60.0), Mm(y_pos), &font);
            current_layer.use_text(&url_display, 8.0, Mm(100.0), Mm(y_pos), &font);
            current_layer.use_text(&record.action, 8.0, Mm(150.0), Mm(y_pos), &font);

            y_pos -= 5.0;
        }

        if data.len() > 30 {
            y_pos -= 3.0;
            current_layer.use_text(&format!("... and {} more records", data.len() - 30), 9.0, Mm(20.0), Mm(y_pos), &font);
        }

        let file = std::fs::File::create(path)
            .map_err(|e| ExportError::PdfError(e.to_string()))?;
        doc.save(&mut std::io::BufWriter::new(file))
            .map_err(|e| ExportError::PdfError(e.to_string()))?;

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
            ExportFormat::Pdf => self.export_to_pdf(data, path),
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
