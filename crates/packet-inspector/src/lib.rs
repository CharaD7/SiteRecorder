//! Wireshark-style packet capture and inspection.
//!
//! A friendly Tauri UI layer wrapping the working `packet-capture` crate
//! (real pcap via datalink, TCP/UDP/HTTP/DNS/TLS parsing). Nothing about this
//! layer makes a measurement claim: it records traffic you tell it to record,
//! and reports only what was observed.

use packet_capture::{CaptureFilter, CaptureSession, PacketCapture};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

/// Errors surfaced to the UI.
#[derive(Debug, Error)]
pub enum InspectorError {
    #[error("Capture failed: {0}")]
    Capture(#[from] packet_capture::CaptureError),

    #[error("Capture not running")]
    NotRunning,

    #[error("No packets captured yet")]
    NoPackets,
}

pub type Result<T> = std::result::Result<T, InspectorError>;

/// Application state holding the capture engine plus the last session.
pub struct PacketInspector {
    engine: Arc<PacketCapture>,
    session: Arc<Mutex<Option<CaptureSession>>>,
}

impl PacketInspector {
    pub fn new() -> Self {
        let (engine, _events) = PacketCapture::new();
        PacketInspector {
            engine: Arc::new(engine),
            session: Arc::new(Mutex::new(None)),
        }
    }
}

impl Default for PacketInspector {
    fn default() -> Self {
        Self::new()
    }
}

/// List available capture interfaces.
pub async fn list_interfaces() -> Vec<packet_capture::NetworkInterfaceInfo> {
    PacketCapture::list_interfaces().await
}

/// Start capturing on an interface.
pub async fn start_capture(
    state: &PacketInspector,
    interface: &str,
    promiscuous: bool,
    bpf_filter: Option<&str>,
) -> Result<Option<CaptureSession>> {
    state
        .engine
        .start_capture(interface, promiscuous, bpf_filter)
        .await?;
    let mut guard = state.session.lock().await;
    *guard = state.engine.get_current_session().await;
    Ok(guard.clone())
}

/// Stop capturing.
pub async fn stop_capture(state: &PacketInspector) -> Result<Option<CaptureSession>> {
    state.engine.stop_capture().await;
    let mut guard = state.session.lock().await;
    *guard = state.engine.get_current_session().await;
    Ok(guard.clone())
}

/// Get captured packets (paginated).
pub async fn get_packets(
    state: &PacketInspector,
    offset: usize,
    limit: usize,
) -> Result<Vec<packet_capture::PacketInfo>> {
    let packets = state.engine.get_packets_paginated(offset, limit).await;
    if packets.is_empty() && limit > 0 {
        return Err(InspectorError::NoPackets);
    }
    Ok(packets)
}

/// Get current capture statistics.
pub async fn get_stats(state: &PacketInspector) -> packet_capture::CaptureStats {
    state.engine.get_stats().await
}

/// Get the current capture session.
pub async fn get_session(state: &PacketInspector) -> Result<Option<CaptureSession>> {
    let guard = state.session.lock().await;
    if let Some(s) = guard.clone() {
        Ok(Some(s))
    } else {
        Ok(state.engine.get_current_session().await)
    }
}

/// Add a display/filter rule.
pub async fn add_filter(state: &PacketInspector, filter: CaptureFilter) {
    state.engine.add_filter(filter).await;
}

/// Remove a filter.
pub async fn remove_filter(state: &PacketInspector, id: &str) {
    state.engine.remove_filter(id).await;
}

/// Get all active filters.
pub async fn get_filters(state: &PacketInspector) -> Vec<CaptureFilter> {
    state.engine.get_filters().await
}

/// Check whether a capture is in progress.
pub async fn is_capturing(state: &PacketInspector) -> bool {
    state.engine.is_running().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspector_default_constructs_without_network_access() {
        let _state = PacketInspector::new(); // does nothing
    }
}
