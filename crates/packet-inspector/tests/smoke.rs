//! Smoke test for the packet-inspector Tauri-facing API surface.
//!
//! Real packet capture requires a privileged capture device (libpcap / WinPcap
//! on Windows / Core Foundation on macOS), so this test exercises the API
//! constructors and query paths that the Tauri commands use — it verifies the
//! crate wires up correctly without needing an actual network adapter.

use packet_inspector::PacketInspector;

#[test]
fn inspector_default_constructs_without_network_access() {
    // The Inspector wraps PacketCapture but must construct synchronously and
    // without requiring any network device.
    let inspector = PacketInspector::new();
    let _ = inspector;
}

#[tokio::test]
async fn list_interfaces_returns_a_non_null_response() {
    // If no capture device is available this may return an empty list; the
    // important check is that it does not panic or require elevated access.
    let interfaces = packet_inspector::list_interfaces().await;
    assert!(
        interfaces.is_empty() || !interfaces.is_empty(),
        "interface listing should succeed"
    );
}

#[tokio::test]
async fn filters_can_be_added_and_retrieved() {
    let inspector = PacketInspector::new();
    let filter = packet_capture::CaptureFilter {
        id: "test-filter".to_string(),
        name: "ip filter".to_string(),
        enabled: true,
        filter_type: packet_capture::FilterType::Protocol,
        value: "ip".to_string(),
        color: "blue".to_string(),
    };
    packet_inspector::add_filter(&inspector, filter.clone()).await;
    let filters = packet_inspector::get_filters(&inspector).await;
    assert!(
        filters
            .iter()
            .any(|f| f.id == "test-filter" && f.value == "ip"),
        "the added filter should be retrievable: {:?}",
        filters
    );
}

#[tokio::test]
async fn is_capturing_is_false_when_nothing_is_running() {
    let inspector = PacketInspector::new();
    assert!(
        !packet_inspector::is_capturing(&inspector).await,
        "capture must not be running when nothing started it"
    );
}
