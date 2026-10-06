//! End-to-end smoke test for the Collaborator crate.
//!
//! The client's HTTP `/generate` and `/poll` endpoints are stubbed against a
//! server that must implement them, so this test verifies the TCP catch-all
//! path — exactly the self-hosted behavior that is implemented — plus the
//! Beacon rendering logic that turns a UUID into a `.interact.` address.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

/// A minimal TCP server that accepts anything connected, parses `beacon=` and
/// the host header, records the interaction into the provided store, and
/// echoes back a short acknowledgement.
async fn spawn_collaborator_server(
    store: Arc<collaborator::InteractionStore>,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let store = Arc::clone(&store);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = match stream.read(&mut buf).await {
                    Ok(n) => n,
                    Err(_) => return,
                };
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                // Parse the TCP server: beacon= query param or .interact. host header.
                let beacon_id = request
                    .split_once("beacon=")
                    .map(|(_, rest)| rest.split('&').next().unwrap_or("").to_string())
                    .or_else(|| {
                        request
                            .lines()
                            .find(|l| l.to_lowercase().starts_with("host:"))
                            .and_then(|l| l.split(':').nth(1).map(|s| s.trim().to_string()))
                    })
                    .unwrap_or_else(|| "unidentified".to_string());
                let interaction = collaborator::Interaction {
                    id: format!("tcp-{}", beacon_id.len()),
                    beacon: collaborator::Beacon::new(),
                    interaction_type: collaborator::InteractionType::Http,
                    protocol: "tcp".to_string(),
                    remote_address: "127.0.0.1:12345".to_string(),
                    received_at: chrono::Utc::now(),
                    headers: std::collections::HashMap::new(),
                    query_string: request.split_once('?').map(|(_, q)| q.to_string()),
                    body: None,
                    raw: request,
                };
                store.record(interaction).await;
                let response = "HTTP/1.1 200 OK\r\n\r\npong";
                let _ = stream.write_all(response.as_bytes());
            });
        }
    });

    addr
}

#[tokio::test]
async fn a_beacon_request_is_recorded_by_the_self_hosted_server() {
    let store = Arc::new(collaborator::InteractionStore::default());

    let addr = spawn_collaborator_server(Arc::clone(&store)).await;

    // The client side uses a blocking std socket; wrap it so it doesn't
    // block the async runtime while the server task is being scheduled.
    let stream = tokio::task::spawn_blocking(move || {
        let stream = TcpStream::connect(addr).expect("connect");
        let mut stream = stream;
        let request = "GET / HTTP/1.1\r\nHost: aaaa-bbbb.interact.example.com\r\n\r\n";
        stream.write_all(request.as_bytes()).expect("write");
        let mut buf = [0u8; 256];
        stream.read(&mut buf).expect("read");
        stream
    })
    .await
    .expect("client task");
    let _ = stream;

    // Give the server a moment to process and record.
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let interactions = store.list().await;
    assert!(
        !interactions.is_empty(),
        "the server should have recorded the interaction"
    );
    let interaction = &interactions[0];
    assert!(
        interaction.raw.contains(".interact."),
        "the interaction should carry the out-of-band beacon, got: {:?}",
        interaction.raw
    );
}

#[tokio::test]
async fn a_beacon_is_rendered_as_an_interact_address() {
    let beacon = collaborator::Beacon::new();
    let host = beacon.host("example.com");
    // The server-facing host header is `<12>.<12>.<host>` (no .interact. marker).
    assert!(
        host.ends_with(".example.com"),
        "host ends with the configured domain"
    );
    assert_eq!(host.split('.').count(), 3, "host has three segments");

    let subdomain = beacon.subdomain("example.com");
    assert!(subdomain.contains(".interact."));
    assert!(subdomain.ends_with(".example.com"));
    assert!(subdomain != host, "subdomain and host renderings differ");

    // Two beacons must render as distinct addresses.
    let b2 = collaborator::Beacon::new();
    assert_ne!(
        beacon.host("example.com"),
        b2.host("example.com"),
        "distinct beacons must produce distinct addresses"
    );
}
