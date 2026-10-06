//! End-to-end smoke test: a capped flood against a real local echo server.
//!
//! The unit tests prove the caps and token generation. This proves the crate can
//! actually drive the request loop, track responses, and report a real summary.

use spammer::{FloodPlan, FloodRun, Spammer, TokenPlan};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A minimal HTTP server that reads a request, echoes it, and sleeps to
/// simulate load. It counts how many requests it receives.
async fn spawn_echo_server(counter: Arc<AtomicUsize>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let handle = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let _ = socket.read(&mut buf).await;
                counter.fetch_add(1, Ordering::SeqCst);
                let response = format!("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong");
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    let _ = handle;
    addr
}

#[tokio::test]
async fn a_capped_flood_reaches_the_server_and_reports_a_summary() {
    let counter = Arc::new(AtomicUsize::new(0));
    let addr = spawn_echo_server(Arc::clone(&counter)).await;

    let plan = FloodPlan {
        method: "GET".to_string(),
        url: format!("http://{addr}/flood"),
        count: 50,
        concurrency: 4,
        headers: vec![(
            "User-Agent".to_string(),
            "SiteRecorder-smoker/1.0".to_string(),
        )],
        body: None,
    };
    plan.validate()
        .expect("plan should be valid under the caps");

    let spammer = Spammer;
    let FloodRun {
        sent,
        ok,
        failed,
        elapsed_ms,
        status_distribution,
        ..
    } = spammer.flood(&plan).await.expect("flood should succeed");

    assert_eq!(sent, 50, "all 50 planned requests should be sent");
    assert_eq!(
        ok, 50,
        "all requests should succeed against the echo server"
    );
    assert_eq!(failed, 0, "no failures expected");
    assert!(
        !status_distribution.is_empty(),
        "some status distribution should be reported"
    );
    assert!(
        status_distribution.iter().any(|(code, _)| *code == 200),
        "the echo server returned 200, expected it in the distribution"
    );
    assert!(elapsed_ms > 0, "some time should be reported as elapsed");
    assert_eq!(
        counter.load(Ordering::SeqCst),
        50,
        "the server should have received every request"
    );
}

#[tokio::test]
async fn count_over_the_cap_is_rejected_not_sent() {
    let plan = FloodPlan {
        method: "GET".to_string(),
        url: "http://127.0.0.1:1/".to_string(),
        count: 10_001,
        concurrency: 4,
        headers: vec![],
        body: None,
    };

    let err = plan
        .validate()
        .expect_err("10,001 requests must be rejected");
    assert!(
        err.to_string().contains("10,000"),
        "cap message should be surfaced"
    );
}

#[tokio::test]
async fn concurrency_over_the_cap_is_rejected() {
    let plan = FloodPlan {
        method: "GET".to_string(),
        url: "http://127.0.0.1:1/".to_string(),
        count: 10,
        concurrency: 33,
        headers: vec![],
        body: None,
    };

    let err = plan
        .validate()
        .expect_err("concurrency 33 must be rejected");
    assert!(
        err.to_string().contains("32"),
        "concurrency cap should be surfaced"
    );
}

#[tokio::test]
async fn token_generation_is_capped_and_validates() {
    // UUIDs
    let spammer = Spammer;
    let uuids = spammer
        .generate_tokens(&TokenPlan::Uuid { count: 10 })
        .await
        .expect("uuid generation should succeed");
    assert_eq!(uuids.count, 10);
    assert_eq!(uuids.kind, "uuid");
    assert!(uuids
        .samples
        .iter()
        .all(|s| uuid::Uuid::parse_str(s).is_ok()));

    // Hex
    let hex = spammer
        .generate_tokens(&TokenPlan::Hex {
            count: 10,
            bytes: 8,
        })
        .await
        .expect("hex generation should succeed");
    assert_eq!(hex.count, 10);
    assert_eq!(hex.kind, "hex");
    assert!(hex
        .samples
        .iter()
        .all(|s| s.len() == 16 && s.chars().all(|c| c.is_ascii_hexdigit())));

    // Base64
    let b64 = spammer
        .generate_tokens(&TokenPlan::Base64 {
            count: 10,
            bytes: 16,
        })
        .await
        .expect("base64 generation should succeed");
    assert_eq!(b64.count, 10);
    assert_eq!(b64.kind, "base64");

    // Over-cap count is rejected.
    let over = TokenPlan::Uuid { count: 100_001 };
    over.validate()
        .expect_err("token count over 100,000 must be rejected");
}
