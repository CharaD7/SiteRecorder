//! End-to-end attacks.
//!
//! A counting sender lets the caps be tested without a network, plus one test
//! that runs a genuine attack over localhost to prove the whole path works.

use intruder::repeater::send::{RepeaterError, SendOutcome, Sender};
use intruder::{
    AttackConfig, IntruderError, MarkedRequest, PayloadSource, ResponseCluster, Runner,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Records what it was asked to do and replies on demand.
///
/// Lets the tests assert *how many* requests went out, which is the property
/// the safety cap exists to guarantee.
struct CountingSender {
    calls: Arc<AtomicUsize>,
    /// Payload substrings that should produce a 500 instead of a 200.
    explode_on: Vec<String>,
}

impl CountingSender {
    fn new(explode_on: Vec<&str>) -> (Self, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Self {
                calls: calls.clone(),
                explode_on: explode_on.into_iter().map(String::from).collect(),
            },
            calls,
        )
    }
}

#[async_trait::async_trait]
impl Sender for CountingSender {
    async fn send(
        &self,
        _url: &str,
        req: &intruder::repeater::ParsedRequest,
    ) -> Result<SendOutcome, RepeaterError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let target = req.target.clone();
        let boom = self.explode_on.iter().any(|e| target.contains(e));
        let (status, body) = if boom {
            (500u16, "server error".to_string())
        } else {
            (200u16, "ok page body".to_string())
        };
        let body_size = body.len();
        Ok(SendOutcome {
            status_code: status,
            reason: "OK".into(),
            headers: vec![],
            body,
            body_truncated_at: None,
            body_size,
            elapsed_ms: 5,
            url: format!("http://example.com{target}"),
        })
    }
}

const TEMPLATE: &str = "GET /search?q=§a§ HTTP/1.1\nHost: example.com\n\n";

fn marked() -> MarkedRequest {
    MarkedRequest::new(TEMPLATE)
}

fn payloads(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("p{i}")).collect()
}

/// The safety cap: an oversized list must not be sent in full, and the report
/// must say so.
#[tokio::test]
async fn the_request_cap_is_enforced_and_reported() {
    let (sender, calls) = CountingSender::new(vec![]);
    let runner = Runner::new(
        sender,
        AttackConfig {
            max_requests: 10,
            ..Default::default()
        },
    );

    let report = runner
        .run(&marked(), &payloads(50), None)
        .await
        .expect("run");

    assert_eq!(calls.load(Ordering::SeqCst), 10, "only the cap was sent");
    assert_eq!(report.attempted, 10);
    assert_eq!(report.total_payloads, 50);

    // Crucially: it must not claim to have covered everything.
    assert!(!report.is_complete());
    let reason = report
        .stopped_because
        .as_ref()
        .expect("the cap must be stated");
    assert!(reason.contains("NOT sent"), "{reason}");
    assert!(
        reason.contains("40"),
        "should say how many were skipped: {reason}"
    );
}

#[tokio::test]
async fn a_run_within_the_cap_is_marked_complete() {
    let (sender, calls) = CountingSender::new(vec![]);
    let report = Runner::new(
        sender,
        AttackConfig {
            max_requests: 100,
            ..Default::default()
        },
    )
    .run(&marked(), &payloads(5), None)
    .await
    .unwrap();

    assert_eq!(calls.load(Ordering::SeqCst), 5);
    assert!(report.is_complete());
    assert!(report.stopped_because.is_none());
    assert_eq!(report.succeeded, 5);
    assert_eq!(report.failed, 0);
}

/// A template with no § marker must fail before a single request goes out.
#[tokio::test]
async fn an_unmarked_template_sends_nothing() {
    let (sender, calls) = CountingSender::new(vec![]);
    let unmarked = MarkedRequest::new("GET /search?q=fixed HTTP/1.1\nHost: example.com\n\n");

    let err = Runner::new(sender, AttackConfig::default())
        .run(&unmarked, &payloads(5), None)
        .await
        .expect_err("no positions must be refused");

    assert!(matches!(err, IntruderError::NoPositions));
    assert_eq!(calls.load(Ordering::SeqCst), 0, "nothing should be sent");
}

/// A request with no Host header cannot be addressed, so it must fail before
/// sending rather than 100 times over.
#[tokio::test]
async fn an_undeliverable_template_fails_before_sending() {
    let (sender, calls) = CountingSender::new(vec![]);
    let no_host = MarkedRequest::new("GET /x?q=§a§ HTTP/1.1\nAccept: */*\n\n");

    let err = Runner::new(sender, AttackConfig::default())
        .run(&no_host, &payloads(3), None)
        .await
        .expect_err("no target must be refused");

    assert!(matches!(err, IntruderError::NoTarget(_)), "{err:?}");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

/// The core value: three payloads behave differently, and the report surfaces
/// that without calling any of them a vulnerability.
#[tokio::test]
async fn differing_responses_are_grouped_and_flagged() {
    let (sender, _) = CountingSender::new(vec!["boom"]);

    let mut list = payloads(30);
    list.push("boom".into());
    list.push("boom2".into());
    list.push("boom3".into());

    let report = Runner::new(sender, AttackConfig::default())
        .run(&marked(), &list, None)
        .await
        .unwrap();

    let outlier = report
        .clusters
        .iter()
        .find(|c| {
            c.cluster
                == ResponseCluster::Response {
                    status: 500,
                    size: 12,
                }
        })
        .expect("the 500 group");
    assert_eq!(outlier.count, 3);
    assert!(outlier.is_outlier, "3 of 33 should be noticed");

    let biggest = &report.clusters[0];
    assert_eq!(
        biggest.cluster,
        ResponseCluster::Response {
            // "ok page body" is 12 bytes. "server error" is also 12, but the
            // status differs, so the two remain distinct clusters.
            status: 200,
            size: 12
        }
    );
    assert_eq!(biggest.count, 30);
}

/// Progress is reported once per request, and totals correctly.
#[tokio::test]
async fn progress_is_reported_for_every_request() {
    let (sender, _) = CountingSender::new(vec![]);
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = seen.clone();

    let report = Runner::new(sender, AttackConfig::default())
        .run(
            &marked(),
            &payloads(7),
            Some(Arc::new(move |done, total| {
                sink.lock().unwrap().push((done, total));
            })),
        )
        .await
        .unwrap();

    let log = seen.lock().unwrap().clone();
    assert_eq!(log.len(), 7, "one callback per request");
    assert!(log.iter().all(|(_, t)| *t == 7));
    assert_eq!(*log.last().unwrap(), (7, 7));
    assert_eq!(report.attempted, 7);
}

fn payloads_from_an_inline_source_round_trip() {
    let src = PayloadSource::Inline {
        values: vec!["a".into(), "b".into()],
    };
    assert_eq!(intruder::load_payloads(&src).unwrap().len(), 2);
}

/// A genuine attack over a real socket.
///
/// The counting-sender tests prove the logic; this proves requests actually
/// reach a server and each payload lands individually.
#[tokio::test]
async fn a_real_attack_reaches_a_real_server() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                if socket.read(&mut buf).await.is_err() {
                    return;
                }
                let req = String::from_utf8_lossy(&buf).to_string();
                // Echo the query value so the test can prove each payload
                // reached the server individually.
                let value = req
                    .split("q=")
                    .nth(1)
                    .and_then(|s| s.split('&').next())
                    .unwrap_or("")
                    .to_string();
                let body = format!("saw:{value}");
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });

    let target = MarkedRequest::new(format!(
        "GET http://{addr}/search?q=§a§ HTTP/1.1\nHost: {addr}\n\n"
    ));
    let list = vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()];

    let report = Runner::new(
        intruder::repeater::send::HttpSender::new(),
        AttackConfig::default(),
    )
    .run(&target, &list, None)
    .await
    .expect("attack");

    assert!(report.is_complete());
    assert_eq!(report.succeeded, 3);
    assert!(
        report.attempts.iter().all(|a| a.result.is_ok()),
        "every payload should have been answered"
    );
    for a in &report.attempts {
        if let Ok(r) = &a.result {
            assert!(r.snippet.starts_with("saw:"), "snippet: {}", r.snippet);
        }
    }
}

/// An unreachable target is reported per payload, never faked as success.
#[tokio::test]
async fn an_unreachable_target_is_reported_not_faked() {
    let raw = MarkedRequest::new("GET http://127.0.0.1:1/x?q=§a§ HTTP/1.1\nHost: 127.0.0.1:1\n\n");
    let report = Runner::new(
        intruder::repeater::send::HttpSender::new(),
        AttackConfig::default(),
    )
    .run(&raw, &["p".to_string()], None)
    .await
    .expect("run");

    assert_eq!(report.succeeded, 0);
    assert_eq!(report.failed, 1);
    assert_eq!(report.no_response_count(), 1);
    // A run where nothing answered must not read as "all clear".
    assert!(report
        .clusters
        .iter()
        .any(|c| c.cluster == ResponseCluster::NoResponse));
    assert!(report.attempts[0].result.is_err());
}
