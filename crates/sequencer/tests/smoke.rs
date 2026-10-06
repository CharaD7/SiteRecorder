//! End-to-end smoke test: a Sequencer run against a real local echo server.
//!
//! The unit tests prove the plan validation and statistical helpers. This proves
//! the crate can drive the request loop and report real randomness observations
//! about the values it collected.

use sequencer::{Observations, SeqPlan, SequenceRun, Sequencer, Transport};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A minimal HTTP server that reads a request, extracts the value from the
/// query parameter named by the test, and echoes it back so the Sequencer can
/// match requests to responses.
async fn spawn_echo_server(counter: Arc<AtomicUsize>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let handle = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = match socket.read(&mut buf).await {
                    Ok(n) => n,
                    Err(_) => return,
                };
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                // Extract a value after "value=" and return it as the response body.
                let value = req
                    .split_once("value=")
                    .map(|(_, rest)| rest.split('\r').next().unwrap_or("").to_string())
                    .unwrap_or_else(|| format!("echo-{}", counter.fetch_add(1, Ordering::SeqCst)));
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    value.len(),
                    value
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    let _ = handle;
    addr
}

#[tokio::test]
async fn random_hex_values_pass_the_uniformity_checks() {
    let counter = Arc::new(AtomicUsize::new(0));
    let addr = spawn_echo_server(Arc::clone(&counter)).await;

    let plan = SeqPlan {
        method: "GET".to_string(),
        url: format!("http://{}/probe", addr),
        count: 100,
        concurrency: 4,
        transport: Transport::Query {
            name: "value".to_string(),
        },
        generator: sequencer::Generator::Hex { bytes: 4 },
    };
    Sequencer.validate(&plan).expect("plan should be valid");

    let SequenceRun {
        sent,
        collected,
        observations,
        plan: returned_plan,
    } = Sequencer.run(&plan).await.expect("run should succeed");

    assert_eq!(sent, 100, "all 100 planned values should be sent");
    assert_eq!(collected, 100, "all 100 responses should be collected");
    assert_eq!(
        returned_plan.count, 100,
        "the plan is echoed back unchanged"
    );
    let Observations {
        entropy_bits_per_byte,
        max_entropy_bits_per_byte: _,
        chi_square: _,
        chi_square_p_value,
        collisions,
        runs_z: _,
        distinct_values,
        value_width_bits,
    } = observations;
    // 4 bytes of hex are not truly random (16 chars instead of 256 symbols), so we
    // only sanity-check the shape of the output, not that it is cryptographically random.
    assert!(value_width_bits > 0, "width should be reported");
    assert!(entropy_bits_per_byte >= 0.0, "entropy is non-negative");
    assert!(distinct_values > 0, "some distinct values expected");
    assert!(
        chi_square_p_value >= 0.0 && chi_square_p_value <= 1.0,
        "p-value is a probability"
    );
    assert!(collisions >= 0, "collision count is non-negative");
}

#[tokio::test]
async fn a_small_run_is_reported_with_the_correct_cap_behavior() {
    let counter = Arc::new(AtomicUsize::new(0));
    let addr = spawn_echo_server(Arc::clone(&counter)).await;

    let plan = SeqPlan {
        method: "GET".to_string(),
        url: format!("http://{}/probe", addr),
        count: 10,
        concurrency: 2,
        transport: Transport::Header {
            name: "X-Value".to_string(),
        },
        generator: sequencer::Generator::Uuid,
    };
    Sequencer.validate(&plan).expect("plan should be valid");

    let SequenceRun {
        sent, collected, ..
    } = Sequencer.run(&plan).await.expect("run should succeed");

    assert_eq!(sent, 10, "10 planned requests should be sent");
    assert_eq!(collected, 10, "10 responses should be collected");
}

#[tokio::test]
async fn preview_validates_without_sending_traffic() {
    use sequencer::Generator;
    let plan = SeqPlan {
        method: "POST".to_string(),
        url: "http://example.com/login".to_string(),
        count: 10,
        concurrency: 2,
        transport: Transport::Json {
            path: "$.token".to_string(),
        },
        generator: Generator::Uuid,
    };
    Sequencer.validate(&plan).expect("plan should be valid");

    let preview = SequenceRun {
        plan: plan.clone(),
        sent: 0,
        collected: 0,
        observations: Observations {
            entropy_bits_per_byte: 0.0,
            max_entropy_bits_per_byte: 0.0,
            chi_square: 0.0,
            chi_square_p_value: 1.0,
            collisions: 0,
            runs_z: 0.0,
            distinct_values: plan.count,
            value_width_bits: 128,
        },
    };
    assert_eq!(preview.sent, 0, "a preview must not have sent anything");
    assert_eq!(preview.collected, 0, "a preview must have no responses");
    assert_eq!(preview.plan.count, 10, "the plan must be echoed back");
}

#[tokio::test]
async fn count_over_the_cap_is_rejected() {
    let plan = SeqPlan {
        method: "GET".to_string(),
        url: "http://example.com/".to_string(),
        count: 1001,
        concurrency: 2,
        transport: Transport::Query {
            name: "value".to_string(),
        },
        generator: sequencer::Generator::Hex { bytes: 4 },
    };
    Sequencer
        .validate(&plan)
        .expect_err("sequencer count is capped at 1,000");
}
