//! End-to-end, against a real HTTP server on localhost.
//!
//! The unit tests prove the parser agrees with itself. These prove the crate
//! can actually take a request off a disk, put it on the wire, and read what
//! comes back -- which is the only claim that matters for a Repeater.

use repeater::send::{HttpSender, Sender};
use repeater::{observe, RawRequest};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A minimal HTTP server that echoes what it received.
///
/// Deliberately not a framework: it reads a raw request, asserts the method and
/// path, and replies with a body that identifies the request. That is enough to
/// prove the Repeater composed the request the operator typed.
async fn spawn_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = match socket.read(&mut buf).await {
                    Ok(n) => n,
                    Err(_) => return,
                };
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("")
                    .to_string();

                let body = format!("ECHO path={path}");
                let response = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: text/plain\r\n\
                     Content-Length: {}\r\n\
                     X-Test-Server: repeater\r\n\
                     \r\n\
                     {}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });

    addr
}

fn request_for(addr: SocketAddr, target: &str) -> RawRequest {
    // Absolute-form request-target (`GET http://host/path HTTP/1.1`), which is
    // what a proxy sees and is valid HTTP/1.1. This also pins the scheme
    // explicitly: the test server is plaintext, and `absolute_url` otherwise
    // defaults to https, which would fail a TLS handshake against it.
    RawRequest::new(format!(
        "GET http://{addr}{target} HTTP/1.1\r\nHost: {addr}\r\nUser-Agent: repeater-test\r\n\r\n"
    ))
}

#[tokio::test]
async fn a_typed_request_reaches_the_server_and_comes_back() {
    let addr = spawn_echo_server().await;
    let raw = request_for(addr, "/hello");
    let parsed = raw.parse().expect("should parse");

    let outcome = HttpSender::new()
        .send(&parsed.absolute_url().unwrap(), &parsed)
        .await
        .expect("send should succeed");

    assert_eq!(outcome.status_code, 200);
    assert_eq!(outcome.reason, "OK");
    assert!(
        outcome.body.contains("path=/hello"),
        "the server should have seen the path we typed, got: {}",
        outcome.body
    );
    assert!(
        outcome
            .headers
            .iter()
            .any(|(k, v)| k == "x-test-server" && v == "repeater"),
        "response headers should be captured: {:?}",
        outcome.headers
    );
}

#[tokio::test]
async fn editing_the_target_changes_where_the_request_lands() {
    // This is the entire Repeater loop: change one thing, observe the result.
    let addr = spawn_echo_server().await;

    for target in ["/one", "/two", "/three?x=1"] {
        let raw = request_for(addr, target);
        let parsed = raw.parse().unwrap();
        let outcome = HttpSender::new()
            .send(&parsed.absolute_url().unwrap(), &parsed)
            .await
            .unwrap();
        assert!(
            outcome.body.contains(&format!("path={target}")),
            "expected {target} to reach the server, got: {}",
            outcome.body
        );
    }
}

#[tokio::test]
async fn an_unreachable_host_is_an_error_not_a_fake_success() {
    // Port 1 on localhost refuses connections. This must surface as an error
    // naming the likely cause -- never a fabricated 200 with an empty body.
    let raw = RawRequest::new("GET / HTTP/1.1\nHost: 127.0.0.1:1\n\n");
    let parsed = raw.parse().unwrap();
    let err = HttpSender::new()
        .send(&parsed.absolute_url().unwrap(), &parsed)
        .await
        .expect_err("a refused connection must not look like a success");

    let msg = err.to_string();
    assert!(
        msg.to_lowercase().contains("connect"),
        "the error should name the cause, got: {msg}"
    );
}

#[tokio::test]
async fn observations_are_computed_on_a_real_request() {
    let addr = spawn_echo_server().await;
    let raw = request_for(addr, "/x?id=1'");
    let parsed = raw.parse().unwrap();
    let obs = observe(&parsed);

    // The apostrophe in the query should be noticed.
    assert!(
        obs.iter().any(|o| o.id == "suspicious-parameter"),
        "expected the quoted value to be flagged, got {obs:?}"
    );
    // And it must still be phrased as something to read, not a verdict.
    for o in &obs {
        assert!(!o.note.to_lowercase().contains("vulnerability"), "{o:?}");
    }
}
