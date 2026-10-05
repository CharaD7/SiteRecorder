//! Manual HTTP request editing and replay (Burp Suite Repeater).
//!
//! # What this is for
//!
//! Take a request, change one thing, send it again, and see exactly what
//! changed. That is the whole loop, and it is how most real findings start:
//! an ID in a URL, a header, a cookie, a body field.
//!
//! # Design note: text, not a form
//!
//! Requests are held as **raw HTTP text** rather than as parsed structures.
//! That is deliberate. A form round-trips only the fields the form knows
//! about, so an unknown or unusual header is silently dropped on send -- and
//! then the operator concludes the server behaved the same way twice. Raw text
//! preserves everything the user can see and edit, including the parts we do
//! not understand.
//!
//! Parsing is therefore separate from storage: [`RawRequest::parse`] produces a
//! view for display, while the original text stays authoritative and is what
//! actually gets sent.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

pub mod compare;
pub mod send;

pub use compare::{compare_outcomes, Comparison, Difference, Importance};
pub use send::{SendOutcome, Sender};

#[derive(Debug, Error)]
pub enum RepeaterError {
    #[error("could not parse the request: {0}")]
    Parse(String),
    #[error("could not send the request: {0}")]
    Send(String),
    #[error("no request is loaded")]
    NoRequest,
}

/// A request as the operator sees and edits it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawRequest {
    pub id: String,
    pub text: String,
}

impl RawRequest {
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            text: text.into(),
        }
    }

    /// Parse for display. The stored text is untouched either way, so a request
    /// this cannot parse is still sendable -- it just gets a less rich editor.
    pub fn parse(&self) -> Result<ParsedRequest, RepeaterError> {
        ParsedRequest::parse(&self.text)
    }

    pub fn set_text(&mut self, text: impl Into<String>) {
        self.text = text.into();
    }
}

/// A parsed view over raw HTTP request text.
///
/// Header order is preserved via [`Header`] rather than a map: duplicate
/// headers and exact ordering are both meaningful when reproducing a request.
/// A parsed view over raw HTTP request text.
///
/// Header order is preserved via [`Header`] rather than a map: duplicate
/// headers and exact ordering are both meaningful when reproducing a request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedRequest {
    pub method: String,
    pub target: String,
    pub version: String,
    pub headers: Vec<Header>,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: String,
}

impl ParsedRequest {
    pub fn parse(text: &str) -> Result<Self, RepeaterError> {
        // Normalise line endings. Copy-paste from Windows or a devtools panel
        // brings CRLF, and a raw request sent with CRLF inside the body is
        // silently altered by some servers.
        let normalised = text.replace("\r\n", "\n");

        let (head, body): (&str, &str) = match normalised.find("\n\n") {
            Some(i) => (&normalised[..i], &normalised[i + 2..]),
            None => (normalised.as_str(), ""),
        };

        let mut lines = head.lines();
        let request_line = lines
            .next()
            .ok_or_else(|| RepeaterError::Parse("the request is empty".into()))?;

        let mut parts = request_line.split_whitespace();
        let method = parts
            .next()
            .ok_or_else(|| RepeaterError::Parse("no method in the request line".into()))?
            .to_string();
        let target = parts
            .next()
            .ok_or_else(|| {
                RepeaterError::Parse(
                    "no request target. The request line must be `METHOD /path HTTP/1.1`; \
                     a browser address-bar URL is not a request line."
                        .into(),
                )
            })?
            .to_string();
        let version = parts.next().unwrap_or("HTTP/1.1").to_string();

        let mut headers = Vec::new();
        for line in lines {
            if line.trim().is_empty() {
                continue;
            }
            match line.split_once(':') {
                Some((name, value)) => headers.push(Header {
                    name: name.trim().to_string(),
                    value: value.trim().to_string(),
                }),
                None => {
                    return Err(RepeaterError::Parse(format!(
                        "header line has no colon: `{}`",
                        line.trim()
                    )))
                }
            }
        }

        Ok(Self {
            method,
            target,
            version,
            headers,
            body: body.to_string(),
        })
    }

    /// The absolute URL to send to.
    ///
    /// An origin-form target (`/path`) needs the `Host` header to become a URL,
    /// so this is where a request copied out of a log gets its destination.
    pub fn absolute_url(&self) -> Result<String, RepeaterError> {
        if self.target.starts_with("http://") || self.target.starts_with("https://") {
            return Ok(self.target.clone());
        }

        let host = self
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("host"))
            .map(|h| h.value.clone())
            .ok_or_else(|| {
                RepeaterError::Parse(
                    "the target is a path like `/foo`, so a `Host` header is required \
                     to know where to send it"
                        .into(),
                )
            })?;

        // Default to https: a Host header on a modern target is far more often
        // 443 than 80, and silently downgrading would send credentials in the
        // clear.
        let scheme = if host.ends_with(":80") {
            "http"
        } else {
            "https"
        };

        // Keep the port. Stripping it would send `Host: 127.0.0.1:8080` to
        // port 443, which fails in a way that looks like the target being down
        // rather than a bug in the URL construction.
        let authority = host
            .rsplit_once(':')
            .filter(|(h, p)| !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
            .map_or(host.clone(), |(h, p)| format!("{h}:{p}"));

        Ok(format!("{scheme}://{authority}{}", self.target))
    }

    /// Header lookup, case-insensitive as HTTP requires.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    pub fn set_header(&mut self, name: &str, value: &str) {
        if let Some(h) = self
            .headers
            .iter_mut()
            .find(|h| h.name.eq_ignore_ascii_case(name))
        {
            h.value = value.to_string();
        } else {
            self.headers.push(Header {
                name: name.to_string(),
                value: value.to_string(),
            });
        }
    }

    /// Re-serialise to raw text, preserving header order.
    pub fn to_raw(&self) -> String {
        let mut out = format!("{} {} {}\n", self.method, self.target, self.version);
        for h in &self.headers {
            out.push_str(&format!("{}: {}\n", h.name, h.value));
        }
        out.push('\n');
        out.push_str(&self.body);
        out
    }
}

/// Things a human would otherwise have to spot by eye.
///
/// This is the "beginner-friendly" part done honestly: not a claim that
/// something is wrong, but a pointer to the line worth reading. Each one
/// states what it saw, never what it concluded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Observation {
    /// Stable id, e.g. "missing-host-header".
    pub id: String,
    /// One sentence, plain language.
    pub note: String,
    /// Why a tester might care. Deliberately phrased as "may", not "is".
    pub why: String,
}

impl Observation {
    fn new(id: &str, note: &str, why: &str) -> Self {
        Self {
            id: id.to_string(),
            note: note.to_string(),
            why: why.to_string(),
        }
    }
}

/// Look at a parsed request and describe what stands out.
///
/// Never returns a verdict. It reports observable facts so an operator knows
/// where to look; deciding whether any of them is a vulnerability is a human
/// judgement, and this crate does not make it.
pub fn observe(req: &ParsedRequest) -> Vec<Observation> {
    let mut out = Vec::new();

    let http_host = req
        .header("Host")
        .map(|h| h.ends_with(":80") || h.starts_with("localhost"))
        .unwrap_or(true);
    if http_host {
        out.push(Observation::new(
            "http-host",
            "This request is addressed to a local host, or to port 80.",
            "Credentials and tokens in this request would travel unencrypted. Confirm whether \
             https is meant to be used here before treating this as expected.",
        ));
    }

    if req.method.eq_ignore_ascii_case("GET") && !req.body.is_empty() {
        out.push(Observation::new(
            "get-with-body",
            "This is a GET request that carries a body.",
            "Some servers and proxies ignore a GET body entirely. If a parameter appears to \
             'not work', this is one reason why.",
        ));
    }

    if let Some(cookie) = req.header("Cookie") {
        let lower = cookie.to_lowercase();
        if !lower.contains("secure") && !lower.contains("httponly") {
            out.push(Observation::new(
                "cookie-flags",
                "The Cookie header carries session cookies without Secure or HttpOnly.",
                "Without Secure a cookie can be sent over plain http; without HttpOnly it is \
                 readable by page scripts. Check whether the server sets these itself.",
            ));
        }
    }

    let lower_body = req.body.to_lowercase();
    if lower_body.contains("password")
        || lower_body.contains("passwd")
        || req.body.contains("secret")
    {
        out.push(Observation::new(
            "sensitive-in-body",
            "The body contains a field that looks like a password or secret.",
            "Worth knowing before replaying this against a system you do not own, and worth \
             checking that the value is not carried in a URL where it would be logged.",
        ));
    }

    for param in [
        "id", "user", "account", "email", "file", "path", "redirect", "url",
    ] {
        if let Some(value) = query_value(&req.target, param) {
            let suspicious = value.contains("..")
                || value.contains("<script")
                || value.contains("%00")
                || value.contains('\'')
                || value.contains(" OR ");
            if suspicious {
                out.push(Observation::new(
                    "suspicious-parameter",
                    &format!(
                        "The `{param}` parameter contains characters that often appear in \
                         injection attempts."
                    ),
                    "This may simply be a URL-encoded value the application needs. It is worth \
                     reading before assuming either way.",
                ));
            }
        }
    }

    if req.method.eq_ignore_ascii_case("POST")
        && req.body.contains('=')
        && !req.header("Content-Type").is_some_and(|c| {
            c.to_lowercase()
                .contains("application/x-www-form-urlencoded")
        })
    {
        out.push(Observation::new(
            "post-without-form-content-type",
            "This POST carries form-looking data but no `application/x-www-form-urlencoded` \
             Content-Type.",
            "A server may parse the body differently than expected, or ignore it. If a parameter \
             seems not to register, check this first.",
        ));
    }

    if req.header("Host").is_none() {
        out.push(Observation::new(
            "missing-host-header",
            "There is no Host header.",
            "HTTP/1.1 requires one. Its absence usually means the request was assembled by \
             hand and may not be what you intended to send.",
        ));
    }

    out
}

/// Extract a query-parameter value without a URL parser, so this stays usable
/// on a hand-edited target string that may not be a valid URL.
fn query_value(target: &str, param: &str) -> Option<String> {
    let query = target.split_once('?')?.1.split('#').next().unwrap_or("");
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k.eq_ignore_ascii_case(param) {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Repeated-header values, for display. `Set-Cookie` legitimately appears many
/// times and a map would collapse them.
pub fn header_map(req: &ParsedRequest) -> BTreeMap<String, Vec<String>> {
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for h in &req.headers {
        map.entry(h.name.to_lowercase())
            .or_default()
            .push(h.value.clone());
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "POST /login HTTP/1.1\n\
                              Host: example.com\n\
                              Content-Type: application/x-www-form-urlencoded\n\
                              \n\
                              username=alice&password=hunter2";

    #[test]
    fn parses_method_target_and_headers() {
        let p = ParsedRequest::parse(SAMPLE).expect("valid request");
        assert_eq!(p.method, "POST");
        assert_eq!(p.target, "/login");
        assert_eq!(p.version, "HTTP/1.1");
        assert_eq!(p.header("Host"), Some("example.com"));
        assert_eq!(p.body, "username=alice&password=hunter2");
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let p = ParsedRequest::parse(SAMPLE).unwrap();
        // HTTP header names are case-insensitive; a form that is not would
        // silently fail to find "Host".
        assert_eq!(p.header("host"), Some("example.com"));
        assert_eq!(p.header("HOST"), Some("example.com"));
    }

    #[test]
    fn origin_form_target_becomes_an_absolute_url() {
        let p = ParsedRequest::parse(SAMPLE).unwrap();
        assert_eq!(
            p.absolute_url().unwrap(),
            "https://example.com/login",
            "a Host header with no port should default to https, not http"
        );
    }

    #[test]
    fn explicit_port_80_selects_http() {
        let p = ParsedRequest::parse("GET /x HTTP/1.1\nHost: example.com:80\n\n").unwrap();
        assert_eq!(p.absolute_url().unwrap(), "http://example.com:80/x");
    }

    /// A non-default port must survive URL construction. Dropping it sends the
    /// request to 443, and the resulting "connection refused" looks like the
    /// target being down rather than a bug here.
    #[test]
    fn a_non_default_port_is_preserved() {
        let p = ParsedRequest::parse("GET /x HTTP/1.1\nHost: 127.0.0.1:38271\n\n").unwrap();
        assert_eq!(p.absolute_url().unwrap(), "https://127.0.0.1:38271/x");
    }

    /// The most common beginner mistake: pasting a browser address-bar URL.
    /// It has no request line, and the error must say so rather than showing a
    /// generic parse failure.
    #[test]
    fn a_browser_url_is_rejected_with_a_useful_message() {
        let err = ParsedRequest::parse("https://example.com/login").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("request line"), "{msg}");
    }

    #[test]
    fn missing_host_header_is_a_named_error_not_a_panic() {
        let p = ParsedRequest::parse("GET /x HTTP/1.1\nAccept: */*\n\n").unwrap();
        let err = p.absolute_url().unwrap_err();
        assert!(err.to_string().contains("Host"), "{err}");
    }

    #[test]
    fn crlf_from_copy_paste_is_normalised() {
        let p = ParsedRequest::parse("GET / HTTP/1.1\r\nHost: a.com\r\n\r\n").unwrap();
        assert_eq!(p.header("Host"), Some("a.com"));
        assert_eq!(p.body, "", "CRLF must not leak into the body");
    }

    #[test]
    fn header_order_is_preserved_on_round_trip() {
        let raw = "GET / HTTP/1.1\nZ-Last: 1\nA-First: 2\nHost: a.com\n\n";
        let p = ParsedRequest::parse(raw).unwrap();
        let back = p.to_raw();
        let z = back.find("Z-Last").unwrap();
        let a = back.find("A-First").unwrap();
        assert!(z < a, "header order must survive a round trip:\n{back}");
    }

    #[test]
    fn duplicate_headers_are_all_kept() {
        let p = ParsedRequest::parse("GET / HTTP/1.1\nHost: a.com\nX-Tag: one\nX-Tag: two\n\n")
            .unwrap();
        assert_eq!(p.headers.iter().filter(|h| h.name == "X-Tag").count(), 2);
        assert_eq!(header_map(&p)["x-tag"].len(), 2);
    }

    #[test]
    fn set_header_replaces_rather_than_duplicating() {
        let mut p = ParsedRequest::parse(SAMPLE).unwrap();
        p.set_header("host", "other.com");
        assert_eq!(p.header("Host"), Some("other.com"));
        assert_eq!(
            p.headers
                .iter()
                .filter(|h| h.name.eq_ignore_ascii_case("host"))
                .count(),
            1
        );
    }

    // Observations: facts, never verdicts.
    #[test]
    fn a_password_in_the_body_is_flagged_as_something_to_read() {
        let p = ParsedRequest::parse(SAMPLE).unwrap();
        let obs = observe(&p);
        assert!(obs.iter().any(|o| o.id == "sensitive-in-body"));
        // The wording must not assert a vulnerability.
        let note = obs.iter().find(|o| o.id == "sensitive-in-body").unwrap();
        assert!(note.why.to_lowercase().contains("worth"), "{note:?}");
    }

    #[test]
    fn a_get_with_a_body_is_noticed() {
        let p = ParsedRequest::parse("GET /x HTTP/1.1\nHost: a.com\n\na=1").unwrap();
        assert!(observe(&p).iter().any(|o| o.id == "get-with-body"));
    }

    #[test]
    fn a_missing_host_header_is_noticed() {
        let p = ParsedRequest::parse("GET /x HTTP/1.1\nAccept: */*\n\n").unwrap();
        assert!(observe(&p).iter().any(|o| o.id == "missing-host-header"));
    }

    #[test]
    fn a_clean_request_produces_no_observations() {
        let p =
            ParsedRequest::parse("GET /about HTTP/1.1\nHost: example.com\nAccept: text/html\n\n")
                .unwrap();
        assert_eq!(
            observe(&p),
            Vec::new(),
            "a plain GET should be unremarkable"
        );
    }

    #[test]
    fn observations_never_claim_a_vulnerability_is_present() {
        // Every `why` must stay hedged. A tool that says "this IS a
        // vulnerability" is asserting something it cannot know.
        let cases = [
            SAMPLE,
            "GET /?id=1' HTTP/1.1\nHost: a.com\n\n",
            "GET /x HTTP/1.1\nHost: a.com:80\nCookie: sid=abc\n\n",
        ];
        for raw in cases {
            for o in observe(&ParsedRequest::parse(raw).unwrap()) {
                let text = format!("{} {}", o.note, o.why).to_lowercase();
                assert!(
                    !text.contains("vulnerability is")
                        && !text.contains("is exploitable")
                        && !text.contains("confirmed vulnerability"),
                    "observation claims too much: {o:?}"
                );
            }
        }
    }
}
