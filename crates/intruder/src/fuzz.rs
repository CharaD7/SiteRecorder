//! Automatic fuzzing (Burp Suite Fuzzer).
//!
//! # How this differs from Intruder
//!
//! Intruder waits for a human to mark positions. The Fuzzer finds them: it
//! parses the query string and the body, works out which values are worth
//! varying, marks each one in turn, and runs the attack. The operator supplies
//! a request and a wordlist; the tool does the placement.
//!
//! # Why that is also a hazard
//!
//! Automatic placement means automatic *damage*. A parameter the operator never
//! considered gets mutated, and some parameters are not safe to vary: a CSRF
//! token, a session id, an `id` that deletes a record. So:
//!
//! - [`FuzzPlan`] is shown **before** anything is sent, listing exactly which
//!   values will be varied. Nothing is sent until the operator has seen it.
//! - [`discover`] skips values that look like tokens by default, because a
//!   mutated session id is a request that will simply be rejected -- noise at
//!   best, and a logged-out session at worst.
//! - The same [`crate::run::AttackConfig`] caps apply, and the report's
//!   `stopped_because` carries through unchanged.
//!
//! # What the results mean
//!
//! Unchanged from Intruder: a differing response is an observation, not a
//! finding. Fuzzing a parameter and getting a different response proves the
//! server took a different path. It does not prove that path was wrong.

use serde::{Deserialize, Serialize};

use crate::{AttackConfig, AttackReport, IntruderError, MarkedRequest};

/// Where a fuzzable value was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParameterLocation {
    /// In the request target, e.g. `?id=1`.
    Query,
    /// In a form-encoded body.
    FormBody,
    /// A field in a JSON body, with its path (`user.name`).
    JsonBody,
}

/// One candidate value to vary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FuzzTarget {
    pub location: ParameterLocation,
    /// Parameter name, or the JSON path.
    pub name: String,
    /// The current value, kept for display.
    pub current_value: String,
    /// Skipped because it looks like a session or CSRF token.
    pub skipped_as_token: bool,
}

/// What the Fuzzer intends to do, shown before anything is sent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FuzzPlan {
    /// Values that will be varied.
    pub targets: Vec<FuzzTarget>,
    /// Values found but skipped as tokens.
    pub skipped: Vec<FuzzTarget>,
    /// Total requests the run will send, before the cap is applied.
    pub planned_requests: usize,
    /// Set when the plan was trimmed to fit `max_requests`.
    pub trimmed_because: Option<String>,
}

impl FuzzPlan {
    /// One-line summary for the confirmation dialog.
    pub fn summary(&self) -> String {
        format!(
            "Will vary {} value(s) across {} request(s). {} value(s) were skipped because \
             they look like session or CSRF tokens.",
            self.targets.len(),
            self.planned_requests,
            self.skipped.len()
        )
    }

    /// The plan is only actionable when there is something to do.
    pub fn is_actionable(&self) -> bool {
        !self.targets.is_empty() && self.planned_requests > 0
    }
}

/// Values that are almost certainly session or CSRF material.
///
/// Deliberately conservative: a false skip costs a missed test, while a false
/// include mutates a live token. Name shapes only -- guessing at length is how
/// you skip a real parameter called `state`.
const TOKEN_NAMES: &[&str] = &[
    "csrf",
    "csrf_token",
    "xsrf",
    "_token",
    "authenticity_token",
    "nonce",
    "state",
    "session",
    "sessionid",
    "session_id",
    "sid",
    "phpsessid",
    "jsessionid",
    "token",
];
/// Find every value the Fuzzer could vary in a raw request.
///
/// Parsing is best-effort by design. A body that is not valid JSON is not an
/// error; it simply yields no JSON targets. A request the tool cannot fully
/// understand is still worth fuzzing on the parts it can.
pub fn discover(text: &str) -> Result<FuzzPlan, IntruderError> {
    let mut targets = Vec::new();
    let mut skipped = Vec::new();

    let Ok(parsed) = crate::repeater::ParsedRequest::parse(text) else {
        return Err(IntruderError::Parse(
            "The request could not be parsed, so there is nothing to fuzz.".into(),
        ));
    };

    // 1. Query parameters, from the target.
    if let Some(query) = parsed.target.split_once('?').map(|(_, q)| q) {
        let query = query.split('#').next().unwrap_or("");
        for pair in query.split('&') {
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let t = FuzzTarget {
                location: ParameterLocation::Query,
                name: name.to_string(),
                current_value: value.to_string(),
                skipped_as_token: false,
            };
            if looks_like_a_token(name) {
                skipped.push(t);
            } else {
                targets.push(t);
            }
        }
    }

    // 2. Form-encoded body, but only when the Content-Type says so. Guessing
    //    from a body that merely contains `=` would mangle a JSON payload.
    let is_form = parsed.header("Content-Type").is_some_and(|c| {
        c.to_lowercase()
            .contains("application/x-www-form-urlencoded")
    });

    if is_form && !parsed.body.is_empty() {
        for pair in parsed.body.split('&') {
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let t = FuzzTarget {
                location: ParameterLocation::FormBody,
                name: name.to_string(),
                current_value: value.to_string(),
                skipped_as_token: false,
            };
            if looks_like_a_token(name) {
                skipped.push(t);
            } else {
                targets.push(t);
            }
        }
    }

    // 3. JSON body.
    let is_json = parsed
        .header("Content-Type")
        .is_some_and(|c| c.to_lowercase().contains("json"));

    if is_json && !parsed.body.trim().is_empty() {
        match serde_json::from_str::<serde_json::Value>(&parsed.body) {
            Ok(value) => {
                collect_json(&value, "", &mut targets, &mut skipped);
            }
            Err(e) => {
                // Not fatal. The query and form parameters above are still good,
                // so say what was missed rather than refusing the whole request.
                skipped.push(FuzzTarget {
                    location: ParameterLocation::JsonBody,
                    name: "(body)".into(),
                    current_value: format!("JSON parse failed: {e}"),
                    skipped_as_token: false,
                });
            }
        }
    }

    Ok(FuzzPlan {
        targets,
        skipped,
        planned_requests: 0,
        trimmed_because: None,
    })
}

/// Walk a JSON document, collecting every scalar leaf.
fn collect_json(
    value: &serde_json::Value,
    prefix: &str,
    targets: &mut Vec<FuzzTarget>,
    skipped: &mut Vec<FuzzTarget>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                collect_json(v, &path, targets, skipped);
            }
        }
        serde_json::Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                let path = format!("{prefix}[{i}]");
                collect_json(v, &path, targets, skipped);
            }
        }
        serde_json::Value::String(s) => {
            push_json_target(prefix, s, targets, skipped);
        }
        // Numbers and booleans are still fuzzable, but their current value has
        // to be rendered as text to sit in the request body.
        serde_json::Value::Number(n) => {
            push_json_target(prefix, &n.to_string(), targets, skipped);
        }
        serde_json::Value::Bool(b) => {
            push_json_target(prefix, &b.to_string(), targets, skipped);
        }
        // null holds no value to replace.
        serde_json::Value::Null => {}
    }
}

fn push_json_target(
    path: &str,
    value: &str,
    targets: &mut Vec<FuzzTarget>,
    skipped: &mut Vec<FuzzTarget>,
) {
    if path.is_empty() {
        return;
    }
    let t = FuzzTarget {
        location: ParameterLocation::JsonBody,
        name: path.to_string(),
        current_value: value.to_string(),
        skipped_as_token: false,
    };
    if looks_like_a_token(path) {
        skipped.push(t);
    } else {
        targets.push(t);
    }
}
/// The text the Fuzzer would send for one target, marked with §.
pub fn build_marked_request(text: &str, target: &FuzzTarget) -> Result<String, IntruderError> {
    let parsed = crate::repeater::ParsedRequest::parse(text)
        .map_err(|e| IntruderError::Parse(e.to_string()))?;

    match target.location {
        ParameterLocation::Query => {
            let (path, query) = parsed
                .target
                .split_once('?')
                .ok_or_else(|| IntruderError::NoPositions)?;
            let rebuilt = query
                .split('&')
                .map(|pair| match pair.split_once('=') {
                    // Empty span, so the payload replaces the original value
                    // rather than being appended to it.
                    Some((name, value)) if name.eq_ignore_ascii_case(&target.name) => {
                        format!("{name}=§{value}§")
                    }
                    _ => pair.to_string(),
                })
                .collect::<Vec<_>>()
                .join("&");
            Ok(format!("{path}?{rebuilt}"))
        }
        ParameterLocation::FormBody => {
            let rebuilt = parsed
                .body
                .split('&')
                .map(|pair| match pair.split_once('=') {
                    // Empty span, so the payload replaces the original value
                    // rather than being appended to it.
                    Some((name, value)) if name.eq_ignore_ascii_case(&target.name) => {
                        format!("{name}=§{value}§")
                    }
                    _ => pair.to_string(),
                })
                .collect::<Vec<_>>()
                .join("&");
            Ok(rebuilt)
        }
        ParameterLocation::JsonBody => {
            // Rebuild through the parsed value rather than string replacement,
            // so a payload containing quotes is escaped correctly instead of
            // producing invalid JSON the server rejects for the wrong reason.
            let mut value: serde_json::Value = serde_json::from_str(&parsed.body).map_err(|e| {
                IntruderError::Parse(format!("JSON body could not be re-parsed: {e}"))
            })?;
            if !mark_json_leaf(&mut value, &target.name) {
                return Err(IntruderError::Parse(format!(
                    "`{}` was not found in the JSON body; it may have moved since the plan \
                     was built",
                    target.name
                )));
            }
            serde_json::to_string(&value).map_err(|e| IntruderError::Parse(e.to_string()))
        }
    }
}

/// Replace the leaf at `path` with a marker.
///
/// The marker goes **inside** the JSON string, and the original value is
/// removed so the marked span is exactly `§...§` with nothing between. That
/// matters twice over:
///
/// - `{"q":"§"}` stays valid JSON whatever payload is substituted, including
///   one containing a quote. Leaving the old value inside the span would
///   produce `{"q":"a"bvalue"}` -- invalid JSON that the server rejects as
///   malformed, which reads like a WAF response and teaches nothing.
/// - The payload is not appended to the original, so `id=§1§` with payload `2`
///   sends `2`, not `12`.
fn mark_json_leaf(value: &mut serde_json::Value, path: &str) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for k in keys {
                let child = if path == k {
                    Some(k.clone())
                } else {
                    path.strip_prefix(&format!("{k}.")).map(str::to_string)
                };
                let Some(rest) = child else { continue };
                let slot = map.get_mut(&k).expect("key came from the map");
                if rest == k {
                    let current = slot
                        .as_str()
                        .map(String::from)
                        .unwrap_or_else(|| slot.to_string());
                    *slot = serde_json::Value::String(format!("§{current}§"));
                    return true;
                }
                if mark_json_leaf(slot, &rest) {
                    return true;
                }
            }
            false
        }
        serde_json::Value::Array(items) => {
            for (i, v) in items.iter_mut().enumerate() {
                let Some(rest) = path.strip_prefix(&format!("[{i}]")) else {
                    continue;
                };
                let rest = rest.trim_start_matches('.');
                if rest.is_empty() {
                    let current = v
                        .as_str()
                        .map(String::from)
                        .unwrap_or_else(|| v.to_string());
                    *v = serde_json::Value::String(format!("§{current}§"));
                    return true;
                }
                if mark_json_leaf(v, rest) {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

/// Build the full plan: discovery, then the request count, trimmed to the cap.
pub fn plan(
    text: &str,
    payload_count: usize,
    config: &AttackConfig,
) -> Result<FuzzPlan, IntruderError> {
    let mut p = discover(text)?;

    // Each target costs `payload_count` requests, and targets run one at a time
    // so a response can be attributed to a specific value.
    let planned = p.targets.len().saturating_mul(payload_count);
    p.planned_requests = planned;

    if planned > config.max_requests {
        let keep = config.max_requests / payload_count.max(1);
        p.trimmed_because = Some(format!(
            "Fuzzing every value would send {planned} requests, above the limit of {}. Only \
             the first {keep} value(s) will be varied. Raise the limit or shorten the payload \
             list to fuzz the rest.",
            config.max_requests
        ));
        p.targets.truncate(keep);
        p.planned_requests = p.targets.len().saturating_mul(payload_count);
    }

    Ok(p)
}

/// Escape a payload for insertion into a JSON string value.
///
/// A JSON body has to be re-encoded per request, or a payload containing a
/// quote produces malformed JSON and the server rejects it as a parse error --
/// which reads like a WAF block and teaches the operator nothing about the
/// parameter under test. `FuzzPlan` records whether the body is JSON so the
/// runner can apply this.
pub fn escape_for_json(payload: &str) -> String {
    serde_json::to_string(payload)
        .map(|s| s.trim_matches('"').to_string())
        .unwrap_or_else(|_| payload.to_string())
}

/// Run the fuzzing plan, one report per varied value.
pub async fn run(
    text: &str,
    payloads: &[String],
    config: AttackConfig,
    runner: &crate::run::Runner<crate::repeater::send::HttpSender>,
    progress: Option<crate::run::AttackProgress>,
) -> Result<Vec<AttackReport>, IntruderError> {
    let plan = plan(text, payloads.len(), &config)?;
    if !plan.is_actionable() {
        return Err(IntruderError::NoPositions);
    }

    let mut reports = Vec::new();
    for target in &plan.targets {
        let marked = MarkedRequest::new(build_marked_request(text, target)?);
        reports.push(runner.run(&marked, payloads, progress.clone()).await?);
    }
    Ok(reports)
}

#[cfg(test)]
#[path = "fuzz_tests.rs"]
mod fuzz_tests;

fn looks_like_a_token(name: &str) -> bool {
    let lower = name.to_lowercase();
    TOKEN_NAMES
        .iter()
        .any(|t| lower == *t || (lower.len() >= t.len() + 3 && lower.contains(t)))
}
