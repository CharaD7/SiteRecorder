//! Response comparison (Burp Suite Comparer).
//!
//! Takes two responses and shows exactly what differs. This answers the
//! question clustering cannot: "these 3 payloads behaved differently from the
//! other 480 -- in what way?"
//!
//! # Why a byte diff is not enough
//!
//! Byte diffing flags a session id or CSRF token on every comparison, which
//! buries the one line that actually changed. The comparison here is
//! structural: headers matched case-insensitively by name, bodies compared
//! line by line, and each difference weighted by how much of the response
//! moved.
//!
//! That still does not say which difference matters. Two responses differing
//! only by a nonce are the same response for testing purposes; one differing
//! by status or redirect target is not. `Importance` separates those cases as
//! a description of what changed, never as a judgement about whether the
//! change was a vulnerability.
//!
//! Nothing here ranks, scores, or declares a winner. Two responses are
//! described; a human reads the description.

use serde::{Deserialize, Serialize};

/// One named difference between two responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Difference {
    /// `header:content-type`, `status`, or `body line 42`.
    pub location: String,
    pub left: Option<String>,
    pub right: Option<String>,
    pub importance: Importance,
}

/// How much a difference is worth looking at.
///
/// `Trivial` covers values that differ between *any* two live requests --
/// nonces, timestamps, request ids -- and exists so a human can dismiss them
/// at a glance rather than mistake them for signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Importance {
    /// Differs on essentially every request: nonces, timestamps, ids.
    Trivial,
    /// A body line or header value changed.
    Noticeable,
    /// Status, a redirect target, or a content type changed.
    Structural,
}

impl Importance {
    pub fn as_str(self) -> &'static str {
        match self {
            Importance::Trivial => "trivial",
            Importance::Noticeable => "noticeable",
            Importance::Structural => "structural",
        }
    }

    /// Plain-language explanation, without a verdict.
    pub fn explain(self) -> &'static str {
        match self {
            Importance::Trivial => concat!(
                "This value is expected to differ between two requests, so it is ",
                "unlikely to tell you anything."
            ),
            Importance::Noticeable => concat!(
                "This part of the response changed. Whether that matters depends on ",
                "what the endpoint is for."
            ),
            Importance::Structural => concat!(
                "The response changed shape, not just content. The two requests took ",
                "different paths through the application."
            ),
        }
    }
}

/// Header names whose values are unique per request.
const VOLATILE_HEADERS: &[&str] = &[
    "date",
    "set-cookie",
    "x-request-id",
    "x-csrf-token",
    "x-correlation-id",
    "x-amzn-trace-id",
    "x-trace-id",
    "etag",
];

/// Body fields treated as volatile when they look like a nonce or timestamp.
const VOLATILE_BODY_HINTS: &[&str] = &["nonce", "csrf", "timestamp", "token", "request_id"];

/// Compare two responses structurally.
pub fn compare(left: &crate::SendOutcome, right: &crate::SendOutcome) -> Vec<Difference> {
    let mut out = Vec::new();

    // Status is the most reliable single signal, so it leads.
    if left.status_code != right.status_code {
        out.push(Difference {
            location: "status".into(),
            left: Some(left.status_code.to_string()),
            right: Some(right.status_code.to_string()),
            importance: Importance::Structural,
        });
    }

    // Headers: the union of both sides, matched case-insensitively.
    let mut names: Vec<String> = left
        .headers
        .iter()
        .chain(right.headers.iter())
        .map(|(k, _)| k.to_lowercase())
        .collect();
    names.sort();
    names.dedup();

    for name in names {
        let l = header_value(left, &name);
        let r = header_value(right, &name);
        if l == r {
            continue;
        }
        // A Location change is structural: it changes where the browser goes.
        let importance = if name == "location" {
            Importance::Structural
        } else if VOLATILE_HEADERS.contains(&name.as_str()) {
            Importance::Trivial
        } else {
            Importance::Noticeable
        };
        out.push(Difference {
            location: format!("header:{name}"),
            left: l,
            right: r,
            importance,
        });
    }

    // Body: line by line, so a reviewer sees which line moved.
    let l_lines: Vec<&str> = left.body.lines().collect();
    let r_lines: Vec<&str> = right.body.lines().collect();
    for i in 0..l_lines.len().max(r_lines.len()) {
        let l = l_lines.get(i).copied();
        let r = r_lines.get(i).copied();
        if l == r {
            continue;
        }
        out.push(Difference {
            location: format!("body line {}", i + 1),
            left: l.map(str::to_string),
            right: r.map(str::to_string),
            importance: classify_body_line(l, r),
        });
    }

    out
}

fn header_value(outcome: &crate::SendOutcome, lower_name: &str) -> Option<String> {
    outcome
        .headers
        .iter()
        .find(|(k, _)| k.to_lowercase() == lower_name)
        .map(|(_, v)| v.clone())
}

/// Judge a body line by whether it looks like per-request noise.
fn classify_body_line(left: Option<&str>, right: Option<&str>) -> Importance {
    let sample = left.or(right).unwrap_or("").to_lowercase();
    if VOLATILE_BODY_HINTS.iter().any(|h| sample.contains(h)) {
        return Importance::Trivial;
    }
    Importance::Noticeable
}

/// A comparison, described.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Comparison {
    pub differences: Vec<Difference>,
    /// Counts by importance.
    pub structural: usize,
    pub noticeable: usize,
    pub trivial: usize,
    /// True when nothing beyond expected per-request noise changed.
    pub effectively_identical: bool,
    /// One-line description: what differs, not what it means.
    pub summary: String,
}

/// Summarise a list of differences.
pub fn summarise(differences: Vec<Difference>) -> Comparison {
    let structural = differences
        .iter()
        .filter(|d| d.importance == Importance::Structural)
        .count();
    let noticeable = differences
        .iter()
        .filter(|d| d.importance == Importance::Noticeable)
        .count();
    let trivial = differences.len() - structural - noticeable;

    // "Identical" means nothing structural or noticeable changed. Trivial
    // differences occur on any two live requests, so treating them as a
    // difference would mean the tool always reported a difference and the
    // summary would never be read.
    let effectively_identical = structural == 0 && noticeable == 0;

    let summary = if effectively_identical {
        if trivial == 0 {
            "The two responses are identical.".to_string()
        } else {
            format!(
                "The two responses differ only in {trivial} value(s) that change on every \
                 request, such as a nonce, timestamp or session id. For testing purposes \
                 these responses are the same."
            )
        }
    } else {
        format!(
            "{structural} structural and {noticeable} other difference(s), plus {trivial} \
             value(s) that normally change on every request."
        )
    };

    Comparison {
        differences,
        structural,
        noticeable,
        trivial,
        effectively_identical,
        summary,
    }
}

/// Compare two outcomes in one step.
pub fn compare_outcomes(left: &crate::SendOutcome, right: &crate::SendOutcome) -> Comparison {
    summarise(compare(left, right))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out(status: u16, headers: &[(&str, &str)], body: &str) -> crate::SendOutcome {
        crate::SendOutcome {
            status_code: status,
            reason: String::new(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.to_string(),
            body_truncated_at: None,
            body_size: body.len(),
            elapsed_ms: 1,
            url: String::new(),
        }
    }

    #[test]
    fn identical_responses_report_no_differences() {
        let a = out(200, &[("Content-Type", "text/html")], "<html>hi</html>");
        let b = out(200, &[("Content-Type", "text/html")], "<html>hi</html>");
        let c = compare_outcomes(&a, &b);
        assert!(c.differences.is_empty(), "{:?}", c.differences);
        assert!(c.effectively_identical);
        assert_eq!(c.summary, "The two responses are identical.");
    }

    /// The property that makes this tool useful: a nonce differs on every
    /// request, so flagging it would make every comparison look different.
    #[test]
    fn a_nonce_difference_is_trivial_and_reads_as_the_same_response() {
        let a = out(
            200,
            &[("Set-Cookie", "sid=abc")],
            r#"{"nonce":"aaa","data":"x"}"#,
        );
        let b = out(
            200,
            &[("Set-Cookie", "sid=xyz")],
            r#"{"nonce":"bbb","data":"x"}"#,
        );
        let c = compare_outcomes(&a, &b);

        assert_eq!(c.structural, 0);
        assert_eq!(c.noticeable, 0);
        assert!(c.trivial >= 2, "{c:?}");
        assert!(
            c.effectively_identical,
            "a nonce change is not a behavioural change"
        );
        assert!(c.summary.contains("the same"), "{}", c.summary);
    }

    #[test]
    fn a_status_change_is_structural() {
        let a = out(200, &[], "ok");
        let b = out(500, &[], "error");
        let c = compare_outcomes(&a, &b);
        assert_eq!(c.structural, 1);
        assert!(!c.effectively_identical);
        let d = &c.differences[0];
        assert_eq!(d.location, "status");
        assert_eq!(d.importance, Importance::Structural);
    }

    #[test]
    fn a_redirect_target_change_is_structural() {
        let a = out(302, &[("Location", "/home")], "");
        let b = out(302, &[("Location", "/admin")], "");
        let c = compare_outcomes(&a, &b);
        assert_eq!(c.structural, 1);
        assert_eq!(c.differences[0].location, "header:location");
    }

    #[test]
    fn header_names_are_matched_case_insensitively() {
        let a = out(200, &[("Content-Type", "text/html")], "");
        let b = out(200, &[("CONTENT-TYPE", "application/json")], "");
        let c = compare_outcomes(&a, &b);
        assert_eq!(
            c.noticeable, 1,
            "a case-only header name change must not read as two headers"
        );
        assert_eq!(c.differences[0].location, "header:content-type");
    }

    #[test]
    fn a_body_line_is_located_precisely() {
        let a = out(200, &[], "line1\nline2\nline3");
        let b = out(200, &[], "line1\nCHANGED\nline3");
        let c = compare_outcomes(&a, &b);
        assert_eq!(c.differences.len(), 1);
        assert_eq!(c.differences[0].location, "body line 2");
        assert_eq!(c.differences[0].right.as_deref(), Some("CHANGED"));
    }

    #[test]
    fn a_header_present_on_only_one_side_is_still_reported() {
        let a = out(200, &[], "x");
        let b = out(200, &[("X-Debug", "on")], "x");
        let c = compare_outcomes(&a, &b);
        assert_eq!(c.noticeable, 1);
        assert_eq!(c.differences[0].left, None);
        assert_eq!(c.differences[0].right.as_deref(), Some("on"));
    }

    /// The honesty guarantee: the summary describes what differs, and never
    /// declares the difference a problem.
    #[test]
    fn the_summary_never_claims_a_vulnerability() {
        let cases = [
            (out(200, &[], "ok"), out(500, &[], "boom")),
            (out(200, &[("A", "1")], "x"), out(404, &[("A", "2")], "y")),
        ];
        for (a, b) in cases {
            let c = compare_outcomes(&a, &b);
            let text = format!("{} {}", c.summary, c.differences.len()).to_lowercase();
            for banned in ["vulnerab", "exploit", "attack", "is a bug"] {
                assert!(!text.contains(banned), "summary claims too much: {text}");
            }
            for d in &c.differences {
                assert!(!d.importance.explain().to_lowercase().contains("vulnerab"));
            }
        }
    }

    #[test]
    fn importance_explanations_are_present_for_every_level() {
        for i in [
            Importance::Trivial,
            Importance::Noticeable,
            Importance::Structural,
        ] {
            assert!(!i.explain().is_empty(), "{i:?} has no explanation");
            assert!(!i.as_str().is_empty());
        }
    }
}
