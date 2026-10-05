// A sibling module, so it imports what it uses rather than relying on
// `use super::*` reaching lib.rs's private items.
use crate::{
    cluster, group_by_signature, load_payloads, AttackConfig, AttackReport, Attempt, AttemptResult,
    IntruderError, MarkedRequest, PayloadSource,
};

#[cfg(test)]
mod tests {
    use super::*;

    const TEMPLATE: &str = "GET /search?q=§fuzz§&page=1 HTTP/1.1\nHost: example.com\n\n";

    fn payloads(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("p{i}")).collect()
    }

    #[test]
    fn a_payload_replaces_the_marked_position() {
        let m = MarkedRequest::new(TEMPLATE);
        let out = m.substitute("hello").unwrap();
        assert!(out.contains("q=hello"));
        assert!(!out.contains('§'));
        // The rest of the request must be untouched.
        assert!(out.contains("page=1"));
        assert!(out.contains("Host: example.com"));
    }

    #[test]
    fn a_request_with_no_marker_is_refused_not_silently_sent() {
        let m = MarkedRequest::new("GET / HTTP/1.1\nHost: a.com\n\n");
        assert!(matches!(m.substitute("x"), Err(IntruderError::NoPositions)));
    }

    #[test]
    fn position_count_reflects_the_markers() {
        assert_eq!(MarkedRequest::new(TEMPLATE).position_count(), 1);
        let two = MarkedRequest::new("GET /?a=§1§&b=§2§ HTTP/1.1\nHost: a.com\n\n");
        assert_eq!(two.position_count(), 2);
    }

    #[test]
    fn display_text_replaces_markers_with_a_readable_placeholder() {
        let shown = MarkedRequest::new(TEMPLATE).display_text();
        assert!(!shown.contains('§'), "{shown}");
        assert!(shown.contains("<payload>"), "{shown}");
    }

    #[test]
    fn inline_payloads_are_trimmed_and_deduped() {
        let src = PayloadSource::Inline {
            values: vec![
                "  a  ".into(),
                "a".into(),
                "".into(),
                "# comment".into(),
                "b".into(),
            ],
        };
        let got = load_payloads(&src).unwrap();
        assert_eq!(got, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn an_empty_payload_list_is_an_error_not_a_zero_request_attack() {
        // "0 requests sent" and "the tool did nothing" look identical, so this
        // has to be loud.
        let src = PayloadSource::Inline {
            values: vec!["".into(), "# only a comment".into()],
        };
        assert!(matches!(
            load_payloads(&src),
            Err(IntruderError::NoPayloads)
        ));
    }

    #[test]
    fn a_missing_payload_file_names_the_path() {
        let src = PayloadSource::File {
            path: "/nonexistent/wordlist.txt".into(),
        };
        let err = load_payloads(&src).unwrap_err();
        assert!(err.to_string().contains("wordlist.txt"), "{err}");
    }

    #[test]
    fn payloads_load_from_a_real_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("list.txt");
        std::fs::write(&path, "one\n# comment\ntwo\n\none\n").unwrap();
        let got = load_payloads(&PayloadSource::File {
            path: path.to_string_lossy().to_string(),
        })
        .unwrap();
        assert_eq!(got, vec!["one".to_string(), "two".to_string()]);
    }

    #[test]
    fn grouping_by_signature_ignores_failed_attempts() {
        let attempts = vec![
            Attempt {
                payload: "a".into(),
                result: Ok(AttemptResult {
                    status_code: 200,
                    body_size: 10,
                    elapsed_ms: 1,
                    signature: "200:10".into(),
                    snippet: String::new(),
                }),
                index: 0,
            },
            Attempt {
                payload: "b".into(),
                result: Err("timed out".into()),
                index: 1,
            },
        ];
        let g = group_by_signature(&attempts);
        assert_eq!(g.len(), 1, "a failed attempt has no signature to group by");
        assert_eq!(g["200:10"], vec![0]);
    }

    #[test]
    fn a_report_knows_whether_it_covered_the_whole_list() {
        let report = AttackReport {
            id: "x".into(),
            started_at: String::new(),
            finished_at: String::new(),
            total_payloads: 10,
            attempted: 4,
            succeeded: 4,
            failed: 0,
            attempts: vec![],
            clusters: vec![],
            stopped_because: Some("capped".into()),
            config: AttackConfig::default(),
        };
        assert!(
            !report.is_complete(),
            "a partial run must not claim completeness"
        );
        assert_eq!(report.no_response_count(), 0);
        let _ = payloads(3);
    }

    #[test]
    fn the_default_caps_are_conservative() {
        let c = AttackConfig::default();
        assert!(
            c.max_requests <= 1000,
            "default cap too high: {}",
            c.max_requests
        );
        assert!(c.max_concurrency <= 8, "default concurrency too high");
    }
}
