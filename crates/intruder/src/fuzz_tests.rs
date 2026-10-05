// A sibling module (declared with #[path]), so it must import what it uses
// rather than relying on `use super::*` reaching fuzz.rs's private items.
use super::{
    build_marked_request, discover, escape_for_json, plan, AttackConfig, FuzzTarget, MarkedRequest,
    ParameterLocation,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn query_req() -> &'static str {
        "GET /search?q=hello&page=2&csrf_token=abc123 HTTP/1.1\nHost: example.com\n\n"
    }

    fn json_req(body: &str) -> String {
        format!("POST /api HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{body}")
    }

    #[test]
    fn query_parameters_are_discovered() {
        let p = discover(query_req()).unwrap();
        let names: Vec<&str> = p.targets.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"q"), "{names:?}");
        assert!(names.contains(&"page"), "{names:?}");
        assert_eq!(
            p.targets
                .iter()
                .find(|t| t.name == "q")
                .unwrap()
                .current_value,
            "hello"
        );
    }

    /// The safety behaviour that matters: mutating a session token is noise at
    /// best and a logged-out session at worst, so it is not auto-selected.
    #[test]
    fn session_and_csrf_parameters_are_skipped_not_fuzzed() {
        let p = discover(query_req()).unwrap();
        assert!(
            p.targets.iter().all(|t| !t.name.contains("csrf")),
            "csrf_token must not be fuzzed"
        );
        assert!(
            p.skipped.iter().any(|t| t.name == "csrf_token"),
            "it should be reported as skipped, not silently dropped: {:?}",
            p.skipped
        );
    }

    #[test]
    fn the_plan_reports_what_it_will_do() {
        let p = plan(query_req(), 3, &AttackConfig::default()).unwrap();
        assert!(p.is_actionable());
        let s = p.summary();
        assert!(s.contains("skipped"), "{s}");
        assert!(s.contains("session or CSRF"), "{s}");
    }

    #[test]
    fn a_json_body_is_walked_including_nested_and_array_fields() {
        let req = json_req(r#"{"user":{"name":"ada","id":7},"tags":["a","b"],"ok":true}"#);
        let p = discover(&req).unwrap();
        let names: Vec<&str> = p.targets.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"user.name"), "{names:?}");
        assert!(names.contains(&"user.id"), "{names:?}");
        assert!(names.contains(&"tags[0]"), "{names:?}");
        assert!(names.contains(&"ok"), "{names:?}");
    }

    #[test]
    fn a_form_body_is_only_read_when_the_content_type_says_so() {
        let form = "POST /login HTTP/1.1\nHost: a.com\nContent-Type: \
                    application/x-www-form-urlencoded\n\nuser=alice&password=x";
        let p = discover(form).unwrap();
        assert!(p.targets.iter().any(|t| t.name == "user"));

        // Same shape, but the header says JSON -- the body must be left alone
        // rather than mangled by form parsing.
        let not_form = "POST /login HTTP/1.1\nHost: a.com\nContent-Type: \
                        application/json\n\nuser=alice&password=x";
        assert!(discover(not_form).unwrap().targets.is_empty());
    }

    #[test]
    fn a_query_target_is_marked_and_leaves_the_rest_alone() {
        let p = discover(query_req()).unwrap();
        let q = p.targets.iter().find(|t| t.name == "q").unwrap();
        let marked = build_marked_request(query_req(), q).unwrap();
        assert!(marked.contains("q=§hello§"), "{marked}");
        assert!(marked.contains("page=2"), "{marked}");
        assert!(
            !marked.contains("csrf_token=§"),
            "other parameters must stay untouched: {marked}"
        );
    }

    #[test]
    fn a_json_target_is_marked_as_valid_json() {
        let req = json_req(r#"{"user":{"name":"ada","id":7}}"#);
        let p = discover(&req).unwrap();
        let name = p.targets.iter().find(|t| t.name == "user.name").unwrap();
        let marked = build_marked_request(&req, name).unwrap();
        assert!(marked.contains("\"name\":\"§ada§\""), "{marked}");
        // The rebuilt body must still parse, or the server rejects it for the
        // wrong reason and the result means nothing.
        let value: serde_json::Value = serde_json::from_str(&marked).expect("valid JSON");
        assert_eq!(value["user"]["id"], 7);
    }

    /// A payload with a quote would make the body malformed if inserted raw.
    /// The runner escapes per request; this proves the escape round-trips and
    /// the value survives rather than being truncated at the quote.
    #[test]
    fn a_payload_with_quotes_survives_json_encoding() {
        let req = json_req(r#"{"q":"value"}"#);
        let p = discover(&req).unwrap();
        let t = &p.targets[0];
        let marked = build_marked_request(&req, t).unwrap();
        let m = MarkedRequest::new(marked);
        let sent = m.substitute(&escape_for_json("a\"b")).unwrap();

        let value: serde_json::Value = serde_json::from_str(&sent).expect("still valid JSON");
        assert_eq!(
            value["q"], "a\"b",
            "the quote must survive, not truncate the value"
        );
    }

    #[test]
    fn escaping_is_only_needed_for_json_bodies() {
        assert_eq!(escape_for_json("plain"), "plain");
        assert_eq!(escape_for_json("a\"b"), "a\\\"b");
        assert_eq!(escape_for_json("back\\slash"), "back\\\\slash");
    }

    #[test]
    fn a_stale_target_name_is_an_error_not_a_silent_no_op() {
        let req = json_req(r#"{"a":1}"#);
        let target = FuzzTarget {
            location: ParameterLocation::JsonBody,
            name: "gone".into(),
            current_value: "1".into(),
            skipped_as_token: false,
        };
        let err = build_marked_request(&req, &target).unwrap_err();
        assert!(err.to_string().contains("not found"), "{err}");
    }

    #[test]
    fn a_plan_over_the_cap_is_trimmed_and_says_so() {
        let cfg = AttackConfig {
            max_requests: 10,
            ..Default::default()
        };
        // 3 targets x 10 payloads = 30, above the cap of 10.
        let p = plan(query_req(), 10, &cfg).unwrap();
        assert!(p.planned_requests <= 10, "planned {}", p.planned_requests);
        let why = p.trimmed_because.as_ref().expect("trimming must be stated");
        assert!(why.contains("above the limit"), "{why}");
    }

    #[test]
    fn a_request_with_nothing_to_fuzz_is_not_actionable() {
        let req = "GET / HTTP/1.1\nHost: a.com\n\n";
        let p = discover(req).unwrap();
        assert!(!p.is_actionable());
        assert!(p.targets.is_empty());
    }
    #[test]
    fn a_broken_json_body_is_reported_not_silently_ignored() {
        let req = json_req("{not json");
        let p = discover(&req).unwrap();
        assert!(
            p.skipped
                .iter()
                .any(|t| t.current_value.contains("JSON parse failed")),
            "a failed parse must be visible: {:?}",
            p.skipped
        );
    }
}
