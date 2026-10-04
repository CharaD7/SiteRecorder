//! Guards the IPC contract between `ui/app.js` and the Tauri command layer.
//!
//! A renamed command compiles cleanly but fails at runtime with a generic
//! "command not found", and only when the operator clicks that button. This
//! test makes the mismatch a build failure instead.

use std::collections::BTreeSet;
use std::fs;

fn ui_commands() -> BTreeSet<String> {
    let js = fs::read_to_string("ui/app.js").expect("ui/app.js must be readable");

    let mut found = BTreeSet::new();
    let mut rest = js.as_str();

    while let Some(idx) = rest.find("invoke('") {
        rest = &rest[idx + "invoke('".len()..];
        match rest.find('\'') {
            Some(end) => {
                let name = &rest[..end];
                if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    found.insert(name.to_string());
                }
                rest = &rest[end + 1..];
            }
            None => break,
        }
    }
    found
}

fn registered_commands() -> BTreeSet<String> {
    let main_rs = fs::read_to_string("src/main.rs").expect("src/main.rs must be readable");

    let start = main_rs
        .find("generate_handler![")
        .expect("generate_handler! block must exist");
    let body = &main_rs[start..];
    let end = body
        .find("])")
        .expect("generate_handler! block must terminate");

    body[..end]
        .lines()
        .filter_map(|l| {
            let t = l.trim().trim_end_matches(',');
            if t.is_empty() || t.starts_with("//") {
                None
            } else if t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                Some(t.to_string())
            } else {
                None
            }
        })
        .collect()
}

#[test]
fn every_ui_invoke_has_a_registered_command() {
    let ui = ui_commands();
    let registered = registered_commands();

    let missing: Vec<&String> = ui.difference(&registered).collect();
    assert!(
        missing.is_empty(),
        "ui/app.js invokes commands that are not registered in generate_handler!: {missing:?}"
    );
}

#[test]
fn newly_added_commands_are_reachable_from_the_ui() {
    // Commands added for Wave 1/2 that the UI must actually use. If one of
    // these stops being called, the feature it backs is unreachable.
    let ui = ui_commands();
    for cmd in [
        "list_findings",
        "create_finding",
        "update_finding_status",
        "get_database_status",
        "list_chained_audit_entries",
        "verify_audit_integrity",
        "run_vulnerability_scan",
    ] {
        assert!(ui.contains(cmd), "expected the UI to invoke `{cmd}`");
    }
}

#[test]
fn parser_finds_a_plausible_number_of_commands() {
    // Guards against the parser silently matching nothing, which would make the
    // tests above pass vacuously.
    let ui = ui_commands();
    assert!(ui.len() > 40, "expected many invokes, found {}", ui.len());

    let registered = registered_commands();
    assert!(
        registered.len() > 40,
        "expected many registered commands, found {}",
        registered.len()
    );
}
