// End-to-end check against the installed ChainScope, including triage.
use std::time::Duration;
fn main() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let cs = bounty::ChainScope::discover().expect("must discover");
        println!("binary = {}", cs.binary());
        match cs.triage("layerzero", 1).await {
            Ok(r) => {
                println!("TRIAGE OK");
                println!("  slug(filled by caller) = {}", r.slug);
                println!(
                    "  fetched={} errors={} hotspots={}",
                    r.fetched,
                    r.errors,
                    r.hotspots.len()
                );
                println!("  indexed_nothing = {}", r.indexed_nothing());
                if let Some(s) = &r.scope {
                    println!(
                        "  scope: {} address(es), {} repo(s)",
                        s.addresses.len(),
                        s.repos.len()
                    );
                }
                for h in r.hotspots.iter().take(3) {
                    println!(
                        "  - {} @ {}:{:?} score={:?}",
                        h.function.clone().unwrap_or_default(),
                        h.file.clone().unwrap_or_default(),
                        h.line,
                        h.score
                    );
                }
            }
            Err(e) => println!("TRIAGE ERROR: {e}"),
        }
        let _ = Duration::from_secs(1);
    });
}
