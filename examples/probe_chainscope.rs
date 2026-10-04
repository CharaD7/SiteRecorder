// Exercise the real ChainScope through the crate, end to end.
use std::time::Duration;
fn main() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let cs = bounty::ChainScope::discover().expect("must discover now");
        println!("binary = {}", cs.binary());

        match cs.programs().await {
            Ok(ps) => {
                println!("programs = {}", ps.len());
                if let Some(p) = ps.first() {
                    println!(
                        "  first: {} / ${:?} audits={:?}",
                        p.slug.clone().unwrap_or_default(),
                        p.max_bounty,
                        p.audits
                    );
                }
            }
            Err(e) => println!("programs ERROR: {e}"),
        }
        match cs.meta("layerzero").await {
            Ok(m) => println!(
                "meta: project={:?} bounty={:?} network={:?} poc={:?}",
                m.project, m.max_bounty, m.network, m.poc_required
            ),
            Err(e) => println!("meta ERROR: {e}"),
        }
        let _ = Duration::from_secs(1);
    });
}
