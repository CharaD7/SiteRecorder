//! Grouping responses by observable signature.
//!
//! # Why clustering instead of a verdict
//!
//! An attack produces hundreds of responses. The useful question is "which
//! ones differ from the others?" — not "which ones are vulnerabilities?" A
//! cluster says: these 480 payloads all produced a 200 with a 1,204-byte body,
//! and these 3 produced a 500. That is an observation, and it is worth looking
//! at. Labelling the 500s as findings would not be.
//!
//! # The signature is deliberately coarse
//!
//! `status:size` groups by status code and body length. It ignores body
//! *content*, on purpose: a fingerprint-style cluster built from a hash of the
//! body would split into dozens of singletons whenever a page embeds a
//! timestamp or a request id, and the operator would drown in noise. Coarse
//! grouping makes outliers visible, which is the actual goal.
//!
//! The cost is real and stated here: two genuinely different responses of the
//! same length and status land in the same cluster. The operator can always
//! open an individual response.

use serde::{Deserialize, Serialize};

use crate::Attempt;

/// One response signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseCluster {
    /// A response arrived: `status:body_size`.
    Response { status: u16, size: usize },
    /// No response arrived within the timeout, or the connection failed.
    NoResponse,
}

impl ResponseCluster {
    pub fn signature(&self) -> String {
        match self {
            ResponseCluster::Response { status, size } => format!("{status}:{size}"),
            ResponseCluster::NoResponse => "no-response".to_string(),
        }
    }

    /// Plain-language description. Says what happened, never what it means.
    pub fn describe(&self) -> String {
        match self {
            ResponseCluster::Response { status, size } => format!(
                "The server answered {status} with a {size}-byte body. Every payload in this \
                 group behaved the same way."
            ),
            ResponseCluster::NoResponse => "No response came back.".to_string(),
        }
    }
}

/// One group of payloads that behaved alike.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClusterSummary {
    pub signature: String,
    pub cluster: ResponseCluster,
    /// How many payloads landed here.
    pub count: usize,
    /// Share of *responses* that landed here, 0.0–1.0. Shown so a 3-of-483
    /// outlier group is obviously small.
    pub share: f64,
    /// Indexes into the attempt list.
    pub attempt_indexes: Vec<usize>,
    /// Example payloads, capped: listing 480 rows helps nobody.
    pub example_payloads: Vec<String>,
    /// True when this group is much smaller than the largest. A prompt to look,
    /// not a finding.
    pub is_outlier: bool,
}

/// Build cluster summaries from attempts.
///
/// `responded` — the number of attempts that produced any result — is the
/// denominator for `share`. Requests that never got a response are excluded
/// from it but still appear as their own `NoResponse` cluster, so a run that
/// mostly failed cannot quietly report 100% in one bucket.
pub fn cluster(attempts: &[Attempt]) -> Vec<ClusterSummary> {
    let mut buckets: Vec<(ResponseCluster, Vec<usize>)> = Vec::new();

    for a in attempts {
        let cluster = match &a.result {
            Ok(r) => {
                let mut parts = r.signature.split(':');
                let status = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
                let size = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
                ResponseCluster::Response { status, size }
            }
            Err(_) => ResponseCluster::NoResponse,
        };

        match buckets.iter_mut().find(|(c, _)| *c == cluster) {
            Some((_, idxs)) => idxs.push(a.index),
            None => buckets.push((cluster, vec![a.index])),
        }
    }

    let responded: usize = attempts.iter().filter(|a| a.result.is_ok()).count();
    let largest = buckets
        .iter()
        .filter(|(c, _)| !matches!(c, ResponseCluster::NoResponse))
        .map(|(_, i)| i.len())
        .max()
        .unwrap_or(0);

    let mut out: Vec<ClusterSummary> = buckets
        .into_iter()
        .map(|(cluster, indexes)| {
            let count = indexes.len();
            // "Outlier" means an order of magnitude smaller than the biggest
            // group, and at least three requests. A single stray result should
            // not be dressed up as a pattern.
            let is_outlier = !matches!(cluster, ResponseCluster::NoResponse)
                && largest >= 10
                && count * 10 <= largest
                && count >= 3;

            ClusterSummary {
                signature: cluster.signature(),
                cluster,
                count,
                share: if responded == 0 {
                    0.0
                } else {
                    count as f64 / responded as f64
                },
                example_payloads: indexes
                    .iter()
                    .take(5)
                    .filter_map(|i| attempts.get(*i).map(|a| a.payload.clone()))
                    .collect(),
                attempt_indexes: indexes,
                is_outlier,
            }
        })
        .collect();

    // Largest group first, so the common case sits at the top and outliers at
    // the bottom where the operator will actually see them.
    out.sort_by(|a, b| b.count.cmp(&a.count).then(a.signature.cmp(&b.signature)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Attempt, AttemptResult};

    fn attempt(i: usize, payload: &str, status: u16, size: usize) -> Attempt {
        Attempt {
            payload: payload.to_string(),
            result: Ok(AttemptResult {
                status_code: status,
                body_size: size,
                elapsed_ms: 10,
                signature: format!("{status}:{size}"),
                snippet: String::new(),
            }),
            index: i,
        }
    }

    #[test]
    fn identical_responses_form_one_group() {
        let attempts: Vec<Attempt> = (0..5).map(|i| attempt(i, "p", 200, 100)).collect();
        let c = cluster(&attempts);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].count, 5);
        assert!((c[0].share - 1.0).abs() < f64::EPSILON);
        assert!(!c[0].is_outlier, "the only group cannot be an outlier");
    }

    #[test]
    fn a_small_different_group_is_flagged_as_an_outlier() {
        let mut attempts: Vec<Attempt> = (0..40).map(|i| attempt(i, "p", 200, 100)).collect();
        for (i, p) in ["quote", "quote2", "quote3"].iter().enumerate() {
            attempts.push(attempt(40 + i, p, 500, 42));
        }

        let small = cluster(&attempts)
            .into_iter()
            .find(|s| s.signature == "500:42")
            .expect("the differing group");
        assert_eq!(small.count, 3);
        assert!(small.is_outlier, "3 responses among 40 should be noticed");

        // Flagged as worth looking at -- NOT as a vulnerability.
        assert!(small.cluster.describe().contains("500"));
        assert!(!small.cluster.describe().contains("vulnerab"));
    }

    #[test]
    fn two_or_fewer_responses_are_not_dressed_up_as_a_pattern() {
        let mut attempts: Vec<Attempt> = (0..40).map(|i| attempt(i, "p", 200, 100)).collect();
        attempts.push(attempt(40, "a", 500, 42));
        attempts.push(attempt(41, "b", 500, 42));

        let small = cluster(&attempts)
            .into_iter()
            .find(|s| s.signature == "500:42")
            .unwrap();
        assert!(!small.is_outlier, "two responses is noise, not a signal");
    }

    #[test]
    fn a_missed_response_is_its_own_group_and_excluded_from_share() {
        let mut attempts: Vec<Attempt> = (0..5).map(|i| attempt(i, "p", 200, 100)).collect();
        attempts.push(Attempt {
            payload: "timeout".into(),
            result: Err("timed out".into()),
            index: 5,
        });

        let c = cluster(&attempts);
        let missed = c
            .iter()
            .find(|s| s.signature == "no-response")
            .expect("group");
        assert_eq!(missed.count, 1);
        assert_eq!(missed.cluster, ResponseCluster::NoResponse);
        // 5 of 5 *responses* landed in the 200 group, not 5 of 6.
        let ok = c.iter().find(|s| s.signature == "200:100").unwrap();
        assert!((ok.share - 1.0).abs() < f64::EPSILON, "got {}", ok.share);
    }

    #[test]
    fn the_largest_group_is_listed_first() {
        let mut attempts: Vec<Attempt> = (0..30).map(|i| attempt(i, "p", 200, 100)).collect();
        for i in 30..33 {
            attempts.push(attempt(i, "q", 500, 42));
        }
        let c = cluster(&attempts);
        assert_eq!(c[0].count, 30, "the common case belongs at the top");
    }

    /// The honesty guarantee, enforced: no cluster description may call
    /// something a vulnerability, however the numbers fall.
    #[test]
    fn no_cluster_ever_claims_a_vulnerability() {
        let mut attempts: Vec<Attempt> = (0..20).map(|i| attempt(i, "p", 200, 100)).collect();
        attempts.push(attempt(20, "x", 500, 1));
        attempts.push(Attempt {
            payload: "y".into(),
            result: Err("timed out".into()),
            index: 21,
        });

        for c in cluster(&attempts) {
            let text = format!("{} {}", c.cluster.describe(), c.signature).to_lowercase();
            for banned in ["vulnerab", "exploit", "is a bug", "confirmed"] {
                assert!(
                    !text.contains(banned),
                    "cluster text claims too much: {text}"
                );
            }
        }
    }
}
