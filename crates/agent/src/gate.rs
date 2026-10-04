//! Capability gating for agent tool access.
//!
//! ## The decision this module encodes
//!
//! This is an enterprise security tool that probes live targets and holds a
//! credential vault. An agent with unrestricted tool access would be the single
//! most dangerous component in the product. So tool availability is expressed as
//! an explicit capability grant rather than an accident of what got registered.
//!
//! Three properties hold by construction, not by convention:
//!
//! 1. **Fail closed.** Only capabilities named in the policy are granted.
//! 2. **Escalation is explicit.** Anything that mutates state or touches a
//!    network target is a `Privileged` capability and is denied unless the
//!    policy grants it. There is no "allow by default".
//! 3. **Deny is auditable.** Every denial returns a reason, so a user can see
//!    *why* an action was refused rather than just that it was.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// What a tool is allowed to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Reads stored findings. Cannot change anything.
    ReadFindings,
    /// Reads the asset inventory.
    ReadAssets,
    /// Reads the audit chain.
    ReadAudit,
    /// Reads policy and compliance state.
    ReadCompliance,
    /// Writes or mutates stored records.
    WriteData,
    /// Executes an external process.
    ExecuteProcess,
    /// Causes network traffic to a scanned target.
    TouchTarget,
}

impl Capability {
    /// Privileged capabilities can change state or reach outside the process.
    pub fn is_privileged(&self) -> bool {
        matches!(
            self,
            Capability::WriteData | Capability::ExecuteProcess | Capability::TouchTarget
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Capability::ReadFindings => "read_findings",
            Capability::ReadAssets => "read_assets",
            Capability::ReadAudit => "read_audit",
            Capability::ReadCompliance => "read_compliance",
            Capability::WriteData => "write_data",
            Capability::ExecuteProcess => "execute_process",
            Capability::TouchTarget => "touch_target",
        }
    }
}

/// Capabilities granted to the agent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Explicit grants. Empty means nothing is permitted.
    #[serde(default)]
    granted: BTreeSet<Capability>,
    /// When true, privileged capabilities are refused even if granted. The
    /// kill switch, for when something looks wrong.
    #[serde(default)]
    read_only: bool,
}

impl Policy {
    /// Read-only policy: the four read capabilities and nothing else.
    pub fn read_only() -> Self {
        Policy {
            granted: [
                Capability::ReadFindings,
                Capability::ReadAssets,
                Capability::ReadAudit,
                Capability::ReadCompliance,
            ]
            .into_iter()
            .collect(),
            read_only: true,
        }
    }

    /// Deny everything. Used when no operator has made a decision.
    pub fn deny_all() -> Self {
        Policy::default()
    }

    /// Grant an additional capability. Privileged grants require lifting
    /// `read_only` explicitly, so enabling them is always a deliberate act.
    pub fn grant(mut self, capability: Capability) -> Self {
        if capability.is_privileged() {
            self.read_only = false;
        }
        self.granted.insert(capability);
        self
    }

    /// Force read-only regardless of grants.
    pub fn enforce_read_only(mut self) -> Self {
        self.read_only = true;
        self
    }

    pub fn is_granted(&self, capability: Capability) -> bool {
        if self.read_only && capability.is_privileged() {
            return false;
        }
        self.granted.contains(&capability)
    }

    pub fn granted(&self) -> Vec<&'static str> {
        self.granted.iter().map(|c| c.as_str()).collect()
    }
}

/// Why a tool call was allowed or refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Allow,
    Deny(String),
}

impl Decision {
    pub fn allowed(&self) -> bool {
        matches!(self, Decision::Allow)
    }
}

/// Decides whether the agent may use a capability.
pub struct Gate {
    policy: Policy,
}

impl Gate {
    pub fn new(policy: Policy) -> Self {
        Gate { policy }
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Evaluate one capability. Denials always carry a reason.
    pub fn check(&self, capability: Capability) -> Decision {
        if self.policy.read_only && capability.is_privileged() {
            return Decision::Deny(format!(
                "policy is read-only; {} is a privileged capability",
                capability.as_str()
            ));
        }
        if !self.policy.granted.contains(&capability) {
            return Decision::Deny(format!("capability not granted: {}", capability.as_str()));
        }
        Decision::Allow
    }

    /// Convenience: refuse with an error if the capability is not permitted.
    pub fn require(&self, capability: Capability) -> Result<(), GateError> {
        match self.check(capability) {
            Decision::Allow => Ok(()),
            Decision::Deny(reason) => Err(GateError::Refused { capability, reason }),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GateError {
    #[error("refused to use {capability:?}: {reason}")]
    Refused {
        capability: Capability,
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_policy_grants_nothing() {
        let gate = Gate::new(Policy::deny_all());
        for cap in [
            Capability::ReadFindings,
            Capability::WriteData,
            Capability::ExecuteProcess,
        ] {
            assert!(!gate.check(cap).allowed(), "{cap:?} must be denied");
        }
    }

    #[test]
    fn read_only_policy_allows_reads() {
        let gate = Gate::new(Policy::read_only());
        assert!(gate.check(Capability::ReadFindings).allowed());
        assert!(gate.check(Capability::ReadAudit).allowed());
    }

    #[test]
    fn read_only_policy_denies_every_privileged_capability() {
        let gate = Gate::new(Policy::read_only());
        for cap in [
            Capability::WriteData,
            Capability::ExecuteProcess,
            Capability::TouchTarget,
        ] {
            match gate.check(cap) {
                Decision::Deny(r) => assert!(r.contains("read-only"), "{cap:?}: {r}"),
                Decision::Allow => panic!("{cap:?} must not be allowed"),
            }
        }
    }

    #[test]
    fn granting_a_privileged_capability_lifts_read_only() {
        // Granting must be an explicit act, so read_only flips with it.
        let policy = Policy::read_only().grant(Capability::WriteData);
        assert!(!policy.is_granted(Capability::ExecuteProcess));
        assert!(Gate::new(policy).check(Capability::WriteData).allowed());
    }

    #[test]
    fn ungranted_privileged_capability_still_denied() {
        let gate = Gate::new(Policy::read_only().grant(Capability::WriteData));
        assert!(!gate.check(Capability::ExecuteProcess).allowed());
        assert!(!gate.check(Capability::TouchTarget).allowed());
    }

    #[test]
    fn enforce_read_only_overrides_a_privileged_grant() {
        // The kill switch: a granted write is still refused.
        let gate = Gate::new(
            Policy::read_only()
                .grant(Capability::WriteData)
                .enforce_read_only(),
        );
        assert!(!gate.check(Capability::WriteData).allowed());
    }

    #[test]
    fn every_denial_carries_a_reason() {
        let gate = Gate::new(Policy::deny_all());
        match gate.check(Capability::TouchTarget) {
            Decision::Deny(r) => assert!(r.contains("touch_target")),
            Decision::Allow => panic!("expected denial"),
        }
    }

    #[test]
    fn require_surfaces_the_capability_and_reason() {
        let gate = Gate::new(Policy::read_only());
        match gate.require(Capability::ExecuteProcess) {
            Err(GateError::Refused { capability, reason }) => {
                assert_eq!(capability, Capability::ExecuteProcess);
                assert!(reason.contains("privileged"));
            }
            Ok(()) => panic!("expected refusal"),
        }
    }

    #[test]
    fn a_fully_granted_policy_still_works_for_reads() {
        let gate = Gate::new(Policy::read_only());
        assert!(gate.require(Capability::ReadFindings).is_ok());
    }
}
