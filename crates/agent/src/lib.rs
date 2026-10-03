//! Advisory security agent.
//!
//! ## Scope of this build: Phase 1 only
//!
//! The agent answers questions about findings already in the database. It has
//! **no** capability to write data, execute processes, or contact a scanned
//! target. Those capabilities exist in [`gate::Capability`] so they can be
//! reasoned about and audited, but they are refused unless an operator grants
//! them explicitly.
//!
//! Rationale: this tool probes live targets and stores credentials. An agent
//! that could act on that surface would be the most dangerous component in the
//! product, and the tamper-evident audit log is the only thing standing between
//! a misbehaving agent and an unattributable change to your own posture.
//!
//! Escalation path, each step a deliberate change:
//! 1. advisory + read-only tools (this build)
//! 2. operator-configured provider with a stated data residency
//! 3. gated write actions, each individually confirmed and audited
//!
//! Every one of those steps should be an explicit operator decision, not a
//! default.

pub mod gate;
pub mod provider;

pub use gate::{Capability, Decision, Gate, GateError, Policy};
pub use provider::{
    AgentError, Completion, CompletionRequest, DataResidency, Provider, ProviderRegistry, Redactor,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_agent_is_inert() {
        // No provider and a read-only policy: the agent cannot act and cannot
        // reach the network. This is the shipped default.
        let registry = ProviderRegistry::new();
        assert!(registry.is_empty());

        let gate = Gate::new(Policy::read_only());
        for cap in [
            Capability::WriteData,
            Capability::ExecuteProcess,
            Capability::TouchTarget,
        ] {
            assert!(
                !gate.check(cap).allowed(),
                "{cap:?} must be refused by default"
            );
        }
    }

    #[tokio::test]
    async fn unconfigured_agent_errors_rather_than_silently_succeeding() {
        let registry = ProviderRegistry::new();
        let err = registry
            .complete(CompletionRequest {
                system: "You advise on findings.".into(),
                prompt: "Summarise the critical findings.".into(),
                max_output_tokens: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, AgentError::NoProvider));
    }

    #[test]
    fn capability_vocabulary_covers_the_dangerous_operations() {
        // If a new dangerous operation is added later, it must be classified as
        // privileged. Anything defaulting to read must be deliberate.
        for cap in [
            Capability::ReadFindings,
            Capability::ReadAssets,
            Capability::ReadAudit,
            Capability::ReadCompliance,
            Capability::WriteData,
            Capability::ExecuteProcess,
            Capability::TouchTarget,
        ] {
            let _ = cap;
        }
        assert!(!Capability::ReadFindings.is_privileged());
        assert!(!Capability::ReadAudit.is_privileged());
        assert!(Capability::WriteData.is_privileged());
        assert!(Capability::ExecuteProcess.is_privileged());
        assert!(Capability::TouchTarget.is_privileged());
    }
}
