//! Pluggable model providers and outbound redaction.
//!
//! ## Why there is no default provider
//!
//! SiteRecorder holds credentials, auth profiles and assessment findings. A
//! provider that silently forwards that data to a remote endpoint would be a
//! data-exfiltration path hidden inside a convenience default. So
//! [`ProviderRegistry`] starts empty and every call fails closed until an
//! operator configures one explicitly.
//!
//! This also keeps the choice of model out of the codebase. Rather than
//! hard-coding a model name that will be stale, the crate defines the seam and
//! the operator picks the backend.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A single turn request to a model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionRequest {
    pub system: String,
    pub prompt: String,
    #[serde(default)]
    pub max_output_tokens: Option<u32>,
}

/// A model response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Completion {
    pub text: String,
    /// Provider-reported model identifier, for audit.
    pub model: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("no model provider is configured; the agent cannot answer questions")]
    NoProvider,
    #[error("provider {0} is configured but unavailable: {1}")]
    ProviderUnavailable(String, String),
    #[error("provider error: {0}")]
    Provider(String),
}

#[async_trait]
pub trait Provider: Send + Sync {
    /// Identifier recorded in audit entries.
    fn name(&self) -> &str;

    /// Where data goes: "local", "remote", etc. Recorded so an operator can see
    /// whether an answer required leaving the machine.
    fn data_residency(&self) -> DataResidency;

    async fn complete(&self, request: CompletionRequest) -> Result<Completion, AgentError>;
}

/// Whether a provider sends data off the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DataResidency {
    /// Inference runs on this machine; findings never leave.
    Local,
    /// Inference runs elsewhere; assessment data leaves the machine.
    Remote,
}

impl DataResidency {
    pub fn as_str(&self) -> &'static str {
        match self {
            DataResidency::Local => "local",
            DataResidency::Remote => "remote",
        }
    }
}

/// Configured providers, keyed by name.
pub struct ProviderRegistry {
    providers: BTreeMap<String, Box<dyn Provider>>,
    default: Option<String>,
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderRegistry {
    /// Empty registry. Nothing works until a provider is added.
    pub fn new() -> Self {
        ProviderRegistry {
            providers: BTreeMap::new(),
            default: None,
        }
    }

    pub fn register(&mut self, provider: Box<dyn Provider>, make_default: bool) {
        let name = provider.name().to_string();
        self.providers.insert(name.clone(), provider);
        if make_default || self.default.is_none() {
            self.default = Some(name);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    pub fn provider_names(&self) -> Vec<&str> {
        self.providers.keys().map(|s| s.as_str()).collect()
    }

    pub fn residency(&self) -> Option<DataResidency> {
        self.default
            .as_ref()
            .and_then(|n| self.providers.get(n))
            .map(|p| p.data_residency())
    }

    /// Complete a prompt. Fails closed when no provider is configured, so an
    /// unconfigured agent errors instead of silently doing nothing or silently
    /// reaching out.
    pub async fn complete(&self, request: CompletionRequest) -> Result<Completion, AgentError> {
        let name = self.default.as_ref().ok_or(AgentError::NoProvider)?;
        let provider = self.providers.get(name).ok_or_else(|| {
            AgentError::ProviderUnavailable(name.clone(), "not registered".into())
        })?;
        provider.complete(request).await
    }
}

/// Strips credential-shaped strings before anything is sent to a provider.
///
/// This is defence in depth, not a guarantee. It exists so that an obvious
/// secret pasted into a prompt does not silently leave the machine.
pub struct Redactor {
    patterns: Vec<regex::Regex>,
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

impl Redactor {
    pub fn new() -> Self {
        let patterns = [
            // AWS-style access key ids.
            r"AKIA[0-9A-Z]{16}",
            // Bearer tokens.
            r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{20,}=*",
            // key=value pairs where the key smells like a secret.
            r"(?i)\b(api[_-]?key|secret|password|passwd|token|credential)\b\s*[:=]\s*\S+",
            // Private key blocks.
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
            // JWTs.
            r"\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
        ]
        .iter()
        .filter_map(|p| regex::Regex::new(p).ok())
        .collect();

        Redactor { patterns }
    }

    pub fn redact(&self, text: &str) -> String {
        let mut out = text.to_string();
        for p in &self.patterns {
            out = p.replace_all(&out, "[REDACTED]").to_string();
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct Stub {
        name: String,
        residency: DataResidency,
        reply: String,
    }

    #[async_trait]
    impl Provider for Stub {
        fn name(&self) -> &str {
            &self.name
        }
        fn data_residency(&self) -> DataResidency {
            self.residency
        }
        async fn complete(&self, _r: CompletionRequest) -> Result<Completion, AgentError> {
            Ok(Completion {
                text: self.reply.clone(),
                model: self.name.clone(),
            })
        }
    }

    fn stub(name: &str, residency: DataResidency) -> Box<dyn Provider> {
        Box::new(Stub {
            name: name.to_string(),
            residency,
            reply: "ok".to_string(),
        })
    }

    fn req() -> CompletionRequest {
        CompletionRequest {
            system: "s".into(),
            prompt: "p".into(),
            max_output_tokens: None,
        }
    }

    #[tokio::test]
    async fn unconfigured_registry_fails_closed() {
        let reg = ProviderRegistry::new();
        assert!(reg.is_empty());
        assert!(matches!(
            reg.complete(req()).await,
            Err(AgentError::NoProvider)
        ));
    }

    #[tokio::test]
    async fn registered_provider_answers() {
        let mut reg = ProviderRegistry::new();
        reg.register(stub("local-llm", DataResidency::Local), true);
        let out = reg.complete(req()).await.unwrap();
        assert_eq!(out.text, "ok");
        assert_eq!(out.model, "local-llm");
    }

    #[tokio::test]
    async fn residency_is_reported_so_operators_can_see_egress() {
        let mut reg = ProviderRegistry::new();
        assert_eq!(reg.residency(), None);
        reg.register(stub("remote", DataResidency::Remote), true);
        assert_eq!(reg.residency(), Some(DataResidency::Remote));
    }

    #[test]
    fn redacts_aws_keys() {
        let r = Redactor::new();
        let out = r.redact("key AKIAIOSFODNN7EXAMPLE here");
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn redacts_jwts_and_bearer_tokens() {
        let r = Redactor::new();
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghij";
        assert!(!r.redact(jwt).contains("eyJhbGciOiJIUzI1NiJ9"));
        assert!(!r
            .redact("Bearer abcdefghijklmnopqrstuvwxyz123456")
            .contains("abcdefghij"));
    }

    #[test]
    fn redacts_secret_assignments() {
        let r = Redactor::new();
        let out = r.redact("password: hunter2xyz");
        assert!(!out.contains("hunter2xyz"));
    }

    #[test]
    fn redacts_private_key_blocks() {
        let r = Redactor::new();
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----";
        assert!(!r.redact(pem).contains("MIIabc"));
    }

    #[test]
    fn leaves_ordinary_text_alone() {
        let r = Redactor::new();
        let text = "SQL injection found in the login form at /api/login";
        assert_eq!(r.redact(text), text);
    }

    #[test]
    fn registry_is_sendable_across_threads() {
        // Providers are used from Tauri's async runtime.
        fn assert_send_sync<T: Send + Sync>(_: &T) {}
        let mut reg = ProviderRegistry::new();
        reg.register(stub("x", DataResidency::Local), true);
        assert_send_sync(&reg);
        let _ = Arc::new(());
    }
}
