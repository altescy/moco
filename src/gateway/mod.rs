mod downstream;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use serde_json::{Value, json};
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::audit::{AuditEvent, AuditLogger, hash_reason, now_timestamp_ms};
use crate::config::SecurityConfig;
use crate::index::{NamespaceError, make_namespaced_tool, parse_namespaced_tool};
use crate::security::{PiiProvider, PolicyEngine, PolicyStatus, ToolCallInput, merge_evaluations};

pub use downstream::{BuildDownstreamError, build_downstream_client};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolDescriptor {
    pub name: String,
    pub description: Option<String>,
    pub input_schema: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCallResult {
    pub content: Value,
    pub is_error: bool,
}

impl ToolCallResult {
    #[must_use]
    pub fn error_text(message: impl AsRef<str>) -> Self {
        Self {
            content: json!([
                {
                    "type": "text",
                    "text": message.as_ref()
                }
            ]),
            is_error: true,
        }
    }
}

#[derive(Debug, Error)]
pub enum DownstreamError {
    #[error("downstream unavailable: {0}")]
    Unavailable(String),
    #[error("downstream call failed: {0}")]
    Call(String),
}

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error(transparent)]
    Namespace(#[from] NamespaceError),
    #[error("unknown downstream server: {0}")]
    UnknownServer(String),
    #[error("tool call denied by policy")]
    PolicyDenied { reasons: Vec<String> },
    #[error("tool call requires confirmation")]
    PolicyConfirmation { reasons: Vec<String> },
    #[error("tool result blocked by policy")]
    OutputPolicyDenied { reasons: Vec<String> },
    #[error("tool result requires confirmation")]
    OutputPolicyConfirmation { reasons: Vec<String> },
    #[error(transparent)]
    Downstream(#[from] DownstreamError),
}

#[async_trait]
pub trait DownstreamClient: Send + Sync {
    async fn list_tools(&self) -> Result<Vec<ToolDescriptor>, DownstreamError>;

    async fn call_tool(
        &self,
        tool_name: &str,
        arguments: &Value,
    ) -> Result<ToolCallResult, DownstreamError>;
}

pub struct Gateway {
    downstreams: HashMap<String, Arc<dyn DownstreamClient>>,
    security: SecurityConfig,
    audit_logger: Option<Arc<AuditLogger>>,
    pii_provider: Option<Arc<dyn PiiProvider>>,
    request_seq: AtomicU64,
}

impl Gateway {
    #[must_use]
    pub fn new(security: SecurityConfig) -> Self {
        Self {
            downstreams: HashMap::new(),
            security,
            audit_logger: None,
            pii_provider: None,
            request_seq: AtomicU64::new(1),
        }
    }

    #[must_use]
    pub fn with_audit_logger(mut self, audit_logger: Arc<AuditLogger>) -> Self {
        self.audit_logger = Some(audit_logger);
        self
    }

    #[must_use]
    pub fn with_pii_provider(mut self, pii_provider: Arc<dyn PiiProvider>) -> Self {
        self.pii_provider = Some(pii_provider);
        self
    }

    pub fn register_downstream(
        &mut self,
        name: impl Into<String>,
        client: Arc<dyn DownstreamClient>,
    ) -> Option<Arc<dyn DownstreamClient>> {
        self.downstreams.insert(name.into(), client)
    }

    pub async fn list_tools(&self) -> Result<Vec<ToolDescriptor>, GatewayError> {
        let mut all = Vec::new();

        for (server, client) in &self.downstreams {
            let tools = client.list_tools().await?;
            all.extend(tools.into_iter().map(|tool| ToolDescriptor {
                name: make_namespaced_tool(server, &tool.name),
                description: tool.description,
                input_schema: tool.input_schema,
            }));
        }

        all.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(all)
    }

    pub async fn call_tool(
        &self,
        namespaced_tool: &str,
        arguments: &Value,
    ) -> Result<ToolCallResult, GatewayError> {
        let request_id = self.request_seq.fetch_add(1, Ordering::Relaxed);
        let namespaced = parse_namespaced_tool(namespaced_tool)?;

        let mut evaluation = PolicyEngine::evaluate_tool_call(
            ToolCallInput {
                tool_name: namespaced_tool,
                arguments,
            },
            &self.security,
        );
        if let Some(provider) = &self.pii_provider {
            let provider_eval = PolicyEngine::evaluate_with_provider(
                namespaced_tool,
                arguments,
                &self.security,
                provider.as_ref(),
            )
            .await;
            evaluation = merge_evaluations(evaluation, provider_eval);
        }

        debug!(
            tool = %namespaced_tool,
            findings = evaluation.findings.len(),
            status = ?evaluation.decision.status,
            "pre-call policy evaluation completed"
        );
        info!(
            target: "audit",
            phase = "pre_call",
            tool = %namespaced_tool,
            status = ?evaluation.decision.status,
            findings = evaluation.findings.len(),
            "policy evaluation"
        );
        self.audit(
            request_id,
            "pre_call",
            namespaced_tool,
            status_to_str(evaluation.decision.status),
            evaluation.findings.len(),
            &evaluation.decision.reasons,
        );

        match evaluation.decision.status {
            PolicyStatus::Deny => {
                warn!(tool = %namespaced_tool, "tool call denied by pre-call policy");
                info!(
                    target: "audit",
                    phase = "pre_call",
                    tool = %namespaced_tool,
                    status = "deny",
                    reasons = evaluation.decision.reasons.len(),
                    "tool call blocked"
                );
                return Err(GatewayError::PolicyDenied {
                    reasons: evaluation.decision.reasons,
                });
            }
            PolicyStatus::Confirm => {
                info!(tool = %namespaced_tool, "tool call requires confirmation by pre-call policy");
                info!(
                    target: "audit",
                    phase = "pre_call",
                    tool = %namespaced_tool,
                    status = "confirm",
                    reasons = evaluation.decision.reasons.len(),
                    "tool call requires confirmation"
                );
                return Err(GatewayError::PolicyConfirmation {
                    reasons: evaluation.decision.reasons,
                });
            }
            PolicyStatus::Allow => {}
        }

        let Some(client) = self.downstreams.get(&namespaced.server) else {
            return Err(GatewayError::UnknownServer(namespaced.server));
        };

        let result = client
            .call_tool(&namespaced.tool, arguments)
            .await
            .map_err(GatewayError::from)?;

        let mut post_evaluation =
            PolicyEngine::evaluate_tool_output(namespaced_tool, &result.content, &self.security);
        if let Some(provider) = &self.pii_provider {
            let provider_eval = PolicyEngine::evaluate_with_provider(
                namespaced_tool,
                &result.content,
                &self.security,
                provider.as_ref(),
            )
            .await;
            post_evaluation = merge_evaluations(post_evaluation, provider_eval);
        }

        debug!(
            tool = %namespaced_tool,
            findings = post_evaluation.findings.len(),
            status = ?post_evaluation.decision.status,
            "post-call policy evaluation completed"
        );
        info!(
            target: "audit",
            phase = "post_call",
            tool = %namespaced_tool,
            status = ?post_evaluation.decision.status,
            findings = post_evaluation.findings.len(),
            "policy evaluation"
        );
        self.audit(
            request_id,
            "post_call",
            namespaced_tool,
            status_to_str(post_evaluation.decision.status),
            post_evaluation.findings.len(),
            &post_evaluation.decision.reasons,
        );

        match post_evaluation.decision.status {
            PolicyStatus::Deny => {
                warn!(tool = %namespaced_tool, "tool result denied by post-call policy");
                info!(
                    target: "audit",
                    phase = "post_call",
                    tool = %namespaced_tool,
                    status = "deny",
                    reasons = post_evaluation.decision.reasons.len(),
                    "tool output blocked"
                );
                Err(GatewayError::OutputPolicyDenied {
                    reasons: post_evaluation.decision.reasons,
                })
            }
            PolicyStatus::Confirm => {
                info!(tool = %namespaced_tool, "tool result requires confirmation by post-call policy");
                info!(
                    target: "audit",
                    phase = "post_call",
                    tool = %namespaced_tool,
                    status = "confirm",
                    reasons = post_evaluation.decision.reasons.len(),
                    "tool output requires confirmation"
                );
                Err(GatewayError::OutputPolicyConfirmation {
                    reasons: post_evaluation.decision.reasons,
                })
            }
            PolicyStatus::Allow => Ok(result),
        }
    }

    pub async fn call_tool_for_mcp(
        &self,
        namespaced_tool: &str,
        arguments: &Value,
    ) -> ToolCallResult {
        match self.call_tool(namespaced_tool, arguments).await {
            Ok(result) => result,
            Err(GatewayError::PolicyDenied { reasons }) => {
                policy_error_result("blocked by security policy", reasons)
            }
            Err(GatewayError::PolicyConfirmation { reasons }) => {
                policy_error_result("requires human confirmation", reasons)
            }
            Err(GatewayError::OutputPolicyDenied { reasons }) => {
                policy_error_result("tool output blocked by security policy", reasons)
            }
            Err(GatewayError::OutputPolicyConfirmation { reasons }) => {
                policy_error_result("tool output requires human confirmation", reasons)
            }
            Err(err) => ToolCallResult::error_text(format!("tool call failed: {err}")),
        }
    }

    fn audit(
        &self,
        request_id: u64,
        phase: &str,
        tool: &str,
        status: &str,
        findings: usize,
        reasons: &[String],
    ) {
        let Some(logger) = &self.audit_logger else {
            return;
        };
        let reason_hashes = reasons.iter().map(|reason| hash_reason(reason)).collect();
        if let Err(err) = logger.log(AuditEvent {
            timestamp_ms: now_timestamp_ms(),
            request_id,
            phase: phase.to_owned(),
            tool: tool.to_owned(),
            status: status.to_owned(),
            findings,
            reasons: reasons.len(),
            reason_hashes,
        }) {
            warn!(error = %err, "failed to write audit event");
        }
    }
}

fn status_to_str(status: PolicyStatus) -> &'static str {
    match status {
        PolicyStatus::Allow => "allow",
        PolicyStatus::Confirm => "confirm",
        PolicyStatus::Deny => "deny",
    }
}

fn policy_error_result(prefix: &str, reasons: Vec<String>) -> ToolCallResult {
    let mut message = String::from(prefix);
    let sanitized = sanitize_reasons(&reasons);
    if !sanitized.is_empty() {
        message.push_str("\n");
        message.push_str(&sanitized.join("\n"));
    }
    ToolCallResult::error_text(message)
}

fn sanitize_reasons(reasons: &[String]) -> Vec<String> {
    const MAX_REASONS: usize = 8;
    const MAX_CHARS_PER_REASON: usize = 200;

    reasons
        .iter()
        .take(MAX_REASONS)
        .map(|reason| {
            let mut chars = reason.chars();
            let clipped: String = chars.by_ref().take(MAX_CHARS_PER_REASON).collect();
            if chars.next().is_some() {
                format!("- {clipped}...")
            } else {
                format!("- {clipped}")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;

    use crate::config::{
        DecodingConfig, DetectorConfig, DetectorTarget, DetectorType, PolicyAction, PresetLevel,
        SecurityConfig, SecurityMode,
    };

    use super::*;

    struct MockDownstream;

    #[async_trait]
    impl DownstreamClient for MockDownstream {
        async fn list_tools(&self) -> Result<Vec<ToolDescriptor>, DownstreamError> {
            Ok(vec![ToolDescriptor {
                name: "create_issue".to_owned(),
                description: Some("create issue".to_owned()),
                input_schema: json!({"type":"object"}),
            }])
        }

        async fn call_tool(
            &self,
            tool_name: &str,
            _arguments: &Value,
        ) -> Result<ToolCallResult, DownstreamError> {
            Ok(ToolCallResult {
                content: json!({"called": tool_name}),
                is_error: false,
            })
        }
    }

    struct MockLeakyDownstream;

    #[async_trait]
    impl DownstreamClient for MockLeakyDownstream {
        async fn list_tools(&self) -> Result<Vec<ToolDescriptor>, DownstreamError> {
            Ok(vec![ToolDescriptor {
                name: "dump".to_owned(),
                description: Some("dump secrets".to_owned()),
                input_schema: json!({"type":"object"}),
            }])
        }

        async fn call_tool(
            &self,
            _tool_name: &str,
            _arguments: &Value,
        ) -> Result<ToolCallResult, DownstreamError> {
            Ok(ToolCallResult {
                content: json!([{"type":"text","text":"token=AKIA1234567890ABCDEF"}]),
                is_error: false,
            })
        }
    }

    fn security_allow() -> SecurityConfig {
        SecurityConfig {
            mode: SecurityMode::Enforce,
            presets: Vec::new(),
            preset_level: PresetLevel::Balanced,
            decoding: DecodingConfig::default(),
            detectors: Vec::new(),
            tool_overrides: Default::default(),
        }
    }

    #[tokio::test]
    async fn namespace_list_tools() {
        let mut gateway = Gateway::new(security_allow());
        gateway.register_downstream("github", Arc::new(MockDownstream));

        let tools = gateway.list_tools().await.expect("list_tools failed");
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "github::create_issue");
    }

    #[tokio::test]
    async fn deny_before_downstream_call() {
        let security = SecurityConfig {
            mode: SecurityMode::Enforce,
            presets: Vec::new(),
            preset_level: PresetLevel::Balanced,
            decoding: DecodingConfig::default(),
            detectors: vec![DetectorConfig {
                name: "deny-github".to_owned(),
                detector_type: DetectorType::HighRiskTool,
                target: DetectorTarget::ToolName,
                patterns: vec!["github::*".to_owned()],
                keywords: Vec::new(),
                rule: None,
                region: None,
                min_length: None,
                entropy_milli_threshold: None,
                action: PolicyAction::Deny,
                decode: false,
            }],
            tool_overrides: Default::default(),
        };

        let mut gateway = Gateway::new(security);
        gateway.register_downstream("github", Arc::new(MockDownstream));

        let err = gateway
            .call_tool("github::create_issue", &json!({"title": "test"}))
            .await
            .expect_err("expected deny");

        match err {
            GatewayError::PolicyDenied { .. } => {}
            other => panic!("unexpected error: {other}"),
        }
    }

    #[tokio::test]
    async fn mcp_call_returns_is_error_for_policy_denial() {
        let security = SecurityConfig {
            mode: SecurityMode::Enforce,
            presets: Vec::new(),
            preset_level: PresetLevel::Balanced,
            decoding: DecodingConfig::default(),
            detectors: vec![DetectorConfig {
                name: "deny-github".to_owned(),
                detector_type: DetectorType::HighRiskTool,
                target: DetectorTarget::ToolName,
                patterns: vec!["github::*".to_owned()],
                keywords: Vec::new(),
                rule: None,
                region: None,
                min_length: None,
                entropy_milli_threshold: None,
                action: PolicyAction::Deny,
                decode: false,
            }],
            tool_overrides: Default::default(),
        };

        let mut gateway = Gateway::new(security);
        gateway.register_downstream("github", Arc::new(MockDownstream));

        let result = gateway
            .call_tool_for_mcp("github::create_issue", &json!({"title": "test"}))
            .await;

        assert!(result.is_error);
        let text = result
            .content
            .as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.get("text"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(text.contains("blocked by security policy"));
    }

    #[tokio::test]
    async fn mcp_call_blocks_sensitive_output() {
        let security = SecurityConfig {
            mode: SecurityMode::Enforce,
            presets: Vec::new(),
            preset_level: PresetLevel::Balanced,
            decoding: DecodingConfig::default(),
            detectors: vec![DetectorConfig {
                name: "deny-secret-output".to_owned(),
                detector_type: DetectorType::Regex,
                target: DetectorTarget::Arguments,
                patterns: vec!["AKIA[0-9A-Z]{16}".to_owned()],
                keywords: Vec::new(),
                rule: None,
                region: None,
                min_length: None,
                entropy_milli_threshold: None,
                action: PolicyAction::Deny,
                decode: true,
            }],
            tool_overrides: Default::default(),
        };

        let mut gateway = Gateway::new(security);
        gateway.register_downstream("mock", Arc::new(MockLeakyDownstream));

        let result = gateway.call_tool_for_mcp("mock::dump", &json!({})).await;
        assert!(result.is_error);
        let text = result
            .content
            .as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.get("text"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(text.contains("tool output blocked by security policy"));
    }
}
