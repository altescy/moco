use globset::{Glob, GlobMatcher};
use regex::Regex;
use serde_json::Value;

use crate::config::{
    BuiltinRuleConfig, DetectorConfig, DetectorRuleConfig, DetectorTarget, PolicyAction,
    SecurityConfig, SecurityMode,
};

use super::decoder::{TextCandidate, extract_text_candidates};
use super::pii::{PiiKind, PiiProvider};

#[derive(Debug, Clone)]
pub struct ToolCallInput<'a> {
    pub tool_name: &'a str,
    pub arguments: &'a Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolicyStatus {
    Allow,
    Confirm,
    Deny,
}

impl From<PolicyAction> for PolicyStatus {
    fn from(value: PolicyAction) -> Self {
        match value {
            PolicyAction::Allow => Self::Allow,
            PolicyAction::Confirm => Self::Confirm,
            PolicyAction::Deny => Self::Deny,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub detector: String,
    pub action: PolicyStatus,
    pub path: String,
    pub message: String,
    pub excerpt: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    pub status: PolicyStatus,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationResult {
    pub decision: PolicyDecision,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Default)]
pub struct PolicyEngine;

impl PolicyEngine {
    #[must_use]
    pub fn evaluate_tool_call(
        input: ToolCallInput<'_>,
        security: &SecurityConfig,
    ) -> EvaluationResult {
        evaluate_internal(input.tool_name, input.arguments, security, true)
    }

    #[must_use]
    pub fn evaluate_tool_output(
        tool_name: &str,
        output: &Value,
        security: &SecurityConfig,
    ) -> EvaluationResult {
        evaluate_internal(tool_name, output, security, false)
    }

    pub async fn evaluate_with_provider(
        tool_name: &str,
        value: &Value,
        security: &SecurityConfig,
        provider: &dyn PiiProvider,
    ) -> EvaluationResult {
        if security.mode == SecurityMode::Off {
            return EvaluationResult {
                decision: PolicyDecision {
                    status: PolicyStatus::Allow,
                    reasons: Vec::new(),
                },
                findings: Vec::new(),
            };
        }

        let candidates = extract_text_candidates(value, &security.decoding);
        let mut findings = Vec::new();

        for detector in &security.detectors {
            let DetectorRuleConfig::Builtin {
                rule: BuiltinRuleConfig::Pii { disabled },
            } = &detector.rule
            else {
                continue;
            };

            let action = PolicyStatus::from(detector.action);
            for candidate in filter_targets(detector.target, tool_name, &candidates) {
                if !detector.decode && candidate.decoded {
                    continue;
                }

                let matches = provider.detect(&candidate.text).await;
                for matched in matches {
                    if disabled.contains(&to_config_pii_kind(&matched.kind)) {
                        continue;
                    }
                    findings.push(Finding {
                        detector: detector.name.clone(),
                        action,
                        path: candidate.path.clone(),
                        message: format!(
                            "builtin rule 'pii' matched via {} ({})",
                            provider.provider_name(),
                            matched.kind.as_str()
                        ),
                        excerpt: clip(&matched.value),
                    });
                }
            }
        }

        let mut status = findings
            .iter()
            .map(|f| f.action)
            .max()
            .unwrap_or(PolicyStatus::Allow);
        if security.mode == SecurityMode::Monitor {
            status = PolicyStatus::Allow;
        }

        let reasons = findings
            .iter()
            .map(|f| format!("{}: {}", f.detector, f.message))
            .collect();

        EvaluationResult {
            decision: PolicyDecision { status, reasons },
            findings,
        }
    }
}

fn to_config_pii_kind(kind: &PiiKind) -> crate::config::PiiKind {
    match kind {
        PiiKind::Email => crate::config::PiiKind::Email,
        PiiKind::Phone => crate::config::PiiKind::Phone,
        PiiKind::Address => crate::config::PiiKind::Address,
        PiiKind::Credential => crate::config::PiiKind::Credential,
        PiiKind::Other => crate::config::PiiKind::Other,
    }
}

#[must_use]
pub fn merge_evaluations(mut a: EvaluationResult, b: EvaluationResult) -> EvaluationResult {
    a.findings.extend(b.findings);
    a.decision.reasons.extend(b.decision.reasons);
    a.decision.status = a.decision.status.max(b.decision.status);
    a
}

fn evaluate_internal(
    tool_name: &str,
    value: &Value,
    security: &SecurityConfig,
    include_tool_overrides: bool,
) -> EvaluationResult {
    if security.mode == SecurityMode::Off {
        return EvaluationResult {
            decision: PolicyDecision {
                status: PolicyStatus::Allow,
                reasons: Vec::new(),
            },
            findings: Vec::new(),
        };
    }

    let candidates = extract_text_candidates(value, &security.decoding);
    let mut findings = Vec::new();

    if let Some(status) = if include_tool_overrides {
        evaluate_tool_overrides(tool_name, security)
    } else {
        None
    } {
        findings.push(Finding {
            detector: "tool_override".to_owned(),
            action: status,
            path: "tool".to_owned(),
            message: format!("tool policy override matched: {tool_name}"),
            excerpt: tool_name.to_owned(),
        });
    }

    for detector in &security.detectors {
        findings.extend(run_detector(detector, tool_name, &candidates));
    }

    let mut status = findings
        .iter()
        .map(|f| f.action)
        .max()
        .unwrap_or(PolicyStatus::Allow);

    if security.mode == SecurityMode::Monitor {
        status = PolicyStatus::Allow;
    }

    let reasons = findings
        .iter()
        .map(|f| format!("{}: {}", f.detector, f.message))
        .collect();

    EvaluationResult {
        decision: PolicyDecision { status, reasons },
        findings,
    }
}

fn evaluate_tool_overrides(tool_name: &str, security: &SecurityConfig) -> Option<PolicyStatus> {
    let mut best = None;

    for (pattern, policy) in &security.tool_overrides {
        let Some(glob) = compile_glob(pattern) else {
            continue;
        };
        if glob.is_match(tool_name) {
            let status = PolicyStatus::from(policy.action);
            best = Some(best.map_or(status, |prev: PolicyStatus| prev.max(status)));
        }
    }

    best
}

fn run_detector(
    detector: &DetectorConfig,
    tool_name: &str,
    candidates: &[TextCandidate],
) -> Vec<Finding> {
    match &detector.rule {
        DetectorRuleConfig::Regex { patterns } => {
            run_regex_detector(detector, tool_name, candidates, patterns)
        }
        DetectorRuleConfig::Keyword { keywords } => {
            run_keyword_detector(detector, tool_name, candidates, keywords)
        }
        DetectorRuleConfig::Builtin { rule } => {
            run_builtin_detector(detector, tool_name, candidates, rule)
        }
        DetectorRuleConfig::HighRiskTool { patterns } => {
            run_high_risk_tool_detector(detector, tool_name, patterns)
        }
    }
}

fn run_regex_detector(
    detector: &DetectorConfig,
    tool_name: &str,
    candidates: &[TextCandidate],
    patterns: &[String],
) -> Vec<Finding> {
    let mut out = Vec::new();
    let action = PolicyStatus::from(detector.action);

    let regexes = patterns
        .iter()
        .filter_map(|pattern| Regex::new(pattern).ok())
        .collect::<Vec<_>>();

    for candidate in filter_targets(detector.target, tool_name, candidates) {
        if !detector.decode && candidate.decoded {
            continue;
        }
        for regex in &regexes {
            if regex.is_match(candidate.text.as_str()) {
                out.push(Finding {
                    detector: detector.name.clone(),
                    action,
                    path: candidate.path.clone(),
                    message: format!("regex matched: {}", regex.as_str()),
                    excerpt: clip(candidate.text.as_str()),
                });
            }
        }
    }

    out
}

fn run_keyword_detector(
    detector: &DetectorConfig,
    tool_name: &str,
    candidates: &[TextCandidate],
    keywords: &[String],
) -> Vec<Finding> {
    let mut out = Vec::new();
    let action = PolicyStatus::from(detector.action);

    for candidate in filter_targets(detector.target, tool_name, candidates) {
        if !detector.decode && candidate.decoded {
            continue;
        }

        let lowered = candidate.text.to_lowercase();
        for keyword in keywords {
            if lowered.contains(&keyword.to_lowercase()) {
                out.push(Finding {
                    detector: detector.name.clone(),
                    action,
                    path: candidate.path.clone(),
                    message: format!("keyword matched: {keyword}"),
                    excerpt: clip(candidate.text.as_str()),
                });
            }
        }
    }

    out
}

fn run_builtin_detector(
    detector: &DetectorConfig,
    tool_name: &str,
    candidates: &[TextCandidate],
    rule: &BuiltinRuleConfig,
) -> Vec<Finding> {
    let action = PolicyStatus::from(detector.action);

    match rule {
        BuiltinRuleConfig::PromptInjection => {
            let patterns = [
                "ignore previous instructions",
                "you are now system",
                "reveal system prompt",
                "do not follow prior directions",
            ];
            let mut out = Vec::new();
            for candidate in filter_targets(detector.target, tool_name, candidates) {
                if !detector.decode && candidate.decoded {
                    continue;
                }
                let lowered = candidate.text.to_lowercase();
                for pattern in patterns {
                    if lowered.contains(pattern) {
                        out.push(Finding {
                            detector: detector.name.clone(),
                            action,
                            path: candidate.path.clone(),
                            message: "builtin rule 'prompt_injection' matched".to_owned(),
                            excerpt: clip(candidate.text.as_str()),
                        });
                        break;
                    }
                }
            }
            out
        }
        BuiltinRuleConfig::CredentialEntropy {
            min_length,
            entropy_milli_threshold,
        } => run_credential_entropy_detector(
            detector,
            tool_name,
            candidates,
            *min_length,
            *entropy_milli_threshold,
        ),
        BuiltinRuleConfig::Pii { .. } => Vec::new(),
    }
}

fn run_credential_entropy_detector(
    detector: &DetectorConfig,
    tool_name: &str,
    candidates: &[TextCandidate],
    min_length: Option<usize>,
    entropy_milli_threshold: Option<u32>,
) -> Vec<Finding> {
    let action = PolicyStatus::from(detector.action);
    let mut findings = Vec::new();
    let min_length = min_length.unwrap_or(20);
    let threshold = entropy_milli_threshold.unwrap_or(3800) as f64 / 1000.0;

    for candidate in filter_targets(detector.target, tool_name, candidates) {
        if !detector.decode && candidate.decoded {
            continue;
        }

        let lower = candidate.text.to_lowercase();
        let has_context = [
            "token",
            "secret",
            "api_key",
            "apikey",
            "authorization",
            "bearer",
            "password",
        ]
        .iter()
        .any(|k| lower.contains(k));

        for token in split_word_candidates(&candidate.text) {
            if token.len() < min_length {
                continue;
            }
            if !token.chars().any(|c| c.is_ascii_digit())
                || !token.chars().any(|c| c.is_ascii_alphabetic())
            {
                continue;
            }
            let entropy = shannon_entropy(token);
            if entropy < threshold {
                continue;
            }
            if !has_context && !looks_like_credential_shape(token) {
                continue;
            }

            findings.push(Finding {
                detector: detector.name.clone(),
                action,
                path: candidate.path.clone(),
                message: format!(
                    "builtin rule 'credential_entropy' matched (entropy={:.2})",
                    entropy
                ),
                excerpt: clip(token),
            });
        }
    }

    findings
}

fn split_word_candidates(input: &str) -> impl Iterator<Item = &str> {
    input
        .split(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',' || c == ';')
        .filter(|part| !part.is_empty())
}

fn shannon_entropy(input: &str) -> f64 {
    if input.is_empty() {
        return 0.0;
    }

    let mut counts = std::collections::HashMap::<char, usize>::new();
    for ch in input.chars() {
        *counts.entry(ch).or_insert(0) += 1;
    }
    let len = input.chars().count() as f64;

    counts
        .into_values()
        .map(|count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn looks_like_credential_shape(token: &str) -> bool {
    token.starts_with("sk-")
        || token.starts_with("ghp_")
        || token.starts_with("AKIA")
        || token
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '/' | '+' | '='))
}

fn run_high_risk_tool_detector(
    detector: &DetectorConfig,
    tool_name: &str,
    patterns: &[String],
) -> Vec<Finding> {
    let action = PolicyStatus::from(detector.action);

    patterns
        .iter()
        .filter_map(|pattern| compile_glob(pattern))
        .filter(|matcher| matcher.is_match(tool_name))
        .map(|_| Finding {
            detector: detector.name.clone(),
            action,
            path: "tool".to_owned(),
            message: format!("high risk tool matched: {tool_name}"),
            excerpt: tool_name.to_owned(),
        })
        .collect()
}

fn filter_targets<'a>(
    target: DetectorTarget,
    tool_name: &'a str,
    candidates: &'a [TextCandidate],
) -> Box<dyn Iterator<Item = TextCandidate> + 'a> {
    match target {
        DetectorTarget::ToolName => Box::new(std::iter::once(TextCandidate {
            path: "tool".to_owned(),
            text: tool_name.to_owned(),
            decoded: false,
        })),
        DetectorTarget::Arguments => Box::new(candidates.iter().cloned()),
        DetectorTarget::All => Box::new(
            std::iter::once(TextCandidate {
                path: "tool".to_owned(),
                text: tool_name.to_owned(),
                decoded: false,
            })
            .chain(candidates.iter().cloned()),
        ),
    }
}

fn compile_glob(pattern: &str) -> Option<GlobMatcher> {
    let glob = Glob::new(pattern).ok()?;
    Some(glob.compile_matcher())
}

fn clip(text: &str) -> String {
    const MAX: usize = 120;
    let mut chars = text.chars();
    let clipped: String = chars.by_ref().take(MAX).collect();
    if chars.next().is_some() {
        format!("{clipped}...")
    } else {
        clipped
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::config::{
        BuiltinRuleConfig, DecodingConfig, DetectorConfig, DetectorRuleConfig, DetectorTarget,
        PiiKind as ConfigPiiKind, PolicyAction, PresetLevel, SecurityConfig, SecurityMode,
    };
    use crate::security::LocalPiiProvider;

    use super::{PolicyEngine, PolicyStatus, ToolCallInput};

    #[test]
    fn denies_on_regex_match_from_decoded_string() {
        let security = SecurityConfig {
            mode: SecurityMode::Enforce,
            presets: Vec::new(),
            preset_level: PresetLevel::Balanced,
            decoding: DecodingConfig {
                max_decode_depth: 3,
                max_decode_bytes: 4096,
            },
            detectors: vec![DetectorConfig {
                name: "secret-regex".to_owned(),
                target: DetectorTarget::Arguments,
                action: PolicyAction::Deny,
                decode: true,
                rule: DetectorRuleConfig::Regex {
                    patterns: vec!["AKIA[0-9A-Z]{16}".to_owned()],
                },
            }],
            tool_overrides: Default::default(),
        };

        let args = json!({
            "blob": "QUtJQUFCQ0RFRkdISUpLTE1OT1BRUlNUVVY="
        });
        let result = PolicyEngine::evaluate_tool_call(
            ToolCallInput {
                tool_name: "github::create_issue",
                arguments: &args,
            },
            &security,
        );

        assert_eq!(result.decision.status, PolicyStatus::Deny);
        assert!(!result.findings.is_empty());
    }

    #[test]
    fn monitor_mode_never_blocks() {
        let security = SecurityConfig {
            mode: SecurityMode::Monitor,
            presets: Vec::new(),
            preset_level: PresetLevel::Balanced,
            decoding: DecodingConfig::default(),
            detectors: vec![DetectorConfig {
                name: "tool-confirm".to_owned(),
                target: DetectorTarget::ToolName,
                action: PolicyAction::Deny,
                decode: false,
                rule: DetectorRuleConfig::HighRiskTool {
                    patterns: vec!["github::*".to_owned()],
                },
            }],
            tool_overrides: Default::default(),
        };

        let args = json!({"title": "hello"});
        let result = PolicyEngine::evaluate_tool_call(
            ToolCallInput {
                tool_name: "github::create_issue",
                arguments: &args,
            },
            &security,
        );

        assert_eq!(result.decision.status, PolicyStatus::Allow);
        assert!(!result.findings.is_empty());
    }

    #[tokio::test]
    async fn pii_rule_can_disable_specific_kinds() {
        let security = SecurityConfig {
            mode: SecurityMode::Enforce,
            presets: Vec::new(),
            preset_level: PresetLevel::Balanced,
            decoding: DecodingConfig::default(),
            detectors: vec![DetectorConfig {
                name: "pii-detector".to_owned(),
                target: DetectorTarget::Arguments,
                action: PolicyAction::Confirm,
                decode: true,
                rule: DetectorRuleConfig::Builtin {
                    rule: BuiltinRuleConfig::Pii {
                        disabled: vec![ConfigPiiKind::Email],
                    },
                },
            }],
            tool_overrides: Default::default(),
        };

        let provider = LocalPiiProvider;
        let args = json!({"text": "contact me at test@example.com or +1 415 555 2671"});
        let result =
            PolicyEngine::evaluate_with_provider("mail::send", &args, &security, &provider).await;

        assert_eq!(result.decision.status, PolicyStatus::Confirm);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.message.contains("(phone)"))
        );
        assert!(
            !result
                .findings
                .iter()
                .any(|f| f.message.contains("(email)"))
        );
    }

    #[test]
    fn detects_high_entropy_credentials() {
        let security = SecurityConfig {
            mode: SecurityMode::Enforce,
            presets: Vec::new(),
            preset_level: PresetLevel::Balanced,
            decoding: DecodingConfig::default(),
            detectors: vec![DetectorConfig {
                name: "entropy-secret".to_owned(),
                target: DetectorTarget::Arguments,
                action: PolicyAction::Deny,
                decode: true,
                rule: DetectorRuleConfig::Builtin {
                    rule: BuiltinRuleConfig::CredentialEntropy {
                        min_length: Some(20),
                        entropy_milli_threshold: Some(3500),
                    },
                },
            }],
            tool_overrides: Default::default(),
        };

        let args = json!({
            "authorization": "Bearer sk-39adFjk29Qpw82JmzR2TnP0w2Bf"
        });
        let result = PolicyEngine::evaluate_tool_call(
            ToolCallInput {
                tool_name: "http::request",
                arguments: &args,
            },
            &security,
        );

        assert_eq!(result.decision.status, PolicyStatus::Deny);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.message.contains("credential_entropy"))
        );
    }

    #[tokio::test]
    async fn provider_rule_detects_email() {
        let security = SecurityConfig {
            mode: SecurityMode::Enforce,
            presets: Vec::new(),
            preset_level: PresetLevel::Balanced,
            decoding: DecodingConfig::default(),
            detectors: vec![DetectorConfig {
                name: "provider-pii".to_owned(),
                target: DetectorTarget::Arguments,
                action: PolicyAction::Confirm,
                decode: true,
                rule: DetectorRuleConfig::Builtin {
                    rule: BuiltinRuleConfig::Pii {
                        disabled: Vec::new(),
                    },
                },
            }],
            tool_overrides: Default::default(),
        };

        let provider = LocalPiiProvider;
        let args = json!({"text":"user@example.com"});
        let result =
            PolicyEngine::evaluate_with_provider("mail::send", &args, &security, &provider).await;

        assert_eq!(result.decision.status, PolicyStatus::Confirm);
        assert!(result.findings.iter().any(|f| f.message.contains("pii")));
    }
}
