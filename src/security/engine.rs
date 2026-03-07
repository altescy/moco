use email_address::EmailAddress;
use globset::{Glob, GlobMatcher};
use phonenumber::{Mode, parse};
use regex::Regex;
use serde_json::Value;

use crate::config::{
    DetectorConfig, DetectorTarget, DetectorType, PolicyAction, SecurityConfig, SecurityMode,
};

use super::decoder::{TextCandidate, extract_text_candidates};
use super::pii::PiiProvider;

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
            let Some(rule) = detector.rule.as_deref() else {
                continue;
            };
            if detector.detector_type != DetectorType::Builtin
                || (rule != "pii" && rule != "pii_provider")
            {
                continue;
            }

            let action = PolicyStatus::from(detector.action);
            for candidate in filter_targets(detector.target, tool_name, &candidates) {
                if !detector.decode && candidate.decoded {
                    continue;
                }

                let matches = provider.detect(&candidate.text).await;
                for matched in matches {
                    findings.push(Finding {
                        detector: detector.name.clone(),
                        action,
                        path: candidate.path.clone(),
                        message: format!(
                            "builtin rule '{rule}' matched via {} ({})",
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

    if include_tool_overrides && let Some(status) = evaluate_tool_overrides(tool_name, security) {
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
    match detector.detector_type {
        DetectorType::Regex => run_regex_detector(detector, tool_name, candidates),
        DetectorType::Keyword => run_keyword_detector(detector, tool_name, candidates),
        DetectorType::Builtin => run_builtin_detector(detector, tool_name, candidates),
        DetectorType::HighRiskTool => run_high_risk_tool_detector(detector, tool_name),
    }
}

fn run_regex_detector(
    detector: &DetectorConfig,
    tool_name: &str,
    candidates: &[TextCandidate],
) -> Vec<Finding> {
    let mut out = Vec::new();
    let action = PolicyStatus::from(detector.action);

    let regexes = detector
        .patterns
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
) -> Vec<Finding> {
    let mut out = Vec::new();
    let action = PolicyStatus::from(detector.action);

    for candidate in filter_targets(detector.target, tool_name, candidates) {
        if !detector.decode && candidate.decoded {
            continue;
        }

        let lowered = candidate.text.to_lowercase();
        for keyword in &detector.keywords {
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
) -> Vec<Finding> {
    let Some(rule) = detector.rule.as_deref() else {
        return Vec::new();
    };
    let action = PolicyStatus::from(detector.action);

    match rule {
        "prompt_injection" => {
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
                            message: format!("builtin rule '{rule}' matched"),
                            excerpt: clip(candidate.text.as_str()),
                        });
                        break;
                    }
                }
            }
            out
        }
        "pii_email" => run_pii_email_detector(detector, tool_name, candidates),
        "pii_phone" => run_pii_phone_detector(detector, tool_name, candidates),
        "pii_address_basic" => run_pii_address_basic_detector(detector, tool_name, candidates),
        "credential_entropy" => run_credential_entropy_detector(detector, tool_name, candidates),
        _ => Vec::new(),
    }
}

fn run_pii_email_detector(
    detector: &DetectorConfig,
    tool_name: &str,
    candidates: &[TextCandidate],
) -> Vec<Finding> {
    let action = PolicyStatus::from(detector.action);
    let mut findings = Vec::new();

    for candidate in filter_targets(detector.target, tool_name, candidates) {
        if !detector.decode && candidate.decoded {
            continue;
        }

        for token in split_word_candidates(&candidate.text) {
            if token.contains('@') && EmailAddress::is_valid(token) {
                findings.push(Finding {
                    detector: detector.name.clone(),
                    action,
                    path: candidate.path.clone(),
                    message: "builtin rule 'pii_email' matched".to_owned(),
                    excerpt: clip(token),
                });
            }
        }
    }

    findings
}

fn run_pii_phone_detector(
    detector: &DetectorConfig,
    tool_name: &str,
    candidates: &[TextCandidate],
) -> Vec<Finding> {
    let action = PolicyStatus::from(detector.action);
    let mut findings = Vec::new();

    for candidate in filter_targets(detector.target, tool_name, candidates) {
        if !detector.decode && candidate.decoded {
            continue;
        }

        for token in extract_phone_candidates(&candidate.text) {
            let parsed = parse(None, token);

            if let Ok(number) = parsed {
                if !number.is_valid() {
                    continue;
                }
                findings.push(Finding {
                    detector: detector.name.clone(),
                    action,
                    path: candidate.path.clone(),
                    message: "builtin rule 'pii_phone' matched".to_owned(),
                    excerpt: clip(&number.format().mode(Mode::E164).to_string()),
                });
            }
        }
    }

    findings
}

fn run_pii_address_basic_detector(
    detector: &DetectorConfig,
    tool_name: &str,
    candidates: &[TextCandidate],
) -> Vec<Finding> {
    let action = PolicyStatus::from(detector.action);
    let mut findings = Vec::new();

    let jp_postal = Regex::new(r"\b\d{3}-\d{4}\b").expect("valid regex");
    let us_street = Regex::new(
        r"\b\d{1,6}\s+[A-Za-z0-9.\-\s]+\s(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd)\b",
    )
    .expect("valid regex");

    for candidate in filter_targets(detector.target, tool_name, candidates) {
        if !detector.decode && candidate.decoded {
            continue;
        }
        if jp_postal.is_match(&candidate.text) || us_street.is_match(&candidate.text) {
            findings.push(Finding {
                detector: detector.name.clone(),
                action,
                path: candidate.path.clone(),
                message: "builtin rule 'pii_address_basic' matched".to_owned(),
                excerpt: clip(candidate.text.as_str()),
            });
        }
    }

    findings
}

fn run_credential_entropy_detector(
    detector: &DetectorConfig,
    tool_name: &str,
    candidates: &[TextCandidate],
) -> Vec<Finding> {
    let action = PolicyStatus::from(detector.action);
    let mut findings = Vec::new();
    let min_length = detector.min_length.unwrap_or(20);
    let threshold = detector.entropy_milli_threshold.unwrap_or(3800) as f64 / 1000.0;

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

fn extract_phone_candidates(input: &str) -> impl Iterator<Item = &str> {
    input
        .split(|c: char| !(c.is_ascii_digit() || matches!(c, '+' | '-' | '(' | ')' | ' ')))
        .filter(|part| {
            let digits = part.chars().filter(|ch| ch.is_ascii_digit()).count();
            digits >= 10
        })
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

fn run_high_risk_tool_detector(detector: &DetectorConfig, tool_name: &str) -> Vec<Finding> {
    let action = PolicyStatus::from(detector.action);

    detector
        .patterns
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
        DecodingConfig, DetectorConfig, DetectorTarget, DetectorType, PolicyAction, PresetLevel,
        SecurityConfig, SecurityMode,
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
                detector_type: DetectorType::Regex,
                target: DetectorTarget::Arguments,
                patterns: vec!["AKIA[0-9A-Z]{16}".to_owned()],
                action: PolicyAction::Deny,
                decode: true,
                ..Default::default()
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
                detector_type: DetectorType::HighRiskTool,
                target: DetectorTarget::ToolName,
                patterns: vec!["github::*".to_owned()],
                action: PolicyAction::Deny,
                decode: false,
                ..Default::default()
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

    #[test]
    fn detects_email_with_builtin_rule() {
        let security = SecurityConfig {
            mode: SecurityMode::Enforce,
            presets: Vec::new(),
            preset_level: PresetLevel::Balanced,
            decoding: DecodingConfig::default(),
            detectors: vec![DetectorConfig {
                name: "email-detector".to_owned(),
                detector_type: DetectorType::Builtin,
                rule: Some("pii_email".to_owned()),
                target: DetectorTarget::Arguments,
                action: PolicyAction::Confirm,
                decode: true,
                ..Default::default()
            }],
            tool_overrides: Default::default(),
        };

        let args = json!({"text": "contact me at test@example.com"});
        let result = PolicyEngine::evaluate_tool_call(
            ToolCallInput {
                tool_name: "mail::send",
                arguments: &args,
            },
            &security,
        );

        assert_eq!(result.decision.status, PolicyStatus::Confirm);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.message.contains("pii_email"))
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
                detector_type: DetectorType::Builtin,
                rule: Some("credential_entropy".to_owned()),
                target: DetectorTarget::Arguments,
                action: PolicyAction::Deny,
                decode: true,
                min_length: Some(20),
                entropy_milli_threshold: Some(3500),
                ..Default::default()
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
                detector_type: DetectorType::Builtin,
                rule: Some("pii".to_owned()),
                target: DetectorTarget::Arguments,
                action: PolicyAction::Confirm,
                decode: true,
                ..Default::default()
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
