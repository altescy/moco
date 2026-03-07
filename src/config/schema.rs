use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

const DEFAULT_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_MAX_DECODE_DEPTH: usize = 4;
const DEFAULT_MAX_DECODE_BYTES: usize = 262_144;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SecurityMode {
    Off,
    Monitor,
    #[default]
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PresetLevel {
    Monitor,
    #[default]
    Balanced,
    Strict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    #[default]
    Allow,
    Confirm,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TransportType {
    #[default]
    Stdio,
    StreamableHttp,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct RawConfig {
    pub mcp: Option<RawMcpConfig>,
    pub security: Option<RawSecurityConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct RawMcpConfig {
    pub default_timeout_ms: Option<u64>,
    pub servers: BTreeMap<String, ServerConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub transport: TransportType,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub url: Option<String>,
    pub headers: BTreeMap<String, String>,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct RawSecurityConfig {
    pub mode: Option<SecurityMode>,
    pub presets: Vec<String>,
    pub preset_level: Option<PresetLevel>,
    pub max_decode_depth: Option<usize>,
    pub max_decode_bytes: Option<usize>,
    pub detectors: Vec<DetectorConfig>,
    pub tool_overrides: BTreeMap<String, ToolPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ToolPolicy {
    pub action: PolicyAction,
    pub reason: Option<String>,
}

impl Default for ToolPolicy {
    fn default() -> Self {
        Self {
            action: PolicyAction::Allow,
            reason: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DetectorType {
    Regex,
    Keyword,
    Builtin,
    #[default]
    HighRiskTool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DetectorTarget {
    ToolName,
    #[default]
    Arguments,
    All,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct DetectorConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub detector_type: DetectorType,
    pub target: DetectorTarget,
    pub patterns: Vec<String>,
    pub keywords: Vec<String>,
    pub rule: Option<String>,
    pub region: Option<String>,
    pub min_length: Option<usize>,
    pub entropy_milli_threshold: Option<u32>,
    pub action: PolicyAction,
    pub decode: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodingConfig {
    pub max_decode_depth: usize,
    pub max_decode_bytes: usize,
}

impl Default for DecodingConfig {
    fn default() -> Self {
        Self {
            max_decode_depth: DEFAULT_MAX_DECODE_DEPTH,
            max_decode_bytes: DEFAULT_MAX_DECODE_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityConfig {
    pub mode: SecurityMode,
    pub presets: Vec<String>,
    pub preset_level: PresetLevel,
    pub decoding: DecodingConfig,
    pub detectors: Vec<DetectorConfig>,
    pub tool_overrides: HashMap<String, ToolPolicy>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            mode: SecurityMode::Enforce,
            presets: Vec::new(),
            preset_level: PresetLevel::Balanced,
            decoding: DecodingConfig::default(),
            detectors: Vec::new(),
            tool_overrides: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpConfig {
    pub default_timeout_ms: u64,
    pub servers: HashMap<String, ServerConfig>,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            default_timeout_ms: DEFAULT_TIMEOUT_MS,
            servers: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResolvedConfig {
    pub mcp: McpConfig,
    pub security: SecurityConfig,
}

impl RawConfig {
    pub fn merge(mut self, overlay: Self) -> Self {
        match (self.mcp.as_mut(), overlay.mcp) {
            (Some(base), Some(ov)) => base.merge(ov),
            (None, Some(ov)) => self.mcp = Some(ov),
            _ => {}
        }

        match (self.security.as_mut(), overlay.security) {
            (Some(base), Some(ov)) => base.merge(ov),
            (None, Some(ov)) => self.security = Some(ov),
            _ => {}
        }

        self
    }

    pub fn resolve(self) -> ResolvedConfig {
        let mut resolved = ResolvedConfig::default();

        if let Some(mcp) = self.mcp {
            if let Some(timeout) = mcp.default_timeout_ms {
                resolved.mcp.default_timeout_ms = timeout;
            }
            resolved.mcp.servers = mcp.servers.into_iter().collect();
        }

        if let Some(sec) = self.security {
            if let Some(mode) = sec.mode {
                resolved.security.mode = mode;
            }
            if !sec.presets.is_empty() {
                resolved.security.presets = sec.presets.clone();
            }
            if let Some(level) = sec.preset_level {
                resolved.security.preset_level = level;
            }
            if let Some(depth) = sec.max_decode_depth {
                resolved.security.decoding.max_decode_depth = depth;
            }
            if let Some(bytes) = sec.max_decode_bytes {
                resolved.security.decoding.max_decode_bytes = bytes;
            }

            let mut detectors_by_name = BTreeMap::new();
            for detector in
                build_preset_detectors(&resolved.security.presets, resolved.security.preset_level)
            {
                detectors_by_name.insert(detector.name.clone(), detector);
            }
            for detector in sec.detectors {
                detectors_by_name.insert(detector.name.clone(), detector);
            }
            resolved.security.detectors = detectors_by_name.into_values().collect();
            resolved.security.tool_overrides = sec.tool_overrides.into_iter().collect();
        }

        resolved
    }
}

impl RawMcpConfig {
    fn merge(&mut self, overlay: Self) {
        if overlay.default_timeout_ms.is_some() {
            self.default_timeout_ms = overlay.default_timeout_ms;
        }
        self.servers.extend(overlay.servers);
    }
}

impl RawSecurityConfig {
    fn merge(&mut self, overlay: Self) {
        if overlay.mode.is_some() {
            self.mode = overlay.mode;
        }
        if !overlay.presets.is_empty() {
            self.presets = overlay.presets;
        }
        if overlay.preset_level.is_some() {
            self.preset_level = overlay.preset_level;
        }
        if overlay.max_decode_depth.is_some() {
            self.max_decode_depth = overlay.max_decode_depth;
        }
        if overlay.max_decode_bytes.is_some() {
            self.max_decode_bytes = overlay.max_decode_bytes;
        }

        let mut merged_by_name = BTreeMap::new();
        for detector in self.detectors.drain(..) {
            merged_by_name.insert(detector.name.clone(), detector);
        }
        for detector in overlay.detectors {
            merged_by_name.insert(detector.name.clone(), detector);
        }
        self.detectors = merged_by_name.into_values().collect();

        self.tool_overrides.extend(overlay.tool_overrides);
    }
}

fn build_preset_detectors(presets: &[String], level: PresetLevel) -> Vec<DetectorConfig> {
    let mut out = Vec::new();
    for preset in presets {
        match preset.as_str() {
            "pii-basic" => {
                out.push(DetectorConfig {
                    name: "preset::pii-basic::provider".to_owned(),
                    detector_type: DetectorType::Builtin,
                    target: DetectorTarget::Arguments,
                    rule: Some("pii".to_owned()),
                    action: match level {
                        PresetLevel::Strict => PolicyAction::Deny,
                        _ => PolicyAction::Confirm,
                    },
                    decode: true,
                    ..Default::default()
                });
            }
            "credential-standard" => {
                out.push(DetectorConfig {
                    name: "preset::credential-standard::entropy".to_owned(),
                    detector_type: DetectorType::Builtin,
                    target: DetectorTarget::Arguments,
                    rule: Some("credential_entropy".to_owned()),
                    action: match level {
                        PresetLevel::Monitor => PolicyAction::Confirm,
                        _ => PolicyAction::Deny,
                    },
                    decode: true,
                    min_length: Some(20),
                    entropy_milli_threshold: Some(3800),
                    ..Default::default()
                });
                out.push(DetectorConfig {
                    name: "preset::credential-standard::regex".to_owned(),
                    detector_type: DetectorType::Regex,
                    target: DetectorTarget::Arguments,
                    patterns: vec![
                        "AKIA[0-9A-Z]{16}".to_owned(),
                        "gh[pousr]_[A-Za-z0-9_]{20,}".to_owned(),
                        "sk-[A-Za-z0-9]{20,}".to_owned(),
                    ],
                    action: match level {
                        PresetLevel::Monitor => PolicyAction::Confirm,
                        _ => PolicyAction::Deny,
                    },
                    decode: true,
                    ..Default::default()
                });
            }
            "prompt-injection-basic" => {
                out.push(DetectorConfig {
                    name: "preset::prompt-injection-basic".to_owned(),
                    detector_type: DetectorType::Builtin,
                    target: DetectorTarget::Arguments,
                    rule: Some("prompt_injection".to_owned()),
                    action: match level {
                        PresetLevel::Strict => PolicyAction::Deny,
                        _ => PolicyAction::Confirm,
                    },
                    decode: true,
                    ..Default::default()
                });
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_detector_by_name() {
        let base = RawConfig {
            security: Some(RawSecurityConfig {
                detectors: vec![DetectorConfig {
                    name: "d1".to_owned(),
                    detector_type: DetectorType::Keyword,
                    keywords: vec!["old".to_owned()],
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let overlay = RawConfig {
            security: Some(RawSecurityConfig {
                detectors: vec![DetectorConfig {
                    name: "d1".to_owned(),
                    detector_type: DetectorType::Keyword,
                    keywords: vec!["new".to_owned()],
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };

        let merged = base.merge(overlay);
        let resolved = merged.resolve();
        assert_eq!(resolved.security.detectors.len(), 1);
        assert_eq!(resolved.security.detectors[0].keywords, vec!["new"]);
    }

    #[test]
    fn expands_presets() {
        let raw = RawConfig {
            security: Some(RawSecurityConfig {
                presets: vec!["pii-basic".to_owned(), "credential-standard".to_owned()],
                preset_level: Some(PresetLevel::Balanced),
                ..Default::default()
            }),
            ..Default::default()
        };

        let resolved = raw.resolve();
        assert!(
            resolved
                .security
                .detectors
                .iter()
                .any(|d| d.name == "preset::pii-basic::provider")
        );
        assert!(
            resolved
                .security
                .detectors
                .iter()
                .any(|d| d.name == "preset::credential-standard::entropy")
        );
    }
}
