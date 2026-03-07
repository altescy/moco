use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NamespaceError {
    #[error("invalid namespaced tool name: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespacedTool {
    pub server: String,
    pub tool: String,
}

impl NamespacedTool {
    #[must_use]
    pub fn as_full_name(&self) -> String {
        format!("{}::{}", self.server, self.tool)
    }
}

pub fn parse_namespaced_tool(full_name: &str) -> Result<NamespacedTool, NamespaceError> {
    let Some((server, tool)) = full_name.split_once("::") else {
        return Err(NamespaceError::Invalid(full_name.to_owned()));
    };

    if server.is_empty() || tool.is_empty() {
        return Err(NamespaceError::Invalid(full_name.to_owned()));
    }

    Ok(NamespacedTool {
        server: server.to_owned(),
        tool: tool.to_owned(),
    })
}

#[must_use]
pub fn make_namespaced_tool(server: &str, tool: &str) -> String {
    format!("{server}::{tool}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_format_roundtrip() {
        let parsed = parse_namespaced_tool("github::create_issue").expect("parse failed");
        assert_eq!(parsed.server, "github");
        assert_eq!(parsed.tool, "create_issue");
        assert_eq!(parsed.as_full_name(), "github::create_issue");
    }

    #[test]
    fn rejects_invalid_names() {
        assert!(parse_namespaced_tool("invalid").is_err());
        assert!(parse_namespaced_tool("::tool").is_err());
        assert!(parse_namespaced_tool("server::").is_err());
    }
}
