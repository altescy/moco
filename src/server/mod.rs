use std::hash::{Hash, Hasher};

use serde_json::{Value, json};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::gateway::{Gateway, ToolDescriptor};

const PROTOCOL_VERSION: &str = "2025-11-25";
const DEFAULT_TOOLS_PAGE_SIZE: usize = 32;
const MAX_TOOLS_PAGE_SIZE: usize = 128;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Default)]
struct SessionState {
    initialized: bool,
    last_toolset_hash: Option<u64>,
}

#[derive(Debug, Default)]
struct OutboundMessages {
    response: Option<Value>,
    notifications: Vec<Value>,
}

pub async fn run_stdio_server(gateway: Gateway) -> Result<(), ServerError> {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin).lines();
    let mut writer = stdout;
    let mut session = SessionState::default();

    while let Some(line) = reader.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }

        let message = match serde_json::from_str::<Value>(&line) {
            Ok(value) => value,
            Err(err) => {
                write_response(
                    &mut writer,
                    &json_rpc_error(Value::Null, -32700, format!("parse error: {err}")),
                )
                .await?;
                continue;
            }
        };

        let outbound = handle_message(&gateway, &mut session, message).await;

        for notification in outbound.notifications {
            write_response(&mut writer, &notification).await?;
        }

        if let Some(response) = outbound.response {
            write_response(&mut writer, &response).await?;
        }
    }

    Ok(())
}

async fn handle_message(
    gateway: &Gateway,
    session: &mut SessionState,
    message: Value,
) -> OutboundMessages {
    let mut outbound = OutboundMessages::default();

    let id = message.get("id").cloned();
    let Some(method) = message.get("method").and_then(Value::as_str) else {
        return outbound;
    };
    let params = message.get("params").cloned().unwrap_or_else(|| json!({}));

    if id.is_none() {
        if method == "notifications/initialized" {
            session.initialized = true;

            if let Ok(tools) = gateway.list_tools().await {
                let hash = toolset_hash(&tools);
                if session.last_toolset_hash != Some(hash) {
                    session.last_toolset_hash = Some(hash);
                    outbound.notifications.push(json_rpc_notification(
                        "notifications/tools/list_changed",
                        None,
                    ));
                }
            }
        }
        return outbound;
    }

    let id = id.unwrap_or(Value::Null);

    if method != "initialize" && method != "ping" && !session.initialized {
        outbound.response = Some(json_rpc_error(
            id,
            -32002,
            "server is not initialized; send notifications/initialized first",
        ));
        return outbound;
    }

    match method {
        "initialize" => {
            let _client_version = params.get("protocolVersion").and_then(Value::as_str);
            session.initialized = true;
            let result = json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {
                        "listChanged": true
                    }
                },
                "serverInfo": {
                    "name": "moco",
                    "version": env!("CARGO_PKG_VERSION")
                }
            });
            outbound.response = Some(json_rpc_result(id, result));
        }
        "ping" => {
            outbound.response = Some(json_rpc_result(id, json!({})));
        }
        "tools/list" => match gateway.list_tools().await {
            Ok(mut tools) => {
                tools.sort_by(|a, b| a.name.cmp(&b.name));

                let hash = toolset_hash(&tools);
                if session
                    .last_toolset_hash
                    .is_some_and(|last_hash| last_hash != hash)
                {
                    outbound.notifications.push(json_rpc_notification(
                        "notifications/tools/list_changed",
                        None,
                    ));
                }
                session.last_toolset_hash = Some(hash);

                let cursor = params
                    .get("cursor")
                    .and_then(Value::as_str)
                    .and_then(parse_cursor)
                    .unwrap_or(0);
                let page_size = params
                    .get("pageSize")
                    .and_then(Value::as_u64)
                    .map(|v| v as usize)
                    .unwrap_or(DEFAULT_TOOLS_PAGE_SIZE)
                    .clamp(1, MAX_TOOLS_PAGE_SIZE);

                let total_tools = tools.len();
                let page = tools
                    .into_iter()
                    .skip(cursor)
                    .take(page_size)
                    .map(|tool| {
                        json!({
                            "name": tool.name,
                            "description": tool.description,
                            "inputSchema": tool.input_schema
                        })
                    })
                    .collect::<Vec<_>>();

                let consumed = cursor.saturating_add(page.len());
                let mut result = json!({ "tools": page });
                if consumed < total_tools {
                    result["nextCursor"] = Value::String(format!("offset:{consumed}"));
                }

                outbound.response = Some(json_rpc_result(id, result));
            }
            Err(err) => {
                outbound.response = Some(json_rpc_error(
                    id,
                    -32000,
                    format!("tools/list failed: {err}"),
                ));
            }
        },
        "tools/call" => {
            let Some(name) = params.get("name").and_then(Value::as_str) else {
                outbound.response =
                    Some(json_rpc_error(id, -32602, "missing tools/call params.name"));
                return outbound;
            };
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));

            let call_result = gateway.call_tool_for_mcp(name, &arguments).await;

            outbound.response = Some(json_rpc_result(
                id,
                json!({
                    "content": call_result.content,
                    "isError": call_result.is_error,
                }),
            ));

            if let Ok(mut tools) = gateway.list_tools().await {
                tools.sort_by(|a, b| a.name.cmp(&b.name));
                let hash = toolset_hash(&tools);
                if session
                    .last_toolset_hash
                    .is_some_and(|last_hash| last_hash != hash)
                {
                    outbound.notifications.push(json_rpc_notification(
                        "notifications/tools/list_changed",
                        None,
                    ));
                }
                session.last_toolset_hash = Some(hash);
            }
        }
        _ => {
            outbound.response = Some(json_rpc_error(
                id,
                -32601,
                format!("method not found: {method}"),
            ));
        }
    }

    outbound
}

async fn write_response<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    value: &Value,
) -> Result<(), std::io::Error> {
    let serialized = serde_json::to_string(value)
        .map_err(|err| std::io::Error::other(format!("failed to serialize response: {err}")))?;
    writer.write_all(serialized.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await
}

fn json_rpc_notification(method: &str, params: Option<Value>) -> Value {
    let mut payload = json!({
        "jsonrpc": "2.0",
        "method": method,
    });
    if let Some(params) = params {
        payload["params"] = params;
    }
    payload
}

fn parse_cursor(cursor: &str) -> Option<usize> {
    let value = cursor.strip_prefix("offset:")?;
    value.parse::<usize>().ok()
}

fn toolset_hash(tools: &[ToolDescriptor]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for tool in tools {
        tool.name.hash(&mut hasher);
    }
    hasher.finish()
}

fn json_rpc_result(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })
}

fn json_rpc_error(id: Value, code: i64, message: impl AsRef<str>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message.as_ref()
        }
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use serde_json::json;

    use crate::config::{DecodingConfig, PresetLevel, SecurityConfig, SecurityMode};
    use crate::gateway::{DownstreamClient, DownstreamError, ToolCallResult, ToolDescriptor};

    use super::*;

    struct MockDownstream;

    #[async_trait]
    impl DownstreamClient for MockDownstream {
        async fn list_tools(&self) -> Result<Vec<ToolDescriptor>, DownstreamError> {
            Ok(vec![
                ToolDescriptor {
                    name: "search".to_owned(),
                    description: Some("search tool".to_owned()),
                    input_schema: json!({"type":"object"}),
                },
                ToolDescriptor {
                    name: "fetch".to_owned(),
                    description: Some("fetch tool".to_owned()),
                    input_schema: json!({"type":"object"}),
                },
                ToolDescriptor {
                    name: "summarize".to_owned(),
                    description: Some("summarize tool".to_owned()),
                    input_schema: json!({"type":"object"}),
                },
            ])
        }

        async fn call_tool(
            &self,
            _tool_name: &str,
            _arguments: &Value,
        ) -> Result<ToolCallResult, DownstreamError> {
            Ok(ToolCallResult {
                content: json!([{"type":"text","text":"ok"}]),
                is_error: false,
            })
        }
    }

    fn gateway() -> Gateway {
        let security = SecurityConfig {
            mode: SecurityMode::Enforce,
            presets: Vec::new(),
            preset_level: PresetLevel::Balanced,
            decoding: DecodingConfig::default(),
            detectors: Vec::new(),
            tool_overrides: Default::default(),
        };
        let mut gateway = Gateway::new(security);
        gateway.register_downstream("mock", Arc::new(MockDownstream));
        gateway
    }

    #[tokio::test]
    async fn initialize_then_tools_list() {
        let gateway = gateway();
        let mut session = SessionState::default();

        let init = handle_message(
            &gateway,
            &mut session,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name":"x","version":"1"}}
            }),
        )
        .await;
        assert!(init.response.is_some());

        let notif = handle_message(
            &gateway,
            &mut session,
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        )
        .await;
        assert!(notif.response.is_none());

        let list = handle_message(
            &gateway,
            &mut session,
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
        )
        .await
        .response
        .expect("tools/list response expected");
        let tools = list
            .get("result")
            .and_then(|v| v.get("tools"))
            .and_then(Value::as_array)
            .expect("tools array missing");
        assert_eq!(tools.len(), 3);
        assert!(
            tools
                .iter()
                .any(|tool| tool.get("name") == Some(&json!("mock::search")))
        );
    }

    #[tokio::test]
    async fn initialize_allows_tools_list_without_initialized_notification() {
        let gateway = gateway();
        let mut session = SessionState::default();

        let init = handle_message(
            &gateway,
            &mut session,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name":"x","version":"1"}}
            }),
        )
        .await;
        assert!(init.response.is_some());

        let list = handle_message(
            &gateway,
            &mut session,
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
        )
        .await;

        assert!(list.response.is_some());
    }

    #[tokio::test]
    async fn tools_list_supports_pagination() {
        let gateway = gateway();
        let mut session = SessionState {
            initialized: true,
            last_toolset_hash: None,
        };

        let first = handle_message(
            &gateway,
            &mut session,
            json!({
                "jsonrpc":"2.0",
                "id":1,
                "method":"tools/list",
                "params":{"pageSize":2}
            }),
        )
        .await
        .response
        .expect("first page response expected");

        let first_result = first.get("result").expect("result missing");
        let first_tools = first_result
            .get("tools")
            .and_then(Value::as_array)
            .expect("tools missing");
        assert_eq!(first_tools.len(), 2);
        let next_cursor = first_result
            .get("nextCursor")
            .and_then(Value::as_str)
            .expect("nextCursor missing")
            .to_owned();

        let second = handle_message(
            &gateway,
            &mut session,
            json!({
                "jsonrpc":"2.0",
                "id":2,
                "method":"tools/list",
                "params":{"pageSize":2,"cursor":next_cursor}
            }),
        )
        .await
        .response
        .expect("second page response expected");

        let second_tools = second
            .get("result")
            .and_then(|v| v.get("tools"))
            .and_then(Value::as_array)
            .expect("tools missing");
        assert!(!second_tools.is_empty());
    }

    #[tokio::test]
    async fn rejects_request_before_initialized_notification() {
        let gateway = gateway();
        let mut session = SessionState::default();

        let response = handle_message(
            &gateway,
            &mut session,
            json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}),
        )
        .await
        .response
        .expect("response expected");

        let code = response
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(Value::as_i64)
            .expect("error code missing");
        assert_eq!(code, -32002);
    }
}
